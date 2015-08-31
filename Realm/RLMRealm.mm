////////////////////////////////////////////////////////////////////////////
//
// Copyright 2014 Realm Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////

#import "RLMRealm_Private.hpp"

#import "RLMAnalytics.hpp"
#import "RLMArray_Private.hpp"
#import "RLMRealmConfiguration_Private.h"
#import "RLMMigration_Private.h"
#import "RLMObjectSchema_Private.hpp"
#import "RLMProperty_Private.h"
#import "RLMObjectStore.h"
#import "RLMObject_Private.h"
#import "RLMObject_Private.hpp"
#import "RLMObservation.hpp"
#import "RLMProperty.h"
#import "RLMQueryUtil.hpp"
#import "RLMRealmUtil.h"
#import "RLMSchema_Private.h"
#import "RLMUpdateChecker.hpp"
#import "RLMUtil.hpp"

#include "object_store.hpp"
#include "shared_realm.hpp"
#include <realm/commit_log.hpp>
#include <realm/disable_sync_to_disk.hpp>
#include <realm/version.hpp>

using namespace std;
using namespace realm;
using namespace realm::util;

@interface RLMSchema ()
+ (instancetype)dynamicSchemaFromObjectStoreSchema:(realm::Schema &)objectStoreSchema;
@end

void RLMDisableSyncToDisk() {
    realm::disable_sync_to_disk();
}

// Notification Token

@interface RLMNotificationToken () {
@public
    Realm::NotificationFunction _notification;
}
@end

@implementation RLMNotificationToken
- (void)dealloc
{
    if (_notification) {
        NSLog(@"RLMNotificationToken released without unregistering a notification. You must hold "
              @"on to the RLMNotificationToken returned from addNotificationBlock and call "
              @"removeNotification: when you no longer wish to recieve RLMRealm notifications.");
    }
    _notification.reset();
}
@end

using namespace std;
using namespace realm;
using namespace realm::util;

//
// Global encryption key cache and validation
//

static bool shouldForciblyDisableEncryption()
{
    static bool disableEncryption = getenv("REALM_DISABLE_ENCRYPTION");
    return disableEncryption;
}

static NSMutableDictionary *s_keysPerPath = [NSMutableDictionary new];
static NSData *keyForPath(NSString *path) {
    if (shouldForciblyDisableEncryption()) {
        return nil;
    }

    @synchronized (s_keysPerPath) {
        return s_keysPerPath[path];
    }
}

static void clearKeyCache() {
    @synchronized(s_keysPerPath) {
        [s_keysPerPath removeAllObjects];
    }
}

NSData *RLMRealmValidatedEncryptionKey(NSData *key) {
    if (shouldForciblyDisableEncryption()) {
        return nil;
    }

    if (key) {
        if (key.length != 64) {
            @throw RLMException(@"Encryption key must be exactly 64 bytes long");
        }
        if (RLMIsDebuggerAttached()) {
            @throw RLMException(@"Cannot open an encrypted Realm with a debugger attached to the process");
        }
#if TARGET_OS_WATCH
        @throw RLMException(@"Cannot open an encrypted Realm on watchOS.");
#endif
    }

    return key;
}

static void setKeyForPath(NSData *key, NSString *path) {
    key = RLMRealmValidatedEncryptionKey(key);
    @synchronized (s_keysPerPath) {
        if (key) {
            s_keysPerPath[path] = key;
        }
        else {
            [s_keysPerPath removeObjectForKey:path];
        }
    }
}

//
// Schema version and migration blocks
//
static NSMutableDictionary *s_migrationBlocks = [NSMutableDictionary new];
static NSMutableDictionary *s_schemaVersions = [NSMutableDictionary new];

static NSUInteger schemaVersionForPath(NSString *path) {
    @synchronized(s_migrationBlocks) {
        NSNumber *version = s_schemaVersions[path];
        if (version) {
            return [version unsignedIntegerValue];
        }
        return 0;
    }
}

static RLMMigrationBlock migrationBlockForPath(NSString *path) {
    @synchronized(s_migrationBlocks) {
        return s_migrationBlocks[path];
    }
}

static void clearMigrationCache() {
    @synchronized(s_migrationBlocks) {
        [s_migrationBlocks removeAllObjects];
        [s_schemaVersions removeAllObjects];
    }
}

void RLMRealmAddPathSettingsToConfiguration(RLMRealmConfiguration *configuration) {
    if (!configuration.encryptionKey) {
        configuration.encryptionKey = keyForPath(configuration.path);
    }
    if (!configuration.migrationBlock) {
        configuration.migrationBlock = migrationBlockForPath(configuration.path);
    }
    if (configuration.schemaVersion == 0) {
        configuration.schemaVersion = schemaVersionForPath(configuration.path);
    }
}

@implementation RLMRealm {
    NSHashTable *_collectionEnumerators;
}

@dynamic path;
@dynamic readOnly;
@dynamic inWriteTransaction;
@dynamic group;
@dynamic autorefresh;

+ (BOOL)isCoreDebug {
    return realm::Version::has_feature(realm::feature_Debug);
}

+ (void)initialize {
    static bool initialized;
    if (initialized) {
        return;
    }
    initialized = true;

    RLMCheckForUpdates();
    RLMInstallUncaughtExceptionHandler();
    RLMSendAnalytics();
}

- (void)verifyThread {
    _realm->verify_thread();
}

- (BOOL)inWriteTransaction {
    return _realm->is_in_transaction();
}

- (NSString *)path {
    return @(_realm->config().path.c_str());
}

- (realm::Group *)group {
    return _realm->read_group();
}

- (BOOL)isReadOnly {
    return _realm->config().read_only;
}

-(BOOL)autorefresh {
    return _realm->auto_refresh();
}

- (void)setAutorefresh:(BOOL)autorefresh {
    _realm->set_auto_refresh(autorefresh);
}

+ (NSString *)defaultRealmPath
{
    return [RLMRealmConfiguration defaultConfiguration].path;
}

+ (void)setDefaultRealmPath:(NSString *)defaultRealmPath {
    [RLMRealmConfiguration setDefaultPath:defaultRealmPath];
}

+ (NSString *)writeableTemporaryPathForFile:(NSString *)fileName
{
    return [NSTemporaryDirectory() stringByAppendingPathComponent:fileName];
}

+ (instancetype)defaultRealm
{
    RLMRealmConfiguration *configuration = [RLMRealmConfiguration defaultConfiguration];
    RLMRealmAddPathSettingsToConfiguration(configuration);
    return [RLMRealm realmWithConfiguration:configuration error:nil];
}

+ (instancetype)realmWithPath:(NSString *)path
{
    return [self realmWithPath:path key:nil readOnly:false inMemory:false dynamic:false schema:nil error:nil];
}

+ (instancetype)realmWithPath:(NSString *)path
                     readOnly:(BOOL)readonly
                        error:(NSError **)outError
{
    return [self realmWithPath:path key:nil readOnly:readonly inMemory:NO dynamic:NO schema:nil error:outError];
}

+ (instancetype)inMemoryRealmWithIdentifier:(NSString *)identifier {
    RLMRealmConfiguration *configuration = [[RLMRealmConfiguration alloc] init];
    configuration.inMemoryIdentifier = identifier;
    return [RLMRealm realmWithConfiguration:configuration error:nil];
}

+ (instancetype)realmWithPath:(NSString *)path
                encryptionKey:(NSData *)key
                     readOnly:(BOOL)readonly
                        error:(NSError **)error
{
    if (!key) {
        @throw RLMException(@"Encryption key must not be nil");
    }

    return [self realmWithPath:path key:key readOnly:readonly inMemory:NO dynamic:NO schema:nil error:error];
}

+ (instancetype)realmWithPath:(NSString *)path
                          key:(NSData *)key
                     readOnly:(BOOL)readonly
                     inMemory:(BOOL)inMemory
                      dynamic:(BOOL)dynamic
                       schema:(RLMSchema *)customSchema
                        error:(NSError **)outError
{
    RLMRealmConfiguration *configuration = [[RLMRealmConfiguration alloc] init];
    configuration.path = path;
    configuration.inMemoryIdentifier = inMemory ? path.lastPathComponent : nil;
    configuration.encryptionKey = key;
    configuration.readOnly = readonly;
    configuration.dynamic = dynamic;
    configuration.customSchema = customSchema;
    configuration.migrationBlock = migrationBlockForPath(path);
    configuration.schemaVersion = schemaVersionForPath(path);
    return [RLMRealm realmWithConfiguration:configuration error:outError];
}

// ARC tries to eliminate calls to autorelease when the value is then immediately
// returned, but this results in significantly different semantics between debug
// and release builds for RLMRealm, so force it to always autorelease.
static id RLMAutorelease(id value) {
    // +1 __bridge_retained, -1 CFAutorelease
    return value ? (__bridge id)CFAutorelease((__bridge_retained CFTypeRef)value) : nil;
}

static void RLMCopyColumnMapping(RLMObjectSchema *targetSchema, const ObjectSchema &tableSchema) {
    REALM_ASSERT_DEBUG(targetSchema.properties.count == tableSchema.properties.size());

    // copy updated column mapping
    for (auto &prop : tableSchema.properties) {
        RLMProperty *targetProp = targetSchema[@(prop.name.c_str())];
        targetProp.column = prop.table_column;
    }

    // re-order properties
    targetSchema.properties = [targetSchema.properties sortedArrayUsingComparator:^NSComparisonResult(RLMProperty *p1, RLMProperty *p2) {
        if (p1.column < p2.column) return NSOrderedAscending;
        if (p1.column > p2.column) return NSOrderedDescending;
        return NSOrderedSame;
    }];
}

static void RLMRealmSetSchemaAndAlign(RLMRealm *realm, RLMSchema *targetSchema) {
    RLMSchema *sharedSchema = [RLMSchema sharedSchema];

    realm.schema = targetSchema;
    for (auto &aligned:*realm->_realm->config().schema) {
        RLMObjectSchema *objectSchema = targetSchema[@(aligned.first.c_str())];
        objectSchema.realm = realm;
        if (RLMObjectSchema *sharedObjectSchema = [sharedSchema schemaForClassName:objectSchema.className]) {
            objectSchema.objectClass = sharedObjectSchema.objectClass;
            objectSchema.isSwiftClass = sharedObjectSchema.isSwiftClass;
            objectSchema.accessorClass = sharedObjectSchema.accessorClass;
            objectSchema.standaloneClass = sharedObjectSchema.standaloneClass;
        }
        RLMCopyColumnMapping(objectSchema, aligned.second);
    }
}

+ (instancetype)realmWithSharedRealm:(SharedRealm)sharedRealm {
    RLMRealm *realm = [RLMRealm new];
    realm->_realm = sharedRealm;
    realm->_dynamic = YES;
    RLMRealmSetSchemaAndAlign(realm, [RLMSchema dynamicSchemaFromObjectStoreSchema:*sharedRealm->config().schema]);

    return RLMAutorelease(realm);
}

+ (SharedRealm)openSharedRealm:(Realm::Config &)config error:(NSError **)outError {
    try {
        return Realm::get_shared_realm(config);
    }
    catch (RealmFileException &ex) {
        switch (ex.kind()) {
            case RealmFileException::Kind::PermissionDenied: {
                NSString *mode = config.read_only ? @"read" : @"read-write";
                NSString *additionalMessage = [NSString stringWithFormat:@"Unable to open a realm at path '%@'. Please use a path where your app has %@ permissions.", @(config.path.c_str()), mode];
                NSString *newMessage = [NSString stringWithFormat:@"%s\n%@", ex.what(), additionalMessage];
                RLMSetErrorOrThrow(RLMMakeError(RLMErrorFilePermissionDenied, File::PermissionDenied(newMessage.UTF8String)), outError);
                break;
            }
            case RealmFileException::Kind::IncompatibleLockFile: {
                NSString *err = @"Realm file is currently open in another process "
                "which cannot share access with this process. All "
                "processes sharing a single file must be the same "
                "architecture. For sharing files between the Realm "
                "Browser and an iOS simulator, this means that you "
                "must use a 64-bit simulator.";
                RLMSetErrorOrThrow(RLMMakeError(RLMErrorIncompatibleLockFile, File::PermissionDenied(err.UTF8String)), outError);
                break;
            }
            case RealmFileException::Kind::Exists:
                RLMSetErrorOrThrow(RLMMakeError(RLMErrorFileExists, ex), outError);
                break;
            case RealmFileException::Kind::AccessError:
                RLMSetErrorOrThrow(RLMMakeError(RLMErrorFileAccessError, ex), outError);
                break;
            default:
                RLMSetErrorOrThrow(RLMMakeError(RLMErrorFail, ex), outError);
                break;
        }
        return nullptr;
    }
    catch(const std::exception &exp) {
        RLMSetErrorOrThrow(RLMMakeError(RLMErrorFail, exp), outError);
        return nullptr;
    }
}

static Schema RLMObjectStoreSchemaForRLMSchema(RLMSchema *rlmSchema) {
    Schema schema;
    for (RLMObjectSchema *objectSchema in rlmSchema.objectSchema) {
        ObjectSchema os = objectSchema.objectStoreCopy;
        schema.emplace(os.name, move(os));
    }
    return schema;
}

+ (instancetype)realmWithConfiguration:(RLMRealmConfiguration *)configuration error:(NSError **)error {
    NSString *path = configuration.path;
    bool inMemory = false;
    if (configuration.inMemoryIdentifier) {
        inMemory = true;
        path = [RLMRealm writeableTemporaryPathForFile:configuration.inMemoryIdentifier];
    }
    RLMSchema *customSchema = configuration.customSchema;
    bool dynamic = configuration.dynamic;
    bool readOnly = configuration.readOnly;

    if (!path || path.length == 0) {
        @throw RLMException([NSString stringWithFormat:@"Path '%@' is not valid", path]);
    }

    if (![NSRunLoop currentRunLoop]) {
        @throw RLMException([NSString stringWithFormat:@"%@ \
                             can only be called from a thread with a runloop.",
                             NSStringFromSelector(_cmd)]);
    }

    // try to reuse existing realm first
    RLMRealm *realm = RLMGetThreadLocalCachedRealmForPath(path);
    if (realm) {
        if (realm.isReadOnly != readOnly) {
            @throw RLMException(@"Realm at path already opened with different read permissions", @{@"path":realm.path});
        }
        if (realm->_realm->config().in_memory != inMemory) {
            @throw RLMException(@"Realm at path already opened with different inMemory settings", @{@"path":realm.path});
        }
        if (realm->_dynamic != dynamic) {
            @throw RLMException(@"Realm at path already opened with different dynamic settings", @{@"path":realm.path});
        }
        return RLMAutorelease(realm);
    }

    NSData *key = configuration.encryptionKey ?: keyForPath(path);
    key = RLMRealmValidatedEncryptionKey(key);

    realm = [RLMRealm new];
    realm->_dynamic = dynamic;

    realm::Realm::Config config;
    config.path = path.UTF8String;
    config.read_only = readOnly;
    config.in_memory = inMemory;
    config.cache = !dynamic;
    if (key) {
        config.encryption_key = std::make_unique<char[]>(key.length);
        memcpy(config.encryption_key.get(), key.bytes, key.length);
    }

    config.schema_version = configuration.schemaVersion;
    config.migration_function = [=](SharedRealm old_realm, SharedRealm realm) {
        RLMMigrationBlock userBlock = configuration.migrationBlock ?: migrationBlockForPath(path);
        if (userBlock) {
            RLMMigration *migration = [[RLMMigration alloc] initWithRealm:[RLMRealm realmWithSharedRealm:realm]
                                                                 oldRealm:[RLMRealm realmWithSharedRealm:old_realm]];
            [migration execute:userBlock];
        }
    };

    // protects the realm cache and accessors cache
    static id initLock = [NSObject new];
    @synchronized(initLock) {
        realm->_realm = [self openSharedRealm:config error:error];
        if (!realm->_realm) {
            return nil;
        }

        // if we have a cached realm on another thread, copy without a transaction
        if (RLMRealm *cachedRealm = RLMGetAnyCachedRealmForPath(path)) {
            realm.schema = [cachedRealm.schema shallowCopy];
            for (RLMObjectSchema *objectSchema in realm.schema.objectSchema) {
                objectSchema.realm = realm;
            }
        }
        else {
            // set/align schema or perform migration if needed
            uint64_t newVersion = configuration.schemaVersion;
            try {
                RLMSchema *targetSchema = customSchema ?: [RLMSchema.sharedSchema copy];
                Schema schema = RLMObjectStoreSchemaForRLMSchema(targetSchema);
                realm->_realm->update_schema(schema, newVersion);
                RLMRealmSetSchemaAndAlign(realm, targetSchema);
            } catch (const std::exception & exception) {
                RLMSetErrorOrThrow(RLMMakeError(RLMException(exception)), error);
                return nil;
            }
        }

        if (!dynamic) {
            RLMRealmCreateAccessors(realm.schema);
            RLMCacheRealm(realm);
        }
    }

    if (!readOnly) {
        // initializing the schema started a read transaction, so end it
        [realm invalidate];

        realm.notifier = [[RLMNotifier alloc] initWithRealm:realm error:error];
        if (!realm.notifier) {
            return nil;
        }
        __weak RLMNotifier *weakNotifier = realm.notifier;
        realm->_realm->m_external_notifier = make_unique<function<void()>>([=]() {
            [weakNotifier notifyOtherRealms];
        });
    }

    return RLMAutorelease(realm);
}

+ (void)setEncryptionKey:(NSData *)key forRealmsAtPath:(NSString *)path {
    RLMRealmConfigurationUsePerPath(_cmd);
    @synchronized (s_keysPerPath) {
        if (RLMGetAnyCachedRealmForPath(path)) {
            NSData *existingKey = keyForPath(path);
            if (!(existingKey == key || [existingKey isEqual:key])) {
                @throw RLMException(@"Cannot set encryption key for Realms that are already open.");
            }
        }

        setKeyForPath(key, path);
    }
}

void RLMRealmSetEncryptionKeyForPath(NSData *encryptionKey, NSString *path) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    [RLMRealm setEncryptionKey:encryptionKey forRealmsAtPath:path];
#pragma clang diagnostic pop
}

+ (void)resetRealmState {
    clearMigrationCache();
    clearKeyCache();
    RLMClearRealmCache();
    realm::Realm::s_global_cache.clear();
    [RLMRealmConfiguration resetRealmConfigurationState];
}

static void CheckReadWrite(RLMRealm *realm, NSString *msg=@"Cannot write to a read-only Realm") {
    if (realm.readOnly) {
        @throw RLMException(msg);
    }
}

- (RLMNotificationToken *)addNotificationBlock:(RLMNotificationBlock)block {
    [self verifyThread];
    CheckReadWrite(self, @"Read-only Realms do not change and do not have change notifications");
    if (!block) {
        @throw RLMException(@"The notification block should not be nil");
    }

    RLMNotificationToken *token = [[RLMNotificationToken alloc] init];
    __weak RLMRealm *weakRealm = self;
    token->_notification = token->_notification.make_shared([=](const std::string notification) {
        if (notification == _realm->RefreshRequiredNotification)
            block(RLMRealmRefreshRequiredNotification, weakRealm);
        else
            block(RLMRealmDidChangeNotification, weakRealm);
    });
    _realm->add_notification(token->_notification);
    return token;
}

- (void)removeNotification:(RLMNotificationToken *)token {
    [self verifyThread];
    if (token) {
        _realm->remove_notification(token->_notification);
        token->_notification.reset();
    }
}

- (RLMRealmConfiguration *)configuration {
#if 0
    RLMRealmConfiguration *configuration = [[RLMRealmConfiguration alloc] init];
    configuration.path = self.path;
    configuration.schemaVersion = [RLMRealm schemaVersionAtPath:_path encryptionKey:_encryptionKey error:nil];
    if (_inMemory) {
        configuration.inMemoryIdentifier = [_path lastPathComponent];
    }
    configuration.readOnly = _readOnly;
    configuration.encryptionKey = _encryptionKey;
    configuration.dynamic = _dynamic;
    configuration.customSchema = _schema;
    return configuration;
#endif
    return nil;
}

- (void)beginWriteTransaction {
    try {
        _realm->begin_transaction();
    }
    catch (std::exception &ex) {
        @throw RLMException(ex);
    }

    // notify any collections currently being enumerated that they need
    // to switch to enumerating a copy as the data may change on them
    for (RLMFastEnumerator *enumerator in _collectionEnumerators) {
        [enumerator detach];
    }
    _collectionEnumerators = nil;
}

- (void)commitWriteTransaction {
    try {
        _realm->commit_transaction();
    }
    catch (std::exception &ex) {
        @throw RLMException(ex);
    }
}

- (void)transactionWithBlock:(void(^)(void))block {
    try {
        _realm->begin_transaction();
        block();
        if (_realm->is_in_transaction()) {
            _realm->commit_transaction();
        }
    }
    catch (std::exception &ex) {
        @throw RLMException(ex);
    }
}

- (void)cancelWriteTransaction {
    try {
        _realm->cancel_transaction();
    }
    catch (std::exception &ex) {
        @throw RLMException(ex);
    }
}

- (void)invalidate {
    if (_realm->is_in_transaction()) {
        NSLog(@"WARNING: An RLMRealm instance was invalidated during a write "
              "transaction and all pending changes have been rolled back.");
    }
    _realm->invalidate();
    for (RLMObjectSchema *objectSchema in _schema.objectSchema) {
        for (RLMObservationInfo *info : objectSchema->_observedObjects) {
            info->didChange(RLMInvalidatedKey);
        }
        objectSchema.table = nullptr;
    }
}

/**
 Replaces all string columns in this Realm with a string enumeration column and compacts the
 database file.
 
 Cannot be called from a write transaction.

 Compaction will not occur if other `RLMRealm` instances exist.
 
 While compaction is in progress, attempts by other threads or processes to open the database will
 wait.
 
 Be warned that resource requirements for compaction is proportional to the amount of live data in
 the database.
 
 Compaction works by writing the database contents to a temporary database file and then replacing
 the database with the temporary one. The name of the temporary file is formed by appending
 `.tmp_compaction_space` to the name of the database.

 @return YES if the compaction succeeded.
 */
- (BOOL)compact
{
    return _realm->compact();
}

- (void)dealloc {
    if (_realm) {
        if (_realm->is_in_transaction()) {
            [self cancelWriteTransaction];
            NSLog(@"WARNING: An RLMRealm instance was deallocated during a write transaction and all "
                  "pending changes have been rolled back. Make sure to retain a reference to the "
                  "RLMRealm for the duration of the write transaction.");
        }
        _realm->remove_all_notifications();
    }
    [_notifier stop];
}

- (void)notify {
    _realm->notify();
}

- (BOOL)refresh {
    return _realm->refresh();
}

- (void)cacheTableAccessors {
    for (RLMObjectSchema *objectSchema in _schema.objectSchema) {
        objectSchema.table = ObjectStore::table_for_object_type(_realm->read_group(), objectSchema.className.UTF8String).get();
    }
}

- (void)addObject:(__unsafe_unretained RLMObject *const)object {
    RLMAddObjectToRealm(object, self, false);
}

- (void)addObjects:(id<NSFastEnumeration>)array {
    for (RLMObject *obj in array) {
        if (![obj isKindOfClass:[RLMObject class]]) {
            NSString *msg = [NSString stringWithFormat:@"Cannot insert objects of type %@ with addObjects:. Only RLMObjects are supported.", NSStringFromClass(obj.class)];
            @throw RLMException(msg);
        }
        [self addObject:obj];
    }
}

- (void)addOrUpdateObject:(RLMObject *)object {
    // verify primary key
    if (!object.objectSchema.primaryKeyProperty) {
        NSString *reason = [NSString stringWithFormat:@"'%@' does not have a primary key and can not be updated", object.objectSchema.className];
        @throw RLMException(reason);
    }

    RLMAddObjectToRealm(object, self, true);
}

- (void)addOrUpdateObjectsFromArray:(id)array {
    for (RLMObject *obj in array) {
        [self addOrUpdateObject:obj];
    }
}

- (void)deleteObject:(RLMObject *)object {
    RLMDeleteObjectFromRealm(object, self);
}

- (void)deleteObjects:(id)array {
    if ([array respondsToSelector:@selector(realm)] && [array respondsToSelector:@selector(deleteObjectsFromRealm)]) {
        if (self != (RLMRealm *)[array realm]) {
            @throw RLMException(@"Can only delete objects from the Realm they belong to.");
        }
        [array deleteObjectsFromRealm];
    }
    else if ([array conformsToProtocol:@protocol(NSFastEnumeration)]) {
        for (id obj in array) {
            if ([obj isKindOfClass:RLMObjectBase.class]) {
                RLMDeleteObjectFromRealm(obj, self);
            }
        }
    }
    else {
        @throw RLMException(@"Invalid array type - container must be an RLMArray, RLMArray, or NSArray of RLMObjects");
    }
}

- (void)deleteAllObjects {
    RLMDeleteAllObjectsFromRealm(self);
}

- (RLMResults *)allObjects:(NSString *)objectClassName {
    return RLMGetObjects(self, objectClassName, nil);
}

- (RLMResults *)objects:(NSString *)objectClassName where:(NSString *)predicateFormat, ... {
    va_list args;
    RLM_VARARG(predicateFormat, args);
    return [self objects:objectClassName where:predicateFormat args:args];
}

- (RLMResults *)objects:(NSString *)objectClassName where:(NSString *)predicateFormat args:(va_list)args {
    return [self objects:objectClassName withPredicate:[NSPredicate predicateWithFormat:predicateFormat arguments:args]];
}

- (RLMResults *)objects:(NSString *)objectClassName withPredicate:(NSPredicate *)predicate {
    return RLMGetObjects(self, objectClassName, predicate);
}

- (RLMObject *)objectWithClassName:(NSString *)className forPrimaryKey:(id)primaryKey {
    return RLMGetObject(self, className, primaryKey);
}

+ (void)setDefaultRealmSchemaVersion:(uint64_t)version withMigrationBlock:(RLMMigrationBlock)block {
    [RLMRealm setSchemaVersion:version forRealmAtPath:[RLMRealm defaultRealmPath] withMigrationBlock:block];
}

+ (void)setSchemaVersion:(uint64_t)version forRealmAtPath:(NSString *)realmPath withMigrationBlock:(RLMMigrationBlock)block {
    RLMRealmConfigurationUsePerPath(_cmd);
    @synchronized(s_migrationBlocks) {
        if (RLMGetAnyCachedRealmForPath(realmPath) && schemaVersionForPath(realmPath) != version) {
            @throw RLMException(@"Cannot set schema version for Realms that are already open.");
        }

        if (version == realm::ObjectStore::NotVersioned) {
            @throw RLMException(@"Cannot set schema version to RLMNotVersioned.");
        }

        if (block) {
            s_migrationBlocks[realmPath] = block;
        }
        else {
            [s_migrationBlocks removeObjectForKey:realmPath];
        }
        s_schemaVersions[realmPath] = @(version);
    }
}

void RLMRealmSetSchemaVersionForPath(uint64_t version, NSString *path, RLMMigrationBlock migrationBlock) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    [RLMRealm setSchemaVersion:version forRealmAtPath:path withMigrationBlock:migrationBlock];
#pragma clang diagnostic pop
}

+ (uint64_t)schemaVersionAtPath:(NSString *)realmPath error:(NSError **)error {
    return [RLMRealm schemaVersionAtPath:realmPath encryptionKey:nil error:error];
}

+ (uint64_t)schemaVersionAtPath:(NSString *)realmPath encryptionKey:(NSData *)key error:(NSError **)outError {
    key = RLMRealmValidatedEncryptionKey(key) ?: keyForPath(realmPath);
    RLMRealm *realm = RLMGetThreadLocalCachedRealmForPath(realmPath);
    if (realm) {
        return realm->_realm->config().schema_version;
    }

    try {
        Realm::Config config;
        config.path = realmPath.UTF8String;
//        config.encryption_key = key ? static_cast<const char *>(key.bytes) : StringData();
        uint64_t version = Realm::get_shared_realm(config)->config().schema_version;
        if (version == realm::ObjectStore::NotVersioned) {
            RLMSetErrorOrThrow([NSError errorWithDomain:RLMErrorDomain code:RLMErrorFail userInfo:@{NSLocalizedDescriptionKey:@"Cannot open an uninitialized realm in read-only mode"}], outError);
        }
        return version;
    }
    catch (std::exception &exp) {
        RLMSetErrorOrThrow(RLMMakeError(RLMErrorFail, exp), outError);
        return RLMNotVersioned;
    }
}

+ (NSError *)migrateRealmAtPath:(NSString *)realmPath {
    RLMRealmConfiguration *configuration = [RLMRealmConfiguration defaultConfiguration];
    configuration.path = realmPath;
    return [self migrateRealm:configuration];
}

+ (NSError *)migrateRealmAtPath:(NSString *)realmPath encryptionKey:(NSData *)key {
    if (!key) {
        @throw RLMException(@"Encryption key must not be nil");
    }
    RLMRealmConfiguration *configuration = [RLMRealmConfiguration defaultConfiguration];
    configuration.path = realmPath;
    configuration.encryptionKey = key;
    return [self migrateRealm:configuration];
}

+ (NSError *)migrateRealm:(RLMRealmConfiguration *)configuration {
    NSString *realmPath = configuration.path;
    if (RLMGetAnyCachedRealmForPath(realmPath)) {
        @throw RLMException(@"Cannot migrate Realms that are already open.");
    }

    NSData *key = configuration.encryptionKey ?: keyForPath(realmPath);

    @autoreleasepool {
        NSError *error;
        [RLMRealm realmWithPath:realmPath key:key readOnly:NO inMemory:NO dynamic:NO schema:nil error:&error];
        return error;
    }
}

- (RLMObject *)createObject:(NSString *)className withValue:(id)value {
    return (RLMObject *)RLMCreateObjectInRealmWithValue(self, className, value, false);
}

- (BOOL)writeCopyToPath:(NSString *)path key:(NSData *)key error:(NSError **)error {
    key = RLMRealmValidatedEncryptionKey(key) ?: keyForPath(path);

    try {
        self.group->write(path.UTF8String, static_cast<const char *>(key.bytes));
        return YES;
    }
    catch (File::PermissionDenied &ex) {
        if (error) {
            *error = RLMMakeError(RLMErrorFilePermissionDenied, ex);
        }
    }
    catch (File::Exists &ex) {
        if (error) {
            *error = RLMMakeError(RLMErrorFileExists, ex);
        }
    }
    catch (File::AccessError &ex) {
        if (error) {
            *error = RLMMakeError(RLMErrorFileAccessError, ex);
        }
    }
    catch (exception &ex) {
        if (error) {
            *error = RLMMakeError(RLMErrorFail, ex);
        }
    }

    return NO;
}

- (BOOL)writeCopyToPath:(NSString *)path error:(NSError **)error {
    return [self writeCopyToPath:path key:nil error:error];
}

- (BOOL)writeCopyToPath:(NSString *)path encryptionKey:(NSData *)key error:(NSError **)error {
    if (!key) {
        @throw RLMException(@"Encryption key must not be nil");
    }

    return [self writeCopyToPath:path key:key error:error];
}

- (void)registerEnumerator:(RLMFastEnumerator *)enumerator {
    if (!_collectionEnumerators) {
        _collectionEnumerators = [NSHashTable hashTableWithOptions:NSPointerFunctionsWeakMemory];
    }
    [_collectionEnumerators addObject:enumerator];

}

- (void)unregisterEnumerator:(RLMFastEnumerator *)enumerator {
    [_collectionEnumerators removeObject:enumerator];
}

@end
