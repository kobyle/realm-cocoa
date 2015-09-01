////////////////////////////////////////////////////////////////////////////
//
// Copyright 2015 Realm Inc.
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

#import "RLMRealmConfiguration_Private.h"

#import "RLMObjectSchema_Private.hpp"
#import "RLMRealm_Private.h"
#import "RLMSchema_Private.h"
#import "RLMUtil.hpp"

#import "shared_realm.hpp"

#include <atomic>

static NSString * const c_RLMRealmConfigurationProperties[] = {
    @"path",
    @"inMemoryIdentifier",
    @"encryptionKey",
    @"readOnly",
    @"schemaVersion",
    @"migrationBlock",
    @"dynamic",
    @"customSchema",
};

typedef NS_ENUM(NSUInteger, RLMRealmConfigurationUsage) {
    RLMRealmConfigurationUsageNone,
    RLMRealmConfigurationUsageConfiguration,
    RLMRealmConfigurationUsagePerPath,
};

static std::atomic<RLMRealmConfigurationUsage> s_configurationUsage;

@implementation RLMRealmConfiguration {
    realm::Realm::Config _config;
}

- (realm::Realm::Config&)config {
    return _config;
}

RLMRealmConfiguration *s_defaultConfiguration;
static NSString * const c_defaultRealmFileName = @"default.realm";

+ (NSString *)defaultRealmPath {
    static NSString *defaultRealmPath = [[self class] writeablePathForFile:c_defaultRealmFileName];
    return defaultRealmPath;
}

+ (NSString *)writeablePathForFile:(NSString*)fileName {
#if TARGET_OS_IPHONE
    // On iOS the Documents directory isn't user-visible, so put files there
    NSString *path = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0];
#else
    // On OS X it is, so put files in Application Support. If we aren't running
    // in a sandbox, put it in a subdirectory based on the bundle identifier
    // to avoid accidentally sharing files between applications
    NSString *path = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES)[0];
    if (![[NSProcessInfo processInfo] environment][@"APP_SANDBOX_CONTAINER_ID"]) {
        NSString *identifier = [[NSBundle mainBundle] bundleIdentifier];
        if ([identifier length] == 0) {
            identifier = [[[NSBundle mainBundle] executablePath] lastPathComponent];
        }
        path = [path stringByAppendingPathComponent:identifier];

        // create directory
        [[NSFileManager defaultManager] createDirectoryAtPath:path
                                  withIntermediateDirectories:YES
                                                   attributes:nil
                                                        error:nil];
    }
#endif
    return [path stringByAppendingPathComponent:fileName];
}

+ (instancetype)defaultConfiguration {
    if (!s_defaultConfiguration) {
        s_defaultConfiguration = [[RLMRealmConfiguration alloc] init];
    }
    return [s_defaultConfiguration copy];
}

+ (void)setDefaultConfiguration:(RLMRealmConfiguration *)configuration {
    if (s_configurationUsage.exchange(RLMRealmConfigurationUsageConfiguration) == RLMRealmConfigurationUsagePerPath) {
        @throw RLMException(@"Cannot set a default configuration after using per-path configuration methods.");
    }
    if (!configuration) {
        @throw RLMException(@"Cannot set the default configuration to nil.");
    }
    s_defaultConfiguration = [configuration copy];
}

+ (void)setDefaultPath:(NSString *)path {
    RLMRealmConfiguration *configuration = [[RLMRealmConfiguration alloc] init];
    configuration.path = path;
    s_defaultConfiguration = configuration;
}

+ (void)resetRealmConfigurationState {
    s_defaultConfiguration = nil;
    s_configurationUsage = RLMRealmConfigurationUsageNone;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        self.path = [[self class] defaultRealmPath];
        self.schemaVersion = 0;
    }

    return self;
}

- (instancetype)copyWithZone:(NSZone *)zone {
    RLMRealmConfiguration *configuration = [[[self class] allocWithZone:zone] init];
    configuration->_config = _config;
    configuration->_dynamic = _dynamic;
    configuration->_migrationBlock = _migrationBlock;
    configuration->_customSchema = _customSchema;
    return configuration;
}

- (NSString *)description {
    NSMutableString *string = [NSMutableString stringWithFormat:@"%@ {\n", self.class];
    for (NSString *key : c_RLMRealmConfigurationProperties) {
        NSString *description = [[self valueForKey:key] description];
        description = [description stringByReplacingOccurrencesOfString:@"\n" withString:@"\n\t"];

        [string appendFormat:@"\t%@ = %@;\n", key, description];
    }
    return [string stringByAppendingString:@"}"];
}

- (NSString *)path {
    return _config.in_memory ? nil :@(_config.path.c_str());
}

static void RLMNSStringToStdString(std::string &out, NSString *in) {
    out.resize([in maximumLengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
    if (out.empty()) {
        return;
    }

    NSUInteger size = out.size();
    [in getBytes:&out[0]
       maxLength:size
      usedLength:&size
        encoding:NSUTF8StringEncoding
         options:0 range:{0, in.length} remainingRange:nullptr];
    out.resize(size);
}

- (void)setPath:(NSString *)path {
    if (!path.length) {
        @throw RLMException(@"Path cannot be empty");
    }

    RLMNSStringToStdString(_config.path, path);
    _config.in_memory = false;
}

- (NSString *)inMemoryIdentifier {
    if (!_config.in_memory) {
        return nil;
    }
    return [@(_config.path.c_str()) lastPathComponent];
}

- (void)setInMemoryIdentifier:(NSString *)inMemoryIdentifier {
    if (!inMemoryIdentifier.length) {
        @throw RLMException(@"Identifier cannot be empty");
    }
    RLMNSStringToStdString(_config.path, [NSTemporaryDirectory() stringByAppendingPathComponent:inMemoryIdentifier]);
    _config.in_memory = true;
}

- (NSData *)encryptionKey {
    return _config.encryption_key.empty() ? nil : [NSData dataWithBytes:_config.encryption_key.data() length:_config.encryption_key.size()];
}

- (void)setEncryptionKey:(NSData * __nullable)encryptionKey {
    if (NSData *key = RLMRealmValidatedEncryptionKey(encryptionKey)) {
        auto bytes = static_cast<const char *>(key.bytes);
        _config.encryption_key.assign(bytes, bytes + key.length);
    }
    else {
        _config.encryption_key.clear();
    }
}
- (BOOL)readOnly {
    return _config.read_only;
}

- (void)setReadOnly:(BOOL)readOnly {
    _config.read_only = readOnly;
}

- (uint64_t)schemaVersion {
    return _config.schema_version;
}

- (void)setSchemaVersion:(uint64_t)schemaVersion {
    if (schemaVersion == RLMNotVersioned) {
        @throw RLMException([NSString stringWithFormat:@"Cannot set schema version to %llu (RLMNotVersioned)", RLMNotVersioned]);
    }
    _config.schema_version = schemaVersion;
}

- (NSArray *)objectClasses {
    return [_customSchema.objectSchema valueForKeyPath:@"objectClass"];
}

- (void)setObjectClasses:(NSArray *)objectClasses {
    self.customSchema = [RLMSchema schemaWithObjectClasses:objectClasses];
}

- (void)setDynamic:(bool)dynamic {
    _dynamic = dynamic;
    _config.cache = !dynamic;
}

- (bool)cache {
    return _config.cache;
}

- (void)setCache:(bool)cache {
    _config.cache = cache;
}

- (void)setCustomSchema:(RLMSchema *)customSchema {
    _customSchema = customSchema;

    // FIXME: can any of this throw?
    if (_customSchema) {
        std::vector<realm::ObjectSchema> schema;
        schema.reserve(customSchema.objectSchema.count);
        for (RLMObjectSchema *objectSchema in customSchema.objectSchema) {
            schema.push_back(objectSchema.objectStoreCopy);
        }
        _config.schema = std::make_unique<realm::Schema>(std::move(schema));
    }
    else {
        _config.schema = nullptr;
    }
}

@end

void RLMRealmConfigurationUsePerPath(SEL callingMethod) {
    if (s_configurationUsage.exchange(RLMRealmConfigurationUsagePerPath) == RLMRealmConfigurationUsageConfiguration) {
        @throw RLMException([NSString stringWithFormat:@"Cannot call %@ after setting a default configuration.", NSStringFromSelector(callingMethod)]);
    }
}
