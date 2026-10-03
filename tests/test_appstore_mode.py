#!/usr/bin/env python3
import pathlib
import sys

source_path = pathlib.Path(sys.argv[1])
source = source_path.read_text(encoding="utf-8")

required = {
    "CFBundleExecutable parsing": 'kExecutableKey @"CFBundleExecutable"',
    "ApplicationSINF option key": 'kApplicationSINFKey @"ApplicationSINF"',
    "iTunesMetadata option key": 'kITunesMetadataKey @"iTunesMetadata"',
    "Mach-O encryption-state detection": 'machOEncryptionState',
    "Mach-O code-signature detection": 'machOHasCodeSignature',
    "decrypted App Store mode detection": 'BOOL decryptedAppStoreIPAMode',
    "unsigned IPA mode detection": 'BOOL unsignedIPAMode',
    "ldid discovery": 'findLdidPath',
    "preserve entitlements": 'extractEntitlementsWithLdid',
    "re-sign executable": 'fakeSignMainExecutableInIPA',
    "fallback entitlements builder": 'fallbackEntitlementsForBundleIdentifier',
    "application identifier fallback": '@"application-identifier"',
    "team identifier fallback": '@"com.apple.developer.team-identifier"',
    "keychain group fallback": '@"keychain-access-groups"',
    "explicit CodeDirectory identifier": '[NSString stringWithFormat:@"-I%@", bundleIdentifier]',
    "ldid identifier argument": '[identifierArgument UTF8String]',
    "unsigned mode diagnostic": 'Unsigned IPA detected',
    "SINF injection": '[options setObject:applicationSINF forKey:kApplicationSINFKey];',
    "metadata injection": '[options setObject:iTunesMetadata forKey:kITunesMetadataKey];',
    "decrypted mode diagnostic": 'Decrypted App Store IPA detected',
}

missing = [name for name, needle in required.items() if needle not in source]
if missing:
    print("Missing App Store/decrypted/unsigned IPA mode features:")
    for item in missing:
        print(f" - {item}")
    sys.exit(1)

print("App Store/decrypted/unsigned IPA mode source checks passed.")
