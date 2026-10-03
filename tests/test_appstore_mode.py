#!/usr/bin/env python3
import pathlib
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: test_appstore_mode.py <appinst.m> <control>")

source_path = pathlib.Path(sys.argv[1])
control_path = pathlib.Path(sys.argv[2])
source = source_path.read_text(encoding="utf-8")
control = control_path.read_text(encoding="utf-8")

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
    "runtime AppSync check": 'isAppSyncUnifiedInstalled',
    "AppSync package id": 'ai.akemi.appsyncunified',
    "dpkg installed status": 'install ok installed',
    "official IPA bypass": 'if (!appStoreIPAMode && !isAppSyncUnifiedInstalled())',
    "missing AppSync diagnostic": 'This IPA requires AppSync Unified.',
    "abort diagnostic": 'Installation aborted.',
}

missing = [name for name, needle in required.items() if needle not in source]
if missing:
    print("Missing App Store/decrypted/unsigned IPA mode features:")
    for item in missing:
        print(f" - {item}")
    sys.exit(1)

gate_pos = source.find('if (!appStoreIPAMode && !isAppSyncUnifiedInstalled())')
session_pos = source.find('// Begin copying the IPA to a temporary directory')
if gate_pos < 0 or session_pos < 0 or gate_pos > session_pos:
    print("Runtime AppSync gate must run before appinst creates an installation session.")
    sys.exit(1)

if 'ai.akemi.appsyncunified' in control:
    print("AppSync Unified must not remain a DEB dependency; it is now checked at runtime only when needed.")
    sys.exit(1)

print("App Store/decrypted/unsigned IPA mode and runtime AppSync gate source checks passed.")
