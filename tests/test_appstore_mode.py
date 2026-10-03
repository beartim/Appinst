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
    "decrypted App Store mode detection": 'BOOL decryptedAppStoreIPAMode',
    "ldid discovery": 'findLdidPath',
    "preserve entitlements": 'extractEntitlementsWithLdid',
    "re-sign executable": 'fakeSignMainExecutableInIPA',
    "SINF injection": '[options setObject:applicationSINF forKey:kApplicationSINFKey];',
    "metadata injection": '[options setObject:iTunesMetadata forKey:kITunesMetadataKey];',
    "decrypted mode diagnostic": 'Decrypted App Store IPA detected',
}

missing = [name for name, needle in required.items() if needle not in source]
if missing:
    print("Missing App Store/decrypted IPA mode features:")
    for item in missing:
        print(f" - {item}")
    sys.exit(1)

print("App Store/decrypted IPA mode source checks passed.")
