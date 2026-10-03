#!/usr/bin/env python3
import pathlib
import sys

source_path = pathlib.Path(sys.argv[1])
source = source_path.read_text(encoding="utf-8")

required = {
    "CFBundleExecutable parsing": 'kExecutableKey @"CFBundleExecutable"',
    "ApplicationSINF option key": 'kApplicationSINFKey @"ApplicationSINF"',
    "iTunesMetadata option key": 'kITunesMetadataKey @"iTunesMetadata"',
    "App Store mode detection": 'BOOL appStoreIPAMode = (applicationSINF != nil && iTunesMetadata != nil);',
    "SINF injection": '[options setObject:applicationSINF forKey:kApplicationSINFKey];',
    "metadata injection": '[options setObject:iTunesMetadata forKey:kITunesMetadataKey];',
    "mode diagnostic": 'Original App Store IPA mode enabled',
}

missing = [name for name, needle in required.items() if needle not in source]
if missing:
    print("Missing App Store IPA mode features:")
    for item in missing:
        print(f" - {item}")
    sys.exit(1)

print("App Store IPA mode source checks passed.")
