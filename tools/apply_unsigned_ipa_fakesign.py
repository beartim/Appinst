#!/usr/bin/env python3
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
source = path.read_text(encoding="utf-8")


def replace_once(old: str, new: str, label: str) -> None:
    global source
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    source = source.replace(old, new, 1)


signature_helpers = r'''
static BOOL machOHasCodeSignatureForSlice(const uint8_t *bytes, size_t length) {
	if (length < 28) {
		return NO;
	}

	BOOL bigEndian = NO;
	BOOL is64Bit = NO;
	if (bytes[0] == 0xce && bytes[1] == 0xfa && bytes[2] == 0xed && bytes[3] == 0xfe) {
		bigEndian = NO;
		is64Bit = NO;
	} else if (bytes[0] == 0xcf && bytes[1] == 0xfa && bytes[2] == 0xed && bytes[3] == 0xfe) {
		bigEndian = NO;
		is64Bit = YES;
	} else if (bytes[0] == 0xfe && bytes[1] == 0xed && bytes[2] == 0xfa && bytes[3] == 0xce) {
		bigEndian = YES;
		is64Bit = NO;
	} else if (bytes[0] == 0xfe && bytes[1] == 0xed && bytes[2] == 0xfa && bytes[3] == 0xcf) {
		bigEndian = YES;
		is64Bit = YES;
	} else {
		return NO;
	}

	size_t headerSize = is64Bit ? 32 : 28;
	if (length < headerSize) {
		return NO;
	}
	uint32_t commandCount = readUInt32(bytes + 16, bigEndian);
	size_t offset = headerSize;
	for (uint32_t i = 0; i < commandCount; ++i) {
		if (offset + 8 > length) {
			return NO;
		}
		uint32_t command = readUInt32(bytes + offset, bigEndian);
		uint32_t commandSize = readUInt32(bytes + offset + 4, bigEndian);
		if (commandSize < 8 || offset + commandSize > length) {
			return NO;
		}
		// LC_CODE_SIGNATURE == 0x1d.
		if (command == 0x1d && commandSize >= 16) {
			return YES;
		}
		offset += commandSize;
	}
	return NO;
}

static BOOL machOHasCodeSignature(NSData *binaryData) {
	if (binaryData == nil || [binaryData length] < 4) {
		return NO;
	}
	const uint8_t *bytes = (const uint8_t *)[binaryData bytes];
	size_t length = [binaryData length];

	BOOL fat32 = (length >= 8 && bytes[0] == 0xca && bytes[1] == 0xfe && bytes[2] == 0xba && bytes[3] == 0xbe);
	BOOL fat64 = (length >= 8 && bytes[0] == 0xca && bytes[1] == 0xfe && bytes[2] == 0xba && bytes[3] == 0xbf);
	if (fat32 || fat64) {
		uint32_t archCount = readUInt32(bytes + 4, YES);
		size_t archSize = fat64 ? 32 : 20;
		size_t tableOffset = 8;
		for (uint32_t i = 0; i < archCount; ++i) {
			if (tableOffset + archSize > length) {
				return NO;
			}
			uint64_t sliceOffset = fat64 ? readUInt64(bytes + tableOffset + 8, YES) : readUInt32(bytes + tableOffset + 8, YES);
			uint64_t sliceSize = fat64 ? readUInt64(bytes + tableOffset + 16, YES) : readUInt32(bytes + tableOffset + 12, YES);
			if (sliceOffset > length || sliceSize > length - sliceOffset) {
				return NO;
			}
			if (machOHasCodeSignatureForSlice(bytes + sliceOffset, (size_t)sliceSize)) {
				return YES;
			}
			tableOffset += archSize;
		}
		return NO;
	}

	return machOHasCodeSignatureForSlice(bytes, length);
}

static NSMutableDictionary *fallbackEntitlementsForBundleIdentifier(NSString *bundleIdentifier) {
	NSString *teamIdentifier = @"APPINST000";
	NSString *applicationIdentifier = [NSString stringWithFormat:@"%@.%@", teamIdentifier, bundleIdentifier];
	return [NSMutableDictionary dictionaryWithObjectsAndKeys:
		applicationIdentifier, @"application-identifier",
		teamIdentifier, @"com.apple.developer.team-identifier",
		[NSNumber numberWithBool:YES], @"get-task-allow",
		[NSArray arrayWithObject:applicationIdentifier], @"keychain-access-groups",
		nil];
}

static NSMutableDictionary *installableEntitlements(NSDictionary *existingEntitlements, NSString *bundleIdentifier) {
	NSMutableDictionary *entitlements = existingEntitlements ? [existingEntitlements mutableCopy] : fallbackEntitlementsForBundleIdentifier(bundleIdentifier);
	NSString *applicationIdentifier = [entitlements objectForKey:@"application-identifier"];
	NSString *teamIdentifier = [entitlements objectForKey:@"com.apple.developer.team-identifier"];

	if (teamIdentifier == nil || ![teamIdentifier isKindOfClass:[NSString class]] || [teamIdentifier length] == 0) {
		teamIdentifier = nil;
		if ([applicationIdentifier isKindOfClass:[NSString class]]) {
			NSRange separator = [applicationIdentifier rangeOfString:@"."];
			if (separator.location != NSNotFound && separator.location > 0) {
				teamIdentifier = [applicationIdentifier substringToIndex:separator.location];
			}
		}
		if (teamIdentifier == nil || [teamIdentifier length] == 0) {
			teamIdentifier = @"APPINST000";
		}
		[entitlements setObject:teamIdentifier forKey:@"com.apple.developer.team-identifier"];
	}

	if (applicationIdentifier == nil || ![applicationIdentifier isKindOfClass:[NSString class]] || [applicationIdentifier length] == 0) {
		applicationIdentifier = [NSString stringWithFormat:@"%@.%@", teamIdentifier, bundleIdentifier];
		[entitlements setObject:applicationIdentifier forKey:@"application-identifier"];
	}
	if ([entitlements objectForKey:@"keychain-access-groups"] == nil) {
		[entitlements setObject:[NSArray arrayWithObject:applicationIdentifier] forKey:@"keychain-access-groups"];
	}
	return entitlements;
}

'''
replace_once(
    'static NSString *findLdidPath(void) {',
    signature_helpers + 'static NSString *findLdidPath(void) {',
    'code-signature and fallback entitlement helpers',
)

replace_once(
    'static BOOL fakeSignMainExecutableInIPA(NSString *ipaPath, NSString *mainExecutablePath, NSString *workPath, NSString *sessionID) {',
    'static BOOL fakeSignMainExecutableInIPA(NSString *ipaPath, NSString *mainExecutablePath, NSString *bundleIdentifier, NSString *workPath, NSString *sessionID) {',
    'fake-sign function signature',
)

old_signing = '''\tBOOL hasEntitlements = extractEntitlementsWithLdid(ldidPath, binaryPath, entitlementsPath);\n\tNSString *signArgument = hasEntitlements ? [NSString stringWithFormat:@"-S%@", entitlementsPath] : @"-S";\n\tprintf("Rebuilding ad-hoc signature with %s%s.\\n", [ldidPath UTF8String], hasEntitlements ? " while preserving original entitlements" : "");\n'''
new_signing = '''\tBOOL hasEntitlements = extractEntitlementsWithLdid(ldidPath, binaryPath, entitlementsPath);\n\tNSDictionary *existingEntitlements = nil;\n\tif (hasEntitlements) {\n\t\tNSData *entitlementsData = [NSData dataWithContentsOfFile:entitlementsPath];\n\t\tif (entitlementsData != nil) {\n\t\t\tid plist = [NSPropertyListSerialization propertyListWithData:entitlementsData options:NSPropertyListImmutable format:NULL error:nil];\n\t\t\tif ([plist isKindOfClass:[NSDictionary class]]) {\n\t\t\t\texistingEntitlements = plist;\n\t\t\t}\n\t\t}\n\t}\n\tNSMutableDictionary *entitlements = installableEntitlements(existingEntitlements, bundleIdentifier);\n\tNSData *entitlementsData = [NSPropertyListSerialization dataWithPropertyList:entitlements format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];\n\tif (entitlementsData == nil || ![entitlementsData writeToFile:entitlementsPath atomically:NO]) {\n\t\tprintf("Unable to create installable fallback entitlements for fake-signing.\\n");\n\t\t[[NSFileManager defaultManager] removeItemAtPath:binaryPath error:nil];\n\t\t[[NSFileManager defaultManager] removeItemAtPath:entitlementsPath error:nil];\n\t\tzip_discard(archive);\n\t\treturn NO;\n\t}\n\tNSString *signArgument = [NSString stringWithFormat:@"-S%@", entitlementsPath];\n\tprintf("Rebuilding ad-hoc signature with %s while %s installable entitlements.\\n", [ldidPath UTF8String], existingEntitlements != nil ? "preserving and completing" : "generating fallback");\n'''
replace_once(old_signing, new_signing, 'installable entitlement generation')

old_modes = '''\t\tNSInteger encryptionState = machOEncryptionState(mainExecutableData);\n\t\tBOOL decryptedAppStoreIPAMode = (applicationSINF != nil && encryptionState == 0);\n\t\tBOOL appStoreIPAMode = (applicationSINF != nil && encryptionState == 1);\n\t\tif (decryptedAppStoreIPAMode) {\n\t\t\tprintf("Decrypted App Store IPA detected (SC_Info + cryptid=0); fake-sign mode enabled.\\n");\n\t\t} else if (appStoreIPAMode) {\n'''
new_modes = '''\t\tNSInteger encryptionState = machOEncryptionState(mainExecutableData);\n\t\tBOOL hasCodeSignature = machOHasCodeSignature(mainExecutableData);\n\t\tBOOL decryptedAppStoreIPAMode = (applicationSINF != nil && encryptionState == 0);\n\t\tBOOL unsignedIPAMode = (mainExecutableData != nil && encryptionState != 1 && !hasCodeSignature);\n\t\tBOOL appStoreIPAMode = (applicationSINF != nil && encryptionState == 1);\n\t\tif (decryptedAppStoreIPAMode) {\n\t\t\tprintf("Decrypted App Store IPA detected (SC_Info + cryptid=0); fake-sign mode enabled.\\n");\n\t\t} else if (unsignedIPAMode) {\n\t\t\tprintf("Unsigned IPA detected (no LC_CODE_SIGNATURE); fallback-entitlement fake-sign mode enabled.\\n");\n\t\t} else if (appStoreIPAMode) {\n'''
replace_once(old_modes, new_modes, 'unsigned IPA mode detection')

old_call = '''\t\tif (decryptedAppStoreIPAMode) {\n\t\t\tif (!fakeSignMainExecutableInIPA(installPath, mainExecutablePath, workPath, sessionID)) {\n\t\t\t\tprintf("Failed to prepare the decrypted App Store IPA for launch.\\n");\n\t\t\t\treturn AppInstExitCodeInject;\n\t\t\t}\n\t\t}\n'''
new_call = '''\t\tif (decryptedAppStoreIPAMode || unsignedIPAMode) {\n\t\t\tif (!fakeSignMainExecutableInIPA(installPath, mainExecutablePath, appIdentifier, workPath, sessionID)) {\n\t\t\t\tprintf("Failed to prepare the IPA with an installable ad-hoc signature.\\n");\n\t\t\t\treturn AppInstExitCodeInject;\n\t\t\t}\n\t\t}\n'''
replace_once(old_call, new_call, 'unsigned/decrypted fake-sign invocation')

path.write_text(source, encoding='utf-8')
print(f'Applied unsigned IPA fallback-entitlement fake-sign mode to {path}')
