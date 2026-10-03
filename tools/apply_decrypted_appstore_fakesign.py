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


replace_once(
    '#import <objc/runtime.h>\n#import <rootless.h>',
    '#import <objc/runtime.h>\n'
    '#include <fcntl.h>\n'
    '#include <sys/wait.h>\n'
    '#import <rootless.h>',
    'POSIX headers',
)

helper = r'''
static uint32_t readUInt32(const uint8_t *bytes, BOOL bigEndian) {
	uint32_t value = 0;
	memcpy(&value, bytes, sizeof(value));
	return bigEndian ? __builtin_bswap32(value) : value;
}

static uint64_t readUInt64(const uint8_t *bytes, BOOL bigEndian) {
	uint64_t value = 0;
	memcpy(&value, bytes, sizeof(value));
	return bigEndian ? __builtin_bswap64(value) : value;
}

// Returns 1 for encrypted, 0 for a Mach-O with an encryption load command whose
// cryptid is zero (the usual shape of a decrypted App Store binary), and -1 when
// no encryption state can be determined.
static NSInteger machOEncryptionStateForSlice(const uint8_t *bytes, size_t length) {
	if (length < 28) {
		return -1;
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
		return -1;
	}

	size_t headerSize = is64Bit ? 32 : 28;
	if (length < headerSize) {
		return -1;
	}
	uint32_t commandCount = readUInt32(bytes + 16, bigEndian);
	size_t offset = headerSize;
	for (uint32_t i = 0; i < commandCount; ++i) {
		if (offset + 8 > length) {
			return -1;
		}
		uint32_t command = readUInt32(bytes + offset, bigEndian);
		uint32_t commandSize = readUInt32(bytes + offset + 4, bigEndian);
		if (commandSize < 8 || offset + commandSize > length) {
			return -1;
		}
		// LC_ENCRYPTION_INFO (0x21) / LC_ENCRYPTION_INFO_64 (0x2c).
		if ((command == 0x21 || command == 0x2c) && commandSize >= 20) {
			uint32_t cryptid = readUInt32(bytes + offset + 16, bigEndian);
			return cryptid == 0 ? 0 : 1;
		}
		offset += commandSize;
	}
	return -1;
}

static NSInteger machOEncryptionState(NSData *binaryData) {
	if (binaryData == nil || [binaryData length] < 4) {
		return -1;
	}
	const uint8_t *bytes = (const uint8_t *)[binaryData bytes];
	size_t length = [binaryData length];

	// Universal/fat Mach-O headers are big-endian on disk.
	BOOL fat32 = (length >= 8 && bytes[0] == 0xca && bytes[1] == 0xfe && bytes[2] == 0xba && bytes[3] == 0xbe);
	BOOL fat64 = (length >= 8 && bytes[0] == 0xca && bytes[1] == 0xfe && bytes[2] == 0xba && bytes[3] == 0xbf);
	if (fat32 || fat64) {
		uint32_t archCount = readUInt32(bytes + 4, YES);
		size_t archSize = fat64 ? 32 : 20;
		size_t tableOffset = 8;
		BOOL sawDecryptedSlice = NO;
		for (uint32_t i = 0; i < archCount; ++i) {
			if (tableOffset + archSize > length) {
				return -1;
			}
			uint64_t sliceOffset = fat64 ? readUInt64(bytes + tableOffset + 8, YES) : readUInt32(bytes + tableOffset + 8, YES);
			uint64_t sliceSize = fat64 ? readUInt64(bytes + tableOffset + 16, YES) : readUInt32(bytes + tableOffset + 12, YES);
			if (sliceOffset > length || sliceSize > length - sliceOffset) {
				return -1;
			}
			NSInteger state = machOEncryptionStateForSlice(bytes + sliceOffset, (size_t)sliceSize);
			if (state == 1) {
				return 1;
			}
			if (state == 0) {
				sawDecryptedSlice = YES;
			}
			tableOffset += archSize;
		}
		return sawDecryptedSlice ? 0 : -1;
	}

	return machOEncryptionStateForSlice(bytes, length);
}

static NSString *findLdidPath(void) {
	NSMutableArray *candidates = [NSMutableArray array];
	const char *rootPath = ROOT_PATH("/usr/bin/ldid");
	if (rootPath != NULL) {
		[candidates addObject:[NSString stringWithUTF8String:rootPath]];
	}
	[candidates addObjectsFromArray:@[@"/usr/bin/ldid", @"/var/jb/usr/bin/ldid", @"/usr/local/bin/ldid"]];
	for (NSString *candidate in candidates) {
		if ([[NSFileManager defaultManager] isExecutableFileAtPath:candidate]) {
			return candidate;
		}
	}
	return nil;
}

static int runLdid(NSString *ldidPath, NSString *argument, NSString *binaryPath, NSString *stdoutPath) {
	pid_t pid = fork();
	if (pid < 0) {
		return -1;
	}
	if (pid == 0) {
		if (stdoutPath != nil) {
			int outputFD = open([stdoutPath fileSystemRepresentation], O_WRONLY | O_CREAT | O_TRUNC, 0600);
			if (outputFD < 0 || dup2(outputFD, STDOUT_FILENO) < 0) {
				_exit(126);
			}
			close(outputFD);
		}
		execl([ldidPath fileSystemRepresentation], [[ldidPath lastPathComponent] UTF8String], [argument UTF8String], [binaryPath fileSystemRepresentation], (char *)NULL);
		_exit(127);
	}
	int status = 0;
	if (waitpid(pid, &status, 0) < 0) {
		return -1;
	}
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static BOOL extractEntitlementsWithLdid(NSString *ldidPath, NSString *binaryPath, NSString *entitlementsPath) {
	if (runLdid(ldidPath, @"-e", binaryPath, entitlementsPath) != 0) {
		return NO;
	}
	NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:entitlementsPath error:nil];
	return [[attributes objectForKey:NSFileSize] unsignedLongLongValue] > 0;
}

static BOOL fakeSignMainExecutableInIPA(NSString *ipaPath, NSString *mainExecutablePath, NSString *workPath, NSString *sessionID) {
	NSString *ldidPath = findLdidPath();
	if (ldidPath == nil) {
		printf("A decrypted App Store IPA needs ldid to rebuild its invalidated code signature, but ldid was not found. Install Link Identity Editor (ldid) and try again.\n");
		return NO;
	}

	int zipError = 0;
	zip_t *archive = zip_open([ipaPath fileSystemRepresentation], 0, &zipError);
	if (archive == NULL) {
		printf("Unable to reopen the temporary IPA for fake-signing.\n");
		return NO;
	}
	zip_int64_t executableIndex = zip_name_locate(archive, [mainExecutablePath UTF8String], 0);
	if (executableIndex < 0) {
		printf("Unable to locate the main executable in the temporary IPA.\n");
		zip_discard(archive);
		return NO;
	}
	NSData *binaryData = dataForZipEntryAtIndex(archive, (zip_uint64_t)executableIndex);
	if (binaryData == nil) {
		printf("Unable to extract the main executable for fake-signing.\n");
		zip_discard(archive);
		return NO;
	}

	NSString *binaryPath = [workPath stringByAppendingPathComponent:[NSString stringWithFormat:@"appinst-session-%@-main", sessionID]];
	NSString *entitlementsPath = [workPath stringByAppendingPathComponent:[NSString stringWithFormat:@"appinst-session-%@-entitlements.plist", sessionID]];
	if (![binaryData writeToFile:binaryPath atomically:NO]) {
		printf("Unable to write the temporary main executable for fake-signing.\n");
		zip_discard(archive);
		return NO;
	}
	chmod([binaryPath fileSystemRepresentation], 0755);

	BOOL hasEntitlements = extractEntitlementsWithLdid(ldidPath, binaryPath, entitlementsPath);
	NSString *signArgument = hasEntitlements ? [NSString stringWithFormat:@"-S%@", entitlementsPath] : @"-S";
	printf("Rebuilding ad-hoc signature with %s%s.\n", [ldidPath UTF8String], hasEntitlements ? " while preserving original entitlements" : "");
	if (runLdid(ldidPath, signArgument, binaryPath, nil) != 0) {
		printf("ldid failed while fake-signing the decrypted App Store executable.\n");
		[[NSFileManager defaultManager] removeItemAtPath:binaryPath error:nil];
		[[NSFileManager defaultManager] removeItemAtPath:entitlementsPath error:nil];
		zip_discard(archive);
		return NO;
	}

	zip_source_t *replacement = zip_source_file(archive, [binaryPath fileSystemRepresentation], 0, 0);
	if (replacement == NULL || zip_file_replace(archive, (zip_uint64_t)executableIndex, replacement, 0) != 0) {
		if (replacement != NULL) {
			zip_source_free(replacement);
		}
		printf("Unable to put the fake-signed executable back into the temporary IPA.\n");
		[[NSFileManager defaultManager] removeItemAtPath:binaryPath error:nil];
		[[NSFileManager defaultManager] removeItemAtPath:entitlementsPath error:nil];
		zip_discard(archive);
		return NO;
	}
	if (zip_close(archive) != 0) {
		printf("Unable to commit the fake-signed executable to the temporary IPA.\n");
		[[NSFileManager defaultManager] removeItemAtPath:binaryPath error:nil];
		[[NSFileManager defaultManager] removeItemAtPath:entitlementsPath error:nil];
		return NO;
	}

	[[NSFileManager defaultManager] removeItemAtPath:binaryPath error:nil];
	[[NSFileManager defaultManager] removeItemAtPath:entitlementsPath error:nil];
	return YES;
}

'''
replace_once(
    'bool doesProcessAtPIDExist(pid_t pid) {',
    helper + 'bool doesProcessAtPIDExist(pid_t pid) {',
    'decrypted App Store helpers',
)

old_scan = '''\t\t// Original App Store IPA mode: preserve and explicitly pass the same FairPlay\n\t\t// installation metadata used by the iTunes/installation_proxy route. This does\n\t\t// not decrypt, modify, or re-sign the application. If either item is absent,\n\t\t// appinst keeps its original standard installation behaviour.\n\t\tNSString *sinfPath = [NSString stringWithFormat:@"%@/SC_Info/%@.sinf", appBundlePath, appExecutable];\n\t\tfor (zip_uint64_t i = 0; i < num_entries; ++i) {\n\t\t\tconst char *name = zip_get_name(archive, i, 0);\n\t\t\tif (!name) {\n\t\t\t\tcontinue;\n\t\t\t}\n\t\t\tNSString *fileName = [NSString stringWithUTF8String:name];\n\t\t\tif (iTunesMetadata == nil && [fileName isEqualToString:@"iTunesMetadata.plist"]) {\n\t\t\t\tiTunesMetadata = dataForZipEntryAtIndex(archive, i);\n\t\t\t} else if (applicationSINF == nil && [fileName isEqualToString:sinfPath]) {\n\t\t\t\tapplicationSINF = dataForZipEntryAtIndex(archive, i);\n\t\t\t}\n\t\t\tif (applicationSINF != nil && iTunesMetadata != nil) {\n\t\t\t\tbreak;\n\t\t\t}\n\t\t}\n\t\tzip_close(archive);\n\n\t\tBOOL appStoreIPAMode = (applicationSINF != nil && iTunesMetadata != nil);\n\t\tif (appStoreIPAMode) {\n\t\t\tprintf("Original App Store IPA mode enabled (ApplicationSINF + iTunesMetadata).\\n");\n\t\t} else if (applicationSINF != nil || iTunesMetadata != nil) {\n\t\t\tprintf("Incomplete App Store metadata detected; using standard appinst mode.\\n");\n\t\t}\n'''

new_scan = '''\t\t// Inspect App Store metadata and the main Mach-O encryption state. A genuine\n\t\t// encrypted App Store package keeps cryptid=1 and is passed through unchanged.\n\t\t// A decrypted App Store package usually keeps SC_Info but has cryptid=0; its\n\t\t// original App Store CodeDirectory no longer hashes the modified executable, so\n\t\t// it must be ad-hoc signed before installation to avoid an immediate launch kill.\n\t\tNSString *sinfPath = [NSString stringWithFormat:@"%@/SC_Info/%@.sinf", appBundlePath, appExecutable];\n\t\tNSString *mainExecutablePath = [NSString stringWithFormat:@"%@/%@", appBundlePath, appExecutable];\n\t\tNSData *mainExecutableData = nil;\n\t\tfor (zip_uint64_t i = 0; i < num_entries; ++i) {\n\t\t\tconst char *name = zip_get_name(archive, i, 0);\n\t\t\tif (!name) {\n\t\t\t\tcontinue;\n\t\t\t}\n\t\t\tNSString *fileName = [NSString stringWithUTF8String:name];\n\t\t\tif (iTunesMetadata == nil && [fileName isEqualToString:@"iTunesMetadata.plist"]) {\n\t\t\t\tiTunesMetadata = dataForZipEntryAtIndex(archive, i);\n\t\t\t} else if (applicationSINF == nil && [fileName isEqualToString:sinfPath]) {\n\t\t\t\tapplicationSINF = dataForZipEntryAtIndex(archive, i);\n\t\t\t} else if (mainExecutableData == nil && [fileName isEqualToString:mainExecutablePath]) {\n\t\t\t\tmainExecutableData = dataForZipEntryAtIndex(archive, i);\n\t\t\t}\n\t\t\tif (applicationSINF != nil && mainExecutableData != nil && iTunesMetadata != nil) {\n\t\t\t\tbreak;\n\t\t\t}\n\t\t}\n\t\tzip_close(archive);\n\n\t\tNSInteger encryptionState = machOEncryptionState(mainExecutableData);\n\t\tBOOL decryptedAppStoreIPAMode = (applicationSINF != nil && encryptionState == 0);\n\t\tBOOL appStoreIPAMode = (applicationSINF != nil && encryptionState == 1);\n\t\tif (decryptedAppStoreIPAMode) {\n\t\t\tprintf("Decrypted App Store IPA detected (SC_Info + cryptid=0); fake-sign mode enabled.\\n");\n\t\t} else if (appStoreIPAMode) {\n\t\t\tprintf("Original encrypted App Store IPA mode enabled (ApplicationSINF%s).\\n", iTunesMetadata != nil ? " + iTunesMetadata" : "");\n\t\t} else if (applicationSINF != nil || iTunesMetadata != nil) {\n\t\t\tprintf("App Store metadata detected, but the main executable encryption state is unknown; using standard appinst mode.\\n");\n\t\t}\n'''
replace_once(old_scan, new_scan, 'App Store encryption-state scan')

old_copy = '''\t\tif (![fileManager copyItemAtPath:filePath toPath:installPath error:nil]) {\n\t\t\tprintf("Failed to copy the specified IPA to the temporary directory. Do you have enough free disk space?\\n");\n\t\t\treturn AppInstExitCodeFileSystem;\n\t\t}\n\n\t\t// Call system APIs to actually install the app\n'''
new_copy = '''\t\tif (![fileManager copyItemAtPath:filePath toPath:installPath error:nil]) {\n\t\t\tprintf("Failed to copy the specified IPA to the temporary directory. Do you have enough free disk space?\\n");\n\t\t\treturn AppInstExitCodeFileSystem;\n\t\t}\n\n\t\tif (decryptedAppStoreIPAMode) {\n\t\t\tif (!fakeSignMainExecutableInIPA(installPath, mainExecutablePath, workPath, sessionID)) {\n\t\t\t\tprintf("Failed to prepare the decrypted App Store IPA for launch.\\n");\n\t\t\t\treturn AppInstExitCodeInject;\n\t\t\t}\n\t\t}\n\n\t\t// Call system APIs to actually install the app\n'''
replace_once(old_copy, new_copy, 'fake-sign before install')

source = source.replace(
    '''\t\t\tif (appStoreIPAMode) {\n\t\t\t\t[options setObject:applicationSINF forKey:kApplicationSINFKey];\n\t\t\t\t[options setObject:iTunesMetadata forKey:kITunesMetadataKey];\n\t\t\t}''',
    '''\t\t\tif (appStoreIPAMode) {\n\t\t\t\t[options setObject:applicationSINF forKey:kApplicationSINFKey];\n\t\t\t\tif (iTunesMetadata != nil) {\n\t\t\t\t\t[options setObject:iTunesMetadata forKey:kITunesMetadataKey];\n\t\t\t\t}\n\t\t\t}'''
)
if source.count('[options setObject:iTunesMetadata forKey:kITunesMetadataKey];') != 2:
    raise SystemExit('optional iTunesMetadata injection: expected two install paths')

path.write_text(source, encoding='utf-8')
print(f'Applied decrypted App Store fake-sign mode to {path}')
