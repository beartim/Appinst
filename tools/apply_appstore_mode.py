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
    '#define kIdentifierKey @"CFBundleIdentifier"\n#define kAppType @"User"',
    '#define kIdentifierKey @"CFBundleIdentifier"\n'
    '#define kExecutableKey @"CFBundleExecutable"\n'
    '#define kApplicationSINFKey @"ApplicationSINF"\n'
    '#define kITunesMetadataKey @"iTunesMetadata"\n'
    '#define kAppType @"User"',
    "install option constants",
)

helper = r'''
static NSData *dataForZipEntryAtIndex(zip_t *archive, zip_uint64_t index) {
	zip_stat_t st;
	zip_stat_init(&st);
	if (zip_stat_index(archive, index, 0, &st) != 0) {
		return nil;
	}

	size_t size = (size_t)st.size;
	if ((zip_uint64_t)size != st.size) {
		return nil;
	}
	if (size == 0) {
		return [NSData data];
	}

	void *buffer = malloc(size);
	if (!buffer) {
		return nil;
	}

	zip_file_t *fileInZip = zip_fopen_index(archive, index, 0);
	if (!fileInZip) {
		free(buffer);
		return nil;
	}

	zip_int64_t bytesRead = zip_fread(fileInZip, buffer, size);
	zip_fclose(fileInZip);
	if (bytesRead < 0 || (zip_uint64_t)bytesRead != st.size) {
		free(buffer);
		return nil;
	}

	return [NSData dataWithBytesNoCopy:buffer length:size freeWhenDone:YES];
}

'''
replace_once(
    'bool doesProcessAtPIDExist(pid_t pid) {',
    helper + 'bool doesProcessAtPIDExist(pid_t pid) {',
    "zip data helper",
)

replace_once(
    '\t\tNSString *appIdentifier = nil;\n\t\tint err = 0;',
    '\t\tNSString *appIdentifier = nil;\n'
    '\t\tNSString *appExecutable = nil;\n'
    '\t\tNSString *appBundlePath = nil;\n'
    '\t\tNSData *applicationSINF = nil;\n'
    '\t\tNSData *iTunesMetadata = nil;\n'
    '\t\tint err = 0;',
    "App Store metadata variables",
)

replace_once(
    '\t\t\t\tappIdentifier = [dict objectForKey:kIdentifierKey];\n\t\t\t\tbreak;',
    '\t\t\t\tappIdentifier = [dict objectForKey:kIdentifierKey];\n'
    '\t\t\t\tappExecutable = [dict objectForKey:kExecutableKey];\n'
    '\t\t\t\tappBundlePath = [fileName stringByDeletingLastPathComponent];\n'
    '\t\t\t\tbreak;',
    "Info.plist fields",
)

old_close_and_validate = '''\t\tzip_close(archive);\n\n\t\tif (appIdentifier == nil) {\n\t\t\tprintf("Failed to resolve app identifier for the specified IPA file.\\n");\n\t\t\treturn AppInstExitCodeMalformed;\n\t\t}\n'''

new_close_and_validate = '''\t\tif (appIdentifier == nil || appExecutable == nil || appBundlePath == nil) {\n\t\t\tzip_close(archive);\n\t\t\tprintf("Failed to resolve app identifier or executable for the specified IPA file.\\n");\n\t\t\treturn AppInstExitCodeMalformed;\n\t\t}\n\n\t\t// Original App Store IPA mode: preserve and explicitly pass the same FairPlay\n\t\t// installation metadata used by the iTunes/installation_proxy route. This does\n\t\t// not decrypt, modify, or re-sign the application. If either item is absent,\n\t\t// appinst keeps its original standard installation behaviour.\n\t\tNSString *sinfPath = [NSString stringWithFormat:@"%@/SC_Info/%@.sinf", appBundlePath, appExecutable];\n\t\tfor (zip_uint64_t i = 0; i < num_entries; ++i) {\n\t\t\tconst char *name = zip_get_name(archive, i, 0);\n\t\t\tif (!name) {\n\t\t\t\tcontinue;\n\t\t\t}\n\t\t\tNSString *fileName = [NSString stringWithUTF8String:name];\n\t\t\tif (iTunesMetadata == nil && [fileName isEqualToString:@"iTunesMetadata.plist"]) {\n\t\t\t\tiTunesMetadata = dataForZipEntryAtIndex(archive, i);\n\t\t\t} else if (applicationSINF == nil && [fileName isEqualToString:sinfPath]) {\n\t\t\t\tapplicationSINF = dataForZipEntryAtIndex(archive, i);\n\t\t\t}\n\t\t\tif (applicationSINF != nil && iTunesMetadata != nil) {\n\t\t\t\tbreak;\n\t\t\t}\n\t\t}\n\t\tzip_close(archive);\n\n\t\tBOOL appStoreIPAMode = (applicationSINF != nil && iTunesMetadata != nil);\n\t\tif (appStoreIPAMode) {\n\t\t\tprintf("Original App Store IPA mode enabled (ApplicationSINF + iTunesMetadata).\\n");\n\t\t} else if (applicationSINF != nil || iTunesMetadata != nil) {\n\t\t\tprintf("Incomplete App Store metadata detected; using standard appinst mode.\\n");\n\t\t}\n'''
replace_once(old_close_and_validate, new_close_and_validate, "App Store metadata scan")

replace_once(
    '\t\t\tNSDictionary *options = [NSDictionary dictionaryWithObject:appIdentifier forKey:kIdentifierKey];',
    '\t\t\tNSMutableDictionary *options = [NSMutableDictionary dictionaryWithObject:appIdentifier forKey:kIdentifierKey];\n'
    '\t\t\tif (appStoreIPAMode) {\n'
    '\t\t\t\t[options setObject:applicationSINF forKey:kApplicationSINFKey];\n'
    '\t\t\t\t[options setObject:iTunesMetadata forKey:kITunesMetadataKey];\n'
    '\t\t\t}',
    "LSApplicationWorkspace App Store options",
)

replace_once(
    '\t\t\tNSDictionary *options = [NSDictionary dictionaryWithObject:kAppType forKey:kAppTypeKey];',
    '\t\t\tNSMutableDictionary *options = [NSMutableDictionary dictionaryWithObject:kAppType forKey:kAppTypeKey];\n'
    '\t\t\tif (appStoreIPAMode) {\n'
    '\t\t\t\t[options setObject:applicationSINF forKey:kApplicationSINFKey];\n'
    '\t\t\t\t[options setObject:iTunesMetadata forKey:kITunesMetadataKey];\n'
    '\t\t\t}',
    "MobileInstallation App Store options",
)

path.write_text(source, encoding="utf-8")
print(f"Applied original App Store IPA mode to {path}")
