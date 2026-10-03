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
    'static int runLdid(NSString *ldidPath, NSString *argument, NSString *binaryPath, NSString *stdoutPath) {',
    'static int runLdid(NSString *ldidPath, NSString *argument, NSString *binaryPath, NSString *identifierArgument, NSString *stdoutPath) {',
    'ldid helper signature',
)

replace_once(
    '\t\texecl([ldidPath fileSystemRepresentation], [[ldidPath lastPathComponent] UTF8String], [argument UTF8String], [binaryPath fileSystemRepresentation], (char *)NULL);',
    '''\t\tif (identifierArgument != nil) {\n\t\t\texecl([ldidPath fileSystemRepresentation], [[ldidPath lastPathComponent] UTF8String], [argument UTF8String], [identifierArgument UTF8String], [binaryPath fileSystemRepresentation], (char *)NULL);\n\t\t} else {\n\t\t\texecl([ldidPath fileSystemRepresentation], [[ldidPath lastPathComponent] UTF8String], [argument UTF8String], [binaryPath fileSystemRepresentation], (char *)NULL);\n\t\t}''',
    'ldid optional identifier argument',
)

replace_once(
    'if (runLdid(ldidPath, @"-e", binaryPath, entitlementsPath) != 0) {',
    'if (runLdid(ldidPath, @"-e", binaryPath, nil, entitlementsPath) != 0) {',
    'ldid entitlement extraction call',
)

replace_once(
    '\tNSString *signArgument = [NSString stringWithFormat:@"-S%@", entitlementsPath];\n',
    '\tNSString *signArgument = [NSString stringWithFormat:@"-S%@", entitlementsPath];\n\tNSString *identifierArgument = [NSString stringWithFormat:@"-I%@", bundleIdentifier];\n',
    'explicit CodeDirectory identifier argument',
)

replace_once(
    'if (runLdid(ldidPath, signArgument, binaryPath, nil) != 0) {',
    'if (runLdid(ldidPath, signArgument, binaryPath, identifierArgument, nil) != 0) {',
    'ldid signing call',
)

path.write_text(source, encoding='utf-8')
print(f'Applied explicit ldid CodeDirectory identifier fix to {path}')
