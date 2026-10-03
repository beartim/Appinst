#!/usr/bin/env python3
import pathlib
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: apply_runtime_appsync_gate.py <appinst.m> <control>")

source_path = pathlib.Path(sys.argv[1])
control_path = pathlib.Path(sys.argv[2])
source = source_path.read_text(encoding="utf-8")
control = control_path.read_text(encoding="utf-8")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


helper = r'''
static NSString *findDpkgQueryPath(void) {
	NSMutableArray *candidates = [NSMutableArray array];
	const char *rootPath = ROOT_PATH("/usr/bin/dpkg-query");
	if (rootPath != NULL) {
		[candidates addObject:[NSString stringWithUTF8String:rootPath]];
	}
	[candidates addObjectsFromArray:@[@"/usr/bin/dpkg-query", @"/var/jb/usr/bin/dpkg-query", @"/usr/local/bin/dpkg-query"]];
	for (NSString *candidate in candidates) {
		if ([[NSFileManager defaultManager] isExecutableFileAtPath:candidate]) {
			return candidate;
		}
	}
	return nil;
}

static BOOL isAppSyncUnifiedInstalled(void) {
	NSString *dpkgQueryPath = findDpkgQueryPath();
	if (dpkgQueryPath == nil) {
		return NO;
	}

	int outputPipe[2];
	if (pipe(outputPipe) != 0) {
		return NO;
	}

	pid_t pid = fork();
	if (pid < 0) {
		close(outputPipe[0]);
		close(outputPipe[1]);
		return NO;
	}
	if (pid == 0) {
		close(outputPipe[0]);
		if (dup2(outputPipe[1], STDOUT_FILENO) < 0) {
			_exit(126);
		}
		close(outputPipe[1]);

		int nullFD = open("/dev/null", O_WRONLY);
		if (nullFD >= 0) {
			dup2(nullFD, STDERR_FILENO);
			close(nullFD);
		}

		execl([dpkgQueryPath fileSystemRepresentation], [[dpkgQueryPath lastPathComponent] UTF8String],
			"-W", "-f=${Status}", "ai.akemi.appsyncunified", (char *)NULL);
		_exit(127);
	}

	close(outputPipe[1]);
	NSMutableData *output = [NSMutableData data];
	uint8_t buffer[128];
	ssize_t bytesRead = 0;
	while ((bytesRead = read(outputPipe[0], buffer, sizeof(buffer))) > 0) {
		[output appendBytes:buffer length:(NSUInteger)bytesRead];
	}
	close(outputPipe[0]);

	int status = 0;
	if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		return NO;
	}

	NSString *statusText = [[NSString alloc] initWithData:output encoding:NSUTF8StringEncoding];
	if (statusText == nil) {
		return NO;
	}
	statusText = [statusText stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
	return [statusText isEqualToString:@"install ok installed"];
}

'''

source = replace_once(
    source,
    'bool doesProcessAtPIDExist(pid_t pid) {',
    helper + 'bool doesProcessAtPIDExist(pid_t pid) {',
    'AppSync runtime helper insertion',
)

gate = '''\t\tif (!appStoreIPAMode && !isAppSyncUnifiedInstalled()) {\n\t\t\tprintf("This IPA requires AppSync Unified.\\n");\n\t\t\tprintf("Please install ai.akemi.appsyncunified and try again.\\n");\n\t\t\tprintf("Installation aborted.\\n");\n\t\t\treturn AppInstExitCodeRuntime;\n\t\t}\n\n'''
source = replace_once(
    source,
    '\t\t// Begin copying the IPA to a temporary directory\n',
    gate + '\t\t// Begin copying the IPA to a temporary directory\n',
    'pre-session AppSync gate',
)

control = replace_once(
    control,
    'Depends: ai.akemi.appsyncunified (>= 5.1)\n',
    '',
    'AppSync hard dependency removal',
)

source_path.write_text(source, encoding="utf-8")
control_path.write_text(control, encoding="utf-8")
print(f"Applied runtime AppSync gate to {source_path} and removed hard dependency from {control_path}")
