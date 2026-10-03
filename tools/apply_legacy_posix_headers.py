#!/usr/bin/env python3
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
source = path.read_text(encoding="utf-8")

old = '#include <fcntl.h>\n#include <sys/wait.h>'
new = (
    '#include <fcntl.h>\n'
    '#include <stdint.h>\n'
    '#include <string.h>\n'
    '#include <sys/stat.h>\n'
    '#include <sys/types.h>\n'
    '#include <sys/wait.h>\n'
    '#include <unistd.h>'
)

count = source.count(old)
if count != 1:
    raise SystemExit(f'POSIX header marker: expected exactly one match, found {count}')

path.write_text(source.replace(old, new, 1), encoding='utf-8')
print(f'Applied legacy SDK POSIX header compatibility to {path}')
