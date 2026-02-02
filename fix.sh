#!/usr/bin/env bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <directory>"
    exit 1
fi

DIR="$1"

if [ ! -d "$DIR" ]; then
    echo "Error: '$DIR' is not a directory"
    exit 1
fi

find "$DIR" -type f \( -name "*.c" -o -name "*.cpp" \) | while read -r file; do
    if grep -q "QuicTraceEvent" "$file"; then
        python3 -c "
import sys

with open('$file', 'r') as f:
    content = f.read()

result = []
i = 0
while i < len(content):
    if content[i:i+15] == 'QuicTraceEvent(':
        depth = 1
        i += 15
        while i < len(content) and depth > 0:
            if content[i] == '(':
                depth += 1
            elif content[i] == ')':
                depth -= 1
            i += 1
        if i < len(content) and content[i] == ';':
            i += 1
        result.append('(void)0;')
    else:
        result.append(content[i])
        i += 1

with open('$file', 'w') as f:
    f.write(''.join(result))
"
        echo "Cleaned: $file"
    fi
done

echo "Done."
