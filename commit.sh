#!/bin/bash

# Auto-commit each git change individually
# Usage: ./git-auto-commit.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if we're in a git repository
if ! git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    echo -e "${RED}Error: Not a git repository${NC}"
    exit 1
fi

# Counters
created=0
modified=0
deleted=0
renamed=0

echo -e "${BLUE}=== Git Auto-Commit Script ===${NC}\n"

# Handle untracked files (new files)
while IFS= read -r file; do
    if [[ -n "$file" ]]; then
        echo -e "${GREEN}[CREATE]${NC} $file"
        git add "$file"
        git commit -m "Create $file"
        ((created++))
    fi
done < <(git ls-files --others --exclude-standard)

# Handle staged and unstaged changes
while IFS= read -r line; do
    if [[ -z "$line" ]]; then
        continue
    fi

    # Get the status code and filename
    status="${line:0:2}"
    file="${line:3}"

    # Handle renamed files (R + space or RM, etc.)
    if [[ "$status" == R* ]] || [[ "$line" =~ ^R[0-9]* ]]; then
        # Format is "R  old -> new" or "R100 old -> new"
        old_file=$(echo "$file" | sed 's/ -> .*//')
        new_file=$(echo "$file" | sed 's/.* -> //')
        echo -e "${YELLOW}[RENAME]${NC} $old_file -> $new_file"
        git add "$old_file" "$new_file" 2>/dev/null || git add "$new_file"
        git commit -m "Rename $old_file to $new_file"
        ((renamed++))
        continue
    fi

    # Handle deleted files
    if [[ "$status" == " D" ]] || [[ "$status" == "D " ]] || [[ "$status" == "D" ]]; then
        echo -e "${RED}[DELETE]${NC} $file"
        git add "$file"
        git commit -m "Delete $file"
        ((deleted++))
        continue
    fi

    # Handle modified files
    if [[ "$status" == " M" ]] || [[ "$status" == "M " ]] || [[ "$status" == "MM" ]] || [[ "$status" == "M" ]]; then
        echo -e "${YELLOW}[UPDATE]${NC} $file"
        git add "$file"
        git commit -m "Update $file"
        ((modified++))
        continue
    fi

    # Handle added files (already staged)
    if [[ "$status" == "A " ]] || [[ "$status" == "A" ]]; then
        echo -e "${GREEN}[CREATE]${NC} $file"
        git add "$file"
        git commit -m "Create $file"
        ((created++))
        continue
    fi

    # Handle any other modifications
    if [[ -n "$file" ]]; then
        echo -e "${BLUE}[CHANGE]${NC} $file (status: $status)"
        git add "$file"
        git commit -m "Update $file"
        ((modified++))
    fi

done < <(git status --porcelain)

# Summary
echo -e "\n${BLUE}=== Summary ===${NC}"
echo -e "${GREEN}Created:${NC}  $created"
echo -e "${YELLOW}Modified:${NC} $modified"
echo -e "${RED}Deleted:${NC}  $deleted"
echo -e "${YELLOW}Renamed:${NC}  $renamed"
echo -e "Total commits: $((created + modified + deleted + renamed))"
