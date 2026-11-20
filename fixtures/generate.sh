#!/bin/sh
# Regenerate the test repositories in this directory.
#
# Each is kept as a `git fast-export` stream rather than a repository, since
# git will not track a nested `.git`. Tests rebuild them with `git fast-import`
# (see src/fixtures.rs), which yields the same commit hashes. Identities,
# dates and configuration are pinned so that rerunning this script changes
# nothing unless the history below does.
#
# Usage: fixtures/generate.sh

set -eu

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@example.com
export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@example.com
time=1767225600 # 2026-01-01T00:00:00Z

# commit FILE TEXT MESSAGE [TAG]: write TEXT to FILE and commit it, an hour
# after the previous commit.
commit() {
    mkdir -p "$(dirname "$1")"
    printf '%b' "$2" > "$1"
    time=$((time + 3600))
    export GIT_AUTHOR_DATE="@$time +0000" GIT_COMMITTER_DATE="@$time +0000"
    git add "$1"
    git commit -q -m "$3"
    if [ $# -ge 4 ]; then git tag "$4"; fi
}

# repository NAME: start a repository, filled by the commands that follow,
# and exported by `export_to`.
repository() {
    rm -rf "${work:?}/$1"
    git init -q -b main "$work/$1"
    cd "$work/$1"
}

export_to() {
    git fast-export --all > "$here/$1.fi"
    cd "$here"
}

# A flaw introduced in v1.1, carried through a refactor in v1.2, and fixed
# in v1.3. The refactor is what blame lands on first.
repository history
commit lib.c 'int f(char *s) {\n  return 0;\n}\n' initial v1.0
commit lib.c 'int f(char *s) {\n  return strlen(s);\n}\n' 'allow binary names' v1.1
commit lib.c 'int f(char *name) {\n  return strlen(name);\n}\n' 'rename argument' v1.2
commit lib.c 'int f(char *name, size_t len) {\n  return len;\n}\n' 'fix length of binary names' v1.3
export_to history

# Two untagged commits under a subdirectory.
repository simple
commit src/lib.c 'int f(void) {\n  return 0;\n}\n' initial
commit src/lib.c 'int f(void) {\n  return 1;\n}\n' fix
export_to simple
