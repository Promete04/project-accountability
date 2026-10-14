#!/bin/bash
# Runnable from anywhere: resolve the build directory relative to this script,
# not to the caller's working directory.
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
exec ./build/unit_tests "$@"
