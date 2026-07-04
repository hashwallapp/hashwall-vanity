#!/bin/bash

set -eu

dir="$(dirname "$0")"

mkdir -p "$dir/build"

#
# compile sqlite
#

if [ ! -f "$dir/build/sqlite3.a" ]; then
    echo "$dir/build/sqlite3.a not found, compiling from source"
    gcc -c -O3 -o "$dir/build/sqlite3.o" "$dir/src/third_party/sqlite3.c"
    ar rcs "$dir/build/sqlite3.a" "$dir/build/sqlite3.o"
fi

#
# compile generator
#

flags_slow="-DHASHWALL_SLOW=1 -O0 -g -G"
flags_fast="-DHASHWALL_FAST=1 -O3 -maxrregcount=128"
flags_internal="-DHASHWALL_INTERNAL=1"

flags_warnings="-Wno-deprecated-gpu-targets -diag-suppress 2464,550,177"

flags_card_1060="-arch=sm_61"
flags_card_1650="-arch=sm_75"
flags_card_3050="-arch=sm_86"
flags_card_5060="-arch=sm_120"

flags="$flags_slow $flags_internal $flags_card_1060 $flags_warnings -I$dir/../../../src/ -std=c++11"

echo "compiling gpu_generator"
nvcc $flags -o "$dir/build/gpu_generator" "$dir/src/gpu_generator.cu" "$dir/build/sqlite3.a" "$dir/src/third_party/libsodium/libsodium_modified.a"
