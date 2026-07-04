#!/bin/bash

mkdir -p build

gcc -ggdb -o ./build/cpu_generator ./src/cpu_generator.c ./src/third_party/libsodium/libsodium.a
