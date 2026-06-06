#!/bin/bash

mkdir -p build

flags_debug="-O0 -g -G"
flags_release="-O3 -maxrregcount=128"
flags_warnings="-Wno-deprecated-gpu-targets -diag-suppress 2464,550"
flags_card_1060="-arch=sm_61"
flags_card_1650="-arch=sm_75"
flags_card_3050="-arch=sm_86"
flags_card_5060="-arch=sm_120"

flags="$flags_release $flags_card_1060 $flags_warnings -std=c++11"

nvcc $flags -o ./build/gpu_generator ./src/gpu_generator.cu
