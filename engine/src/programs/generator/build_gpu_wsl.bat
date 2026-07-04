@echo off

wsl --cd "%~dp0" --shell-type standard ./build_gpu.sh
