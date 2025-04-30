#!/bin/bash

# 激活虚拟环境
source "/home/kai/SuriVisor/venv/bin/activate"

# 使用sudo -E保持环境变量并以root权限运行应用
sudo -E /home/kai/SuriVisor/venv/bin/python3 src/main.py
