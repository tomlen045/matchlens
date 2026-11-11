#!/usr/bin/env python3
"""matchlens 独立自测入口（与 matchlens.py selftest 子命令同源）。"""
import sys
from matchlens import selftest

if __name__ == "__main__":
    sys.exit(selftest())
