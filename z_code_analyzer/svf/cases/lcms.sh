#!/bin/bash
# =============================================================================
# Case: lcms (Little CMS) — In-tree harness + autotools
# =============================================================================
# 特点:
#   - Harness 在项目内: fuzzers/fuzzers.c (C 语言, 不是 C++)
#   - autotools 构建 (configure.ac)
#   - 依赖: libm, libpthread (系统自带)
#   - 简单, 零外部依赖
# =============================================================================

PROJECT_NAME="lcms"
BUILD_MODE="intree-autotools"

# 源码路径
PROJECT_SRC="$SRC/lcms"
INSTALL_PREFIX="$SRC/lcms_install"

# Harness 配置
HARNESS_SRC="$SRC/lcms/fuzzers"
HARNESS_FILES="fuzzers.c"
HARNESS_LANG="c"
OUTPUT_BINARY="lcms_fuzzer"

# 构建参数 — lcms 的 configure 很简单
CONFIGURE_FLAGS=""

# 链接: 只需 libm
EXTRA_LIBS="-lm -lpthread"
