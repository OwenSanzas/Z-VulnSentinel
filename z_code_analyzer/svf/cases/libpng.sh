#!/bin/bash
# =============================================================================
# Case: libpng — In-tree harness + autotools
# =============================================================================
# 特点:
#   - Harness 在项目内: contrib/oss-fuzz/libpng_read_fuzzer.cc
#   - autotools 构建 (configure.ac)
#   - 依赖: zlib (系统自带)
#   - 简单, 无外部 oss-fuzz 依赖
# =============================================================================

PROJECT_NAME="libpng"
BUILD_MODE="intree-autotools"

# 源码路径 (Docker 中的标准位置)
PROJECT_SRC="$SRC/libpng"
INSTALL_PREFIX="$SRC/libpng_install"

# Harness 配置
HARNESS_SRC="$SRC/libpng/contrib/oss-fuzz"
HARNESS_FILES="libpng_read_fuzzer.cc"
HARNESS_LANG="c++"
OUTPUT_BINARY="libpng_read_fuzzer"

# 构建参数
CONFIGURE_FLAGS="--without-libpng-prefix"

# 链接: 静态 libpng + zlib
EXTRA_LIBS="-lz -lm -lpthread"
