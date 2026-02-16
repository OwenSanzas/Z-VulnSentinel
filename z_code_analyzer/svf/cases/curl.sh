#!/bin/bash
# =============================================================================
# Case: curl — External harness (oss-fuzz) + ossfuzz-script
# =============================================================================
# 特点:
#   - Harness 在外部仓库: curl_fuzzer (由 oss-fuzz Dockerfile 解压)
#   - curl 自身用 autotools 构建
#   - 依赖: openssl, zlib (Docker 中已有)
#   - curl_fuzzer 的 ossfuzz.sh 会安装额外依赖 (nghttp2 等)
#   - 最复杂的 case, 需要自定义构建流程
#
# Docker 要求:
#   使用 oss-fuzz-aixcc 的 Dockerfile 构建的 base image
#   里面已有: $SRC/curl, $SRC/curl_fuzzer, openssl, nghttp2 等
# =============================================================================

PROJECT_NAME="curl"
BUILD_MODE="ossfuzz-script"

# 输出配置
OUTPUT_BINARY="curl_fuzzer"

# Harness 配置 (用于 extract-bc, 不直接编译)
HARNESS_SRC="$SRC/curl_fuzzer"
HARNESS_FILES="curl_fuzzer.cc curl_fuzzer_tlv.cc curl_fuzzer_callback.cc"
HARNESS_LANG="c++"

# curl_fuzzer 的 ossfuzz.sh 自己会安装 nghttp2-dev, 但我们要绕过它
# 因为 ossfuzz.sh 依赖 LIB_FUZZING_ENGINE 等 OSS-Fuzz 特有变量
# 所以我们手动构建
EXTRA_LIBS="-lssl -lcrypto -lz -lpthread -lm"

# ---- 自定义构建函数 ----
run_ossfuzz_build() {
    local INSTALLDIR="$SRC/curl_install"
    mkdir -p "$INSTALLDIR"

    # 安装 curl_fuzzer 的构建依赖
    apt-get install -y -qq \
        autoconf automake libtool pkg-config \
        libssl-dev zlib1g-dev 2>&1 | tail -3

    # ---- Build curl ----
    echo "  Building curl..."
    cd "$SRC/curl"

    if [ -f buildconf ]; then
        ./buildconf 2>&1 | tail -3
    else
        autoreconf -fi 2>&1 | tail -3
    fi

    ./configure --prefix="$INSTALLDIR" \
        --disable-shared \
        --enable-static \
        --enable-debug \
        --enable-ipv6 \
        --enable-websockets \
        --without-libpsl \
        --without-nghttp2 \
        --with-ssl \
        --with-random=/dev/null 2>&1 | tail -5

    make -j$(nproc) 2>&1 | tail -5
    make install 2>&1 | tail -3

    # ---- Build harness ----
    echo "  Building curl_fuzzer harness..."
    cd "$SRC/curl_fuzzer"

    local HARNESS_CXXFLAGS="-g -O0 -I${INSTALLDIR}/include -I. -DFUZZ_PROTOCOLS_ALL"

    $CXX $HARNESS_CXXFLAGS -c curl_fuzzer.cc -o curl_fuzzer.o 2>&1 | tail -3
    $CXX $HARNESS_CXXFLAGS -c curl_fuzzer_tlv.cc -o curl_fuzzer_tlv.o 2>&1 | tail -3
    $CXX $HARNESS_CXXFLAGS -c curl_fuzzer_callback.cc -o curl_fuzzer_callback.o 2>&1 | tail -3

    # Stub engine
    cat > /tmp/svf_stub_engine.cc << 'STUBEOF'
#include <cstdint>
#include <cstdlib>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int main(int argc, char **argv) { return 0; }
STUBEOF
    $CXX -c -g -O0 /tmp/svf_stub_engine.cc -o /tmp/svf_stub_engine.o

    # Link
    mkdir -p /out
    $CXX -g -o /out/curl_fuzzer \
        curl_fuzzer.o curl_fuzzer_tlv.o curl_fuzzer_callback.o \
        /tmp/svf_stub_engine.o \
        "${INSTALLDIR}/lib/libcurl.a" \
        -lssl -lcrypto -lz -lpthread -lm 2>&1

    echo "  Built: $(ls -lh /out/curl_fuzzer)"
}

# 因为 ossfuzz-script 模式自己处理构建和链接,
# 告诉 pipeline 跳过通用的 harness 编译和链接步骤
SKIP_GENERIC_HARNESS="yes"
