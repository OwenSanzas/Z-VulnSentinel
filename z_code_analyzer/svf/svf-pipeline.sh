#!/bin/bash
# =============================================================================
# SVF Bitcode Extraction Pipeline — Library-Only Version
# =============================================================================
# Migrated from experiment/sast-test/pipeline/svf-pipeline.sh
# Key change: produces library-only .bc (excludes fuzzer source .bc files)
#
# Usage: svf-pipeline.sh <case-config.sh>
#
# Three modes (auto-selected by case config):
#   A) intree-autotools — harness in project, autotools build (libpng, lcms)
#   B) intree-cmake     — harness in project, cmake build
#   C) ossfuzz-script   — harness in external oss-fuzz repo, Docker build (curl)
#
# Environment variables from case config:
#   PROJECT_NAME, BUILD_MODE, PROJECT_SRC, HARNESS_SRC, HARNESS_FILES,
#   HARNESS_LANG, OUTPUT_BINARY, CONFIGURE_FLAGS, CMAKE_FLAGS, etc.
#
# New env var for library-only mode:
#   FUZZER_SOURCE_FILES — space-separated list of fuzzer source files to exclude
#                         from llvm-link (e.g. "fuzz/fuzz1.c fuzz/fuzz2.cc")
# =============================================================================

set -e

# ---- Load case config ----
CASE_CONFIG="${1:?Usage: svf-pipeline.sh <case-config.sh>}"
if [ ! -f "$CASE_CONFIG" ]; then
    echo "ERROR: Case config not found: $CASE_CONFIG"
    exit 1
fi
source "$CASE_CONFIG"

echo "================================================================"
echo " SVF Bitcode Pipeline (Library-Only): ${PROJECT_NAME}"
echo " Mode: ${BUILD_MODE}"
echo "================================================================"

# ---- Defaults ----
PROJECT_SRC="${PROJECT_SRC:-$SRC/$PROJECT_NAME}"
INSTALL_PREFIX="${INSTALL_PREFIX:-$SRC/${PROJECT_NAME}_install}"
OUTPUT_BINARY="${OUTPUT_BINARY:-${PROJECT_NAME}_fuzzer}"
HARNESS_LANG="${HARNESS_LANG:-c++}"
EXTRA_LIBS="${EXTRA_LIBS:-}"
EXTRA_INCLUDES="${EXTRA_INCLUDES:-}"
SKIP_INSTALL="${SKIP_INSTALL:-no}"
FUZZER_SOURCE_FILES="${FUZZER_SOURCE_FILES:-}"

# ---- Step 0: Install toolchain ----
echo "=== [0/6] Installing wllvm + llvm-link ==="

pip3 install wllvm 2>&1 | tail -3

# Detect clang version and install matching llvm-link
LLVM_VER=$(clang --version | grep -oP 'clang version \K[0-9]+')
echo "Detected clang version: ${LLVM_VER}"

if command -v llvm-link &>/dev/null; then
    EXISTING_VER=$(llvm-link --version 2>&1 | grep -oP 'LLVM version \K[0-9]+' || echo "0")
    if [ "$EXISTING_VER" = "$LLVM_VER" ]; then
        echo "llvm-link-${LLVM_VER} already installed"
    else
        apt-get update -qq && apt-get install -y -qq llvm-${LLVM_VER} 2>&1 | tail -3
        ln -sf /usr/bin/llvm-link-${LLVM_VER} /usr/bin/llvm-link
    fi
else
    apt-get update -qq && apt-get install -y -qq llvm-${LLVM_VER} 2>&1 | tail -3
    ln -sf /usr/bin/llvm-link-${LLVM_VER} /usr/bin/llvm-link
fi
# Symlink llvm-dis too (needed for .ll generation)
if [ -f "/usr/bin/llvm-dis-${LLVM_VER}" ]; then
    ln -sf /usr/bin/llvm-dis-${LLVM_VER} /usr/bin/llvm-dis
fi
echo "llvm-link version: $(llvm-link --version 2>&1 | head -1)"

# ---- Step 1: Set z-wllvm environment (forces -g) ----
echo "=== [1/6] Setting z-wllvm as compiler ==="
export LLVM_COMPILER=clang
export LLVM_CC_NAME=clang
export LLVM_CXX_NAME=clang++
export LLVM_LINK_NAME=llvm-link
export LLVM_AR_NAME=llvm-ar

# Create z-wllvm / z-wllvm++ wrappers that force -g
WRAPPER_DIR="/tmp/z-wllvm-bin"
mkdir -p "$WRAPPER_DIR"
cat > "$WRAPPER_DIR/z-wllvm" << 'EOF'
#!/bin/bash
exec wllvm -g "$@"
EOF
cat > "$WRAPPER_DIR/z-wllvm++" << 'EOF'
#!/bin/bash
exec wllvm++ -g "$@"
EOF
chmod +x "$WRAPPER_DIR/z-wllvm" "$WRAPPER_DIR/z-wllvm++"

export CC="$WRAPPER_DIR/z-wllvm"
export CXX="$WRAPPER_DIR/z-wllvm++"
export CFLAGS="${CFLAGS:-} -O0 -g"
export CXXFLAGS="${CXXFLAGS:-} -O0 -g"

echo "  CC=$CC  CXX=$CXX"

# ---- Step 2: Pre-build hook ----
if [ -n "${PRE_BUILD_HOOK:-}" ]; then
    echo "=== [PRE] Running pre-build hook ==="
    $PRE_BUILD_HOOK
fi

# ---- Step 3: Build project ----
echo "=== [2/6] Building project: ${PROJECT_NAME} (${BUILD_MODE}) ==="

case "$BUILD_MODE" in
    intree-autotools)
        cd "$PROJECT_SRC"
        if [ -f configure.ac ] || [ -f configure.in ]; then
            autoreconf -fi 2>&1 | tail -3
        fi
        ./configure --disable-shared --enable-static \
            --prefix="$INSTALL_PREFIX" \
            ${CONFIGURE_FLAGS:-} 2>&1 | tail -5
        make -j$(nproc) 2>&1 | tail -5
        if [ "$SKIP_INSTALL" != "yes" ]; then
            make install 2>&1 | tail -3
        fi
        ;;

    intree-cmake)
        mkdir -p "$PROJECT_SRC/build-svf"
        cd "$PROJECT_SRC/build-svf"
        cmake .. \
            -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
            -DBUILD_SHARED_LIBS=OFF \
            ${CMAKE_FLAGS:-} 2>&1 | tail -5
        make -j$(nproc) 2>&1 | tail -5
        if [ "$SKIP_INSTALL" != "yes" ]; then
            make install 2>&1 | tail -3
        fi
        ;;

    ossfuzz-script)
        if type run_ossfuzz_build &>/dev/null; then
            run_ossfuzz_build
        else
            echo "ERROR: BUILD_MODE=ossfuzz-script requires run_ossfuzz_build() function"
            exit 1
        fi
        ;;

    ossfuzz-native)
        # Run oss-fuzz build.sh directly with injected z-wllvm environment.
        # OSSFUZZ_BUILD_SH must point to the build.sh inside the fuzz tooling repo.
        if [ -z "${OSSFUZZ_BUILD_SH:-}" ]; then
            echo "ERROR: BUILD_MODE=ossfuzz-native requires OSSFUZZ_BUILD_SH"
            exit 1
        fi
        if [ ! -f "$OSSFUZZ_BUILD_SH" ]; then
            echo "ERROR: OSSFUZZ_BUILD_SH not found: $OSSFUZZ_BUILD_SH"
            exit 1
        fi

        # Set up oss-fuzz expected environment
        export OUT="/out"
        export WORK="/tmp/ossfuzz-work"
        mkdir -p "$OUT" "$WORK"

        # Stub fuzzing engine — oss-fuzz build.sh links against LIB_FUZZING_ENGINE
        echo 'int main(){return 0;}' > /tmp/stub_engine.c
        $CC -c /tmp/stub_engine.c -o /tmp/stub_engine.o
        ar rcs /tmp/libFuzzingEngine.a /tmp/stub_engine.o
        export LIB_FUZZING_ENGINE="/tmp/libFuzzingEngine.a"
        export FUZZING_ENGINE="libfuzzer"
        export SANITIZER="${SANITIZER:-none}"
        export ARCHITECTURE="${ARCHITECTURE:-x86_64}"

        echo "  OSSFUZZ_BUILD_SH=$OSSFUZZ_BUILD_SH"
        echo "  LIB_FUZZING_ENGINE=$LIB_FUZZING_ENGINE"
        bash "$OSSFUZZ_BUILD_SH"
        ;;

    *)
        echo "ERROR: Unknown BUILD_MODE: $BUILD_MODE"
        exit 1
        ;;
esac

echo "  Project build complete."

# ---- Step 4: Extract bitcode from static libraries ----
echo "=== [3/6] Extracting bitcode from static libraries ==="

# Strategy: extract-bc on .a files (not individual .o files).
# This avoids duplicate symbols from libtool, autotools hidden files, and test programs.
# wllvm's extract-bc handles .a natively — it extracts and links all member .o bitcode.

STATIC_LIBS=$(find "$PROJECT_SRC" "$INSTALL_PREFIX" -name "*.a" \
    -not -path '*/.libs/*' \
    -type f 2>/dev/null || true)

LIB_BC=""
for lib in $STATIC_LIBS; do
    echo "  Extracting: $lib"
    if extract-bc "$lib" 2>&1; then
        # extract-bc on .a produces .bca (bitcode archive)
        bca_file="${lib%.a}.bca"
        if [ -f "$bca_file" ]; then
            # Convert .bca (archive) to single .bc via llvm-link
            bc_file="${lib%.a}.bc"
            llvm-link "$bca_file" -o "$bc_file" 2>&1
            echo "    -> $bc_file ($(du -h "$bc_file" | cut -f1))"
            LIB_BC="$LIB_BC $bc_file"
        fi
    else
        echo "    -> extract-bc failed (skipped)"
    fi
done

BC_COUNT=$(echo $LIB_BC | wc -w)
echo "  Static library .bc files: $BC_COUNT"

if [ "$BC_COUNT" -eq 0 ]; then
    echo "ERROR: No library .bc files found. Ensure the project builds static libraries."
    exit 1
fi

# ---- Step 5: llvm-link library .bc -> library.bc ----
echo "=== [4/6] Linking library bitcode ==="
echo "  Files to link:"
for f in $LIB_BC; do echo "    $f"; done
mkdir -p /output
if [ "$BC_COUNT" -eq 1 ]; then
    cp $LIB_BC /output/library.bc
else
    llvm-link $LIB_BC -o /output/library.bc 2>&1
fi
echo "  library.bc: $(ls -lh /output/library.bc)"

# ---- Step 6: Generate .ll for debug info extraction ----
echo "=== [5/6] Disassembling to .ll ==="
llvm-dis /output/library.bc -o /output/library.ll 2>&1
echo "  library.ll: $(ls -lh /output/library.ll)"

# ---- Step 7: Copy fuzzer harness sources to output ----
echo "=== [6/6] Copying fuzzer harness sources ==="
mkdir -p /output/fuzzer_sources
if [ -n "${HARNESS_SRC:-}" ] && [ -d "$HARNESS_SRC" ]; then
    cp -r "$HARNESS_SRC"/*.cc "$HARNESS_SRC"/*.c "$HARNESS_SRC"/*.h /output/fuzzer_sources/ 2>/dev/null || true
    echo "  Copied from HARNESS_SRC: $(ls /output/fuzzer_sources/ 2>/dev/null | wc -l) files"
fi
# Also scan common locations for external fuzzer repos
for fuzz_dir in "$SRC"/*fuzzer* "$SRC"/*fuzz*; do
    if [ -d "$fuzz_dir" ] && [ "$fuzz_dir" != "$PROJECT_SRC" ]; then
        cp -r "$fuzz_dir"/*.cc "$fuzz_dir"/*.c "$fuzz_dir"/*.h /output/fuzzer_sources/ 2>/dev/null || true
        echo "  Copied from $fuzz_dir"
    fi
done
echo "  Total fuzzer source files: $(ls /output/fuzzer_sources/ 2>/dev/null | wc -l)"

echo ""
echo "================================================================"
echo " SUCCESS: /output/library.bc (library-only)"
echo "================================================================"
