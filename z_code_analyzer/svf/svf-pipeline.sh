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

    *)
        echo "ERROR: Unknown BUILD_MODE: $BUILD_MODE"
        exit 1
        ;;
esac

echo "  Project build complete."

# ---- Step 4: Collect .bc files (library-only) ----
echo "=== [3/6] Collecting library-only .bc files ==="

# Find all .o files produced by wllvm (they have .bc manifest)
BC_FILES=""
BC_DIR="/tmp/bc-collect"
mkdir -p "$BC_DIR"

# Collect all .o -> .bc using extract-bc on individual .o files
find "$PROJECT_SRC" -name "*.o" -type f | while read -r obj; do
    # Try to extract bc from each .o
    extract-bc "$obj" 2>/dev/null || true
done

# Also check install dir
if [ "$SKIP_INSTALL" != "yes" ] && [ -d "$INSTALL_PREFIX" ]; then
    find "$INSTALL_PREFIX" -name "*.o" -type f | while read -r obj; do
        extract-bc "$obj" 2>/dev/null || true
    done
fi

# Collect all .bc files, excluding fuzzer sources
echo "  Fuzzer source files to exclude: ${FUZZER_SOURCE_FILES:-none}"
ALL_BC=$(find "$PROJECT_SRC" "$INSTALL_PREFIX" -name "*.o.bc" -type f 2>/dev/null || true)
LIB_BC=""
for bc in $ALL_BC; do
    exclude=false
    for fuzzer_src in $FUZZER_SOURCE_FILES; do
        # Match by base filename: fuzz1.c -> fuzz1.o.bc
        fuzzer_base=$(basename "$fuzzer_src" | sed 's/\.\(c\|cc\|cpp\|cxx\)$/.o.bc/')
        if [[ "$(basename "$bc")" == "$fuzzer_base" ]]; then
            echo "  Excluding fuzzer bc: $bc"
            exclude=true
            break
        fi
    done
    if [ "$exclude" = false ]; then
        LIB_BC="$LIB_BC $bc"
    fi
done

BC_COUNT=$(echo $LIB_BC | wc -w)
echo "  Library .bc files: $BC_COUNT"

if [ "$BC_COUNT" -eq 0 ]; then
    echo "ERROR: No library .bc files found"
    exit 1
fi

# ---- Step 5: llvm-link library .bc -> library.bc ----
echo "=== [4/6] Linking library bitcode ==="
mkdir -p /output
llvm-link $LIB_BC -o /output/library.bc 2>&1
echo "  library.bc: $(ls -lh /output/library.bc)"

# ---- Step 6: Generate .ll for debug info extraction ----
echo "=== [5/6] Disassembling to .ll ==="
llvm-dis /output/library.bc -o /output/library.ll 2>&1
echo "  library.ll: $(ls -lh /output/library.ll)"

echo ""
echo "================================================================"
echo " SUCCESS: /output/library.bc (library-only)"
echo "================================================================"
