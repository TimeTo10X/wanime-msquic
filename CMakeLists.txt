# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 4.0.1)

# Disable in-source builds to prevent source tree corruption.
if("${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
    message(FATAL_ERROR "
FATAL: In-source builds are not allowed.
       You should create a separate directory for build files.
")
endif()

message(STATUS "CMAKE Version: ${CMAKE_VERSION}")

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

message(STATUS "Source Dir: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "Host System name: ${CMAKE_HOST_SYSTEM_NAME}")

if(POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
    message(STATUS "Setting policy 0091")
endif()

if (POLICY CMP0111)
    cmake_policy(SET CMP0111 NEW)
endif()

project(msquic)

set(default_build_type "Release")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE
        STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
                 "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

message(STATUS "System name: ${CMAKE_SYSTEM_NAME}")
message(STATUS "System version: ${CMAKE_SYSTEM_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

set(QUIC_MAJOR_VERSION 2)
set(QUIC_FULL_VERSION 2.6.0)

if (APPLE)
    set(CX_PLATFORM "darwin")
elseif (UNIX)
    set(CX_PLATFORM "linux")
else()
    message(FATAL_ERROR "Unsupported platform. Only macOS and Linux are supported.")
endif()
message(STATUS "QUIC Platform: ${CX_PLATFORM}")

enable_testing()

if (NOT "${QUIC_TLS}" STREQUAL "")
    message(FATAL_ERROR "QUIC_TLS is deprecated, Use QUIC_TLS_LIB instead")
endif()

set(QUIC_TLS_LIB "quictls" CACHE STRING "TLS Library to use")

option(QUIC_BUILD_SHARED "Builds msquic as a dynamic library" ON)
option(QUIC_SKIP_SANITIZE_SUBMODULES "Skip passing sanitizer settings to submodule build" ON)
option(QUIC_ENABLE_POOL_ALLOC "Enables pool allocations" ON)
option(QUIC_EXTERNAL_TOOLCHAIN "Enable if system libs and include paths are configured by CMake toolchain" OFF)
if (UNIX AND NOT APPLE)
    option(QUIC_LINUX_IOURING_ENABLED "Enables io_uring support" ON)
    option(QUIC_LINUX_XDP_ENABLED "Enables XDP support" OFF)
endif()
option(QUIC_EMBED_GIT_HASH "Embed git commit hash in the binary" OFF)
option(QUIC_OPTIMIZE_LOCAL "Optimize code for local machine architecture" OFF)
option(QUIC_SKIP_CI_CHECKS "Disable CI specific build checks" ON)
if (UNIX AND NOT APPLE)
    option(QUIC_HIGH_RES_TIMERS "Configure the system to use high resolution timers" OFF)
endif()
option(QUIC_OFFICIAL_RELEASE "Configured the build for an official release" OFF)

set(QUIC_FOLDER_PREFIX "" CACHE STRING "Optional prefix for source group folders when using an IDE generator")
set(QUIC_LIBRARY_NAME "msquic" CACHE STRING "Override the output library name")
set(QUIC_LOGGING_TYPE "" CACHE STRING "Explicitly choose logging backend (\"lttng\" or \"stdout\")")
string(TOLOWER "${QUIC_LOGGING_TYPE}" QUIC_LOGGING_TYPE)
if(NOT "${QUIC_LOGGING_TYPE}" MATCHES "^(lttng|stdout|)$")
    message(FATAL_ERROR "QUIC_LOGGING_TYPE must be \"lttng\" or \"stdout\", not \"${QUIC_LOGGING_TYPE}\"")
endif()

if (QUIC_ENABLE_ALL_SANITIZERS)
    set(QUIC_SANITIZER_ACTIVE ON)
    set(QUIC_ENABLE_ASAN ON)
    set(QUIC_ENABLE_LSAN ON)
    set(QUIC_ENABLE_UBSAN ON)
    set(QUIC_ENABLE_EXTRA_SANITIZERS ON)
elseif (QUIC_ENABLE_ASAN)
    set(QUIC_SANITIZER_ACTIVE ON)
elseif (QUIC_ENABLE_LSAN)
    set(QUIC_SANITIZER_ACTIVE ON)
elseif (QUIC_ENABLE_UBSAN)
    set(QUIC_SANITIZER_ACTIVE ON)
elseif (QUIC_ENABLE_TSAN)
    set(QUIC_SANITIZER_ACTIVE ON)
elseif (QUIC_ENABLE_EXTRA_SANITIZERS)
    set(QUIC_SANITIZER_ACTIVE ON)
else()
    set(QUIC_SANITIZER_ACTIVE OFF)
endif()

if (NOT QUIC_BUILD_SHARED)
    cmake_minimum_required(VERSION 3.20)
endif()

set(BUILD_SHARED_LIBS ${QUIC_BUILD_SHARED})

include(${PROJECT_SOURCE_DIR}/cmake/GitCommands.cmake)
get_git_current_hash(${PROJECT_SOURCE_DIR} GIT_CURRENT_HASH)

if(NOT GIT_CURRENT_HASH)
    message("Failed to get git hash. Binary will not contain git hash")
    set(QUIC_EMBED_GIT_HASH OFF)
endif()

set(QUIC_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(QUIC_OUTPUT_DIR ${QUIC_BUILD_DIR}/bin/$<IF:$<CONFIG:Debug>,Debug,Release> CACHE STRING "Output directory for build artifacts")

string(GENEX_STRIP ${QUIC_OUTPUT_DIR} QUIC_OUTPUT_DIR_STRIPPED)

string(COMPARE EQUAL ${QUIC_OUTPUT_DIR} ${QUIC_OUTPUT_DIR_STRIPPED} QUIC_HAS_GENERATOR_OUTPUT_DIR)

if (QUIC_HAS_GENERATOR_OUTPUT_DIR)
    set(QUIC_PGO_DIR ${QUIC_OUTPUT_DIR})
else ()
    set(QUIC_PGO_DIR ${QUIC_BUILD_DIR}/PGO)
endif ()

set(QUIC_VER_BUILD_ID "0" CACHE STRING "The version build ID")
set(QUIC_VER_SUFFIX "-private" CACHE STRING "The version suffix")

message(STATUS "Version Build ID: ${QUIC_VER_BUILD_ID}")
message(STATUS "Version Suffix: ${QUIC_VER_SUFFIX}")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${QUIC_BUILD_DIR}/obj/$<IF:$<CONFIG:Debug>,Debug,Release>)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${QUIC_OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${QUIC_OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE ${QUIC_OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${QUIC_OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG ${QUIC_OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${QUIC_OUTPUT_DIR})

set(QUIC_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/inc)

include(GNUInstallDirs)

include(CheckSymbolExists)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckCCompilerFlag)

check_symbol_exists(_SC_PHYS_PAGES unistd.h HAS__SC_PHYS_PAGES)
check_function_exists(sysconf HAS_SYSCONF)

if (CX_PLATFORM STREQUAL "linux")
    check_symbol_exists(UDP_SEGMENT netinet/udp.h HAS_UDP_SEGMENT)
    if (NOT HAS_UDP_SEGMENT)
        message(STATUS "UDP_SEGMENT is missing. Send performance will be reduced")
    endif()

    check_symbol_exists(SO_ATTACH_REUSEPORT_CBPF sys/socket.h HAS_SO_ATTACH_REUSEPORT_CBPF)
    if(NOT HAS_SO_ATTACH_REUSEPORT_CBPF)
        message(STATUS "SO_ATTACH_REUSEPORT_CBPF is missing. Server receive performance will be reduced")
    endif()

    check_function_exists(sendmmsg HAS_SENDMMSG)
    if(NOT HAS_SENDMMSG)
        message(STATUS "sendmmsg is missing. Send performance will be reduced")
    endif()

    # Error if flags are missing in CI
    if(QUIC_CI AND NOT QUIC_SKIP_CI_CHECKS)
        if (NOT HAS_UDP_SEGMENT)
            message(FATAL_ERROR "UDP_SEGMENT must exist for CI builds")
        endif()

        if(NOT HAS_SO_ATTACH_REUSEPORT_CBPF)
            message(FATAL_ERROR "SO_ATTACH_REUSEPORT_CBPF must exist for CI builds")
        endif()
    endif()

    if(QUIC_ENABLE_LOGGING AND QUIC_LOGGING_TYPE STREQUAL "")
        set(QUIC_LOGGING_TYPE "lttng")
        message(STATUS "Choosing lttng as default logging type for platform")
    endif()

    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm|aarch64)$")
        set(QUIC_LINUX_XDP_ENABLED OFF CACHE BOOL "XDP not supported on ARM architectures" FORCE)
    endif()

elseif(CX_PLATFORM STREQUAL "darwin")
    check_function_exists(sysctl HAS_SYSCTL)
    if(QUIC_ENABLE_LOGGING)
        if(QUIC_LOGGING_TYPE STREQUAL "stdout")
            message(STATUS "Choosing stdout as logging type for platform")
        elseif(QUIC_LOGGING_TYPE STREQUAL "")
            message(WARNING "Must explicitly set QUIC_LOGGING_TYPE to \"stdout\" to enable due to performance overhead; disabling logging")
            set(QUIC_ENABLE_LOGGING OFF)
        endif()
    endif()
endif()

set(QUIC_COMMON_FLAGS "")
set(QUIC_COMMON_DEFINES _GNU_SOURCE)
if (HAS_SENDMMSG)
    list(APPEND QUIC_COMMON_DEFINES HAS_SENDMMSG)
endif()
if (HAS__SC_PHYS_PAGES)
    list(APPEND QUIC_COMMON_DEFINES HAS__SC_PHYS_PAGES)
endif()
if (HAS_SYSCONF)
    list(APPEND QUIC_COMMON_DEFINES HAS_SYSCONF)
endif()
if (HAS_SYSCTL)
    list(APPEND QUIC_COMMON_DEFINES HAS_SYSCTL)
endif()

set(QUIC_WARNING_FLAGS -Werror -Wall -Wextra -Wformat=2 -Wno-type-limits
    -Wno-unknown-pragmas -Wno-multichar -Wno-missing-field-initializers
    CACHE INTERNAL "")
if (CMAKE_COMPILER_IS_GNUCC AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 7.0)
    list(APPEND QUIC_WARNING_FLAGS -Wno-strict-aliasing)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    list(APPEND QUIC_WARNING_FLAGS -Wno-missing-braces -Wno-microsoft-anon-tag)
    if (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 18 OR
        (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 16 AND CMAKE_CXX_COMPILER_ID MATCHES "AppleClang"))
        list(APPEND QUIC_WARNING_FLAGS -Wno-invalid-unevaluated-string)
    endif()
endif()

list(APPEND QUIC_COMMON_DEFINES VER_BUILD_ID=${QUIC_VER_BUILD_ID})
list(APPEND QUIC_COMMON_DEFINES VER_SUFFIX=${QUIC_VER_SUFFIX})

if (QUIC_EMBED_GIT_HASH)
    list(APPEND QUIC_COMMON_DEFINES VER_GIT_HASH=${GIT_CURRENT_HASH})
endif()

if(QUIC_TELEMETRY_ASSERTS)
    list(APPEND QUIC_COMMON_DEFINES QUIC_TELEMETRY_ASSERTS=1)
endif()

if(QUIC_HIGH_RES_TIMERS)
    list(APPEND QUIC_COMMON_DEFINES QUIC_HIGH_RES_TIMERS=1)
endif()

if (QUIC_SANITIZER_ACTIVE OR NOT QUIC_ENABLE_POOL_ALLOC)
    list(APPEND QUIC_COMMON_DEFINES DISABLE_CXPLAT_POOL=1)
endif()

if(QUIC_OFFICIAL_RELEASE)
    list(APPEND QUIC_COMMON_DEFINES QUIC_OFFICIAL_RELEASE=1)
    message(STATUS "Configured for official release build")
endif()

if(QUIC_TLS_LIB STREQUAL "quictls" OR QUIC_TLS_LIB STREQUAL "openssl")
    message(STATUS "Enabling quictls/openssl configuration tests")
    list(APPEND QUIC_COMMON_DEFINES QUIC_TEST_OPENSSL_FLAGS=1)
    message(STATUS "Enabling CA file tests")
    list(APPEND QUIC_COMMON_DEFINES QUIC_ENABLE_CA_CERTIFICATE_FILE_TESTS)
endif()

if(QUIC_ENABLE_LOGGING)
    if (QUIC_LOGGING_TYPE STREQUAL "lttng")
        if (QUIC_SANITIZER_ACTIVE)
            message(WARNING "LTTng logging is incompatible with sanitizers. Skipping logging")
            set(QUIC_ENABLE_LOGGING OFF)
        else()
            if (${CMAKE_VERSION} VERSION_LESS "3.6.0")
                message(WARNING "Logging unsupported on this version of CMake. Please upgrade to 3.6 or later.")
                set(QUIC_ENABLE_LOGGING OFF)
            else()
                check_include_file(lttng/ust-config.h HAS_LTTNG)
                if (NOT HAS_LTTNG)
                    message(WARNING "LTTng logging not found. Disabling logging")
                    set(QUIC_ENABLE_LOGGING OFF)
                else()
                    check_symbol_exists(LTTNG_UST_HAVE_SDT_INTEGRATION lttng/ust-config.h HAS_LTTNG_SDT)
                    if(HAS_LTTNG_SDT)
                        message(WARNING "LTTng with SDT integration does not work. Disabling logging")
                        set(QUIC_ENABLE_LOGGING OFF)
                    else()
                        message(STATUS "Configuring for LTTng logging")
                        list(APPEND QUIC_COMMON_DEFINES QUIC_CLOG)
                        include(FindLTTngUST)
                    endif()
                endif()
            endif()
        endif()

    elseif (QUIC_LOGGING_TYPE STREQUAL "stdout")
        message(STATUS "Configuring for stdout logging")
        list(APPEND QUIC_COMMON_DEFINES QUIC_EVENTS_STDOUT QUIC_LOGS_STDOUT)
    endif()
else()
    message(STATUS "QUIC_ENABLE_LOGGING is false. Disabling logging")
endif()

if (NOT QUIC_ENABLE_LOGGING)
    list(APPEND QUIC_COMMON_DEFINES QUIC_EVENTS_STUB QUIC_LOGS_STUB)
endif()

# Find libatomic and libnuma (Linux only)
if (NOT APPLE AND NOT ANDROID)
    find_library(ATOMIC NAMES atomic libatomic.so.1)
    if (ATOMIC)
        message(STATUS "Found libatomic: ${ATOMIC}")
    else()
        message(STATUS "libatomic not found. If build fails, install libatomic")
    endif()

    find_library(NUMA NAMES NUMA libnuma.so.1)
    if (NUMA)
        message(STATUS "Found libnuma: ${NUMA}")
        find_file(NUMA-HEADER NAMES "numa.h")
        if (NUMA-HEADER)
            message(STATUS "Found numa.h: ${NUMA-HEADER}")
            list(APPEND QUIC_COMMON_DEFINES CXPLAT_NUMA_AWARE)
        else()
            message(STATUS "numa.h not found. If build fails, install libnuma-dev")
        endif()
    else()
        message(STATUS "libnuma not found. If build fails, install libnuma")
    endif()
endif()

if (QUIC_LINUX_IOURING_ENABLED)
    find_library(LIBURING NAMES liburing-ffi.so)
    if (LIBURING)
        message(STATUS "Found liburing: ${LIBURING}")
    else()
        message(STATUS "liburing not found. If build fails, install liburing")
    endif()
endif()

if (CMAKE_GENERATOR_PLATFORM STREQUAL "")
    string(TOLOWER ${CMAKE_SYSTEM_PROCESSOR} SYSTEM_PROCESSOR)
else()
    string(TOLOWER ${CMAKE_GENERATOR_PLATFORM} SYSTEM_PROCESSOR)
endif()

# Custom build flags
if (QUIC_OPTIMIZE_LOCAL AND NOT CMAKE_SYSTEM_PROCESSOR STREQUAL arm)
    set(MARCH -march=native)
endif()

set(CMAKE_C_FLAGS_DEBUG "-O0 -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O3 -fno-omit-frame-pointer ${MARCH} -DNDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 ${MARCH} -DNDEBUG")
if (CX_PLATFORM STREQUAL "darwin")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -gdwarf")
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} -gdwarf")
else()
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -ggdb3")
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} -ggdb3")
endif()
set(CMAKE_CXX_FLAGS_DEBUG ${CMAKE_C_FLAGS_DEBUG})
set(CMAKE_CXX_FLAGS_MINSIZEREL ${CMAKE_C_FLAGS_MINSIZEREL})
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO ${CMAKE_C_FLAGS_RELWITHDEBINFO})
set(CMAKE_CXX_FLAGS_RELEASE ${CMAKE_C_FLAGS_RELEASE})

list(APPEND QUIC_COMMON_FLAGS -fms-extensions -fPIC)
if (CX_PLATFORM STREQUAL "darwin")
    list(APPEND QUIC_COMMON_DEFINES CX_PLATFORM_DARWIN)
    list(APPEND QUIC_COMMON_FLAGS -Wno-microsoft-anon-tag -Wno-tautological-constant-out-of-range-compare -Wmissing-field-initializers)
    message(STATUS "Disabling (client) shared port support")
    list(APPEND QUIC_COMMON_DEFINES QUIC_DISABLE_SHARED_PORT_TESTS)
else()
    list(APPEND QUIC_COMMON_DEFINES CX_PLATFORM_LINUX)
    message(STATUS "Enabling shared ephemeral port work around")
    list(APPEND QUIC_COMMON_DEFINES QUIC_SHARED_EPHEMERAL_WORKAROUND)
endif()

if (QUIC_SANITIZER_ACTIVE)
    message(STATUS "Configuring sanitizers: ASAN:${QUIC_ENABLE_ASAN} LSAN:${QUIC_ENABLE_LSAN} UBSAN:${QUIC_ENABLE_UBSAN} TSAN:${QUIC_ENABLE_TSAN} EXTRA:${QUIC_ENABLE_EXTRA_SANITIZERS}")
    list(APPEND QUIC_COMMON_FLAGS -O0 -fno-omit-frame-pointer -fno-optimize-sibling-calls)

    check_c_compiler_flag(-fno-var-tracking-assignments HAS_NO_VAR_TRACKING)
    if (HAS_NO_VAR_TRACKING)
        list(APPEND QUIC_COMMON_FLAGS -fno-var-tracking-assignments)
    endif()

    if (CX_PLATFORM STREQUAL "darwin")
        list(APPEND QUIC_COMMON_FLAGS -gdwarf)
    else()
        list(APPEND QUIC_COMMON_FLAGS -ggdb3)
    endif()

    if (QUIC_ENABLE_ASAN)
        list(APPEND QUIC_COMMON_FLAGS -fsanitize=address)
    endif()

    if (QUIC_ENABLE_LSAN)
        list(APPEND QUIC_COMMON_FLAGS -fsanitize=leak)
    endif()

    if (QUIC_ENABLE_UBSAN)
        list(APPEND QUIC_COMMON_FLAGS -fsanitize=undefined)
    endif()

    if (QUIC_ENABLE_TSAN)
        list(APPEND QUIC_COMMON_FLAGS -fsanitize=thread)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=thread")
    endif()

    if (QUIC_ENABLE_EXTRA_SANITIZERS)
        list(APPEND QUIC_COMMON_FLAGS -fsanitize=alignment -fsanitize-address-use-after-scope)
        if (CMAKE_C_COMPILER_ID MATCHES "Clang")
            list(APPEND QUIC_COMMON_FLAGS -fsanitize=unsigned-integer-overflow -fsanitize=local-bounds -fsanitize=integer -fsanitize=nullability)
        endif()
    endif()
endif()

set(QUIC_C_FLAGS ${QUIC_COMMON_FLAGS})
set(QUIC_CXX_FLAGS ${QUIC_COMMON_FLAGS})

if(QUIC_TLS_LIB STREQUAL "quictls" OR QUIC_TLS_LIB STREQUAL "openssl")
    add_library(OpenSSL INTERFACE)

    include(FetchContent)

    FetchContent_Declare(
        OpenSSLQuic
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/submodules
        CMAKE_ARGS "-DQUIC_USE_SYSTEM_LIBCRYPTO=${QUIC_USE_SYSTEM_LIBCRYPTO}"
    )
    FetchContent_MakeAvailable(OpenSSLQuic)

    target_link_libraries(OpenSSL
        INTERFACE
        OpenSSLQuic::OpenSSLQuic
    )
endif()

if (QUIC_USE_SYSTEM_LIBCRYPTO)
    list(APPEND QUIC_COMMON_DEFINES CXPLAT_SYSTEM_CRYPTO)
endif()

if (QUIC_LINUX_XDP_ENABLED)
    list(APPEND QUIC_COMMON_DEFINES CXPLAT_LINUX_XDP_ENABLED)
endif()

if (QUIC_LINUX_IOURING_ENABLED)
    list(APPEND QUIC_COMMON_DEFINES CXPLAT_USE_IO_URING)
endif()

if(QUIC_CODE_CHECK)
    find_program(CLANGTIDY NAMES clang-tidy)
    if(CLANGTIDY)
        message(STATUS "Found clang-tidy: ${CLANGTIDY}")
        set(CLANG_TIDY_CHECKS *
            -altera-*
            -android-cloexec-fopen
            -android-cloexec-socket
            -bugprone-assignment-in-if-condition
            -bugprone-casting-through-void
            -bugprone-easily-swappable-parameters
            -bugprone-implicit-widening-of-multiplication-result
            -bugprone-macro-parentheses
            -bugprone-multi-level-implicit-pointer-conversion
            -bugprone-narrowing-conversions
            -bugprone-reserved-identifier
            -bugprone-sizeof-expression
            -bugprone-switch-missing-default-case
            -cert-dcl37-c
            -cert-dcl51-cpp
            -cert-err33-c
            -clang-analyzer-optin.core.EnumCastOutOfRange
            -clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling
            -clang-diagnostic-invalid-unevaluated-string
            -clang-diagnostic-microsoft-anon-tag
            -concurrency-mt-unsafe
            -cppcoreguidelines-avoid-magic-numbers
            -cppcoreguidelines-avoid-non-const-global-variables
            -cppcoreguidelines-init-variables
            -cppcoreguidelines-macro-to-enum
            -cppcoreguidelines-narrowing-conversions
            -google-readability-casting
            -google-readability-function-size
            -google-readability-todo
            -hicpp-function-size
            -hicpp-no-assembler
            -hicpp-signed-bitwise
            -llvmlibc-restrict-system-libc-headers
            -misc-include-cleaner
            -misc-no-recursion
            -misc-header-include-cycle
            -modernize-macro-to-enum
            -readability-avoid-const-params-in-decls
            -readability-avoid-nested-conditional-operator
            -readability-duplicate-include
            -readability-function-cognitive-complexity
            -readability-function-size
            -readability-identifier-length
            -readability-identifier-naming
            -readability-isolate-declaration
            -readability-magic-numbers
            -readability-non-const-parameter
            -readability-redundant-casting
        )
        string(REPLACE ";" "," CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS}")
        set(CMAKE_C_CLANG_TIDY_AVAILABLE ${CLANGTIDY} -checks=${CLANG_TIDY_CHECKS}
            -system-headers --warnings-as-errors=*)
    else()
        message(STATUS "clang-tidy not found")
    endif()

    find_program(CPPCHECK NAMES cppcheck)
    if(CPPCHECK)
        message(STATUS "Found cppcheck: ${CPPCHECK}")
        set(CMAKE_C_CPPCHECK_AVAILABLE ${CPPCHECK} -q --inline-suppr
            --suppress=duplicateValueTernary --suppress=objectIndex
            --suppress=varFuncNullUB --suppress=constParameter
            --suppress=nullPointer --suppress=nullPointerRedundantCheck
            --suppress=knownConditionTrueFalse --suppress=invalidscanf
            --enable=warning,style,performance,portability -D__linux__)
    else()
        message(STATUS "cppcheck not found")
    endif()
endif()

add_subdirectory(src/inc)

# Product code
add_subdirectory(src/core)
add_subdirectory(src/platform)
add_subdirectory(src/bin)

# Tool code
if(QUIC_BUILD_TOOLS)
    add_subdirectory(src/tools)
endif()

# Performance code
if(QUIC_BUILD_PERF)
    add_subdirectory(src/perf/lib)
    add_subdirectory(src/perf/bin)
endif()

# Test code
if(QUIC_BUILD_TEST)
    include(FetchContent)

    enable_testing()

    set(PREV_BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS} CACHE INTERNAL "")
    set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
    set(BUILD_GMOCK OFF CACHE BOOL "Builds the googlemock subproject")
    set(INSTALL_GTEST OFF CACHE BOOL "Enable installation of googletest.")
    FetchContent_Declare(
        googletest
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/submodules/googletest
    )
    FetchContent_MakeAvailable(googletest)
    set(BUILD_SHARED_LIBS ${PREV_BUILD_SHARED_LIBS} CACHE INTERNAL "")

    set_property(TARGET gtest PROPERTY CXX_STANDARD 17)
    set_property(TARGET gtest PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}tests")

    set_property(TARGET gtest_main PROPERTY CXX_STANDARD 17)
    set_property(TARGET gtest_main PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}tests")
    set_property(TARGET gtest_main PROPERTY EXCLUDE_FROM_ALL ON)
    set_property(TARGET gtest_main PROPERTY EXCLUDE_FROM_DEFAULT_BUILD ON)

    add_subdirectory(src/core/unittest)
    add_subdirectory(src/platform/unittest)
    add_subdirectory(src/test/lib)
    add_subdirectory(src/test/bin)
endif()
