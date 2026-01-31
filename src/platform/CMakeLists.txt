# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

if (QUIC_CODE_CHECK)
    # enable static analyzers for this directory
    set(CMAKE_C_CLANG_TIDY ${CMAKE_C_CLANG_TIDY_AVAILABLE})
    set(CMAKE_CXX_CLANG_TIDY ${CMAKE_C_CLANG_TIDY_AVAILABLE})
    set(CMAKE_C_CPPCHECK ${CMAKE_C_CPPCHECK_AVAILABLE})
    set(CMAKE_CXX_CPPCHECK ${CMAKE_C_CPPCHECK_AVAILABLE})
endif()

set(SOURCES crypt.c hashtable.c pcp.c platform_worker.c toeplitz.c)

# POSIX platforms only (Linux and macOS)
set(SOURCES ${SOURCES} platform_posix.c storage_posix.c cgroup.c datapath_unix.c)

if(CX_PLATFORM STREQUAL "linux" AND NOT CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    set(SOURCES ${SOURCES} datapath_linux.c)
    if (QUIC_LINUX_IOURING_ENABLED)
        set(SOURCES ${SOURCES} datapath_iouring.c)
    else()
        set(SOURCES ${SOURCES} datapath_epoll.c)
    endif()
    if (QUIC_LINUX_XDP_ENABLED)
        set(SOURCES ${SOURCES} datapath_xplat.c datapath_raw.c datapath_raw_linux.c datapath_raw_socket.c datapath_raw_socket_linux.c datapath_raw_xdp_linux.c)
    else()
        set(SOURCES ${SOURCES} datapath_xplat.c datapath_raw_dummy.c)
    endif()
else()
    # macOS uses kqueue
    set(SOURCES ${SOURCES} datapath_kqueue.c)
endif()

# TLS configuration - only quictls/openssl supported
if(QUIC_TLS_LIB STREQUAL "quictls")
    message(STATUS "Configuring for QuicTLS")
    set(SOURCES ${SOURCES} tls_quictls.c crypt_openssl.c)
elseif(QUIC_TLS_LIB STREQUAL "openssl")
    message(STATUS "Configuring for OpenSSL")
    set(SOURCES ${SOURCES} tls_openssl.c crypt_openssl.c)
else()
    message(FATAL_ERROR "TLS Provider not configured. Use quictls or openssl.")
endif()

# Platform-specific certificate handling
if(CX_PLATFORM STREQUAL "linux")
    set(SOURCES ${SOURCES} certificates_posix.c selfsign_openssl.c)
else()
    # macOS
    set(SOURCES ${SOURCES} certificates_darwin.c selfsign_openssl.c)
endif()

add_library(msquic_platform STATIC ${SOURCES})
add_library(msquic::platform ALIAS msquic_platform)
set_target_properties(msquic_platform PROPERTIES EXPORT_NAME platform)

# Linux XDP support
if(QUIC_LINUX_XDP_ENABLED)
    find_library(NL_LIB nl-3)
    find_library(NL_ROUTE_LIB nl-route-3)
    find_library(XDP_LIB libxdp.so)
    find_library(BPF_LIB libbpf.so)
    target_include_directories(msquic_platform PRIVATE /usr/include/xdp)
    target_include_directories(msquic_platform PRIVATE /usr/include/bpf)
    set(XDP_PROG_INCLUDE_DIR "-I/usr/include/bpf")

    # building XDP program
    add_custom_command(
        OUTPUT ${QUIC_OUTPUT_DIR}/datapath_raw_xdp_kern.o
        COMMAND clang -O2 -g -target bpf
        -c ${PROJECT_SOURCE_DIR}/src/platform/datapath_raw_xdp_linux_kern.c
        -o ${QUIC_OUTPUT_DIR}/datapath_raw_xdp_kern.o
        ${XDP_PROG_INCLUDE_DIR}
        -I/usr/include/x86_64-linux-gnu
        DEPENDS ${PROJECT_SOURCE_DIR}/src/platform/datapath_raw_xdp_linux_kern.c
    )
    add_custom_target(xdp_program DEPENDS ${QUIC_OUTPUT_DIR}/datapath_raw_xdp_kern.o)
    add_dependencies(msquic_platform xdp_program)

    if (NOT BUILD_SHARED_LIBS)
        find_library(ELF_LIB elf)
        find_library(Z_LIB z)
        find_library(ZSTD_LIB zstd)
        string(REPLACE ".so" ".a" NL_LIB ${NL_LIB})
        string(REPLACE ".so" ".a" NL_ROUTE_LIB ${NL_ROUTE_LIB})
        string(REPLACE ".so" ".a" ELF_LIB ${ELF_LIB})
        string(REPLACE ".so" ".a" Z_LIB ${Z_LIB})
        string(REPLACE ".so" ".a" ZSTD_LIB ${ZSTD_LIB})
        string(REPLACE ".so" ".a" XDP_LIB ${XDP_LIB})
        string(REPLACE ".so" ".a" BPF_LIB ${BPF_LIB})
    endif()

    target_link_libraries(msquic_platform PUBLIC ${XDP_LIB} ${BPF_LIB} ${NL_LIB} ${NL_ROUTE_LIB} ${ELF_LIB} ${Z_LIB} ${ZSTD_LIB})
    include_directories(/usr/include/libnl3)
    target_include_directories(msquic_platform PRIVATE ${EXTRA_PLATFORM_INCLUDE_DIRECTORIES})
endif()

target_link_libraries(msquic_platform PUBLIC inc)
target_link_libraries(msquic_platform PRIVATE warnings main_binary_link_args)

set_property(TARGET msquic_platform PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}libraries")

# OpenSSL/QuicTLS linking
target_link_libraries(msquic_platform PUBLIC OpenSSL)
if (CX_PLATFORM STREQUAL "darwin")
    target_link_libraries(msquic_platform PUBLIC "-framework CoreFoundation" "-framework Security")
endif()
