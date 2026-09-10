cmake_minimum_required(VERSION 3.14.0)
project(bssl_dart LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(BORINGSSL_ROOT ../third_party/boringssl/)

include(../third_party/boringssl/sources.cmake)

# Symbol prefixing: all BoringSSL symbols become bssl_dart_<symbol>
add_definitions(-DBORINGSSL_PREFIX=bssl_dart)

# Architecture and platform detection
if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64" OR "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "amd64" OR "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "AMD64")
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(ARCH "x86_64")
  else()
    set(ARCH "x86")
  endif()
elseif("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86" OR "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "i386" OR "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "i686")
  set(ARCH "x86")
elseif("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "arm64" OR "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "arm64e")
  set(ARCH "aarch64")
elseif("${CMAKE_SYSTEM_PROCESSOR}" MATCHES "^arm*")
  set(ARCH "arm")
elseif("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "ppc64le")
  set(ARCH "ppc64le")
else()
  set(ARCH "generic")
endif()

if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
  set(PLATFORM "win")
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin" OR ${CMAKE_SYSTEM_NAME} STREQUAL "iOS")
  set(PLATFORM "apple")
else()
  set(PLATFORM "linux")
endif()

if(NOT DEFINED crypto_sources_${PLATFORM}_${ARCH})
  add_definitions(-DOPENSSL_NO_ASM)
  set(crypto_sources_${PLATFORM}_${ARCH})
endif()

if(MSVC)
  set(MSVC_DISABLED_WARNINGS_LIST "C4100" "C4127" "C4132" "C4244" "C4267" "C4706" "C4141" "C4201")
  string(REPLACE "C" " -wd" MSVC_DISABLED_WARNINGS_STR ${MSVC_DISABLED_WARNINGS_LIST})
  set(CMAKE_C_FLAGS "-utf-8 -W4 -WX ${MSVC_DISABLED_WARNINGS_STR}")
  set(CMAKE_CXX_FLAGS "-utf-8 -W4 -WX ${MSVC_DISABLED_WARNINGS_STR}")
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY $<1:${CMAKE_BINARY_DIR}>)
endif()

if(WIN32)
  enable_language(ASM_NASM)
  set(OPENSSL_NASM TRUE)
  set(CMAKE_ASM_NASM_FLAGS "${CMAKE_ASM_NASM_FLAGS} -gcv8")
  set(CMAKE_GENERATOR_CC cl)
  add_definitions(-D_HAS_EXCEPTIONS=0)
  add_definitions(-DWIN32_LEAN_AND_MEAN)
  add_definitions(-DNOMINMAX)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
  add_definitions(-DBORINGSSL_UNSAFE_DETERMINISTIC_MODE=0)
endif()

add_library(
  bssl_dart
  SHARED
  ${crypto_sources}
  ${crypto_sources_${PLATFORM}_${ARCH}}
)

target_include_directories(
  bssl_dart
  PUBLIC
  ../third_party/boringssl/src/include/
  PRIVATE
  ../third_party/boringssl/src/gen/
)

set_target_properties(
  bssl_dart
  PROPERTIES
  C_VISIBILITY_PRESET default
  VISIBILITY_INLINES_HIDDEN 0
  WINDOWS_EXPORT_ALL_SYMBOLS TRUE
)

install(
  TARGETS bssl_dart
  RUNTIME DESTINATION .
  LIBRARY DESTINATION .
  ARCHIVE DESTINATION .
)
