cmake_minimum_required(VERSION 3.1)
project(suola)

file(GLOB SOURCES "*.c" "debug/*.c" "meths/*.c" "ossl/*.c")
add_library(suola SHARED ${SOURCES})
include_directories(${CMAKE_SOURCE_DIR})

option(USE_HACL "Use libhacl instead of libsodium" OFF)
option(USE_DONNA "Use static donna instead of libsodium" OFF)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "~/.cmake/Modules")
set(CMAKE_VERBOSE_MAKEFILE ON)
#SET(CMAKE_SKIP_RPATH TRUE)

find_package(OpenSSL REQUIRED)
message("OpenSSL root dir: ${OPENSSL_ROOT_DIR}")
message("OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message("OpenSSL libraries: ${OPENSSL_LIBRARIES}")
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(suola ${OPENSSL_LIBRARIES})

IF(USE_HACL)
    set(HACL_PREFIX "/usr/local" CACHE STRING "Prefix PATH for HACL")
    find_library(hacl_LIBRARIES NAMES hacl PATHS "${HACL_PREFIX}" PATH_SUFFIXES "lib")
    find_file(hacl_INCLUDE_DIR include PATHS "${HACL_PREFIX}" NO_DEFAULT_PATH)
    message("hacl prefix: ${HACL_PREFIX}")
    message("hacl include dir: ${hacl_INCLUDE_DIR}")
    message("hacl libraries: ${hacl_LIBRARIES}")

    include_directories(${hacl_INCLUDE_DIR})
    target_link_libraries(suola ${hacl_LIBRARIES})

    file(GLOB LIBSUOLA_PROVIDER "providers/hacl/*.c" "providers/ossl/rng.c" "providers/_dummy/base.c")
    target_compile_definitions(suola PRIVATE SUOLA_ENGINE_NAME="An engine gluing together OpenSSL and HACL*")
ELSEIF(USE_DONNA)
    IF(${CMAKE_SYSTEM_PROCESSOR} MATCHES "^arm")
        set(DONNA_CFLAGS "-mfpu=neon")
        set(DONNA_URL "https://raw.githubusercontent.com/floodyberry/supercop/master/crypto_scalarmult/curve25519/neon2/scalarmult.s")
        set(DONNA_FILE scalarmult.s)
        set(DONNA_OBJECT scalarmult.o)
        set(DONNA_PATCH mv ../${DONNA_FILE} .)
        target_compile_definitions(suola PRIVATE _SCALARMULT_CURVE25519_NEON2)
        target_compile_definitions(suola PRIVATE SUOLA_ENGINE_NAME="An engine gluing together OpenSSL and donna [NEON2]")
    ELSE()
        IF(${CMAKE_SYSTEM_PROCESSOR} MATCHES "^aarch64")
        ELSE()
            set(DONNA_CFLAGS "-DED25519_SSE2")
        ENDIF()
        set(DONNA_URL "https://raw.githubusercontent.com/floodyberry/supercop/master/crypto_scalarmult/curve25519/donna_c64/smult.c")
        set(DONNA_FILE smult.c)
        set(DONNA_OBJECT smult.o)
        set(DONNA_PATCH mv ../${DONNA_FILE} . COMMAND echo "int crypto_scalarmult(unsigned char *mypublic, const unsigned char *secret, const unsigned char *basepoint)$<SEMICOLON>" > crypto_scalarmult.h )
        target_compile_definitions(suola PRIVATE SUOLA_ENGINE_NAME="An engine gluing together OpenSSL and donna [donna_c64]")
    ENDIF()

    include(ExternalProject)
    ExternalProject_Add(ed25519-donna
    GIT_REPOSITORY "https://github.com/floodyberry/ed25519-donna.git"
    GIT_TAG "master"
    UPDATE_COMMAND ""
    PATCH_COMMAND ""
    TEST_COMMAND ""
    INSTALL_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_IN_SOURCE 1
    BUILD_COMMAND ${CMAKE_C_COMPILER} -c ed25519.c -fPIC -O3 ${DONNA_CFLAGS} -I${OPENSSL_INCLUDE_DIR}
    )
    add_dependencies(suola ed25519-donna)
    ExternalProject_Get_Property(ed25519-donna SOURCE_DIR)
    target_link_libraries(suola ${SOURCE_DIR}/ed25519.o)

    ExternalProject_Add(x25519-donna
    DOWNLOAD_COMMAND curl -L -O ${DONNA_URL}
    UPDATE_COMMAND ""
    PATCH_COMMAND ${DONNA_PATCH}
    TEST_COMMAND ""
    INSTALL_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_IN_SOURCE 1
    BUILD_COMMAND ${CMAKE_C_COMPILER} -c ${DONNA_FILE} -fPIC -O3
    )
    add_dependencies(suola x25519-donna)
    ExternalProject_Get_Property(x25519-donna SOURCE_DIR)
    target_link_libraries(suola ${SOURCE_DIR}/${DONNA_OBJECT})

    file(GLOB LIBSUOLA_PROVIDER "providers/donna/*.c" "providers/ossl/rng.c" "providers/_dummy/base.c")
ELSE()
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
    find_package(sodium REQUIRED)
    SET(sodium_LIBRARIES ${sodium_LIBRARY_DEBUG})
    message("sodium include dir: ${sodium_INCLUDE_DIR}")
    message("sodium libraries: ${sodium_LIBRARIES}")
    include_directories(${sodium_INCLUDE_DIR})
    target_link_libraries(suola ${sodium_LIBRARIES})

    file(GLOB LIBSUOLA_PROVIDER "providers/libsodium/*.c")
ENDIF(USE_HACL)
target_sources(suola PRIVATE ${LIBSUOLA_PROVIDER})

set_target_properties(suola PROPERTIES INSTALL_RPATH_USE_LINK_PATH TRUE)

set_target_properties(suola PROPERTIES COMPILE_FLAGS "-Werror=implicit-function-declaration -Wno-discarded-qualifiers")

get_filename_component(OPENSSL_CRYPTO_LIB_PATH ${OPENSSL_CRYPTO_LIBRARY} DIRECTORY)

if(${OPENSSL_VERSION} VERSION_LESS 1.1.0)
    #set_target_properties(suola PROPERTIES COMPILE_FLAGS "-Werror=implicit-function-declaration -Wno-incompatible-pointer-types -Wno-discarded-qualifiers")
    set_target_properties(suola PROPERTIES COMPILE_FLAGS "-Werror=implicit-function-declaration -Wno-discarded-qualifiers")

    target_compile_definitions(suola PRIVATE OPENSSL_V102_COMPAT)

    set_target_properties(suola PROPERTIES PREFIX "liblib")
    install(TARGETS suola DESTINATION ${OPENSSL_CRYPTO_LIB_PATH}/engines)
else()
    install(TARGETS suola DESTINATION ${OPENSSL_CRYPTO_LIB_PATH}/engines-1.1)
endif(${OPENSSL_VERSION} VERSION_LESS 1.1.0)

target_compile_definitions(suola PRIVATE _DEBUG)
target_compile_definitions(suola PRIVATE DEBUG_COLORS)
target_compile_definitions(suola PRIVATE DEBUG_BASE64_SGNVRF)

target_link_libraries(suola "-Wl,-z,defs") # Throw an error in case of undefined symbols during libsuola linking

SET(test_apps_SRC "tests/apps.c" "tests/ossl_compat.c")

add_executable(evp_pkey tests/evp_pkey.c ${test_apps_SRC})
target_link_libraries(evp_pkey suola)
if(${OPENSSL_VERSION} VERSION_LESS 1.1.0)
    target_compile_definitions(evp_pkey PRIVATE OPENSSL_V102_COMPAT)
endif(${OPENSSL_VERSION} VERSION_LESS 1.1.0)
set_target_properties(evp_pkey PROPERTIES COMPILE_FLAGS "-Werror=implicit-function-declaration")

add_executable(evp_test tests/evp_test.c "tests/ossl_compat.c" "ossl/ossl_compat.c")
set_target_properties(evp_test PROPERTIES COMPILE_DEFINITIONS "CUSTOM_OPENSSL_INIT;OPENSSL_NO_POLY1305;OPENSSL_NO_SIPHASH")
target_link_libraries(evp_test ${OPENSSL_LIBRARIES})
if(${OPENSSL_VERSION} VERSION_LESS 1.1.0)
    target_compile_definitions(evp_test PRIVATE OPENSSL_V102_COMPAT)
endif(${OPENSSL_VERSION} VERSION_LESS 1.1.0)
set_target_properties(evp_test PROPERTIES COMPILE_FLAGS "-Werror=implicit-function-declaration")

enable_testing()

set(RFC8032_PRIV "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")

add_test(NAME rfc8032_priv_pem
    COMMAND evp_pkey 1 ED25519 ${RFC8032_PRIV})
set_tests_properties(rfc8032_priv_pem PROPERTIES ENVIRONMENT
    "OPENSSL_ENGINES=${CMAKE_BINARY_DIR}")
set_tests_properties(rfc8032_priv_pem PROPERTIES PASS_REGULAR_EXPRESSION
    "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIM/5iQJI3udYux3WHUgkR6adZzsHRl1W32pAbltyj1C
-----END PRIVATE KEY-----")

add_test(NAME rfc8032_pub_pem
    COMMAND evp_pkey 2 ED25519 ${RFC8032_PRIV})
set_tests_properties(rfc8032_pub_pem PROPERTIES ENVIRONMENT
    "OPENSSL_ENGINES=${CMAKE_BINARY_DIR}")
set_tests_properties(rfc8032_pub_pem PROPERTIES PASS_REGULAR_EXPRESSION
    "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA7Bcrk61eVjv0kyxw4SRQNMNUZ\\+8u/U1k6/gZaDRn4r8=
-----END PUBLIC KEY-----")


add_test(NAME rfc7748_x25519_evp_tests
    COMMAND evp_test ${CMAKE_SOURCE_DIR}/tests/rfc7748.txt )
set_tests_properties(rfc7748_x25519_evp_tests PROPERTIES ENVIRONMENT
    "OPENSSL_CONF=${CMAKE_SOURCE_DIR}/tests/libsuola.cnf")
set_property(TEST rfc7748_x25519_evp_tests APPEND PROPERTY ENVIRONMENT
    "OPENSSL_ENGINES=${CMAKE_BINARY_DIR}")
set_tests_properties(rfc7748_x25519_evp_tests PROPERTIES PASS_REGULAR_EXPRESSION
    " 0 errors, 0 skipped")

add_test(NAME evp_tests
    COMMAND evp_test ${CMAKE_SOURCE_DIR}/tests/libsuola_tests.txt )
set_tests_properties(evp_tests PROPERTIES ENVIRONMENT
    "OPENSSL_CONF=${CMAKE_SOURCE_DIR}/tests/libsuola.cnf")
set_property(TEST evp_tests APPEND PROPERTY ENVIRONMENT
    "OPENSSL_ENGINES=${CMAKE_BINARY_DIR}")
set_tests_properties(evp_tests PROPERTIES PASS_REGULAR_EXPRESSION
    " 0 errors, 0 skipped")

add_test(NAME gnupg_evp_tests
    COMMAND evp_test ${CMAKE_SOURCE_DIR}/tests/gnugpg_t-ed25519.txt )
set_tests_properties(gnupg_evp_tests PROPERTIES ENVIRONMENT
    "OPENSSL_CONF=${CMAKE_SOURCE_DIR}/tests/libsuola.cnf")
set_property(TEST gnupg_evp_tests APPEND PROPERTY ENVIRONMENT
    "OPENSSL_ENGINES=${CMAKE_BINARY_DIR}")
set_tests_properties(gnupg_evp_tests PROPERTIES PASS_REGULAR_EXPRESSION
    " 0 errors, 0 skipped")

