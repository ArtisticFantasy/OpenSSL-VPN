cmake_minimum_required(VERSION 3.28.3)

project(SSL_VPN_DEMO)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED PATHS ${PROJECT_SOURCE_DIR}/tools/openssl/lib64/cmake ${PROJECT_SOURCE_DIR}/tools/openssl/lib/cmake)
set(OPENSSL_LIBS ${OPENSSL_CRYPTO_LIBRARIES} ${OPENSSL_SSL_LIBRARIES})

message(STATUS "find openssl libraries: ${OPENSSL_LIBS}")
message(STATUS "find openssl include directory: ${OPENSSL_INCLUDE_DIR}")

include_directories(${OPENSSL_INCLUDE_DIR})

add_subdirectory(src)