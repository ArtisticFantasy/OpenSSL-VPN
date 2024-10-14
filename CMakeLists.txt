cmake_minimum_required(VERSION 3.28.3)

project(OPENSSL_VPN_DEMO)

set(CMAKE_CXX_STANDARD 17)

if (OPENSSL_IN_TOOL)
   find_package(OpenSSL REQUIRED PATHS ${PROJECT_SOURCE_DIR}/tools/openssl/lib64/cmake ${PROJECT_SOURCE_DIR}/tools/openssl/lib/cmake)
else()
   find_package(OpenSSL ${OPENSSL_VERSION} REQUIRED)
endif()

set(OPENSSL_LIBS ${OPENSSL_CRYPTO_LIBRARIES} ${OPENSSL_SSL_LIBRARIES})

message(STATUS "Found OpenSSL version:           ${OPENSSL_VERSION}")
message(STATUS "Found openssl libraries:         ${OPENSSL_LIBS}")
message(STATUS "Found openssl include directory: ${OPENSSL_INCLUDE_DIR}")

include_directories(${OPENSSL_INCLUDE_DIR} ${PROJECT_SOURCE_DIR}/include)

add_subdirectory(common)
add_subdirectory(network)
add_subdirectory(utils)
add_subdirectory(application)