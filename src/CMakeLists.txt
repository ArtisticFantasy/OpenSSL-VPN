add_definitions(-DCERT_PATH="${PROJECT_SOURCE_DIR}/certs")

include_directories(${PROJECT_SOURCE_DIR}/include)

add_library(vpn_common SHARED vpn_common.c)
target_link_libraries(vpn_common ${OPENSSL_LIBS})
set_target_properties(vpn_common PROPERTIES
  LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)

add_executable(vpn_client vpn_client.c)
target_link_libraries(vpn_client vpn_common pthread)
set_target_properties(vpn_client PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)

add_executable(vpn_server vpn_server.c)
target_link_libraries(vpn_server vpn_common pthread)
set_target_properties(vpn_server PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)