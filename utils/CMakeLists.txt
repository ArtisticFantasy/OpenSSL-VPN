add_library(vpn_utils SHARED ssl.c)
target_link_libraries(vpn_utils ${OPENSSL_LIBS} vpn_common)
set_target_properties(vpn_utils PROPERTIES
  LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
target_compile_definitions(vpn_utils PRIVATE -DCERT_PATH="${PROJECT_SOURCE_DIR}/certs")