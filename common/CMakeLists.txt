add_library(vpn_common SHARED application.c signal.c)
set_target_properties(vpn_common PROPERTIES
  LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)