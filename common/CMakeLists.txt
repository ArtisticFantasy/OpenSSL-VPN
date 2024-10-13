add_library(vpn_common SHARED common.c)
set_target_properties(vpn_common PROPERTIES
  LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)

add_library(vpn_application_common SHARED application.c signal.c)
target_link_libraries(vpn_application_common vpn_common)
set_target_properties(vpn_application_common PROPERTIES
  LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)