add_library(vpn_network SHARED setup.c subnet.c)
target_link_libraries(vpn_network vpn_common)
set_target_properties(vpn_network PROPERTIES
  LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)