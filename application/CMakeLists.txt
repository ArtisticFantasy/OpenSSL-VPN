set(APP_LINK_LIBS vpn_common vpn_network vpn_utils pthread)

add_executable(vpn_client client.c)
target_link_libraries(vpn_client ${APP_LINK_LIBS})
set_target_properties(vpn_client PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)

  add_executable(vpn_server server.c)
target_link_libraries(vpn_server ${APP_LINK_LIBS})
set_target_properties(vpn_server PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)