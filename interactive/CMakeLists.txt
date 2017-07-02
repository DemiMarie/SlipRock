if (UNIX)
   add_executable(sliprock-shell ./main.c)
   target_link_libraries(sliprock-shell sliprock_static)
   set_target_properties(sliprock-shell PROPERTIES OUTPUT_NAME sliprock)
   install(TARGETS sliprock-shell
      DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif()
