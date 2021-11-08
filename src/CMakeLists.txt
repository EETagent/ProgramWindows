# DLL pro server
add_library(payload_demo_dll SHARED "server/payload/dll/main.cpp")
set_target_properties(payload_demo_dll PROPERTIES LINKER_LANGUAGE CXX) 

add_executable(payload_demo_executable "server/payload/exe/main.cpp")
set_target_properties(payload_demo_executable PROPERTIES LINKER_LANGUAGE CXX) 

# Client
add_executable (client "./client/main.c")
set_target_properties(client PROPERTIES LINKER_LANGUAGE C) 

if(WIN32)
  target_link_libraries(client wsock32 ws2_32 iphlpapi)
endif()

