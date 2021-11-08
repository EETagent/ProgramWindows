
# Client
add_executable (client "./client/main.c ./client/modules/http/client.c" ./client/modules/icmp/client.c")

set_target_properties(client PROPERTIES LINKER_LANGUAGE C) 

target_link_libraries(client wsock32 ws2_32 iphlpapi)\w
