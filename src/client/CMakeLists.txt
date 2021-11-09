# Klient
add_executable (client main.c)
set_target_properties(client PROPERTIES LINKER_LANGUAGE C) 

# ICMP modul
add_library(module_icmp STATIC "modules/icmp/client.c")
# HTTP modul
add_library(module_http STATIC "modules/http/client.c")

target_link_libraries(client module_icmp module_http)
target_link_libraries(client wsock32 ws2_32 iphlpapi)