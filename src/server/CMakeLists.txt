if(WIN32)
  # DLL Payload
  add_library(payload_demo_dll SHARED "payload/dll/main.cpp")
  set_target_properties(payload_demo_dll PROPERTIES LINKER_LANGUAGE CXX) 
  # EXE Payload
  add_executable(payload_demo_executable "payload/exe/main.cpp")
  set_target_properties(payload_demo_executable PROPERTIES LINKER_LANGUAGE CXX) 
endif()

# HTTP server
add_library(mongoose STATIC "http/mongoose/mongoose.c")
target_include_directories(mongoose PRIVATE http/mongoose)

add_executable(http_server http/main.c)
target_link_libraries(http_server PRIVATE mongoose)
target_include_directories(http_server PRIVATE http/mongoose)
if(WIN32)
	target_link_libraries(http_server PRIVATE wsock32 ws2_32)
endif()

# ICMP server
# BPF projekt, nutno manuálně přes přidané Makefile