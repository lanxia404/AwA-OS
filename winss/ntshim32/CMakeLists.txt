cmake_minimum_required(VERSION 3.16)

add_library(ntshim32 STATIC
  ntshim32.c
  ../ntdll32/teb.c
  ../ntdll32/error.c
  ../ntdll32/tls.c
  ../ntdll32/thread.c
  ../ntdll32/teb_init.c
  ../loader/pe32_spawn_bridge.c
)

target_include_directories(ntshim32 PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/../include
)

# 32-bit 編譯與連結
target_compile_options(ntshim32 PRIVATE -m32 -fvisibility=hidden)
target_link_options(ntshim32 PRIVATE -m32)

# thread.c 依賴 pthread
target_link_libraries(ntshim32 PUBLIC pthread)
