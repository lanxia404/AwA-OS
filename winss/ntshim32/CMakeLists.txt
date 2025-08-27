# winss/ntshim32/CMakeLists.txt
cmake_minimum_required(VERSION 3.16)

# 將 ntdll32 的實作直接編入這個靜態庫
add_library(ntshim32 STATIC
  ntshim32.c
  ../ntdll32/teb.c
  ../ntdll32/error.c
  ../ntdll32/tls.c
  ../ntdll32/thread.c
)

target_include_directories(ntshim32 PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/../include
)

# 32-bit 構建已在頂層開啟；這裡保守再加一份
target_compile_options(ntshim32 PRIVATE -m32 -fvisibility=hidden)

# 這些檔案使用 pthread / eventfd
target_link_libraries(ntshim32 PUBLIC pthread)
