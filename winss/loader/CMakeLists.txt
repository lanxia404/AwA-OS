cmake_minimum_required(VERSION 3.16)

add_executable(pe_loader32
  pe_loader32.c 
  hooks_table.c
)

target_include_directories(pe_loader32 PRIVATE
  ../include
  ../ntshim32
)

target_link_libraries(pe_loader32 PRIVATE ntshim32 pthread)

install(TARGETS pe_loader32 RUNTIME DESTINATION lib/awaos)
target_include_directories(pe_loader32 PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/../include
)

# 32-bit 編譯與連結
target_compile_options(pe_loader32 PRIVATE -m32 -fvisibility=hidden)
target_link_options(pe_loader32 PRIVATE -m32)

# 連結 ntshim32 與 pthread
target_link_libraries(pe_loader32 PRIVATE ntshim32 pthread)

# 安裝到 /usr/lib/awaos/pe_loader32
install(TARGETS pe_loader32 RUNTIME DESTINATION lib/awaos)
