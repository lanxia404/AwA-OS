# winss/loader/CMakeLists.txt
cmake_minimum_required(VERSION 3.16)

add_executable(pe_loader32
  pe_loader32.c
)

target_include_directories(pe_loader32 PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/../include
)

target_compile_options(pe_loader32 PRIVATE -m32 -fvisibility=hidden)

# 關鍵：鏈入 ntshim32 以及 pthread（保險起見，這裡也顯式加上）
target_link_libraries(pe_loader32 PRIVATE ntshim32 pthread)

# 安裝路徑維持不變
install(TARGETS pe_loader32 RUNTIME DESTINATION lib/awaos)
