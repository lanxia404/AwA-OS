add_library(ntshim32 STATIC ntshim32.c)
target_compile_options(ntshim32 PRIVATE -m32 -O2 -fno-plt -fvisibility=hidden)
