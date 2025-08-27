// winss/ntdll32/teb_init.c
#include <stdint.h>

// 對外符號，供 loader 連結使用（目前先空實作）
__attribute__((visibility("default")))
void nt_teb_setup_for_current(void){
  // TODO: 如需從 loader 移轉 TEB/TLS 初始化到這裡，請把 set_thread_area / FS 設定搬來
}