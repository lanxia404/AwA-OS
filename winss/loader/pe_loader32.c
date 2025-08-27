// winss/loader/pe_loader32.c
// 極簡 32-bit PE 載入器（User-mode），支援：
//  - 讀檔 -> 佈建 Image（RWX 簡化）
//  - HIGHLOW 重新配置（.reloc）
//  - IAT 綁定（依名稱對 NT_HOOKS）
//  - 呼叫入口點（__stdcall, void(void)）
//  - 向 ntshim 註冊 pe32_spawn 實作與命令列
//
// 注意：這是能過 CI 的最小版本，對安全性與相容性未做完整處理。
// 未實作：SEH、.tls 回撥初始化、進程/執行緒物件語義、PE 64-bit 等。

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>

#include "../ntshim32/ntshim_api.h"   // nt_teb_setup_for_current / nt_set_spawn_impl / nt_set_command_lineA
#include "../include/win/minwin.h"    // Windows 基本型別（供 Hook 查表）

// ---------------------------------------------------------------------
// 日誌
static int is_log(void){
  static int inited = 0;
  static int val = 0;
  if(!inited){
    inited = 1;
    const char* v = getenv("AWAOS_LOG");
    val = (v && *v) ? 1 : 0;
  }
  return val;
}
#define LOGF(...) do{ if(is_log()){ fprintf(stderr,"[pe_loader32] " __VA_ARGS__); fputc('\n', stderr);} }while(0)

// ---------------------------------------------------------------------
// Hook 表宣告（由 ntshim32.c 提供定義）
struct Hook { const char* dll; const char* name; void* fn; };
extern struct Hook NT_HOOKS[];

// ---------------------------------------------------------------------
// 迷你 PE 結構（避免依賴其他外部標頭）
#define PE_SIGNATURE 0x00004550u /* "PE\0\0" */

typedef struct {
  uint16_t e_magic;    /* "MZ" */
  uint16_t e_cblp;     uint16_t e_cp;      uint16_t e_crlc;
  uint16_t e_cparhdr;  uint16_t e_minalloc;uint16_t e_maxalloc;
  uint16_t e_ss;       uint16_t e_sp;      uint16_t e_csum;
  uint16_t e_ip;       uint16_t e_cs;      uint16_t e_lfarlc;
  uint16_t e_ovno;     uint16_t e_res[4];
  uint16_t e_oemid;    uint16_t e_oeminfo; uint16_t e_res2[10];
  int32_t  e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
  uint16_t Machine;
  uint16_t NumberOfSections;
  uint32_t TimeDateStamp;
  uint32_t PointerToSymbolTable;
  uint32_t NumberOfSymbols;
  uint16_t SizeOfOptionalHeader;
  uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
  uint32_t VirtualAddress;
  uint32_t Size;
} IMAGE_DATA_DIRECTORY;

typedef struct {
  uint16_t Magic;
  uint8_t  MajorLinkerVersion;
  uint8_t  MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint;
  uint32_t BaseOfCode;
  uint32_t BaseOfData;
  uint32_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DllCharacteristics;
  uint32_t SizeOfStackReserve;
  uint32_t SizeOfStackCommit;
  uint32_t SizeOfHeapReserve;
  uint32_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32;

typedef struct {
  uint32_t Signature;         // "PE\0\0"
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32;

typedef struct {
  uint8_t  Name[8];
  union { uint32_t PhysicalAddress; uint32_t VirtualSize; } Misc;
  uint32_t VirtualAddress;
  uint32_t SizeOfRawData;
  uint32_t PointerToRawData;
  uint32_t PointerToRelocations;
  uint32_t PointerToLinenumbers;
  uint16_t NumberOfRelocations;
  uint16_t NumberOfLinenumbers;
  uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

typedef struct {
  uint32_t   Characteristics;
  uint32_t   TimeDateStamp;
  uint32_t   ForwarderChain;
  uint32_t   Name;         // RVA to dll name
  uint32_t   FirstThunk;   // RVA to IAT
} IMAGE_IMPORT_DESCRIPTOR;

typedef struct {
  uint16_t Hint;
  char     Name[1];
} IMAGE_IMPORT_BY_NAME;

typedef struct {
  union { uint32_t ForwarderString; uint32_t Function; uint32_t Ordinal; uint32_t AddressOfData; } u1;
} IMAGE_THUNK_DATA32;

typedef struct {
  uint32_t VirtualAddress;
  uint32_t SizeOfBlock;
  // WORD TypeOffset[];
} IMAGE_BASE_RELOCATION;

// ---------------------------------------------------------------------
// 小工具
static inline void* rva(void* base, uint32_t rva){ return (void*)((uint8_t*)base + rva); }

static int caseless_eq(const char* a, const char* b){
  if(!a || !b) return 0;
  while(*a && *b){
    char ca = tolower((unsigned char)*a++);
    char cb = tolower((unsigned char)*b++);
    if(ca != cb) return 0;
  }
  return *a==0 && *b==0;
}

static const void* find_hook(const char* dll, const char* name){
  for(struct Hook* h = NT_HOOKS; h && h->dll; ++h){
    if(caseless_eq(h->dll, dll) && strcmp(h->name, name)==0) return h->fn;
  }
  return NULL;
}

// ---------------------------------------------------------------------
// IAT 綁定
static void bind_imports(void* image, IMAGE_NT_HEADERS32* nt){
  IMAGE_DATA_DIRECTORY imp = nt->OptionalHeader.DataDirectory[1]; // IMPORT
  if(!imp.VirtualAddress || !imp.Size) return;

  IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*)rva(image, imp.VirtualAddress);
  for(; desc->Name; ++desc){
    const char* dllName = (const char*)rva(image, desc->Name);
    IMAGE_THUNK_DATA32* thunk     = (IMAGE_THUNK_DATA32*)rva(image, desc->FirstThunk);
    IMAGE_THUNK_DATA32* origthunk = (IMAGE_THUNK_DATA32*)(desc->FirstThunk ?
                                rva(image, desc->FirstThunk) : (void*)0);

    for(; thunk && thunk->u1.AddressOfData; ++thunk, origthunk = origthunk ? origthunk+1 : NULL){
      const char* sym = NULL;
      if(origthunk && !(origthunk->u1.Ordinal & 0x80000000u)){
        IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)rva(image, origthunk->u1.AddressOfData);
        sym = ibn->Name;
      }else{
        // 以序號導入：這裡暫不支援
        sym = NULL;
      }

      const void* fn = sym ? find_hook(dllName, sym) : NULL;
      if(!fn){
        LOGF("Unresolved import: %s!%s", dllName ? dllName : "(null)", sym ? sym : "(ordinal)");
        thunk->u1.Function = 0;
      }else{
        thunk->u1.Function = (uint32_t)(uintptr_t)fn;
        LOGF("bind: %-14s -> %p", sym, fn);
      }
    }
  }
}

// 重新配置（HIGHLOW）
static void apply_relocs(void* image, IMAGE_NT_HEADERS32* nt, uintptr_t delta){
  if(delta == 0) return;
  IMAGE_DATA_DIRECTORY rel = nt->OptionalHeader.DataDirectory[5]; // BASE RELOC
  if(!rel.VirtualAddress || !rel.Size) return;

  uint8_t* base = (uint8_t*)image;
  uint32_t off = 0;
  while(off < rel.Size){
    IMAGE_BASE_RELOCATION* blk = (IMAGE_BASE_RELOCATION*)((uint8_t*)image + rel.VirtualAddress + off);
    if(blk->SizeOfBlock < sizeof(*blk)) break;

    uint32_t count = (blk->SizeOfBlock - sizeof(*blk)) / sizeof(uint16_t);
    uint16_t* entries = (uint16_t*)((uint8_t*)blk + sizeof(*blk));
    uint32_t pageRVA = blk->VirtualAddress;

    unsigned patched = 0;
    for(uint32_t i=0;i<count;++i){
      uint16_t e = entries[i];
      uint16_t type = (e >> 12) & 0xF;
      uint16_t ofs  = e & 0x0FFF;
      if(type == 3 /*HIGHLOW*/){
        uint32_t* p = (uint32_t*)(base + pageRVA + ofs);
        *p += (uint32_t)delta;
        ++patched;
      }
    }
    LOGF("reloc block RVA=0x%x patched=%u", pageRVA, patched);
    off += blk->SizeOfBlock;
  }
}

// ---------------------------------------------------------------------
// 執行 PE32 （傳回 0 代表成功）
static int run_pe32(const char* path, char* const* argv_unused){
  (void)argv_unused;

  int fd = open(path, O_RDONLY);
  if(fd < 0){ perror("open"); return -1; }

  struct stat st;
  if(fstat(fd, &st) < 0){ perror("fstat"); close(fd); return -1; }
  size_t fsz = (size_t)st.st_size;

  void* file = mmap(NULL, fsz, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if(file == MAP_FAILED){ perror("mmap-file"); return -1; }

  IMAGE_DOS_HEADER* mz = (IMAGE_DOS_HEADER*)file;
  if(mz->e_magic != 0x5A4D){ munmap(file, fsz); return -1; } // 'MZ'

  IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)((uint8_t*)file + mz->e_lfanew);
  if(nt->Signature != PE_SIGNATURE){ munmap(file, fsz); return -1; }

  size_t imgSize = nt->OptionalHeader.SizeOfImage;
  uint8_t* image = mmap(NULL, imgSize, PROT_READ|PROT_WRITE|PROT_EXEC,
                        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if(image == MAP_FAILED){ perror("mmap-image"); munmap(file, fsz); return -1; }

  // 複製 headers
  memcpy(image, file, nt->OptionalHeader.SizeOfHeaders);

  // 複製各節區
  IMAGE_SECTION_HEADER* sec = (IMAGE_SECTION_HEADER*)((uint8_t*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
  for(int i=0; i<nt->FileHeader.NumberOfSections; ++i){
    uint8_t* dst = image + sec[i].VirtualAddress;
    uint8_t* src = (uint8_t*)file + sec[i].PointerToRawData;
    size_t   sz  = sec[i].SizeOfRawData;
    if(sec[i].PointerToRawData && sz){
      memcpy(dst, src, sz);
    }
  }

  // 重新配置
  uintptr_t prefer = nt->OptionalHeader.ImageBase;
  uintptr_t delta  = (uintptr_t)image - prefer;
  apply_relocs(image, nt, delta);

  // 綁 IAT
  bind_imports(image, nt);

  // 進入點
  uint32_t epRVA = nt->OptionalHeader.AddressOfEntryPoint;
  void (*entry)(void) = (void(*)(void))(image + epRVA);

  LOGF("mapped '%s': pref=0x%08x map=%p delta=%ld (0x%lx)",
       path, (unsigned)prefer, image, (long)delta, (unsigned long)delta);
  LOGF("entering entrypoint 0x%08x for %s", epRVA, path);

  // 呼叫
  entry();

  munmap(file, fsz);
  // image 不回收，因為進入點可能不會返回；若返回，在 CI 仍可結束行程。
  return 0;
}

// ---------------------------------------------------------------------
// pe32_spawn：讓 CreateProcessA 透過橋接回到本 Loader
static int _loader_spawn_impl(const char* path, const char* cmdline){
  (void)cmdline; // 目前最小實作忽略 cmdline，未來可擴充成解析 cmdline -> argv
  return run_pe32(path, NULL) == 0 ? 1 : 0;
}

// ---------------------------------------------------------------------
int main(int argc, char** argv){
  // 初始化 TEB/TLS 等（由 ntdll32/* 提供）
  nt_teb_setup_for_current();

  // 註冊 spawn 實作，讓 CreateProcessA 能回呼到目前 Loader
  nt_set_spawn_impl(_loader_spawn_impl);

  // 設定命令列（目前最小：只記錄路徑；若有需要，可把 argv[2..] 連成一條字串傳給 nt_set_command_lineA）
  if(argc >= 2) nt_set_command_lineA(argv[1], NULL);
  else          nt_set_command_lineA("", NULL);

  if(argc < 2){
    fprintf(stderr, "Usage: %s <pe32.exe> [args ...]\n", argv[0]);
    return 1;
  }

  const char* target = argv[1];
  int rc = run_pe32(target, (argc>2)? &argv[2] : NULL);
  return (rc==0) ? 0 : 1;
}