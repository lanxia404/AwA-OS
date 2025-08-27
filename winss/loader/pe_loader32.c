// winss/loader/pe_loader32.c — PE32 loader (imports + reloc) + init TEB + set command line
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include "../include/win/minwin.h"
#include "../include/nt/hooks.h"

/* 弱符號：若與 ntdll32 連結，能初始化 TEB；否則自動略過 */
__attribute__((weak)) void* NtCurrentTeb(void);
__attribute__((weak)) void nt_set_command_lineA(const char* s);

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#pragma pack(push,1)
typedef struct {
  uint16_t e_magic;      uint16_t e_cblp;       uint16_t e_cp;         uint16_t e_crlc;
  uint16_t e_cparhdr;    uint16_t e_minalloc;   uint16_t e_maxalloc;   uint16_t e_ss;
  uint16_t e_sp;         uint16_t e_csum;       uint16_t e_ip;         uint16_t e_cs;
  uint16_t e_lfarlc;     uint16_t e_ovno;       uint16_t e_res[4];     uint16_t e_oemid;
  uint16_t e_oeminfo;    uint16_t e_res2[10];   int32_t  e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct { uint32_t VirtualAddress, Size; } IMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_DIRECTORY_ENTRY_IMPORT     1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC  5

typedef struct {
  uint16_t Machine, NumberOfSections;
  uint32_t TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
  uint16_t SizeOfOptionalHeader, Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
  uint16_t Magic;
  uint8_t  MajorLinkerVersion, MinorLinkerVersion;
  uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint, BaseOfCode, BaseOfData;
  uint32_t ImageBase;
  uint32_t SectionAlignment, FileAlignment;
  uint16_t MajorOSVersion, MinorOSVersion, MajorImageVersion, MinorImageVersion;
  uint16_t MajorSubsystemVersion, MinorSubsystemVersion;
  uint32_t Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
  uint16_t Subsystem, DllCharacteristics;
  uint32_t SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
  uint32_t LoaderFlags, NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32;

typedef struct {
  uint32_t Signature;
  IMAGE_FILE_HEADER        FileHeader;
  IMAGE_OPTIONAL_HEADER32  OptionalHeader;
} IMAGE_NT_HEADERS32;

typedef struct {
  uint8_t  Name[8];
  union { uint32_t PhysicalAddress; uint32_t VirtualSize; } Misc;
  uint32_t VirtualAddress, SizeOfRawData, PointerToRawData, PointerToRelocations,
           PointerToLinenumbers; uint16_t NumberOfRelocations, NumberOfLinenumbers;
  uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

typedef struct {
  uint32_t   OriginalFirstThunk;
  uint32_t   TimeDateStamp;
  uint32_t   ForwarderChain;
  uint32_t   Name;
  uint32_t   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;

typedef struct { uint32_t u1; } IMAGE_THUNK_DATA32;
#define IMAGE_ORDINAL_FLAG32 0x80000000u

typedef struct { uint16_t Hint; char Name[1]; } IMAGE_IMPORT_BY_NAME;

typedef struct { uint32_t VirtualAddress, SizeOfBlock; } IMAGE_BASE_RELOCATION;
#pragma pack(pop)

/* 與 ntshim32 對應的 Hook 表 */
extern struct Hook NT_HOOKS[];

static void die(const char* s){ perror(s); _exit(127); }
static void* rva(void* base, uint32_t off){ return off ? (uint8_t*)base + off : NULL; }

static int ieq(const char* a, const char* b){
  for (; *a && *b; ++a,++b){
    int ca=tolower((unsigned char)*a), cb=tolower((unsigned char)*b);
    if (ca!=cb) return 0;
  }
  return *a==0 && *b==0;
}

/* 去底線前綴 + 去 stdcall 尾端 @NN 裝飾 */
static void undecorate(const char* in, char* out, size_t cap){
  size_t i=0, j=0;
  if (in[0]=='_') ++i;
  for (; in[i] && j+1<cap; ++i){
    if (in[i]=='@'){
      size_t k=i+1; int all_digit=1;
      while (in[k]){ if (in[k]<'0'||in[k]>'9'){ all_digit=0; break; } ++k; }
      if (all_digit) break;
    }
    out[j++] = in[i];
  }
  out[j]=0;
}

/* 規範化 DLL 名：轉小寫 + 去掉尾端 ".dll"（若有） */
static void canon_dll(const char* in, char* out, size_t cap){
  size_t j=0;
  for (size_t i=0; in && in[i] && j+1<cap; ++i){
    char c = in[i];
    if (c>='A' && c<='Z') c = (char)(c+32);
    out[j++] = c;
  }
  out[j]=0;
  size_t L = strlen(out);
  if (L>=4 && out[L-4]=='.' && out[L-3]=='d' && out[L-2]=='l' && out[L-1]=='l'){
    out[L-4]=0; /* strip ".dll" */
  }
}

/* 更魯棒的匯入解析：先只看函式名；不行再看 DLL+函式名 */
static void* resolve_import(const char* dll, const char* sym){
  char clean[128]; undecorate(sym, clean, sizeof(clean));

  /* 1) 名稱直配（忽略 DLL） */
  for (struct Hook* h=NT_HOOKS; h && h->dll; ++h){
    if (strcmp(h->name, clean)==0) return h->fn;
  }

  /* 2) DLL + 名稱（兩邊 DLL 規範化後比較） */
  char want[64]; canon_dll(dll, want, sizeof(want));
  for (struct Hook* h=NT_HOOKS; h && h->dll; ++h){
    char have[64]; canon_dll(h->dll, have, sizeof(have));
    if (strcmp(have, want)==0 && strcmp(h->name, clean)==0) return h->fn;
  }

  return NULL;
}

static void* map_image_at(uint32_t base, size_t sz, int try_fixed){
  int flags = MAP_PRIVATE|MAP_ANON;
  void* p;
  if (try_fixed){
    p = mmap((void*)(uintptr_t)base, sz, PROT_READ|PROT_WRITE|PROT_EXEC, flags|MAP_FIXED_NOREPLACE, -1, 0);
    if (p != MAP_FAILED) return p;
  }
  p = mmap(NULL, sz, PROT_READ|PROT_WRITE|PROT_EXEC, flags, -1, 0);
  if (p == MAP_FAILED) die("mmap image");
  return p;
}

static void apply_relocs(void* image, IMAGE_NT_HEADERS32* nt, uint32_t actual_base){
  uint32_t pref = nt->OptionalHeader.ImageBase;
  if (actual_base == pref) return;

  IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  if (!dir.VirtualAddress || !dir.Size) return;

  uint8_t* cur = (uint8_t*)rva(image, dir.VirtualAddress);
  uint8_t* end = cur + dir.Size;
  uint32_t delta = actual_base - pref;

  while (cur < end){
    IMAGE_BASE_RELOCATION* blk = (IMAGE_BASE_RELOCATION*)cur;
    if (!blk->SizeOfBlock) break;
    uint32_t page = blk->VirtualAddress;
    uint32_t count = (blk->SizeOfBlock - 8)/2;
    uint16_t* ent = (uint16_t*)(blk + 1);
    for (uint32_t i=0;i<count;i++){
      uint16_t typeoff = ent[i];
      uint16_t type = typeoff >> 12;
      uint16_t off  = typeoff & 0x0FFF;
      if (type == 0) continue;   // ABSOLUTE
      if (type == 3){            // HIGHLOW
        uint32_t* slot = (uint32_t*)((uint8_t*)image + page + off);
        *slot += delta;
      }
    }
    cur += blk->SizeOfBlock;
  }
}

static void set_cmdline_from_argv(int argc, char** argv){
  if (!nt_set_command_lineA) return;
  if (argc <= 1){ nt_set_command_lineA(""); return; }
  size_t len = 0; for (int i=1;i<argc;i++) len += strlen(argv[i]) + 1;
  if (!len){ nt_set_command_lineA(""); return; }
  char* buf = (char*)malloc(len); if (!buf){ nt_set_command_lineA(""); return; }
  buf[0]=0;
  for (int i=1;i<argc;i++){ strcat(buf, argv[i]); if (i+1<argc) strcat(buf," "); }
  nt_set_command_lineA(buf);
  free(buf);
}

int main(int argc, char** argv){
  if (NtCurrentTeb) NtCurrentTeb();            /* 初始化 TEB（若可用） */
  set_cmdline_from_argv(argc, argv);           /* 先設命令列，便於早期使用 */

  if (argc < 2){
    fprintf(stderr,"usage: %s program.exe [args...]\n", argv[0]);
    return 2;
  }
  const char* path = argv[1];

  int fd = open(path, O_RDONLY);
  if (fd < 0) die("open exe");

  struct stat st;
  if (fstat(fd,&st) < 0) die("stat exe");

  uint8_t* file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (file == MAP_FAILED) die("mmap exe");

  IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)file;
  if (dos->e_magic != 0x5A4D){ fprintf(stderr,"Not MZ\n"); return 1; }

  IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(file + dos->e_lfanew);
  if (nt->Signature != 0x4550 || nt->OptionalHeader.Magic != 0x10B){
    fprintf(stderr,"Not PE32\n"); return 1;
  }

  uint32_t image_base  = nt->OptionalHeader.ImageBase;
  uint32_t size_image  = nt->OptionalHeader.SizeOfImage;
  uint32_t size_hdrs   = nt->OptionalHeader.SizeOfHeaders;

  void* image = map_image_at(image_base, size_image, 1);
  memcpy(image, file, size_hdrs);

  IMAGE_SECTION_HEADER* sec = (IMAGE_SECTION_HEADER*)((uint8_t*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
  for (int i=0; i<nt->FileHeader.NumberOfSections; ++i){
    void* dst = (uint8_t*)image + sec[i].VirtualAddress;
    size_t vsz = sec[i].Misc.VirtualSize;
    size_t rsz = sec[i].SizeOfRawData;
    if (rsz) memcpy(dst, file + sec[i].PointerToRawData, rsz);
    if (vsz > rsz) memset((uint8_t*)dst + rsz, 0, vsz - rsz);
  }

  if ((uint32_t)(uintptr_t)image != image_base){
    apply_relocs(image, nt, (uint32_t)(uintptr_t)image);
  }

  IMAGE_DATA_DIRECTORY impdir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (impdir.VirtualAddress && impdir.Size){
    for (IMAGE_IMPORT_DESCRIPTOR* d = (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)image + impdir.VirtualAddress);
         d && d->Name; ++d){
      const char* dll = (const char*)((uint8_t*)image + d->Name);
      if (!dll) continue;

      IMAGE_THUNK_DATA32* oft = (IMAGE_THUNK_DATA32*)((uint8_t*)image + d->OriginalFirstThunk);
      IMAGE_THUNK_DATA32* ft  = (IMAGE_THUNK_DATA32*)((uint8_t*)image + d->FirstThunk);
      if (!oft) oft = ft;

      for (; oft && oft->u1; ++oft, ++ft){
        if (oft->u1 & IMAGE_ORDINAL_FLAG32){
          fprintf(stderr, "Ordinal import not supported for %s\n", dll);
          return 1;
        }else{
          IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)((uint8_t*)image + oft->u1);
          const char* sym = (const char*)ibn->Name;
          void* fn = resolve_import(dll, sym);
          if (!fn){
            fprintf(stderr, "Unresolved import %s!%s\n", dll, sym);
            return 1;
          }
          ft->u1 = (uint32_t)(uintptr_t)fn;
        }
      }
    }
  }

  void* entry = (uint8_t*)image + nt->OptionalHeader.AddressOfEntryPoint;
  if (!entry){ fprintf(stderr,"No entry\n"); return 1; }

  typedef void (WINAPI *entry_t)(void);
  ((entry_t)entry)();
  return 0;
}