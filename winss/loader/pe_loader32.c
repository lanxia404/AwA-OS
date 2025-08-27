// winss/loader/pe_loader32.c
// Minimal PE32 loader for AwA-OS (i386)
// 改點：以 nt_get_hooks() 取得匯入掛鉤，不再直接引用 NT_HOOKS。

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#include "../include/win/minwin.h"
#include "../include/nt/hooks.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

static int env_log = -1;
static int is_log(void){
  if (env_log < 0){
    const char* s = getenv("AWAOS_LOG");
    env_log = (s && *s) ? 1 : 0;
  }
  return env_log;
}
#define LOGF(...) do{ if(is_log()){ fprintf(stderr, "[pe_loader32] " __VA_ARGS__); fputc('\n',stderr);} }while(0)

/* ---- 簡化的 PE 結構（只保留必要欄位） ---- */
#pragma pack(push,1)
typedef struct {
  uint16_t e_magic; /* MZ */
  uint16_t e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc, e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
  uint16_t e_res[4], e_oemid, e_oeminfo, e_res2[10];
  uint32_t e_lfanew;
} DOS_HDR;

typedef struct {
  uint32_t Signature;      /* "PE\0\0" */
  uint16_t Machine;        /* 0x14c */
  uint16_t NumberOfSections;
  uint32_t TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
  uint16_t SizeOfOptionalHeader, Characteristics;
} COFF_HDR;

typedef struct {
  uint16_t  Magic;         /* 0x10b */
  uint8_t   MajorLinkerVersion, MinorLinkerVersion;
  uint32_t  SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
  uint32_t  AddressOfEntryPoint;     /* RVA */
  uint32_t  BaseOfCode, BaseOfData;
  uint32_t  ImageBase;
  uint32_t  SectionAlignment, FileAlignment;
  uint16_t  MajorOSVersion, MinorOSVersion;
  uint16_t  MajorImageVersion, MinorImageVersion;
  uint16_t  MajorSubsystemVersion, MinorSubsystemVersion;
  uint32_t  Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
  uint16_t  Subsystem, DllCharacteristics;
  uint32_t  SizeOfStackReserve, SizeOfStackCommit;
  uint32_t  SizeOfHeapReserve, SizeOfHeapCommit;
  uint32_t  LoaderFlags, NumberOfRvaAndSizes;
  struct { uint32_t RVA, Size; } DataDirectory[16];
} OPT_HDR32;

typedef struct {
  uint8_t  Name[8];
  uint32_t VirtualSize, VirtualAddress;
  uint32_t SizeOfRawData, PointerToRawData;
  uint32_t PointerToRelocations, PointerToLinenumbers;
  uint16_t NumberOfRelocations, NumberOfLinenumbers;
  uint32_t Characteristics;
} SEC_HDR;

typedef struct {
  uint32_t OriginalFirstThunk; /* RVA of INT (or characteristics) */
  uint32_t TimeDateStamp, ForwarderChain, Name, FirstThunk; /* Name: RVA of DLL name, FirstThunk: IAT */
} IMAGE_IMPORT_DESCRIPTOR;
#pragma pack(pop)

/* ---- 封裝映像 ---- */
typedef struct {
  uint8_t*  map;
  uint32_t  prefer_base;
  int32_t   delta;
  uint32_t  entry_rva;
  uint32_t  import_rva, import_size;
  uint32_t  reloc_rva,  reloc_size;
  const char* path;
} PEIMG;

/* ---- 小工具 ---- */
static uint16_t rd16(const void* p){ const uint8_t* b=p; return (uint16_t)(b[0] | (b[1]<<8)); }
static uint32_t rd32(const void* p){ const uint8_t* b=p; return (uint32_t)(b[0] | (b[1]<<8) | (b[2]<<16) | (b[3]<<24)); }
static uint8_t*  rva(PEIMG* img, uint32_t v){ return img->map + v; }

/* ---- 載入 ---- */
static int load_pe32(const char* path, PEIMG* out){
  memset(out, 0, sizeof(*out));
  FILE* f = fopen(path, "rb");
  if(!f){ perror("fopen"); return -1; }
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  uint8_t* buf = (uint8_t*)malloc(sz);
  if(!buf){ fclose(f); return -1; }
  if(fread(buf,1,sz,f) != (size_t)sz){ fclose(f); free(buf); return -1; }
  fclose(f);

  if (sz < (long)sizeof(DOS_HDR)) { free(buf); return -1; }
  DOS_HDR* dos = (DOS_HDR*)buf;
  if (rd16(&dos->e_magic) != 0x5a4d) { free(buf); return -1; }

  uint32_t peoff = dos->e_lfanew;
  if (peoff + 4 + sizeof(COFF_HDR) + sizeof(OPT_HDR32) > (uint32_t)sz){ free(buf); return -1; }
  if (rd32(buf+peoff) != 0x00004550){ free(buf); return -1; }

  COFF_HDR*  coff = (COFF_HDR*)(buf + peoff + 4);
  OPT_HDR32* opt  = (OPT_HDR32*)((uint8_t*)coff + sizeof(COFF_HDR));
  if (opt->Magic != 0x10b){ free(buf); return -1; }

  uintptr_t map_sz = (opt->SizeOfImage + PAGE_SIZE-1) & ~(PAGE_SIZE-1);
  uint8_t* map = mmap(NULL, map_sz, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if (map == MAP_FAILED){ free(buf); return -1; }

  memcpy(map, buf, opt->SizeOfHeaders);

  SEC_HDR* sec = (SEC_HDR*)((uint8_t*)opt + coff->SizeOfOptionalHeader);
  for (uint16_t i=0;i<coff->NumberOfSections;++i){
    if (sec[i].SizeOfRawData && sec[i].PointerToRawData &&
        sec[i].PointerToRawData + sec[i].SizeOfRawData <= (uint32_t)sz){
      memcpy(map + sec[i].VirtualAddress, buf + sec[i].PointerToRawData, sec[i].SizeOfRawData);
    }
  }

  out->map         = map;
  out->prefer_base = opt->ImageBase;
  out->delta       = (int32_t)((intptr_t)map - (intptr_t)opt->ImageBase);
  out->entry_rva   = opt->AddressOfEntryPoint;
  out->import_rva  = opt->DataDirectory[1].RVA;
  out->import_size = opt->DataDirectory[1].Size;
  out->reloc_rva   = opt->DataDirectory[5].RVA;
  out->reloc_size  = opt->DataDirectory[5].Size;
  out->path        = path;

  LOGF("mapped '%s': pref=0x%08x map=%p delta=%d (0x%08x)",
       path, out->prefer_base, (void*)map, out->delta, (uint32_t)out->delta);
  free(buf);
  return 0;
}

/* ---- 重定位（HIGHLOW） ---- */
static void apply_relocs(PEIMG* img){
  if (!img->reloc_rva || !img->reloc_size || !img->delta) return;

  uint8_t* p = rva(img, img->reloc_rva);
  uint8_t* end = p + img->reloc_size;
  int patched=0, blocks=0;

  while (p + 8 <= end){
    uint32_t page_rva  = rd32(p+0);
    uint32_t block_sz  = rd32(p+4);
    p += 8;
    uint32_t cnt = (block_sz - 8) / 2;
    for (uint32_t i=0;i<cnt;++i){
      uint16_t e = rd16(p + i*2);
      uint16_t type = e >> 12;
      uint16_t off  = e & 0xfff;
      if (type == 3 /*HIGHLOW*/){
        uint32_t* patch = (uint32_t*)(img->map + page_rva + off);
        *patch += (uint32_t)img->delta;
        ++patched;
      }
    }
    p += cnt*2;
    ++blocks;
  }
  LOGF("reloc blocks=%d, HIGHLOW patched=%d", blocks, patched);
}

/* ---- 匯入解析（改為使用 nt_get_hooks()） ---- */
static void* lookup_import(const char* dll, const char* name){
  const struct Hook* hk = nt_get_hooks();
  for (; hk && hk->dll; ++hk){
    if (strcasecmp(hk->dll, dll)==0 && strcmp(hk->name, name)==0){
      return hk->fn;
    }
  }
  return NULL;
}

static void bind_imports(PEIMG* img){
  if (!img->import_rva || !img->import_size) return;

  IMAGE_IMPORT_DESCRIPTOR* desc =
      (IMAGE_IMPORT_DESCRIPTOR*)rva(img, img->import_rva);

  for (; desc->Name; ++desc){
    const char* dll = (const char*)rva(img, desc->Name);
    LOGF("bind: %s", dll);

    uint32_t* IAT = (uint32_t*)rva(img, desc->FirstThunk);
    uint32_t* INT = desc->OriginalFirstThunk
                  ? (uint32_t*)rva(img, desc->OriginalFirstThunk)
                  : IAT;
    for (; *IAT; ++IAT, ++INT){
      uint32_t hint_name_rva = *INT;
      void* fn = NULL;
      if (!(hint_name_rva & 0x80000000u)){
        const char* name = (const char*)rva(img, hint_name_rva + 2);
        fn = lookup_import(dll, name);
        if (!fn) LOGF("Unresolved import: %s!%s", dll, name);
        LOGF("    %-20s -> %p", name, fn);
      }
      *IAT = (uint32_t)(uintptr_t)fn;
    }
  }
}

/* ---- 執行 ---- */
static int run_pe32(const char* path){
  PEIMG img;
  if (load_pe32(path, &img) != 0) return 1;

  apply_relocs(&img);
  bind_imports(&img);

  if (!img.entry_rva){ LOGF("no entry"); return 1; }
  void (*entry_fn)(void) = (void(*)(void))(img.map + img.entry_rva);
  LOGF("entering entrypoint 0x%08x for %s", img.entry_rva, path);

  /* 設定 TEB（由 ntdll32/teb.c 提供） */
  extern void _nt_teb_setup_for_current(void);
  _nt_teb_setup_for_current();

  entry_fn();
  return 0;
}

int main(int argc, char** argv){
  if (argc < 2){
    fprintf(stderr, "usage: %s <pe32.exe> [args...]\n", argv[0]);
    return 2;
  }
  return run_pe32(argv[1]);
}