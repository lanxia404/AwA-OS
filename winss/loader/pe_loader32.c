// winss/loader/pe_loader32.c
// Tiny PE32 loader for AwA-OS (i386)
// Logs early failures as well, so CI can capture root cause.
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../include/win/minwin.h"      // basic Win types/macros for tests
#include "../ntshim32/ntshim_api.h"     // Nt shim API (teb/tls/thread/err)
#include "../include/nt/hooks.h"        // Hook entry table decl
#include <stdlib.h>
#include "../ntdll32/teb_tls.h"      // 改用 nt_teb_setup_for_current 聲明

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

static int is_log(void){
  static int inited=0, val=0;
  if(!inited){ inited=1; val = (getenv("AWAOS_LOG")!=NULL); }
  return val;
}
#define LOGF(...) do{ if(is_log()){ fprintf(stderr,"[pe_loader32] " __VA_ARGS__); fputc('\n',stderr);} }while(0)
#define DIEF(rc, ...) do{ LOGF(__VA_ARGS__); return (rc); }while(0)

/* --- minimal PE structs (32-bit) --- */
#pragma pack(push,1)
typedef struct { uint16_t e_magic; uint16_t e_cblp; uint16_t e_cp; uint16_t e_crlc;
  uint16_t e_cparhdr; uint16_t e_minalloc; uint16_t e_maxalloc; uint16_t e_ss;
  uint16_t e_sp; uint16_t e_csum; uint16_t e_ip; uint16_t e_cs; uint16_t e_lfarlc;
  uint16_t e_ovno; uint16_t e_res[4]; uint16_t e_oemid; uint16_t e_oeminfo;
  uint16_t e_res2[10]; uint32_t e_lfanew; } DOS_HDR;

typedef struct { uint32_t sig; } NT_SIG;

typedef struct { uint16_t Machine, NumberOfSections;
  uint32_t TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
  uint16_t SizeOfOptionalHeader, Characteristics; } COFF_HDR;

typedef struct {
  uint16_t Magic; uint8_t MajorLinkerVersion, MinorLinkerVersion;
  uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint, BaseOfCode, BaseOfData, ImageBase;
  uint32_t SectionAlignment, FileAlignment;
  uint16_t MajorOSVersion, MinorOSVersion, MajorImageVersion, MinorImageVersion;
  uint16_t MajorSubsystemVersion, MinorSubsystemVersion;
  uint32_t Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
  uint16_t Subsystem, DllCharacteristics;
  uint32_t SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
  uint32_t LoaderFlags, NumberOfRvaAndSizes;
  uint32_t DataDirectory[16*2]; /* RVA, Size x16 */
} OPT_HDR32;

typedef struct { char Name[8]; uint32_t VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData;
  uint32_t PointerToRelocations, PointerToLinenumbers; uint16_t NumberOfRelocations, NumberOfLinenumbers; uint32_t Characteristics; } SEC_HDR;
#pragma pack(pop)

/* from nshim side */
extern struct Hook NT_HOOKS[];

/* map+reloc+bind minimal */
static int load_pe32(const char* path, void** entry_out){
  int fd = open(path, O_RDONLY);
  if(fd<0) DIEF(1, "open('%s') failed: %s", path, strerror(errno));

  struct stat st; if(fstat(fd,&st)<0){ int e=errno; close(fd); DIEF(2,"fstat failed: %s",strerror(e)); }
  void* file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if(file==MAP_FAILED){ int e=errno; close(fd); DIEF(3, "mmap file failed: %s", strerror(e)); }

  const uint8_t* p = (const uint8_t*)file;
  const DOS_HDR* dos = (const DOS_HDR*)p;
  if(dos->e_magic != 0x5A4D){ munmap(file, st.st_size); close(fd); DIEF(4,"not MZ"); }
  const NT_SIG* sig = (const NT_SIG*)(p + dos->e_lfanew);
  if(sig->sig != 0x00004550){ munmap(file, st.st_size); close(fd); DIEF(5,"not PE"); }

  const COFF_HDR* coff = (const COFF_HDR*)(sig+1);
  const OPT_HDR32* opt = (const OPT_HDR32*)(coff+1);
  if(opt->Magic != 0x10b){ munmap(file, st.st_size); close(fd); DIEF(6,"not PE32"); }

  /* allocate image */
  size_t imgsz = opt->SizeOfImage;
  void* map = mmap(NULL, imgsz, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if(map==MAP_FAILED){ int e=errno; munmap(file, st.st_size); close(fd); DIEF(7,"mmap image failed: %s",strerror(e)); }

  /* copy headers */
  memcpy(map, p, opt->SizeOfHeaders);

  /* sections */
  const SEC_HDR* sec = (const SEC_HDR*)((const uint8_t*)opt + coff->SizeOfOptionalHeader);
  for(int i=0;i<coff->NumberOfSections;++i){
    if(sec[i].SizeOfRawData && sec[i].PointerToRawData){
      uint8_t* dst = (uint8_t*)map + sec[i].VirtualAddress;
      const uint8_t* src = p + sec[i].PointerToRawData;
      size_t n = sec[i].SizeOfRawData;
      if((size_t)((uint8_t*)dst-(uint8_t*)map)+n > imgsz){
        munmap(map,imgsz); munmap(file,st.st_size); close(fd); DIEF(8,"section OOB");
      }
      memcpy(dst, src, n);
    }
  }

  /* reloc directory (VERY tiny: HIGHLOW only) */
  uint32_t reloc_rva = opt->DataDirectory[5*2+0], reloc_sz = opt->DataDirectory[5*2+1];
  intptr_t delta = (intptr_t)((uint8_t*)map - (uint8_t*)(uintptr_t)opt->ImageBase);
  if(delta && reloc_rva && reloc_sz){
    const uint8_t* rp = (const uint8_t*)map + reloc_rva;
    const uint8_t* rEnd = rp + reloc_sz;
    while(rp < rEnd){
      uint32_t page   = *(uint32_t*)rp;    rp+=4;
      uint32_t size   = *(uint32_t*)rp;    rp+=4;
      uint32_t count  = (size-8)/2;
      for(uint32_t k=0;k<count;++k){
        uint16_t e = *(uint16_t*)rp; rp+=2;
        uint16_t type = e>>12, off = e & 0x0fff;
        if(type==3){ /* HIGHLOW */
          uint32_t* patch = (uint32_t*)((uint8_t*)map + page + off);
          *patch += (uint32_t)delta;
        }
      }
    }
  }

  /* import directory: name-based hook */
  uint32_t imp_rva = opt->DataDirectory[1*2+0], imp_sz = opt->DataDirectory[1*2+1];
  if(imp_rva && imp_sz){
    typedef struct { uint32_t OrigFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk; } IDESC;
    IDESC* id = (IDESC*)((uint8_t*)map + imp_rva);
    for(; id->Name; ++id){
      const char* dllname = (const char*)map + id->Name;
      uint32_t* thunk = (uint32_t*)((uint8_t*)map + (id->OrigFirstThunk? id->OrigFirstThunk : id->FirstThunk));
      uint32_t* ft    = (uint32_t*)((uint8_t*)map + id->FirstThunk);
      if(is_log()) LOGF("bind: %s", dllname);
      for(; *thunk; ++thunk, ++ft){
        const char* sym = (const char*)((uint8_t*)map + (*thunk + 2)); // skip hint
        void* target = NULL;
        for(struct Hook* h = NT_HOOKS; h && h->dll; ++h){
          if(strcasecmp(h->dll, dllname)==0 && strcmp(h->name, sym)==0){ target = h->fn; break; }
        }
        if(!target){
          if(is_log()) LOGF("Unresolved import: %s!%s", dllname, sym);
          *ft = 0; /* leave NULL -> 若呼叫會觸發崩潰，便於定位 */
        }else{
          *ft = (uint32_t)(uintptr_t)target;
          if(is_log()) LOGF("    %-20s -> %p", sym, target);
        }
      }
    }
  }

  munmap((void*)file, st.st_size);
  close(fd);

  *entry_out = (uint8_t*)map + opt->AddressOfEntryPoint;
  if(is_log()){
    LOGF("mapped '%s': pref=0x%08x map=%p delta=%td", path, opt->ImageBase, map, delta);
    LOGF("entering entrypoint 0x%08x for %s", opt->AddressOfEntryPoint, path);
  }
  return 0;
}

static int run_pe32(const char* path, char* const* argv){
  /* 將命令列字串傳入 NT shim，讓 GetCommandLineA 可用 */
  nt_set_command_lineA(path, argv);

  void* entry = NULL;
  int rc = load_pe32(path, &entry);
  if(rc) return rc;

  /* 為目前執行緒建好 TEB */
  _nt_teb_setup_for_current();

  /* 直接 jump-to-entry（cdecl） */
  void (*entry_fn)(void) = (void(*)(void))entry;
  entry_fn();
  return 0;
}

int main(int argc, char** argv){
  if(is_log()){
    LOGF("start argc=%d", argc);
    for(int i=0;i<argc;++i) LOGF("argv[%d]='%s'", i, argv[i]);
  }
  if(argc < 2) DIEF(64, "usage: pe_loader32 <pe32.exe> [args]");

  const char* exe = argv[1];

  /* 存在性檢查 + 可讀取檢查 */
  if(access(exe, R_OK) != 0){
    DIEF(66, "access('%s') failed: %s", exe, strerror(errno));
  }

  return run_pe32(exe, &argv[1]);
}