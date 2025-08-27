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
#include <signal.h>
#include <ucontext.h>
#include "../include/win/minwin.h"
#include "../include/nt/hooks.h"

__attribute__((weak)) void* NtCurrentTeb(void);
__attribute__((weak)) void nt_set_command_lineA(const char* s);

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

/* ---- SIGSEGV 診斷：印出 fault 位址與 EIP（i386） ---- */
static void segv_handler(int sig, siginfo_t* si, void* vctx){
  (void)sig;
  ucontext_t* ctx = (ucontext_t*)vctx;
#if defined(__i386__)
  void* eip = (void*)ctx->uc_mcontext.gregs[REG_EIP];
  fprintf(stderr, "[pe_loader32] SIGSEGV at %p (EIP=%p)\n", si->si_addr, eip);
#else
  fprintf(stderr, "[pe_loader32] SIGSEGV at %p\n", si->si_addr);
#endif
  _exit(139);
}
static void install_segv(void){
  struct sigaction sa; memset(&sa,0,sizeof(sa));
  sa.sa_sigaction = segv_handler; sa.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &sa, NULL);
}

#pragma pack(push,1)
typedef struct { uint16_t e_magic,e_cblp,e_cp,e_crlc,e_cparhdr,e_minalloc,e_maxalloc,e_ss,e_sp,e_csum,e_ip,e_cs,e_lfarlc,e_ovno,e_res[4],e_oemid,e_oeminfo,e_res2[10]; int32_t e_lfanew; } IMAGE_DOS_HEADER;
typedef struct { uint32_t VirtualAddress, Size; } IMAGE_DATA_DIRECTORY;
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_DIRECTORY_ENTRY_IMPORT     1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC  5
typedef struct { uint16_t Machine, NumberOfSections; uint32_t TimeDateStamp, PointerToSymbolTable, NumberOfSymbols; uint16_t SizeOfOptionalHeader, Characteristics; } IMAGE_FILE_HEADER;
typedef struct {
  uint16_t Magic; uint8_t MajorLinkerVersion, MinorLinkerVersion;
  uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint, BaseOfCode, BaseOfData;
  uint32_t ImageBase, SectionAlignment, FileAlignment;
  uint16_t MajorOSVersion, MinorOSVersion, MajorImageVersion, MinorImageVersion;
  uint16_t MajorSubsystemVersion, MinorSubsystemVersion;
  uint32_t Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
  uint16_t Subsystem, DllCharacteristics;
  uint32_t SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
  uint32_t LoaderFlags, NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32;
typedef struct { uint32_t Signature; IMAGE_FILE_HEADER FileHeader; IMAGE_OPTIONAL_HEADER32 OptionalHeader; } IMAGE_NT_HEADERS32;
typedef struct { uint8_t Name[8]; union { uint32_t PhysicalAddress; uint32_t VirtualSize; } Misc; uint32_t VirtualAddress, SizeOfRawData, PointerToRawData, PointerToRelocations, PointerToLinenumbers; uint16_t NumberOfRelocations, NumberOfLinenumbers; uint32_t Characteristics; } IMAGE_SECTION_HEADER;
typedef struct { uint32_t OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk; } IMAGE_IMPORT_DESCRIPTOR;
typedef struct { uint32_t u1; } IMAGE_THUNK_DATA32;
#define IMAGE_ORDINAL_FLAG32 0x80000000u
typedef struct { uint16_t Hint; char Name[1]; } IMAGE_IMPORT_BY_NAME;
typedef struct { uint32_t VirtualAddress, SizeOfBlock; } IMAGE_BASE_RELOCATION;
#pragma pack(pop)

extern struct Hook NT_HOOKS[];

static void* rva(void* base, uint32_t off){ return off ? (uint8_t*)base + off : NULL; }

static void undecorate(const char* in, char* out, size_t cap){
  size_t i=0,j=0; if (in[0]=='_') ++i;
  for(; in[i] && j+1<cap; ++i){
    if (in[i]=='@'){ size_t k=i+1; int all=1; while(in[k]){ if (in[k]<'0'||in[k]>'9'){ all=0; break; } ++k; } if(all) break; }
    out[j++]=in[i];
  }
  out[j]=0;
}

static void canon_dll(const char* in, char* out, size_t cap){
  size_t j=0; for(size_t i=0; in && in[i] && j+1<cap; ++i){ char c=in[i]; if(c>='A'&&c<='Z') c=(char)(c+32); out[j++]=c; }
  out[j]=0; size_t L=strlen(out); if(L>=4 && out[L-4]=='.'&&out[L-3]=='d'&&out[L-2]=='l'&&out[L-1]=='l') out[L-4]=0;
}

static void* resolve_import(const char* dll, const char* sym){
  char clean[128]; undecorate(sym, clean, sizeof(clean));
  for (struct Hook* h=NT_HOOKS; h && h->dll; ++h){ if (strcmp(h->name, clean)==0) return h->fn; }
  char want[64]; canon_dll(dll, want, sizeof(want));
  for (struct Hook* h=NT_HOOKS; h && h->dll; ++h){ char have[64]; canon_dll(h->dll, have, sizeof(have)); if (strcmp(have,want)==0 && strcmp(h->name,clean)==0) return h->fn; }
  return NULL;
}

static void* map_image_at(uint32_t base, size_t sz, int try_fixed){
  int flags = MAP_PRIVATE|MAP_ANON; void* p;
  if (try_fixed){
    p = mmap((void*)(uintptr_t)base, sz, PROT_READ|PROT_WRITE|PROT_EXEC, flags|MAP_FIXED_NOREPLACE, -1, 0);
    if (p != MAP_FAILED) return p;
  }
  p = mmap(NULL, sz, PROT_READ|PROT_WRITE|PROT_EXEC, flags, -1, 0);
  if (p == MAP_FAILED){ perror("mmap image"); _exit(127); }
  return p;
}

static void apply_relocs(void* image, IMAGE_NT_HEADERS32* nt, uint32_t actual_base){
  uint32_t pref = nt->OptionalHeader.ImageBase; if (actual_base == pref) return;
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
  if (!nt_set_command_lineA){ return; }
  if (argc <= 1){ nt_set_command_lineA(""); return; }
  size_t len=0; for(int i=1;i<argc;i++) len += strlen(argv[i]) + 1;
  if (!len){ nt_set_command_lineA(""); return; }
  char* buf=(char*)malloc(len); if(!buf){ nt_set_command_lineA(""); return; }
  buf[0]=0; for(int i=1;i<argc;i++){ strcat(buf,argv[i]); if(i+1<argc) strcat(buf," "); }
  nt_set_command_lineA(buf); free(buf);
}

int main(int argc, char** argv){
  install_segv();
  if (NtCurrentTeb) NtCurrentTeb();
  set_cmdline_from_argv(argc, argv);

  if (argc < 2){ fprintf(stderr,"usage: %s program.exe [args...]\n", argv[0]); return 2; }
  const char* path = argv[1];

  int fd = open(path, O_RDONLY); if (fd < 0){ perror("open exe"); return 127; }
  struct stat st; if (fstat(fd,&st) < 0){ perror("stat exe"); return 127; }
  uint8_t* file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0); if (file == MAP_FAILED){ perror("mmap exe"); return 127; }

  /* 解析 DOS/NT 頭 */
  typedef struct IMAGE_DOS_HEADER_s { uint16_t e_magic; uint16_t _r[29]; int32_t e_lfanew; } DOS;
  DOS* dos = (DOS*)file;
  IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(file + dos->e_lfanew);
  if (dos->e_magic != 0x5A4D || nt->Signature != 0x4550 || nt->OptionalHeader.Magic != 0x10B){
    fprintf(stderr,"Not a PE32\n"); return 1;
  }

  uint32_t image_base = nt->OptionalHeader.ImageBase;
  uint32_t size_image = nt->OptionalHeader.SizeOfImage;
  uint32_t size_hdrs  = nt->OptionalHeader.SizeOfHeaders;

  void* image = map_image_at(image_base, size_image, 1);
  memcpy(image, file, size_hdrs);

  IMAGE_SECTION_HEADER* sec = (IMAGE_SECTION_HEADER*)((uint8_t*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
  for (int i=0; i<nt->FileHeader.NumberOfSections; ++i){
    void* dst = (uint8_t*)image + sec[i].VirtualAddress;
    size_t vsz = sec[i].Misc.VirtualSize, rsz = sec[i].SizeOfRawData;
    if (rsz) memcpy(dst, file + sec[i].PointerToRawData, rsz);
    if (vsz > rsz) memset((uint8_t*)dst + rsz, 0, vsz - rsz);
  }

  if ((uint32_t)(uintptr_t)image != image_base){ apply_relocs(image, nt, (uint32_t)(uintptr_t)image); }

  /* IAT 解析 */
  IMAGE_DATA_DIRECTORY impdir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (impdir.VirtualAddress && impdir.Size){
    for (IMAGE_IMPORT_DESCRIPTOR* d = (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)image + impdir.VirtualAddress); d && d->Name; ++d){
      const char* dll = (const char*)((uint8_t*)image + d->Name); if (!dll) continue;
      IMAGE_THUNK_DATA32* oft = (IMAGE_THUNK_DATA32*)((uint8_t*)image + d->OriginalFirstThunk);
      IMAGE_THUNK_DATA32* ft  = (IMAGE_THUNK_DATA32*)((uint8_t*)image + d->FirstThunk);
      if (!oft) oft = ft;
      for (; oft && oft->u1; ++oft, ++ft){
        if (oft->u1 & IMAGE_ORDINAL_FLAG32){ fprintf(stderr,"Ordinal import not supported for %s\n", dll); return 1; }
        IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)((uint8_t*)image + oft->u1);
        const char* sym = (const char*)ibn->Name;
        void* fn = resolve_import(dll, sym);
        if (!fn){ fprintf(stderr,"Unresolved import %s!%s\n", dll, sym); return 1; }
        ft->u1 = (uint32_t)(uintptr_t)fn;
      }
    }
  }

  void* entry = (uint8_t*)image + nt->OptionalHeader.AddressOfEntryPoint;
  fprintf(stderr, "[pe_loader32] entering entrypoint %p for %s\n", entry, path);
  typedef void (WINAPI *entry_t)(void);
  ((entry_t)entry)();
  return 0;
}