// winss/loader/pe_loader32.c
// Minimal PE32 loader for AwA-OS (WinSS) with proper reloc (HIGHLOW), robust IAT binding,
// basic diagnostics, and minimal 32-bit TEB/PEB + FS base setup for Windows-style TLS access.
//
// Build: part of AwA-OS (32-bit). Links with ntshim32.a.
//
// References:
// - TEB/TIB offsets (x86 FS): FS:[0x18] = self, FS:[0x30] = PEB, FS:[0x34] = LastError.
// - Linux i386 set_thread_area(2) to set FS base.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>

/* ---- minimal user_desc for set_thread_area (linux i386) ---- */
#ifndef __x86_64__
struct user_desc {
  unsigned int  entry_number;
  unsigned long base_addr;
  unsigned int  limit;
  unsigned int  seg_32bit:1;
  unsigned int  contents:2;
  unsigned int  read_exec_only:1;
  unsigned int  limit_in_pages:1;
  unsigned int  seg_not_present:1;
  unsigned int  useable:1;
  unsigned int  lm:1;
};
#ifndef SYS_set_thread_area
 #define SYS_set_thread_area 243
#endif
static int set_thread_area_compat(struct user_desc* u)
{
  return (int)syscall(SYS_set_thread_area, u);
}
#endif

#include "../include/win/minwin.h"
#include "../include/nt/hooks.h"

/* ---- PE structures (subset) ---- */
#pragma pack(push,1)
typedef struct {            /* DOS */
  uint16_t e_magic;         /* 'MZ' */
  uint16_t e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc;
  uint16_t e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
  uint16_t e_res[4];
  uint16_t e_oemid, e_oeminfo;
  uint16_t e_res2[10];
  int32_t  e_lfanew;        /* PE header offset */
} IMAGE_DOS_HEADER;

typedef struct { uint32_t Signature; } IMAGE_NT_HEADERS_SIG;

typedef struct {
  uint16_t Machine, NumberOfSections;
  uint32_t TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
  uint16_t SizeOfOptionalHeader, Characteristics;
} IMAGE_FILE_HEADER;

typedef struct { uint32_t VirtualAddress, Size; } IMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct { /* Optional Header 32 */
  uint16_t Magic;
  uint8_t  MajorLinkerVersion, MinorLinkerVersion;
  uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint, BaseOfCode, BaseOfData;
  uint32_t ImageBase;
  uint32_t SectionAlignment, FileAlignment;
  uint16_t MajorOperatingSystemVersion, MinorOperatingSystemVersion;
  uint16_t MajorImageVersion, MinorImageVersion;
  uint16_t MajorSubsystemVersion, MinorSubsystemVersion;
  uint32_t Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
  uint16_t Subsystem, DllCharacteristics;
  uint32_t SizeOfStackReserve, SizeOfStackCommit;
  uint32_t SizeOfHeapReserve, SizeOfHeapCommit;
  uint32_t LoaderFlags, NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32;

typedef struct {
  uint32_t Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32;

typedef struct {
  uint8_t  Name[8];
  union { uint32_t PhysicalAddress; uint32_t VirtualSize; } Misc;
  uint32_t VirtualAddress, SizeOfRawData, PointerToRawData;
  uint32_t PointerToRelocations, PointerToLinenumbers;
  uint16_t NumberOfRelocations, NumberOfLinenumbers;
  uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

/* Import */
typedef struct {
  uint32_t   OriginalFirstThunk;
  uint32_t   TimeDateStamp;
  uint32_t   ForwarderChain;
  uint32_t   Name;
  uint32_t   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;

typedef struct {
  uint16_t Hint;
  char     Name[1];
} IMAGE_IMPORT_BY_NAME;

typedef union {
  uint32_t ForwarderString;
  uint32_t Function;
  uint32_t Ordinal;
  uint32_t AddressOfData;
} IMAGE_THUNK_DATA32;

/* Reloc */
typedef struct {
  uint32_t VirtualAddress;
  uint32_t SizeOfBlock;
} IMAGE_BASE_RELOCATION;
#pragma pack(pop)

/* Data directories */
#define IMAGE_DIRECTORY_ENTRY_IMPORT     1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC  5

/* reloc types */
#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_REL_BASED_HIGHLOW  3

/* ---- logging ---- */
static int g_log = 0;
#define LOGF(...) do{ if(g_log){ fprintf(stderr,"[pe_loader32] " __VA_ARGS__); fputc('\n',stderr);} }while(0)

/* ---- external hooks ---- */
extern struct Hook NT_HOOKS[]; /* provided by ntshim32 */

/* ---- helpers ---- */
static int ieq(const char* a, const char* b){
  while(*a && *b){
    int ca = (*a>='A'&&*a<='Z')? *a+32 : (unsigned char)*a;
    int cb = (*b>='A'&&*b<='Z')? *b+32 : (unsigned char)*b;
    if (ca!=cb) return 0; ++a; ++b;
  }
  return *a==0 && *b==0;
}
static void undecorate(const char* in, char* out, size_t cap){
  size_t i=0,j=0;
  if (in[0]=='_') ++i;
  for (; in[i] && j+1<cap; ++i){
    if (in[i]=='@'){
      size_t k=i+1; int all=1;
      while(in[k]){ if(!isdigit((unsigned char)in[k])){ all=0; break; } ++k; }
      if (all) break;
    }
    out[j++] = in[i];
  }
  out[j]=0;
}
static void* resolve_import(const char* dll, const char* name){
  for (struct Hook* p=NT_HOOKS; p && p->dll; ++p){
    if (ieq(p->dll, dll) && strcmp(p->name, name)==0) return p->fn;
  }
  char clean[128]; undecorate(name, clean, sizeof(clean));
  for (struct Hook* p=NT_HOOKS; p && p->dll; ++p){
    if (ieq(p->dll, dll) && strcmp(p->name, clean)==0) return p->fn;
  }
  LOGF("Unresolved import: %s!%s", dll, name);
  return NULL;
}
static uint8_t* read_file(const char* path, size_t* outSz){
  int fd = open(path, O_RDONLY);
  if (fd<0) return NULL;
  struct stat st; if (fstat(fd,&st)<0){ close(fd); return NULL; }
  size_t sz = (size_t)st.st_size;
  uint8_t* buf = (uint8_t*)malloc(sz);
  if(!buf){ close(fd); return NULL; }
  size_t off=0;
  while(off<sz){
    ssize_t n = read(fd, buf+off, sz-off);
    if (n<=0){ free(buf); close(fd); return NULL; }
    off += (size_t)n;
  }
  close(fd);
  if (outSz) *outSz = sz;
  return buf;
}
static void segv_handler(int sig, siginfo_t* si, void* ctx){
  (void)sig; (void)ctx;
  void* addr = si ? si->si_addr : NULL;
  LOGF("SIGSEGV at %p", addr);
  _exit(139);
}

/* ---- minimal TEB/PEB setup for i386 ---- */
#ifndef __x86_64__
static void* g_teb32 = NULL;
static void* g_peb32 = NULL;

static int setup_teb_fs32(void){
  /* 4KB zero page for TEB, another for PEB (very minimal) */
  g_teb32 = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  g_peb32 = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if (g_teb32==MAP_FAILED || g_peb32==MAP_FAILED) return -1;

  /* Fill key TEB fields (x86 offsets): FS:[0x18]=Self, FS:[0x30]=PEB, FS:[0x34]=LastError(0) */
  *(uint32_t*)((uint8_t*)g_teb32 + 0x18) = (uint32_t)(uintptr_t)g_teb32;
  *(uint32_t*)((uint8_t*)g_teb32 + 0x30) = (uint32_t)(uintptr_t)g_peb32;
  *(uint32_t*)((uint8_t*)g_teb32 + 0x34) = 0;

  /* Set FS base to g_teb32 via set_thread_area */
  struct user_desc ud;
  memset(&ud, 0, sizeof(ud));
  ud.entry_number   = (unsigned)-1; /* ask kernel to pick */
  ud.base_addr      = (unsigned long)(uintptr_t)g_teb32;
  ud.limit          = 0xFFFFF;
  ud.seg_32bit      = 1;
  ud.read_exec_only = 0;
  ud.limit_in_pages = 1;
  ud.seg_not_present= 0;
  ud.useable        = 1;

  if (set_thread_area_compat(&ud) != 0) return -1;

  unsigned short sel = (unsigned short)((ud.entry_number << 3) | 0x3);
  /* load %fs = sel */
  __asm__ __volatile__("movw %0, %%fs" : : "r"(sel));

  LOGF("TEB set: fs selector=0x%hx base=%p", sel, g_teb32);
  return 0;
}
#else
static int setup_teb_fs32(void){ return 0; } /* not used on x86_64 */
#endif

/* ---- core load/reloc/bind/enter ---- */
static int run_pe32(const char* path, int argc, char** argv){
  size_t fsz=0; uint8_t* file = read_file(path,&fsz);
  if(!file){ fprintf(stderr,"[pe_loader32] cannot read file: %s\n", path); return 127; }

  IMAGE_DOS_HEADER* mz = (IMAGE_DOS_HEADER*)file;
  if (fsz < sizeof(*mz) || mz->e_magic != 0x5A4D){ fprintf(stderr,"[pe_loader32] bad MZ\n"); free(file); return 127; }
  if ((size_t)mz->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > fsz){ fprintf(stderr,"[pe_loader32] bad e_lfanew\n"); free(file); return 127; }

  IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(file + mz->e_lfanew);
  IMAGE_NT_HEADERS_SIG* sig = (IMAGE_NT_HEADERS_SIG*)nt;
  if (sig->Signature != 0x00004550){ fprintf(stderr,"[pe_loader32] bad PE sig\n"); free(file); return 127; }

  IMAGE_FILE_HEADER* fh = &nt->FileHeader;
  IMAGE_OPTIONAL_HEADER32* oh = &nt->OptionalHeader;
  IMAGE_SECTION_HEADER* sh = (IMAGE_SECTION_HEADER*)((uint8_t*)&nt->OptionalHeader + fh->SizeOfOptionalHeader);

  uint32_t imageSize = oh->SizeOfImage;
  uint32_t headersSz = oh->SizeOfHeaders;
  uint8_t* base = (uint8_t*)mmap(NULL, imageSize, PROT_READ|PROT_WRITE|PROT_EXEC,
                                 MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if (base == MAP_FAILED){ perror("[pe_loader32] mmap"); free(file); return 127; }

  memcpy(base, file, headersSz);

  for (int i=0;i<fh->NumberOfSections;++i){
    uint32_t vsize = sh[i].Misc.VirtualSize;
    uint32_t vaddr = sh[i].VirtualAddress;
    uint32_t rawsz = sh[i].SizeOfRawData;
    uint32_t rawoff= sh[i].PointerToRawData;
    if (vsize==0) continue;
    if (vaddr + vsize > imageSize){ fprintf(stderr,"[pe_loader32] section overflow\n"); munmap(base,imageSize); free(file); return 127; }

    uint8_t* dst = base + vaddr;
    if (rawsz){
      if ((size_t)rawoff + rawsz > fsz){ fprintf(stderr,"[pe_loader32] raw overflow\n"); munmap(base,imageSize); free(file); return 127; }
      memcpy(dst, file + rawoff, rawsz);
    }
    if (vsize > rawsz) memset(dst + rawsz, 0, vsize - rawsz);
  }

  uintptr_t preferred = (uintptr_t)oh->ImageBase;
  uintptr_t mapped    = (uintptr_t)base;
  intptr_t  delta     = (intptr_t)(mapped - preferred);

  if (getenv("AWAOS_LOG")) g_log = 1;
  LOGF("mapped '%s': pref=0x%08lx map=0x%08lx delta=%ld (0x%08lx)",
       path, (unsigned long)preferred, (unsigned long)mapped,
       (long)delta, (unsigned long)delta);

  /* reloc */
  uint32_t reloc_rva  = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
  uint32_t reloc_size = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
  size_t blocks=0, patches=0;
  if (delta!=0 && reloc_rva && reloc_size){
    uint32_t off = reloc_rva, end = reloc_rva + reloc_size;
    while (off + sizeof(IMAGE_BASE_RELOCATION) <= end){
      IMAGE_BASE_RELOCATION* br = (IMAGE_BASE_RELOCATION*)(base + off);
      if (br->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;
      uint32_t page = br->VirtualAddress;
      uint32_t cnt  = (br->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
      uint16_t* ent = (uint16_t*)(base + off + sizeof(IMAGE_BASE_RELOCATION));
      ++blocks;

      for (uint32_t i=0;i<cnt;++i){
        uint16_t e = ent[i];
        uint16_t type   = (e >> 12) & 0xF;
        uint16_t offset = (e & 0x0FFF);
        uint32_t* spot  = (uint32_t*)(base + page + offset);
        if ((uint8_t*)spot < base || (uint8_t*)spot+4 > base+imageSize) continue;
        if (type == IMAGE_REL_BASED_HIGHLOW){ *spot = (uint32_t)((uint32_t)(*spot) + (uint32_t)delta); ++patches; }
        else if (type == IMAGE_REL_BASED_ABSOLUTE){ /* no-op */ }
        else { LOGF("reloc: unsupported type %u at rva 0x%08x", (unsigned)type, (unsigned)(page+offset)); }
      }
      off += br->SizeOfBlock;
    }
  }
  LOGF("reloc blocks=%zu, HIGHLOW patched=%zu", blocks, patches);

  /* imports */
  uint32_t imp_rva  = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
  uint32_t imp_size = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
  if (imp_rva && imp_size){
    IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + imp_rva);
    for (; imp->Name; ++imp){
      const char* dll = (const char*)(base + imp->Name);
      if (!dll) break;
      char dllnorm[64]; size_t j=0;
      for (size_t i=0; dll[i] && j+1<sizeof(dllnorm); ++i){ char c=dll[i]; dllnorm[j++]=(c>='a'&&c<='z')?(c-32):c; }
      dllnorm[j]=0;
      LOGF("bind: %s", dllnorm);

      uint32_t oft = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
      IMAGE_THUNK_DATA32* ntab = (IMAGE_THUNK_DATA32*)(base + oft);
      IMAGE_THUNK_DATA32* iat  = (IMAGE_THUNK_DATA32*)(base + imp->FirstThunk);

      for (; ntab->AddressOfData; ++ntab, ++iat){
        if (ntab->Ordinal & 0x80000000u){
          LOGF("  import by ordinal: 0x%08x", (unsigned)(ntab->Ordinal & 0xFFFF));
          iat->Function = 0; /* not supported yet */
        }else{
          IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(base + ntab->AddressOfData);
          const char* name = (const char*)ibn->Name;
          void* fn = resolve_import(dllnorm, name);
          iat->Function = (uint32_t)(uintptr_t)(fn ? fn : 0);
          LOGF("    %-20s -> %p", name, (void*)(uintptr_t)iat->Function);
        }
      }
    }
  }

  /* entrypoint */
  uint32_t ep_rva = oh->AddressOfEntryPoint;
  if (!ep_rva){ fprintf(stderr,"[pe_loader32] no entrypoint\n"); munmap(base,imageSize); free(file); return 127; }
  void (*entry)(void) = (void(*)(void))(base + ep_rva);
  LOGF("entering entrypoint 0x%08x for %s", ep_rva, path);

  /* SIGSEGV diagnostics */
  struct sigaction sa; memset(&sa,0,sizeof(sa));
  sa.sa_sigaction = segv_handler; sa.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &sa, NULL);

#ifndef __x86_64__
  /* set up minimal TEB and FS for 32-bit before jumping */
  if (setup_teb_fs32()!=0){
    LOGF("warning: setup_teb_fs32 failed; PE may crash if it touches FS");
  }
#endif

  /* pass command line to NT shim (optional) */
  {
    char cmdbuf[256]; size_t k=0;
    for (int i=0;i<argc && k+2<sizeof(cmdbuf); ++i){
      const char* s = argv[i]; if (i) cmdbuf[k++]=' ';
      while(*s && k+1<sizeof(cmdbuf)) cmdbuf[k++]=*s++;
    }
    cmdbuf[k]=0;
    extern void nt_set_command_lineA(const char* s);
    nt_set_command_lineA(cmdbuf);
  }

  entry();

  munmap(base,imageSize);
  free(file);
  return 0;
}

int main(int argc, char** argv){
  if (getenv("AWAOS_LOG")) g_log = 1;
  if (argc < 2){
    fprintf(stderr,"Usage: pe_loader32 <pe.exe> [args...]\n");
    return 2;
  }
  return run_pe32(argv[1], argc-1, &argv[1]);
}
