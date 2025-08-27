// winss/loader/pe_loader32.c
// Minimal PE32 loader for AwA-OS (WinSS) with proper .reloc HIGHLOW patching,
// robust IAT binding, and basic diagnostics.
// Build: part of AwA-OS CMake (m32). Depends on ntshim32.a (NT_HOOKS).

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

typedef struct {
  uint32_t Signature;       /* 'PE\0\0' */
} IMAGE_NT_HEADERS_SIG;

typedef struct {
  uint16_t Machine, NumberOfSections;
  uint32_t TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
  uint16_t SizeOfOptionalHeader, Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
  uint32_t VirtualAddress, Size;
} IMAGE_DATA_DIRECTORY;

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
  uint32_t   OriginalFirstThunk; /* RVA to IMAGE_THUNK_DATA (names) */
  uint32_t   TimeDateStamp;
  uint32_t   ForwarderChain;
  uint32_t   Name;               /* RVA to dll name */
  uint32_t   FirstThunk;         /* RVA to IAT (to write) */
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

/* Data directory indices */
#define IMAGE_DIRECTORY_ENTRY_IMPORT     1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC  5

/* relocation types (winnt.h) */
#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_REL_BASED_HIGHLOW  3

/* ---- logging ---- */
static int g_log = 0;
#define LOGF(...) do{ if(g_log){ fprintf(stderr,"[pe_loader32] " __VA_ARGS__); fputc('\n',stderr);} }while(0)

/* ---- external hooks ---- */
extern struct Hook NT_HOOKS[]; /* from ntshim32 */

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
    if (in[i]=='@'){ /* if suffix all digits -> cut */
      size_t k=i+1; int all=1;
      while(in[k]){ if(!isdigit((unsigned char)in[k])){ all=0; break; } ++k; }
      if (all) break;
    }
    out[j++] = in[i];
  }
  out[j]=0;
}

/* resolve import name to function pointer via NT_HOOKS */
static void* resolve_import(const char* dll, const char* name){
  /* try exact, then undecorated */
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

/* read whole file */
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
  /* best-effort: try get EIP from ucontext if available (glibc layout varies) */
  void* addr = si ? si->si_addr : NULL;
#if defined(__i386__)
  /* nothing portable for EIP; print nullptr */
  LOGF("SIGSEGV at %p", addr);
#else
  LOGF("SIGSEGV at %p", addr);
#endif
  _exit(139);
}

/* ---- main loader routine ---- */
static int run_pe32(const char* path, int argc, char** argv){
  size_t fsz=0; uint8_t* file = read_file(path,&fsz);
  if(!file){ fprintf(stderr,"[pe_loader32] cannot read file: %s\n", path); return 127; }

  IMAGE_DOS_HEADER* mz = (IMAGE_DOS_HEADER*)file;
  if (fsz < sizeof(*mz) || mz->e_magic != 0x5A4D /*MZ*/) { fprintf(stderr,"[pe_loader32] bad MZ\n"); free(file); return 127; }

  if ((size_t)mz->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > fsz){ fprintf(stderr,"[pe_loader32] bad e_lfanew\n"); free(file); return 127; }
  IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(file + mz->e_lfanew);
  IMAGE_NT_HEADERS_SIG* sig = (IMAGE_NT_HEADERS_SIG*)nt;
  if (sig->Signature != 0x00004550 /* 'PE\0\0' */){ fprintf(stderr,"[pe_loader32] bad PE sig\n"); free(file); return 127; }

  IMAGE_FILE_HEADER* fh = &nt->FileHeader;
  IMAGE_OPTIONAL_HEADER32* oh = &nt->OptionalHeader;
  IMAGE_SECTION_HEADER* sh = (IMAGE_SECTION_HEADER*)((uint8_t*)&nt->OptionalHeader + fh->SizeOfOptionalHeader);

  uint32_t imageSize = oh->SizeOfImage;
  uint32_t headersSz = oh->SizeOfHeaders;
  uint8_t* base = (uint8_t*)mmap(NULL, imageSize, PROT_READ|PROT_WRITE|PROT_EXEC,
                                 MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if (base == MAP_FAILED){ perror("[pe_loader32] mmap"); free(file); return 127; }

  /* copy headers */
  memcpy(base, file, headersSz);

  /* copy sections, zero bss tail */
  for (int i=0;i<fh->NumberOfSections;++i){
    uint32_t vsize = sh[i].Misc.VirtualSize;
    uint32_t vaddr = sh[i].VirtualAddress;
    uint32_t rawsz = sh[i].SizeOfRawData;
    uint32_t rawoff= sh[i].PointerToRawData;

    if (vsize==0) continue;
    if (vaddr + vsize > imageSize){ fprintf(stderr,"[pe_loader32] section overflow\n"); munmap(base,imageSize); free(file); return 127; }

    uint8_t* dst = base + vaddr;
    if (rawsz>0){
      if ((size_t)rawoff + rawsz > fsz){ fprintf(stderr,"[pe_loader32] raw overflow\n"); munmap(base,imageSize); free(file); return 127; }
      memcpy(dst, file + rawoff, rawsz);
    }
    if (vsize > rawsz){
      memset(dst + rawsz, 0, vsize - rawsz); /* <-- .bss zero */
    }
  }

  uintptr_t preferred = (uintptr_t)oh->ImageBase;
  uintptr_t mapped    = (uintptr_t)base;
  intptr_t  delta     = (intptr_t)(mapped - preferred);

  /* diagnostics */
  if (getenv("AWAOS_LOG")) g_log = 1;
  LOGF("mapped '%s': pref=0x%08lx map=0x%08lx delta=%ld (0x%08lx)",
       path, (unsigned long)preferred, (unsigned long)mapped,
       (long)delta, (unsigned long)delta);

  /* relocations */
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

        if (type == IMAGE_REL_BASED_HIGHLOW){
          *spot = (uint32_t)((uint32_t)(*spot) + (uint32_t)delta);
          ++patches;
        }else if (type == IMAGE_REL_BASED_ABSOLUTE){
          /* no-op */
        }else{
          LOGF("reloc: unsupported type %u at rva 0x%08x", (unsigned)type, (unsigned)(page+offset));
        }
      }
      off += br->SizeOfBlock;
    }
  }
  LOGF("reloc blocks=%zu, HIGHLOW patched=%zu", blocks, patches);

  /* import binding */
  uint32_t imp_rva  = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
  uint32_t imp_size = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
  if (imp_rva && imp_size){
    IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + imp_rva);
    for (; imp->Name; ++imp){
      const char* dll = (const char*)(base + imp->Name);
      if (!dll) break;

      /* Normalize DLL name (upper) */
      char dllnorm[64]; size_t j=0;
      for (size_t i=0; dll[i] && j+1<sizeof(dllnorm); ++i){ char c=dll[i]; dllnorm[j++]=(c>='a'&&c<='z')?(c-32):c; }
      dllnorm[j]=0;
      LOGF("bind: %s", dllnorm);

      uint32_t oft = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
      IMAGE_THUNK_DATA32* ntab = (IMAGE_THUNK_DATA32*)(base + oft);
      IMAGE_THUNK_DATA32* iat  = (IMAGE_THUNK_DATA32*)(base + imp->FirstThunk);

      for (; ntab->AddressOfData; ++ntab, ++iat){
        if (ntab->Ordinal & 0x80000000u){
          /* import by ordinal (not used in our tests) */
          LOGF("  import by ordinal: 0x%08x", (unsigned)(ntab->Ordinal & 0xFFFF));
          iat->Function = 0; /* not supported yet */
        }else{
          IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(base + ntab->AddressOfData);
          const char* name = (const char*)ibn->Name;
          void* fn = resolve_import(dllnorm, name);
          if (!fn){
            /* safety stub: return 0 to reduce instant crash; better是補齊 hook */
            iat->Function = (uint32_t)(uintptr_t)0;
          }else{
            iat->Function = (uint32_t)(uintptr_t)fn;
          }
          LOGF("    %-20s -> %p", name, (void*)(uintptr_t)iat->Function);
        }
      }
    }
  }

  /* prepare entrypoint */
  uint32_t ep_rva = oh->AddressOfEntryPoint;
  if (!ep_rva){ fprintf(stderr,"[pe_loader32] no entrypoint\n"); munmap(base,imageSize); free(file); return 127; }
  void (*entry)(void) = (void(*)(void))(base + ep_rva);

  LOGF("entering entrypoint 0x%08x for %s", ep_rva, path);

  /* set up segv handler for better report */
  struct sigaction sa; memset(&sa,0,sizeof(sa));
  sa.sa_sigaction = segv_handler; sa.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &sa, NULL);

  /* Provide command line to our NT shim (optional) */
  {
    char cmdbuf[256]; size_t k=0;
    for (int i=0;i<argc && k+2<sizeof(cmdbuf); ++i){
      const char* s = argv[i]; if (i) cmdbuf[k++]=' ';
      while(*s && k+1<sizeof(cmdbuf)) cmdbuf[k++]=*s++;
    }
    cmdbuf[k]=0;
    extern void nt_set_command_lineA(const char* s); /* from ntshim32.c */
    nt_set_command_lineA(cmdbuf);
  }

  /* jump! */
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