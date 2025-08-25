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
#include <strings.h>
#include "../include/win/minwin.h"

#pragma pack(push,1)
typedef struct {
  uint16_t e_magic; uint16_t e_cblp; uint16_t e_cp; uint16_t e_crlc;
  uint16_t e_cparhdr; uint16_t e_minalloc; uint16_t e_maxalloc; uint16_t e_ss;
  uint16_t e_sp; uint16_t e_csum; uint16_t e_ip; uint16_t e_cs; uint16_t e_lfarlc;
  uint16_t e_ovno; uint16_t e_res[4]; uint16_t e_oemid; uint16_t e_oeminfo;
  uint16_t e_res2[10]; int32_t e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
  uint32_t Signature;
  struct {
    uint16_t Machine, NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable, NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
  } FileHeader;
  struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint, BaseOfCode, BaseOfData, ImageBase, SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOSVersion, MinorOSVersion, MajorImageVersion, MinorImageVersion;
    uint16_t MajorSubsystemVersion, MinorSubsystemVersion;
    uint32_t Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    uint16_t Subsystem, DllCharacteristics;
    uint32_t SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
    uint32_t LoaderFlags, NumberOfRvaAndSizes;
  } Opt;
} IMAGE_NT_HEADERS32;

typedef struct {
  uint8_t  Name[8];
  union { uint32_t PhysicalAddress; uint32_t VirtualSize; } Misc;
  uint32_t VirtualAddress, SizeOfRawData, PointerToRawData, PointerToRelocations,
           PointerToLinenumbers;
  uint16_t NumberOfRelocations, NumberOfLinenumbers;
  uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

typedef struct {
  uint32_t   OriginalFirstThunk;
  uint32_t   TimeDateStamp;
  uint32_t   ForwarderChain;
  uint32_t   Name;
  uint32_t   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;
#pragma pack(pop)

struct Hook { const char* dll; const char* name; void* fn; };
extern struct Hook NT_HOOKS[];

static void die(const char* s){ perror(s); _exit(127); }
static void* map_rw_x(size_t sz){
  void* p = mmap(NULL, sz, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
  if (p==MAP_FAILED) die("mmap");
  return p;
}
static void* rva(void* base, uint32_t off){ return (uint8_t*)base + off; }

static void* resolve_import(const char* dll, const char* sym){
  for (struct Hook* h=NT_HOOKS; h->dll; ++h){
    if (!strcasecmp(h->dll, dll) && strcmp(h->name, sym) == 0){
      return h->fn;
    }
  }
  return NULL;
}

int main(int argc, char** argv){
  if (argc<2){
    fprintf(stderr,"usage: %s program.exe [args...]\n", argv[0]);
    return 2;
  }
  const char* path = argv[1];
  int fd = open(path, O_RDONLY);
  if (fd<0) die("open");
  struct stat st; if (fstat(fd,&st)<0) die("stat");
  uint8_t* file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (file==MAP_FAILED) die("mmap file");

  IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)file;
  if (dos->e_magic != 0x5A4D){ fprintf(stderr,"Not MZ\n"); return 1; }
  IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(file + dos->e_lfanew);
  if (nt->Signature != 0x4550 || nt->Opt.Magic != 0x10B){
    fprintf(stderr,"Not PE32\n");
    return 1;
  }

  void* image = map_rw_x(nt->Opt.SizeOfImage);
  memcpy(image, file, nt->Opt.SizeOfHeaders);

  IMAGE_SECTION_HEADER* sec = (IMAGE_SECTION_HEADER*)((uint8_t*)&nt->Opt + nt->FileHeader.SizeOfOptionalHeader);
  for (int i=0; i<nt->FileHeader.NumberOfSections; i++){
    void* dst = rva(image, sec[i].VirtualAddress);
    if (sec[i].SizeOfRawData){
      memcpy(dst, file + sec[i].PointerToRawData, sec[i].SizeOfRawData);
    }
  }

  IMAGE_IMPORT_DESCRIPTOR* iid = NULL;
  for (uint32_t off=0; off < nt->Opt.SizeOfImage - sizeof(IMAGE_IMPORT_DESCRIPTOR); off+=4){
    IMAGE_IMPORT_DESCRIPTOR* tryi = (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)image + off);
    if (tryi->Name && tryi->FirstThunk && tryi->OriginalFirstThunk && tryi->TimeDateStamp==0){
      const char* name = (const char*)rva(image, tryi->Name);
      if (name && strstr(name, ".DLL")){
        iid = tryi;
        break;
      }
    }
  }
  if (iid){
    for (; iid->Name; iid++){
      const char* dll = (const char*)rva(image, iid->Name);
      uint32_t* oft = (uint32_t*)rva(image, iid->OriginalFirstThunk);
      uint32_t* ft  = (uint32_t*)rva(image, iid->FirstThunk);
      for (; *oft; oft++, ft++){
        uint32_t hintname_rva = *oft;
        const char* name = (const char*)rva(image, hintname_rva + 2);
        void* p = resolve_import(dll, name);
        if (!p){
          fprintf(stderr,"Unresolved import %s!%s\n", dll, name);
          return 1;
        }
        *ft = (uint32_t)(uintptr_t)p;
      }
    }
  }

  typedef void (WINAPI *entry_t)(void);
  entry_t entry = (entry_t)rva(image, nt->Opt.AddressOfEntryPoint);
  entry();
  return 0;
}
