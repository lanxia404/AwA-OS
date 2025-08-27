// winss/loader/pe_loader32.c

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

#include "../ntshim32/ntshim_api.h"
#include "../include/win/minwin.h"

static int is_log(void){
  static int inited=0,val=0;
  if(!inited){ inited=1; val=(getenv("AWAOS_LOG") && *getenv("AWAOS_LOG"))?1:0; }
  return val;
}
#define LOGF(...) do{ if(is_log()){ fprintf(stderr,"[pe_loader32] " __VA_ARGS__); fputc('\n',stderr);} }while(0)

struct Hook { const char* dll; const char* name; void* fn; };
extern struct Hook NT_HOOKS[];

#define PE_SIGNATURE 0x00004550u

typedef struct { uint16_t e_magic; uint16_t e_cblp,e_cp,e_crlc,e_cparhdr,e_minalloc,e_maxalloc,e_ss,e_sp,e_csum,e_ip,e_cs,e_lfarlc,e_ovno,e_res[4],e_oemid,e_oeminfo,e_res2[10]; int32_t e_lfanew; } IMAGE_DOS_HEADER;
typedef struct { uint16_t Machine,NumberOfSections; uint32_t TimeDateStamp,PointerToSymbolTable,NumberOfSymbols; uint16_t SizeOfOptionalHeader,Characteristics; } IMAGE_FILE_HEADER;
typedef struct { uint32_t VirtualAddress, Size; } IMAGE_DATA_DIRECTORY;
typedef struct {
  uint16_t Magic; uint8_t MajorLinkerVersion,MinorLinkerVersion;
  uint32_t SizeOfCode,SizeOfInitializedData,SizeOfUninitializedData,AddressOfEntryPoint,BaseOfCode,BaseOfData,ImageBase,SectionAlignment,FileAlignment;
  uint16_t MajorOperatingSystemVersion,MinorOperatingSystemVersion,MajorImageVersion,MinorImageVersion,MajorSubsystemVersion,MinorSubsystemVersion;
  uint32_t Win32VersionValue,SizeOfImage,SizeOfHeaders,CheckSum;
  uint16_t Subsystem,DllCharacteristics;
  uint32_t SizeOfStackReserve,SizeOfStackCommit,SizeOfHeapReserve,SizeOfHeapCommit,LoaderFlags,NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32;
typedef struct { uint32_t Signature; IMAGE_FILE_HEADER FileHeader; IMAGE_OPTIONAL_HEADER32 OptionalHeader; } IMAGE_NT_HEADERS32;
typedef struct { uint8_t Name[8]; union { uint32_t PhysicalAddress; uint32_t VirtualSize; } Misc; uint32_t VirtualAddress,SizeOfRawData,PointerToRawData,PointerToRelocations,PointerToLinenumbers; uint16_t NumberOfRelocations,NumberOfLinenumbers; uint32_t Characteristics; } IMAGE_SECTION_HEADER;
typedef struct { uint32_t Characteristics,TimeDateStamp,ForwarderChain,Name,FirstThunk; } IMAGE_IMPORT_DESCRIPTOR;
typedef struct { uint16_t Hint; char Name[1]; } IMAGE_IMPORT_BY_NAME;
typedef struct { union { uint32_t ForwarderString,Function,Ordinal,AddressOfData; } u1; } IMAGE_THUNK_DATA32;
typedef struct { uint32_t VirtualAddress, SizeOfBlock; } IMAGE_BASE_RELOCATION;

static inline void* rva(void* base, uint32_t off){ return (void*)((uint8_t*)base + off); }

static int caseless_eq(const char* a, const char* b){
  if(!a||!b) return 0;
  while(*a && *b){ if(tolower((unsigned char)*a++)!=tolower((unsigned char)*b++)) return 0; }
  return *a==0 && *b==0;
}
static const void* find_hook(const char* dll, const char* name){
  for(struct Hook* h=NT_HOOKS; h && h->dll; ++h)
    if(caseless_eq(h->dll,dll) && strcmp(h->name,name)==0) return h->fn;
  return NULL;
}

static void bind_imports(void* image, IMAGE_NT_HEADERS32* nt){
  IMAGE_DATA_DIRECTORY imp = nt->OptionalHeader.DataDirectory[1];
  if(!imp.VirtualAddress || !imp.Size) return;
  IMAGE_IMPORT_DESCRIPTOR* d = (IMAGE_IMPORT_DESCRIPTOR*)rva(image, imp.VirtualAddress);
  for(; d->Name; ++d){
    const char* dll = (const char*)rva(image, d->Name);
    IMAGE_THUNK_DATA32* thunk = (IMAGE_THUNK_DATA32*)rva(image, d->FirstThunk);
    IMAGE_THUNK_DATA32* orig  = (IMAGE_THUNK_DATA32*)(d->FirstThunk? rva(image,d->FirstThunk):0);
    for(; thunk && thunk->u1.AddressOfData; ++thunk, orig=orig?orig+1:NULL){
      const char* sym = NULL;
      if(orig && !(orig->u1.Ordinal & 0x80000000u)){
        IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)rva(image, orig->u1.AddressOfData);
        sym = ibn->Name;
      }
      const void* fn = sym ? find_hook(dll, sym) : NULL;
      if(!fn){ LOGF("Unresolved import: %s!%s", dll?dll:"(null)", sym?sym:"(ordinal)"); thunk->u1.Function=0; }
      else   { thunk->u1.Function=(uint32_t)(uintptr_t)fn; LOGF("bind: %-22s -> %p", sym, fn); }
    }
  }
}

static void apply_relocs(void* image, IMAGE_NT_HEADERS32* nt, uintptr_t delta){
  if(delta==0) return;
  IMAGE_DATA_DIRECTORY rel = nt->OptionalHeader.DataDirectory[5];
  if(!rel.VirtualAddress || !rel.Size) return;
  uint8_t* base = (uint8_t*)image;
  uint32_t off=0;
  while(off<rel.Size){
    IMAGE_BASE_RELOCATION* blk = (IMAGE_BASE_RELOCATION*)((uint8_t*)image + rel.VirtualAddress + off);
    if(blk->SizeOfBlock < sizeof(*blk)) break;
    uint32_t count = (blk->SizeOfBlock - sizeof(*blk))/sizeof(uint16_t);
    uint16_t* ents = (uint16_t*)((uint8_t*)blk + sizeof(*blk));
    uint32_t pageRVA = blk->VirtualAddress;
    unsigned patched=0;
    for(uint32_t i=0;i<count;++i){
      uint16_t e = ents[i]; uint16_t type=(e>>12)&0xF, ofs=e&0x0FFF;
      if(type==3){ uint32_t* p=(uint32_t*)(base+pageRVA+ofs); *p += (uint32_t)delta; ++patched; }
    }
    LOGF("reloc blocks=1, HIGHLOW patched=%u", patched);
    off += blk->SizeOfBlock;
  }
}

static int run_pe32(const char* path, char* const* argv_unused){
  (void)argv_unused;
  int fd = open(path, O_RDONLY);
  if(fd<0){ perror("open"); return -1; }
  struct stat st; if(fstat(fd,&st)<0){ perror("fstat"); close(fd); return -1; }
  size_t fsz=(size_t)st.st_size;

  void* file = mmap(NULL, fsz, PROT_READ, MAP_PRIVATE, fd, 0); close(fd);
  if(file==MAP_FAILED){ perror("mmap-file"); return -1; }

  IMAGE_DOS_HEADER* mz = (IMAGE_DOS_HEADER*)file;
  if(mz->e_magic!=0x5A4D){ munmap(file,fsz); return -1; }
  IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)((uint8_t*)file + mz->e_lfanew);
  if(nt->Signature!=PE_SIGNATURE){ munmap(file,fsz); return -1; }

  size_t imgSize = nt->OptionalHeader.SizeOfImage;
  uint8_t* image = mmap(NULL, imgSize, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if(image==MAP_FAILED){ perror("mmap-image"); munmap(file,fsz); return -1; }

  memcpy(image, file, nt->OptionalHeader.SizeOfHeaders);
  IMAGE_SECTION_HEADER* sec = (IMAGE_SECTION_HEADER*)((uint8_t*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
  for(int i=0;i<nt->FileHeader.NumberOfSections;++i){
    if(sec[i].PointerToRawData && sec[i].SizeOfRawData){
      memcpy(image + sec[i].VirtualAddress,
             (uint8_t*)file + sec[i].PointerToRawData,
             sec[i].SizeOfRawData);
    }
  }

  uintptr_t prefer = nt->OptionalHeader.ImageBase;
  uintptr_t delta  = (uintptr_t)image - prefer;
  apply_relocs(image, nt, delta);
  bind_imports(image, nt);

  uint32_t epRVA = nt->OptionalHeader.AddressOfEntryPoint;
  void (*entry)(void) = (void(*)(void))(image + epRVA);

  LOGF("mapped '%s': pref=0x%08x map=%p delta=%ld (0x%lx)", path, (unsigned)prefer, image, (long)delta, (unsigned long)delta);
  LOGF("entering entrypoint 0x%08x for %s", epRVA, path);

  entry();
  munmap(file, fsz);
  return 0;
}

// pe32_spawn 供 CreateProcessA 回呼
static int _loader_spawn_impl(const char* path, const char* cmdline){
  (void)cmdline;
  return run_pe32(path, NULL)==0 ? 1 : 0;
}

int main(int argc, char** argv){
  nt_teb_setup_for_current();
  nt_set_spawn_impl(_loader_spawn_impl);
  if(argc>=2) nt_set_command_lineA(argv[1], NULL);
  else        nt_set_command_lineA("", NULL);

  if(argc<2){
    fprintf(stderr, "Usage: %s <pe32.exe> [args ...]\n", argv[0]);
    return 1;
  }
  return run_pe32(argv[1], (argc>2)? &argv[2] : NULL)==0 ? 0 : 1;
}
