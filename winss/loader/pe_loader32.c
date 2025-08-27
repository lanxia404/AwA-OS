// winss/loader/pe_loader32.c
// Minimal PE32 (i386) loader for AwA-OS Win32 personality.
// - Maps a PE32 image, applies base relocations, resolves imports via NT_HOOKS,
//   then transfers control to the image entrypoint.
// - Integrates with NT shim for TEB/TLS setup and GetCommandLineA.
//
// NOTE:
// * Do NOT implement pe32_spawn() here. That symbol is provided by the bridge
//   (compiled into libntshim32). Keeping it out avoids multiple-definition link errors.
// * This file expects the following headers to exist in the repo:
//     ../ntshim32/ntshim_api.h   (nt_set_command_lineA, nt_teb_setup_for_current or similar)
//     ../include/win/minwin.h    (Win32 basic typedefs)
//     ../include/nt/hooks.h      (extern struct Hook NT_HOOKS[] with kernel32 shims)

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>   // getenv, malloc, free
#include <string.h>   // memcpy, memset, strcmp, strcasecmp (if available)
#include <sys/mman.h> // mmap, PROT_*
#include <unistd.h>   // getpagesize
#include "../ntshim32/ntshim_api.h"
#include "../include/win/minwin.h"
#include "../include/nt/hooks.h"

// ---------- logging ----------
static int is_log(void) {
  static int inited = 0, val = 0;
  if (!inited) {
    inited = 1;
    const char* v = getenv("AWAOS_LOG");
    val = (v && *v) ? 1 : 0;
  }
  return val;
}
#define LOGF(...) do{ if(is_log()){ fprintf(stderr,"[pe_loader32] " __VA_ARGS__); fputc('\n',stderr);} }while(0)

// ---------- local helpers ----------
static size_t pagesz(void){ long p = sysconf(_SC_PAGESIZE); return (p>0)?(size_t)p:4096; }
static size_t round_up(size_t x, size_t a){ size_t m=a-1; return (x+a-1)&~m; }

static int str_ieq(const char* a, const char* b){
  if(!a||!b) return 0;
  for(;;){
    unsigned char ca=(unsigned char)*a++;
    unsigned char cb=(unsigned char)*b++;
    if(ca>='A'&&ca<='Z') ca += 'a'-'A';
    if(cb>='A'&&cb<='Z') cb += 'a'-'A';
    if(ca!=cb) return 0;
    if(ca==0) return 1;
  }
}

static char* join_args(int argc, char** argv){
  if(argc<=0) return NULL;
  size_t len=0;
  for(int i=0;i<argc;++i) len += strlen(argv[i]) + 1;
  char* out = (char*)malloc(len+1);
  if(!out) return NULL;
  out[0]=0;
  for(int i=0;i<argc;++i){
    strcat(out, argv[i]);
    if(i+1<argc) strcat(out, " ");
  }
  return out;
}

// ---------- PE structures (minimal) ----------
#pragma pack(push,1)
typedef struct {
  uint16_t e_magic;      // 'MZ' = 0x5A4D
  uint16_t e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc;
  uint16_t e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
  uint16_t e_res[4];
  uint16_t e_oemid, e_oeminfo;
  uint16_t e_res2[10];
  uint32_t e_lfanew;     // PE header offset
} IMAGE_DOS_HEADER;

typedef struct {
  uint32_t   VirtualAddress;
  uint32_t   Size;
} IMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_DIRECTORY_ENTRY_IMPORT     1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC  5

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
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32;

typedef struct {
  uint32_t Signature;     // 'PE\0\0' = 0x00004550
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
  union { uint32_t Characteristics; uint32_t OriginalFirstThunk; } u1;
  uint32_t TimeDateStamp;
  uint32_t ForwarderChain;
  uint32_t Name;
  uint32_t FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;

typedef struct {
  uint16_t Hint;
  char     Name[1];
} IMAGE_IMPORT_BY_NAME;

typedef struct {
  uint32_t VirtualAddress;
  uint32_t SizeOfBlock;
  // WORD TypeOffset[] follows
} IMAGE_BASE_RELOCATION;
#pragma pack(pop)

// ---------- hook table ----------
struct Hook { const char* dll; const char* name; void* fn; };
extern struct Hook NT_HOOKS[]; // declared in ../include/nt/hooks.h

static void* find_hook(const char* dll, const char* name){
  if(!dll || !name) return NULL;
  for (int i=0; NT_HOOKS[i].dll; ++i){
    if (str_ieq(NT_HOOKS[i].dll, dll) && strcmp(NT_HOOKS[i].name, name)==0)
      return NT_HOOKS[i].fn;
  }
  return NULL;
}

// ---------- PE mapping / relocation / import binding ----------
typedef struct {
  uint8_t*  map;        // mapped image base
  size_t    map_size;   // mmap size
  uint32_t  image_base; // preferred image base
  uint32_t  entry_rva;  // RVA
  uint32_t  import_rva; uint32_t import_size;
  uint32_t  reloc_rva;  uint32_t reloc_size;
} PE_IMAGE;

static int read_file_all(const char* path, uint8_t** out, size_t* outlen){
  FILE* f = fopen(path, "rb");
  if(!f) return 0;
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  if (sz <= 0){ fclose(f); return 0; }
  fseek(f, 0, SEEK_SET);
  uint8_t* buf = (uint8_t*)malloc((size_t)sz);
  if(!buf){ fclose(f); return 0; }
  if (fread(buf, 1, (size_t)sz, f) != (size_t)sz){ fclose(f); free(buf); return 0; }
  fclose(f);
  *out = buf; *outlen = (size_t)sz;
  return 1;
}

static int map_pe32_image(const char* path, PE_IMAGE* out){
  memset(out, 0, sizeof(*out));

  uint8_t* file = NULL; size_t flen = 0;
  if(!read_file_all(path, &file, &flen)) return 0;

  if (flen < sizeof(IMAGE_DOS_HEADER)) { free(file); return 0; }
  const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)file;
  if (dos->e_magic != 0x5A4D) { free(file); return 0; } // 'MZ'

  if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > flen) { free(file); return 0; }
  const IMAGE_NT_HEADERS32* nt = (const IMAGE_NT_HEADERS32*)(file + dos->e_lfanew);
  if (nt->Signature != 0x00004550) { free(file); return 0; } // 'PE\0\0'

  uint32_t size_of_image   = nt->OptionalHeader.SizeOfImage;
  uint32_t size_of_headers = nt->OptionalHeader.SizeOfHeaders;
  uint32_t image_base      = nt->OptionalHeader.ImageBase;
  uint16_t nsec            = nt->FileHeader.NumberOfSections;

  size_t msize = round_up(size_of_image, pagesz());
  uint8_t* map = (uint8_t*)mmap(NULL, msize, PROT_READ|PROT_WRITE|PROT_EXEC,
                                MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if (map == MAP_FAILED){ free(file); return 0; }
  memset(map, 0, msize);

  // copy headers
  size_t hcopy = size_of_headers < flen ? size_of_headers : flen;
  memcpy(map, file, hcopy);

  // copy sections
  const IMAGE_SECTION_HEADER* sec = (const IMAGE_SECTION_HEADER*)
      ( (const uint8_t*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader );
  for (uint16_t i=0; i<nsec; ++i){
    uint32_t va = sec[i].VirtualAddress;
    uint32_t vs = sec[i].Misc.VirtualSize;
    uint32_t rs = sec[i].SizeOfRawData;
    uint32_t pr = sec[i].PointerToRawData;

    uint32_t csz = rs;
    if (csz > vs && vs>0) csz = vs;
    if (pr && csz && ((size_t)pr + csz) <= flen){
      memcpy(map + va, file + pr, csz);
    }
  }

  out->map = map;
  out->map_size = msize;
  out->image_base = image_base;
  out->entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
  out->import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
  out->import_size= nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
  out->reloc_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
  out->reloc_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

  // log basic map info
  LOGF("mapped '%s': pref=0x%08x map=%p delta=%d (%p)",
      path, image_base, map, (int)((intptr_t)map - (intptr_t)image_base),
      (void*)((uintptr_t)map - (uintptr_t)image_base));

  free(file);
  return 1;
}

static int apply_relocs(PE_IMAGE* img){
  if (!img->reloc_rva || !img->reloc_size) return 1; // nothing to do
  uint8_t* base = img->map;
  intptr_t delta = (intptr_t)base - (intptr_t)img->image_base;

  uint32_t rva = img->reloc_rva;
  uint32_t end = rva + img->reloc_size;
  int blocks=0, patched=0;

  while (rva + sizeof(IMAGE_BASE_RELOCATION) <= end){
    IMAGE_BASE_RELOCATION* bl = (IMAGE_BASE_RELOCATION*)(base + rva);
    if (!bl->SizeOfBlock) break;
    uint32_t count = (bl->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
    uint16_t* entries = (uint16_t*)(bl + 1);

    for (uint32_t i=0;i<count;++i){
      uint16_t e = entries[i];
      uint16_t type = e >> 12;
      uint16_t off  = e & 0x0FFF;
      if (type == 3 /*HIGHLOW*/){
        uint32_t* p = (uint32_t*)(base + bl->VirtualAddress + off);
        *p = (uint32_t)((uintptr_t)(*p) + delta);
        ++patched;
      }
    }
    ++blocks;
    rva += bl->SizeOfBlock;
  }

  LOGF("reloc blocks=%d, HIGHLOW patched=%d", blocks, patched);
  return 1;
}

static int bind_imports(PE_IMAGE* img){
  if (!img->import_rva || !img->import_size) return 1;
  uint8_t* base = img->map;
  IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + img->import_rva);

  // count modules
  LOGF("bind: KERNEL32.DLL");

  for (; imp->Name; ++imp){
    const char* dll = (const char*)(base + imp->Name);
    if (!dll || !*dll) continue;

    // choose name thunk table
    uint32_t oft_rva = imp->u1.OriginalFirstThunk ? imp->u1.OriginalFirstThunk : imp->FirstThunk;
    uint32_t ft_rva  = imp->FirstThunk;
    if (!ft_rva) continue;

    uint32_t* oft = oft_rva ? (uint32_t*)(base + oft_rva) : NULL;
    uint32_t* ft  = (uint32_t*)(base + ft_rva);

    for (;;){
      uint32_t hintOrOrd = oft ? *oft : *ft;
      if (!hintOrOrd) break;

      void* addr = NULL;
      if (hintOrOrd & 0x80000000U){
        // import by ordinal (not handled)
        addr = NULL;
      } else {
        IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(base + hintOrOrd);
        const char* name = (const char*)ibn->Name;
        if (str_ieq(dll, "KERNEL32.DLL")){
          addr = find_hook("KERNEL32.DLL", name);
          if (is_log()){
            if (addr) {
              LOGF("    %-20s -> %p", name, addr);
            } else {
              LOGF("    %-20s -> (nil)", name);
            }
          }
        } else {
          // other DLLs not supported yet
          addr = NULL;
          if (is_log()){
            LOGF("Unresolved import: %s!%s", dll, name);
          }
        }
      }

      *ft = (uint32_t)(uintptr_t)addr;
      if (oft) ++oft;
      ++ft;
    }
  }
  return 1;
}

// ---------- run PE ----------
static int run_mapped_pe32(const char* path, PE_IMAGE* img){
  if (!apply_relocs(img)) return 0;
  if (!bind_imports(img)) return 0;

  uint32_t entry_rva = img->entry_rva;
  uint8_t* entry     = img->map + entry_rva;

  LOGF("entering entrypoint 0x%08x for %s", entry_rva, path);

  // 初始化當前執行緒的 TEB/TLS（如果你的 ntshim_api.h 有這個介面）。
  // 這裡我們不打印 selector/base，避免對內部實作做假設。
  // （若你需要日誌，可在 ntshim 的實作內自行列印）
  #if defined(nt_teb_setup_for_current) || defined(HAVE_NT_TEB_SETUP_FOR_CURRENT)
  nt_teb_setup_for_current();
  #endif

  // Entrypoint 約定：多數 Win32 console 程式會自行呼叫 ExitProcess。
  // 這裡以 "void (*) (void)" 直接跳入；若它返回，我們就回傳 0。
  typedef void (*entry_fn_t)(void);
  entry_fn_t ep = (entry_fn_t)(uintptr_t)entry;
  ep();
  return 0;
}

static int run_pe32(const char* path){
  PE_IMAGE img;
  if (!map_pe32_image(path, &img)) return 1;
  int rc = run_mapped_pe32(path, &img);
  // 讓被載入的程式自行 ExitProcess；若它返回，我們釋放映像。
  if (img.map && img.map_size) munmap(img.map, img.map_size);
  return rc;
}

// ---------- main ----------
int main(int argc, char** argv){
  if (argc < 2){
    fprintf(stderr, "Usage: %s <pe32.exe> [args...]\n", argv[0]);
    return 1;
  }

  const char* path = argv[1];
  char* args = join_args(argc-2, &argv[2]);
  // 設定給 Win32 GetCommandLineA 的視圖（由 ntshim32 提供）
  nt_set_command_lineA(path, args);
  if (args) free(args);

  return run_pe32(path);
}
