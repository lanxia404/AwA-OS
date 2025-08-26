# AwA-OS

以 **Arch Linux** 為基底，嘗試實作可原生執行 **Windows 應用（Win32/NT Personality，先從 32 位開始）** 與 **Android（容器化）** 的 Linux 作業系統原型。  
目前聚焦：**Route A — NT/Win32 Personality（32-bit 先行）**，提供最小可用的 **PE32 載入器** 與 **KERNEL32 API shim**，並附一個可互動的 `cmdlite.exe`（支援 `run`）。

![build](https://github.com/lanxia404/AwA-OS/actions/workflows/build.yml/badge.svg)

- 專案名：**AwA-OS**
- 授權：**GPL v3**
- 目前狀態：PoC（PE32 載入、IAT 依名稱修補、`HIGHLOW` 重定位；KERNEL32 部分 API；`cmdlite.exe` 可互動與執行其他 EXE）

---

## 目錄結構（精簡）

- `winss/loader/pe_loader32.c`：PE32 載入器（映射、IAT 解析、`HIGHLOW` 重定位、跳入入口前設定命令列）
- `winss/ntshim32/ntshim32.c`：最小 **KERNEL32** shim（`GetStdHandle/ReadFile/WriteFile/ExitProcess`、`CreateProcessA/W`、`WaitForSingleObject`、`GetExitCodeProcess`、`CloseHandle`、`GetCommandLineA/W`）
- `winss/include/win/minwin.h`：簡化型別/常數與結構（`DWORD/HANDLE/WINAPI`、`STARTUPINFOA/W`、`PROCESS_INFORMATION` 等）
- `tests/win32-hello/hello.c`：無 CRT 的 Win32 範例（只用 KERNEL32）
- `tests/win32-cmdlite/cmdlite.c`：互動殼層（支援 `help / echo / run <exe> [args...] / exit`）
- `packaging/arch/binfmt/pe.conf`：binfmt 規則（讓 `.exe` 直接可執行）
- `packaging/arch/awaos-pe-loader/PKGBUILD`：Arch 包裝雛形
- `.github/workflows/build.yml`：CI（Arch 容器建置）

---

## 系統需求（Arch x86_64）

1. 啟用 multilib（若已啟用可略）
```bash
sudo nano /etc/pacman.conf
#取消以下段落註解
[multilib]
Include = /etc/pacman.d/mirrorlist
sudo pacman -Syu
```

2. 安裝建置與 32 位相依（關鍵）

```bash
sudo pacman -S --needed base-devel cmake ninja gcc-multilib lib32-glibc lib32-gcc-libs mingw-w64-gcc
```

> pe_loader32 是 32 位 ELF；在 x86_64 Arch 執行它需要 lib32-glibc 與 lib32-gcc-libs。

---

建置

```bash
git clone https://github.com/lanxia404/AwA-OS.git
cd AwA-OS
mkdir -p build && cd build
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr ..
ninja
```

快速檢查：

```bash
file winss/loader/pe_loader32
ldd  winss/loader/pe_loader32
```

---

安裝與註冊 binfmt

> 目的：把 loader 安裝到 /usr/lib/awaos/pe_loader32，並讓 .exe 在 shell 直接可執行。


```bash
# 安裝（會安到 /usr/lib/awaos/pe_loader32）
sudo cmake --install .

# 安裝 binfmt 規則並啟用
sudo install -Dm644 ../packaging/arch/binfmt/pe.conf /etc/binfmt.d/pe.conf
sudo systemctl restart systemd-binfmt

# 驗證
cat /proc/sys/fs/binfmt_misc/status          # 應含 enabled
ls /proc/sys/fs/binfmt_misc/ | grep pe32ex
sudo cat /proc/sys/fs/binfmt_misc/pe32ex     # 路徑應指向 /usr/lib/awaos/pe_loader32

# 若未掛載 binfmt：
# sudo mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
```

---

測試（hello 與 cmdlite）

1) 編譯並執行 hello.exe（無 CRT）

```bash
cd ../tests/win32-hello
i686-w64-mingw32-gcc hello.c -s -o hello.exe \
  -ffreestanding -fno-asynchronous-unwind-tables \
  -nostdlib -Wl,--entry=_main@0 -Wl,--subsystem,console -lkernel32
file hello.exe   # 應為 PE32 console
```

執行（擇一）：

```bash
/usr/lib/awaos/pe_loader32 ./hello.exe   # 直接呼叫 loader
# 或（已註冊 binfmt）
./hello.exe
```

2) 互動殼層 cmdlite.exe（含 run）

```bash
cd ../win32-cmdlite
i686-w64-mingw32-gcc cmdlite.c -s -o cmdlite.exe \
  -ffreestanding -fno-asynchronous-unwind-tables \
  -nostdlib -Wl,--entry=_main@0 -Wl,--subsystem,console -lkernel32

# 執行
/usr/lib/awaos/pe_loader32 ./cmdlite.exe
# 範例互動：
# A> help
# A> echo hello
# A> run ../win32-hello/hello.exe arg1 arg2
# exit code: 0
# A> exit
```

---

已知限制 / 待辦

目前只支援 PE32（i386）；尚未支援 PE32+（x64）。

IAT 僅支援名稱匯入；不支援序號匯入與延遲載入。

未實作 PEB/TEB/TLS/SEH、線程、更多同步原語；USER32/GDI32/NtDll 也未覆蓋。

CreateProcess* 的命令列解析（引號/跳脫）是簡化版；lpEnvironment/Handle 轉遞等旗標多忽略。

未實作 DLL 載入鏈（LoadLibrary/GetProcAddress）。



---

路線圖（精簡）

Win32 Personality：覆蓋更多 KERNEL32/NTDLL API → 加入 Thread/同步/PEB/TEB/TLS/SEH → x64

Loader 強化：更完整的重定位/保護屬性，支援 Ordinal Imports、延遲載入與 DLL 依賴

Android 容器：Waydroid/Anbox 安裝腳本與啟動服務

自動化測試：CI 交叉編譯測例 → 以 loader 執行並驗證輸出/退出碼



---

授權

本專案以 GPL v3 授權釋出。詳見 LICENSE。
