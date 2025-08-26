
# AwA-OS

以 **Arch Linux** 為基底，嘗試實作可原生執行 **Windows 應用（Win32/NT Personality，先從 32 位開始）** 與 **Android（容器化）** 的 Linux 作業系統原型。  
目前聚焦：**Route A — NT/Win32 Personality（32-bit 先行）**，實作最小可用的 PE32 載入器與極簡 KERNEL32 API shim。

- 專案名：**AwA-OS**
- 授權：**GPL v3**
- 目前狀態：PoC（能載入簡單 PE32，支援 `GetStdHandle / WriteFile / ExitProcess` 等）

---

## 目錄結構（精簡）

- `winss/loader/pe_loader32.c`：PE32 載入器（映射、IAT 解析、基底重定位）
- `winss/ntshim32/ntshim32.c`：最小 KERNEL32 API stub（供載入器解 IAT）
- `winss/include/win/minwin.h`：簡化型別/常數（DWORD、HANDLE 等）
- `tests/win32-hello/hello.c`：無 CRT 的 Win32 範例程式（PE32）
- `packaging/arch/binfmt/pe.conf`：binfmt 規則（讓 `.exe` 直接可執行）
- `packaging/arch/awaos-pe-loader/PKGBUILD`：Arch 打包腳本（雛形）
- `.github/workflows/build.yml`：CI（Arch 容器建置）

---

## 系統需求（Arch x86_64）

1. 啟用 multilib（若已啟用可略過）
   ```bash
   sudo nano /etc/pacman.conf
   # 取消以下段落註解
   [multilib]
   Include = /etc/pacman.d/mirrorlist
   sudo pacman -Syu

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

> 目的：把 loader 安裝到 /usr/lib/awaos/pe_loader32，並讓 .exe 可直接執行。

```bash
# 安裝（會安到 /usr/lib/awaos/pe_loader32）
sudo cmake --install .

# 安裝 binfmt 規則並啟用
sudo install -Dm644 ../packaging/arch/binfmt/pe.conf /etc/binfmt.d/pe.conf
sudo systemctl restart systemd-binfmt

驗證：

cat /proc/sys/fs/binfmt_misc/status        # 應為 enabled
ls  /proc/sys/fs/binfmt_misc/ | grep pe32ex
sudo cat /proc/sys/fs/binfmt_misc/pe32ex   # 路徑應指向 /usr/lib/awaos/pe_loader32

> 若未掛載 binfmt：
sudo mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
```



---

測試：編譯並執行 32 位 Win32 範例

專案已附 tests/win32-hello/hello.c（無 CRT、WINAPI 進入點、只匯入 KERNEL32）。

編譯（PE32，無 CRT）：

cd ../tests/win32-hello
i686-w64-mingw32-gcc hello.c -s -o hello.exe \
  -ffreestanding -fno-asynchronous-unwind-tables \
  -nostdlib -Wl,--entry=_main@0 -Wl,--subsystem,console -lkernel32

file hello.exe    # 應為 PE32 console

執行（兩種方式擇一）：

# 直接呼叫 loader
/usr/lib/awaos/pe_loader32 ./hello.exe

# 若已註冊 binfmt，可直接：
./hello.exe

預期輸出：

Hello from PE32 via AwA-OS WinSS!


---

常見問題（Troubleshooting）

bash: ./hello.exe: cannot execute: required file not found

大多是 binfmt 指向的 loader 路徑不對 或 loader 缺 32 位相依。

檢查 /etc/binfmt.d/pe.conf、/usr/lib/awaos/pe_loader32 是否存在，並 sudo systemctl restart systemd-binfmt。

確認：sudo pacman -S --needed lib32-glibc lib32-gcc-libs。


直接跑 loader 顯示 No such file or directory

pe_loader32 本身缺 32 位相依：ldd /usr/lib/awaos/pe_loader32 檢查並補裝 lib32-*。


連結錯誤 undefined reference to '__main'（編譯 hello.exe）

無 CRT 串接時需自備空的 __main，範例檔已內建。


Unresolved import XXX!YYY

範例只匯入少量 KERNEL32 API；你的 EXE 匯入了尚未支援的 API。

先用範例的「無 CRT、只用 KERNEL32」寫法測通；再逐步擴充 ntshim32.c 的函式。


Segmentation fault

多半是 PE 沒做重定位或 IAT 解析不全。

目前載入器已實作 HIGHLOW 重定位與名稱匯入；若仍有問題請開 Issue 附 EXE 與輸出。




---

CI（GitHub Actions）

.github/workflows/build.yml 在 Arch 容器內建置：

- run: pacman -Syu --noconfirm base-devel cmake ninja gcc-multilib
- run: pacman -S --noconfirm lib32-glibc lib32-gcc-libs
- run: |
    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build


---

開發路線圖（精簡）

Win32 Personality（32 位 → 64 位）

擴充 KERNEL32 / NTDLL shim 覆蓋率

Android：容器化執行路徑（後續規劃）

打包與發行：優化 PKGBUILD / AUR、安裝腳本

測試：自動化測試樣例與覆蓋率



---

授權

本專案以 GPL v3 授權釋出。詳見 LICENSE。
