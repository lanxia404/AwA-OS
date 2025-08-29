# AwA-OS

> 以 Arch Linux 為基底，目標是在 **Linux 原生**提供一個 Win32/NT 的 *personality*（先從 32-bit 開始），透過使用者空間（user‑space）的 **PE32 載入器**與 **最小 KERNEL32/NTDLL shim** 來執行 Windows 應用程式；同時規劃整合 **Android 容器（Waydroid）**。目前已能在 x86\_64 Arch Linux 上直接以 `binfmt_misc` 執行 `.exe`。

---

## 功能總覽（Highlights）

* **PE32 載入器（ELF 32-bit）**：映射區段、解析 IAT（名稱匯入）、套用 `HIGHLOW` 重定位、在跳入入口前設定命令列。
* **Win32/KERNEL32 Shim（最小可用）**：提供執行序/同步、基本 I/O 與程序 API 等核心能力，用以支援無 CRT 的範例程式以及互動殼層 `cmdlite.exe`。
* **系統整合**：提供 `systemd-binfmt` 規則，讓 `.exe` 在 shell 直接當作指令執行。
* **CI**：使用 GitHub Actions（Arch Linux 容器）建置。

> 註：Android（Waydroid）整合為後續路線項目；目前聚焦 Win32 Personality 與載入器。

---

## 目前進度（2025-08-29）

* **可執行範例**：`hello.exe`、`cmdlite.exe`、`tls_demo.exe`。
* **已通過測試的能力**：**TLS**、**執行緒**、**基本 I/O** 與 **程序 API**。
* **已掛鉤/實作之 API（節錄）**：

  * I/O 與程序：`WriteFile`、`ReadFile`、`GetStdHandle`、`CloseHandle`、`CreateProcessA`、`ExitProcess`、`GetStartupInfoA`、`WaitForSingleObject`、`GetExitCodeProcess`。
  * 執行緒：`CreateThread`、`ExitThread`、`Sleep`。
  * TLS：`TlsAlloc`、`TlsFree`、`TlsGetValue`、`TlsSetValue`。
  * 其他：`SetLastError`。
* **執行記錄**：將環境變數 `AWAOS_LOG=1` 設定為開啟以觀察詳細日誌。

> 若你從舊版 README 前來：上述幾項（如 TLS/執行緒）是近期新增並已在測試案例中驗證的部分。

---

## 專案結構（精簡）

* `winss/loader/pe_loader32.c`：PE32 載入器（映射、IAT 名稱匯入、`HIGHLOW` 重定位、命令列設定）。
* `winss/ntshim32/ntshim32.c`：最小 Win32/KERNEL32 shim（涵蓋 I/O/程序/執行緒/TLS 等基礎 API）。
* `winss/include/win/minwin.h`：Windows 基本型別、常數與結構（`DWORD`、`HANDLE`、`WINAPI`、`STARTUPINFOA/W`、`PROCESS_INFORMATION` ...）。
* `tests/win32-hello/hello.c`：無 CRT 的 Win32 範例（僅依賴 KERNEL32）。
* `tests/win32-cmdlite/cmdlite.c`：互動殼層（`help` / `echo` / `run <exe> [args...]` / `exit`）。
* `packaging/arch/binfmt/pe.conf`：`binfmt_misc` 規則（讓 `.exe` 直接可執行）。
* `packaging/arch/awaos-pe-loader/PKGBUILD`：Arch 套件雛形。
* `.github/workflows/`：CI 設定（Arch Linux 容器建置）。

---

## 系統需求（Arch Linux x86\_64）

1. 啟用 multilib（若已啟用可略）：

```bash
sudo nano /etc/pacman.conf
# 取消以下段落註解
[multilib]
Include = /etc/pacman.d/mirrorlist
sudo pacman -Syu
```

2. 安裝建置與 32 位相依（關鍵）：

```bash
sudo pacman -S --needed base-devel cmake ninja gcc-multilib lib32-glibc lib32-gcc-libs mingw-w64-gcc
```

> `pe_loader32` 為 32 位 ELF；在 x86\_64 Arch 執行需要 `lib32-glibc` 與 `lib32-gcc-libs`。

---

## 建置（Build）

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

## 安裝與註冊 `binfmt_misc`

目的：把 loader 安裝到 `/usr/lib/awaos/pe_loader32`，並讓 `.exe` 在 shell 直接可執行。

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

# 若未掛載 binfmt（選用）
# sudo mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
```

**移除（可選）**：

```bash
sudo rm -f /etc/binfmt.d/pe.conf
sudo systemctl restart systemd-binfmt
sudo rm -f /usr/lib/awaos/pe_loader32
```

---

## 測試與範例

### 1) `hello.exe`（無 CRT）

```bash
cd tests/win32-hello
i686-w64-mingw32-gcc hello.c -s -o hello.exe \
  -ffreestanding -fno-asynchronous-unwind-tables \
  -nostdlib -Wl,--entry=_main@0 -Wl,--subsystem,console -lkernel32
file hello.exe   # 應為 PE32 console

# 執行（擇一）
/usr/lib/awaos/pe_loader32 ./hello.exe   # 直接呼叫 loader
./hello.exe                               # 已註冊 binfmt 時
```

### 2) 互動殼層 `cmdlite.exe`

```bash
cd tests/win32-cmdlite
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

### 3) `tls_demo.exe`

> 用於驗證 TLS API（`TlsAlloc/TlsSetValue/TlsGetValue/TlsFree`）與多執行緒協作。若你在 `tests/` 目錄中找到 `tls_demo`，可直接照該子目錄內的說明建置；若無，以下為通用最小範例供自行建立：

```c
// tls_demo.c（最小示意）
#include <windows.h>
#include <stdio.h>
DWORD g_idx;
DWORD WINAPI worker(LPVOID p){
  TlsSetValue(g_idx, p);
  printf("tid=%lu tls=%s\n", GetCurrentThreadId(), (const char*)TlsGetValue(g_idx));
  return 0;
}
int _main(){
  g_idx = TlsAlloc();
  HANDLE t1 = CreateThread(NULL,0,worker,(LPVOID)"A",0,NULL);
  HANDLE t2 = CreateThread(NULL,0,worker,(LPVOID)"B",0,NULL);
  WaitForSingleObject(t1,INFINITE);
  WaitForSingleObject(t2,INFINITE);
  TlsFree(g_idx);
  return 0;
}
```

```bash
i686-w64-mingw32-gcc tls_demo.c -s -o tls_demo.exe \
  -ffreestanding -fno-asynchronous-unwind-tables \
  -nostdlib -Wl,--entry=_main@0 -Wl,--subsystem,console -lkernel32
/usr/lib/awaos/pe_loader32 ./tls_demo.exe
```

---

## 設定與除錯

* **詳細日誌**：在執行 loader 前匯出 `AWAOS_LOG=1` 以開啟更多輸出。

  ```bash
  export AWAOS_LOG=1
  /usr/lib/awaos/pe_loader32 ./your.exe
  ```
* **常見問題**：

  * `No such file or directory`：請確認 `binfmt_misc` 規則已啟用，或直接以 loader 路徑執行。
  * `Exec format error`：檢查 `hello.exe` 是否正確編譯為 **PE32（i386）** 主控台程式。
  * 連結錯誤：請確認 `-lkernel32` 與 `_main@0` 入口設定。

---

## 限制（Known Limitations）與路線圖（Roadmap）

**現況**

* 僅支援 **PE32（i386）**；尚未支援 **PE32+（x64）**。
* IAT 目前僅支援 **名稱匯入**；未支援 **序號匯入** 與 **延遲載入**。
* DLL 載入鏈（`LoadLibrary/GetProcAddress`）仍在規劃中。
* 一般 Win32 子系統（如 `USER32`/`GDI32`）尚屬未覆蓋或僅最低限度。

**規劃**

* 擴充 KERNEL32/NTDLL 覆蓋面，強化執行緒、同步、記憶體管理與例外（SEH）等。
* Loader 支援更完整的重定位/保護屬性、Ordinal Imports、Delay-Load 與 DLL 依賴。
* x64（PE32+）支援。
* 整合 Waydroid 的 Android 容器腳本與服務。
* 加入自動化測試：交叉編譯測例 → 透過 loader 執行驗證輸出與退出碼。

---

## 貢獻（Contributing）

歡迎 PR/Issue：

* 以 **最小可重現** 的測試案例描述問題（建議提供 `.c` 最小檔）。
* 針對 API/行為差異，請附上在 Windows 實機/VM 上的對照輸出。
* 提交前請跑過 `clang-format`（或遵循現行程式風格），並附上測試步驟。

---

## 授權（License）

本專案以 **GPL-3.0** 授權釋出；詳見 `LICENSE`。

---

## 鳴謝（Acknowledgements）

* 感謝 Windows/PE 生態相關文件與社群的公開資源。
* 感謝 Arch Linux 與 Waydroid 專案。

---

## 版本資訊

此 README 為 2025-08-29 版本，會隨著專案進度更新。
