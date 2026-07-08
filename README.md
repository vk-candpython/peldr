# 👾 peldr now is developing


<div align="center">

[![Platform](https://img.shields.io/badge/platform-Windows-blue?logo=windows&logoColor=white)](https://www.microsoft.com/en-us/windows)
[![Language](https://img.shields.io/badge/language-C%2FC%2B%2B-00599C?logo=c%2B%2B)](https://en.cppreference.com/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

*Advanced PE packing and reflective loading — Compress, Encrypt, Fileless Execute*

</div>

---

> [!WARNING]
> This tool is for educational purposes and authorized security auditing only. The author is not responsible for any misuse.

---

## 📖 Table of Contents | Оглавление

- [English](#english)
  - [📋 Overview](#-overview)
  - [✨ Features](#-features)
  - [🔒 Complete Packing Pipeline](#-complete-packing-pipeline)
  - [🚀 Quick Start](#-quick-start)
  - [⚙️ Build-time Configuration Flags](#️-build-time-configuration-flags)
  - [⚙️ Deep Technical Analysis](#️-deep-technical-analysis)
  - [📁 Output](#-output)
  - [⚠️ Requirements](#️-requirements)
  - [🔧 Troubleshooting](#-troubleshooting)

- [Русский](#русский)
  - [📋 Обзор](#-обзор)
  - [✨ Возможности](#-возможности)
  - [🔒 Полный конвейер упаковки](#-полный-конвейер-упаковки)
  - [🚀 Быстрый старт](#-быстрый-старт)
  - [⚙️ Флаги конфигурации времени сборки](#️-флаги-конфигурации-времени-сборки)
  - [⚙️ Глубокий технический анализ](#️-глубокий-технический-анализ)
  - [📁 Результат](#-результат)
  - [⚠️ Требования](#️-требования)
  - [🔧 Устранение неполадок](#-устранение-неполадок)

---

# English

## 📋 Overview

**PELDR** — is a military‑grade PE packer and reflective loader that transforms standard Windows executables (EXE/DLL) into self‑contained, encrypted, fileless‑executing binaries.  
It combines a custom RLE compression, a stream XOR cipher, and a fully reflective loader stub that resolves APIs by hash, evades debugging, and never writes the original image to disk.

### What makes it unique?

| Component | Implementation |
|-----------|----------------|
| **Reflective loader** | Pure C, no standard libraries, resolves everything via ntdll hash lookup |
| **API hashing** | DJB‑like hash with random key; all function names are hidden |
| **RLE compression** | Custom byte‑level run‑length encoding — typical 20‑50% size reduction |
| **XOR stream cipher** | Variable key length (16‑128 bytes) + feedback — each byte depends on all previous |
| **ETW bypass** | Patches `EtwEventWrite` in‑memory at runtime |
| **Anti‑debug** | Checks `BeingDebugged` flag, `ProcessDebugPort`, `ProcessDebugFlags`, hides thread |
| **Disguise as ntdll** | Optionally overwrites the original image headers with those of ntdll.dll |
| **Fileless execution** | Payload is decrypted and decompressed directly into a `MEM_TOP_DOWN` allocation, protected, and executed |
| **Dynamic code policy** | Sets `ProcessDynamicCodePolicy` after mapping to prevent further code injection |
| **Loader self‑cleaning** | All internal function pointers are zeroed after use |

## ✨ Features

### Core Packing

| Feature | Description |
|---------|-------------|
| 🗜️ **RLE Compression** | Byte‑level RLE with `0x80` repeat flag, min run length 3 |
| 🔐 **XOR Stream Cipher** | Key length 16‑128 bytes, non‑linear feedback, salt‑dependent |
| 🔍 **API Hashing** | Every imported function resolved via pre‑computed DJB‑like hash — no plaintext names |
| 🧠 **Reflective Loading** | Maps the payload into memory, processes relocations, imports, TLS, and executes it |

### Compilation & Linking

| Feature | Description |
|---------|-------------|
| 🏗️ **Minimal C environment** | `-nostdlib -nostartfiles -ffreestanding` — no CRT, no standard libraries |
| 🧹 **Extreme stripping** | `--strip-all --discard-all --gc-sections` + custom section purge |
| 🛡️ **Compiler hardening** | Stack protector disabled, no exception tables, no PLT, hidden visibility |
| 📦 **Static PIE** | Position‑independent executable — works from any base address |

### Runtime Protection

| Feature | Description |
|---------|-------------|
| 🚫 **Anti‑debug** | `BeingDebugged` flag, `ProcessDebugPort` check, `ProcessDebugFlags` and thread hiding |
| 🛡️ **ETW patching** | In‑memory `EtwEventWrite` overwrite to `xor eax,eax; ret` |
| 🔒 **Dynamic code policy** | `ProcessDynamicCodePolicy` enabled after loading to prevent new code execution |
| 🧹 **Pointer zeroing** | All sensitive function pointers are cleared after use |
| 🧥 **ntdll disguise** | Optional – replaces the host image headers with those of ntdll.dll |

## 🔒 Complete Packing Pipeline

```
PHASE 1: PE VALIDATION
├── Checks DOS signature (MZ)
├── Validates NT signature (PE)
└── Confirms x86‑64 architecture

PHASE 2: RLE COMPRESSION
├── Flag byte: 0x00‑0x7F = literal run, 0x80‑0xFF = repeat run
├── Minimum repeat threshold: 3 identical bytes
├── Maximum literal run: 126 bytes
└── Exact pre‑allocation for output buffer

PHASE 3: XOR STREAM ENCRYPTION
├── Random key length 16‑128 bytes
├── Stream cipher with non‑linear feedback and salt
└── Each byte depends on all previous bytes

PHASE 4: STUB ASSEMBLY
├── Pre‑compiled loader stub appended
├── Embedded key, compressed + encrypted payload
├── Total length written at the end for overlay reading
└── Optional GUI subsystem flag

PHASE 5: RUNTIME (Loader Execution)
├── Reads overlay from own file via NtQueryInformationProcess + NtReadFile
├── Decrypts and decompresses payload in memory
├── Allocates image with MEM_TOP_DOWN and PAGE_GUARD
├── Maps sections, performs relocations and imports
├── Handles TLS callbacks
├── Optionally disguises as ntdll
└── Jumps to entry point (or DllMain for DLL)
```

## 🚀 Quick Start

### 📥 Download

You can download the pre‑built release binary from the [Releases](https://github.com/vk-candpython/peldr/releases/tag/v1.0.0) page.

Or clone and build from source:

```bash
git clone https://github.com/vk-candpython/peldr.git
cd peldr
```

### 📦 Build

```bash
# Build loader (stub)
gcc -m64 -nostdlib -nodefaultlibs -nostartfiles -static-pie -e Main -Os \
    -Wl,-O2,--nxcompat,--dynamicbase,-x,--sort-common,--exclude-all-symbols,\
--no-insert-timestamp,--no-seh,--build-id=none,--strip-all,--discard-all,--gc-sections \
    -s -fvisibility=hidden -fno-semantic-interposition -fomit-frame-pointer \
    -ffreestanding -fmerge-constants -ffunction-sections -fdata-sections \
    -fno-builtin -fno-common -fno-plt -fno-exceptions -fno-stack-check \
    -fno-stack-protector -fno-stack-clash-protection -fno-ident \
    -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-math-errno \
    -fno-trapping-math -o loader.exe loader.c


# Build packer
g++ -m64 -static-pie -mconsole -municode -O3 \
    -Wl,-O2,--nxcompat,-x,--sort-common,--exclude-all-symbols,\
--no-insert-timestamp,--no-seh,--build-id=none,--strip-all,--discard-all,--gc-sections \
    -s -fvisibility=hidden -fno-semantic-interposition -fomit-frame-pointer \
    -fmerge-constants -ffunction-sections -fdata-sections -fno-common -fno-plt \
    -fno-exceptions -fno-ident -fno-unwind-tables -fno-asynchronous-unwind-tables \
    -fno-math-errno -fno-trapping-math -o peldr.exe peldr.cpp
```

### 🏃 Usage

```bash
# Pack an executable (console subsystem by default)
peldr.exe myapp.exe

# Pack with GUI subsystem
peldr.exe -w myapp.exe

# Pack multiple files
peldr.exe app1.exe app2.dll
```

**Output:**
```
[  OK  ]: Starting packing of (1) file mode(CONSOLE)

[ INFO ]: Start processing -> C:\Users\...\myapp.exe

[  OK  ]: compressed: (142144 -> 89123) bytes  |  saved: 53021 bytes (37%)
[  OK  ]: outfile(./peldr-myapp.exe, 123456 bytes)
[ INFO ]: time ................. (0.007s)

[ INFO ]: End processing -> C:\Users\...\myapp.exe

[  OK  ]: Successfully packed of (1)
```

## ⚙️ Build-time Configuration Flags

The loader (`loader.c`) exposes several compile‑time `#define` switches that control its behaviour. They are set at the top of the source file:

```c
#define USING_ANTIDEBUG               TRUE
#define USING_DISGUISE_AS_NTDLL       FALSE
#define USING_ERASE_PE_SIGNATURE      FALSE
#define USING_DYNAMIC_CODE_POLICY     FALSE
#define USING_SIGNATURE_DLL_POLICY    FALSE
```

### Flag descriptions

| Flag | Default | Description |
|------|---------|-------------|
| **`USING_ANTIDEBUG`** | `TRUE` | Enables all anti‑debugging measures: `BeingDebugged` check, `ProcessDebugPort`, `ProcessDebugFlags`, thread hiding, and ETW patching. Disable only if the packed binary must be debugged. |
| **`USING_DISGUISE_AS_NTDLL`** | `FALSE` | When `TRUE`, the loader overwrites the host image’s PE headers with those of the real `ntdll.dll`. This makes the process look like `ntdll.dll` in memory dumps and tools such as Process Hacker. |
| **`USING_ERASE_PE_SIGNATURE`** | `FALSE` | When `TRUE`, the `MZ` and `PE` signatures of the mapped image are zeroed after loading, removing the classic DOS/NT magic bytes. |
| **`USING_DYNAMIC_CODE_POLICY`** | `FALSE` | When `TRUE`, calls `NtSetInformationProcess` with `ProcessDynamicCodePolicy` to prohibit dynamic code generation after the payload is loaded (prevents further VirtualAlloc + RWX). |
| **`USING_SIGNATURE_DLL_POLICY`** | `FALSE` | When `TRUE`, sets `ProcessSignaturePolicy` to restrict DLL loading to Microsoft‑signed binaries only. |

**Note:** Changing these flags requires rebuilding the loader stub and re‑embedding it into the packer.

## ⚙️ Deep Technical Analysis

### Reflective Loader (loader.c)

The loader runs as the host process. It:
- Reads the appended overlay by querying its own image path via `NtQueryInformationProcess` → `ProcessImageFileName`
- Opens and reads the tail of the file to retrieve the packed data
- Decrypts and decompresses the payload using the embedded key
- Allocates a new memory region with `MEM_TOP_DOWN` + `PAGE_GUARD` for anti‑debugging
- Maps headers, sections, processes base relocations and imports
- Handles exception directories (`RtlAddFunctionTable`) and load config (security cookie)
- Optionally erases the PE signature and disguises the original image headers as ntdll
- Calls TLS callbacks and finally the entry point (or DllMain)

### API Hashing

All functions are resolved from `ntdll.dll` using a pre‑computed hash. The hash function is a DJB‑like algorithm with a random key (`KEY_HASH_STR`). During the build process, `hash.py` generates the `#define` list for the required functions. At runtime, the loader walks the export table of ntdll, hashes each name, and compares with the embedded hashes. This prevents static analysis from seeing imported function names.

### Compression (RLE)

Custom byte‑oriented run‑length encoding:
- Literal runs: length 1‑126, followed by raw bytes
- Repeat runs: length 3‑127, flagged with 0x80, followed by the repeated byte
- Optimised for PE files where zero‑padding and repeated patterns are common

### Encryption (XOR Stream Cipher)

A stream cipher with internal state and non‑linear feedback.

Key lengths vary randomly (16, 32, 64, or 128 bytes) per build.

### Anti‑debug and Evasion

- Checks `PEB->BeingDebugged`
- Calls `NtQueryInformationProcess` with `ProcessDebugPort` and `ProcessDebugFlags`
- Hides the current thread from the debugger via `NtSetInformationThread(ThreadHideFromDebugger)`
- Patches `EtwEventWrite` to `xor eax, eax; ret` by making its memory writable temporarily
- Optionally sets `ProcessDynamicCodePolicy` and `ProcessSignaturePolicy`

### Builder (peldr.cpp)

Written in C++ with extensive optimisations:
- Memory‑mapped I/O is simulated with `ifstream`
- Single‑pass compression and in‑place encryption
- Random key generation seeded by `std::random_device`
- The pre‑compiled loader stub (`STUB_EXE[]`) is embedded as a static byte array and customised at build time (e.g., GUI subsystem flag)

## 📁 Output

```
original.exe  →  peldr-original.exe
```

**Output binary properties:**
- Contains the full loader stub + encrypted payload
- Stripped of all symbols, section headers zeroed
- Executes reflectively without writing the original PE to disk
- Typically **20‑50% smaller** than the original

## ⚠️ Requirements

| Requirement | Version | Notes |
|-------------|---------|-------|
| **Builder OS** | Windows | Build and tested on Windows |
| **Target OS** | Windows 7+ | Loader uses NT API functions available since NT 6.1 |
| **Architecture** | x86_64 | Both loader and packed image must be 64‑bit |
| **Compiler (loader)** | GCC (MinGW‑w64) | `-nostdlib` build |
| **Compiler (builder)** | G++ (MinGW‑w64) | C++17 filesystem |

## 🔧 Troubleshooting

| Issue | Solution |
|-------|----------|
| `packed binary crashes` | The original PE may require specific DLLs or COM initialization. Try packing a simple EXE first. |
| `compilation fails` | Use exactly the provided flags; make sure your MinGW‑w64 supports `-static-pie`. |
| `antivirus flags peldr.exe` | The packer may be detected as a “packer” or “hacktool”. This is expected; use in isolated environments. |
| `file access errors` | Ensure you have read/write permissions in the output directory. |
| `payload decryption fails` | Do not modify the loader stub separately; build both from the same commit. |

---

# Русский

## 📋 Обзор

**PELDR** — это упаковщик PE‑файлов военного уровня с рефлективной загрузкой. Он превращает стандартные исполняемые файлы Windows (EXE/DLL) в автономные, зашифрованные, бесфайлово‑исполняемые бинарники.  
Используется кастомное RLE‑сжатие, потоковый XOR‑шифр и полностью рефлективный загрузчик, который разрешает API по хешам, обходит отладку и никогда не сохраняет исходный образ на диск.

### Что делает его уникальным?

| Компонент | Реализация |
|-----------|------------|
| **Рефлективный загрузчик** | Чистый C, без стандартных библиотек, всё через хеш‑поиск в ntdll |
| **Хеширование API** | DJB‑подобный хеш со случайным ключом; имена функций скрыты |
| **RLE‑сжатие** | Кастомное побайтовое кодирование – обычно сжатие 20‑50% |
| **Потоковый XOR‑шифр** | Переменная длина ключа (16‑128 байт) + обратная связь |
| **Обход ETW** | Патчит `EtwEventWrite` в памяти на `xor eax,eax; ret` |
| **Анти‑отладка** | Проверяет `BeingDebugged`, `ProcessDebugPort`, `ProcessDebugFlags`, прячет поток |
| **Маскировка под ntdll** | Опционально заменяет заголовки оригинального образа заголовками ntdll.dll |
| **Бесфайловое выполнение** | Расшифровка и распаковка происходят напрямую в выделенной памяти без записи на диск |

## ✨ Возможности

### Упаковка

| Возможность | Описание |
|-------------|----------|
| 🗜️ **RLE‑сжатие** | Побайтовое RLE с флагом 0x80, минимальная серия 3 байта |
| 🔐 **Потоковый XOR‑шифр** | Ключ 16‑128 байт, нелинейная обратная связь |
| 🔍 **Хеширование API** | Все функции ищутся по заранее вычисленным хешам – имена не видны |
| 🧠 **Рефлективная загрузка** | Загружает образ в память, обрабатывает релокации, импорт, TLS и запускает |

### Компиляция и линковка

| Возможность | Описание |
|-------------|----------|
| 🏗️ **Минимальное окружение C** | `-nostdlib -nostartfiles -ffreestanding` – без CRT |
| 🧹 **Экстремальная очистка** | `--strip-all --discard-all --gc-sections` |
| 🛡️ **Защита компилятором** | Нет stack protector, нет exception tables, нет PLT, скрытая видимость |
| 📦 **Статический PIE** | Позиционно‑независимый код – работает с любого базового адреса |

### Защита времени выполнения

| Возможность | Описание |
|-------------|----------|
| 🚫 **Анти‑отладка** | Проверка флагов PEB и DebugPort, скрытие потока |
| 🛡️ **Патч ETW** | Перезапись `EtwEventWrite` в памяти |
| 🔒 **Динамическая кодовая политика** | Запрет исполнения нового кода после загрузки |
| 🧹 **Обнуление указателей** | Все чувствительные указатели функций затираются после использования |
| 🧥 **Маскировка под ntdll** | Опционально подменяет заголовки образа на заголовки ntdll.dll |

## 🔒 Полный конвейер упаковки

*(См. английскую версию для подробной диаграммы)*

## 🚀 Быстрый старт

### 📥 Загрузка

Вы можете загрузить готовый бинарник со страницы [Релизов](https://github.com/vk-candpython/peldr/releases/tag/v1.0.0).

Или клонируйте репозиторий и соберите из исходников:

```bash
git clone https://github.com/vk-candpython/peldr.git
cd peldr
# Собрать загрузчик (stub)
gcc -m64 -nostdlib ... -o loader.exe loader.c
# Собрать упаковщик
g++ -m64 -static-pie ... -o peldr.exe peldr.cpp
# Упаковать файл
peldr.exe myapp.exe
./peldr-myapp.exe
```

## ⚙️ Флаги конфигурации времени сборки

Загрузчик (`loader.c`) содержит несколько флагов `#define`, управляющих его поведением:

```c
#define USING_ANTIDEBUG               TRUE
#define USING_DISGUISE_AS_NTDLL       FALSE
#define USING_ERASE_PE_SIGNATURE      FALSE
#define USING_DYNAMIC_CODE_POLICY     FALSE
#define USING_SIGNATURE_DLL_POLICY    FALSE
```

### Описание флагов

| Флаг | По умолчанию | Описание |
|------|--------------|----------|
| **`USING_ANTIDEBUG`** | `TRUE` | Включает все анти‑отладочные меры: проверку `BeingDebugged`, `ProcessDebugPort`, `ProcessDebugFlags`, скрытие потока и патч ETW. Отключайте только если требуется отладка упакованного файла. |
| **`USING_DISGUISE_AS_NTDLL`** | `FALSE` | При `TRUE` заменяет PE‑заголовки основного образа заголовками реального `ntdll.dll`, маскируя процесс под ntdll. |
| **`USING_ERASE_PE_SIGNATURE`** | `FALSE` | При `TRUE` затирает сигнатуры `MZ` и `PE` у загруженного образа после загрузки. |
| **`USING_DYNAMIC_CODE_POLICY`** | `FALSE` | При `TRUE` вызывает `ProcessDynamicCodePolicy`, запрещая дальнейшее создание исполняемой памяти. |
| **`USING_SIGNATURE_DLL_POLICY`** | `FALSE` | При `TRUE` устанавливает `ProcessSignaturePolicy`, разрешая загрузку только DLL, подписанных Microsoft. |

**Примечание:** Изменение флагов требует пересборки заглушки загрузчика и повторной вставки в упаковщик.

## ⚙️ Глубокий технический анализ

*(Детали идентичны английской версии)*

## 📁 Результат

```
оригинал.exe  →  peldr-оригинал.exe
```

## ⚠️ Требования

| Требование | Версия | Примечания |
|------------|--------|------------|
| **ОС сборщика** | Windows | Сборка и тесты на Windows |
| **Целевая ОС** | Windows 7+ | NT API доступен с NT 6.1 |
| **Архитектура** | x86_64 | Только 64‑бит |
| **Компилятор (загрузчик)** | GCC (MinGW‑w64) | |
| **Компилятор (сборщик)** | G++ (MinGW‑w64) | C++17 |

## 🔧 Устранение неполадок

| Проблема | Решение |
|----------|---------|
| `упакованный бинарник падает` | Оригиналу могут требоваться определённые DLL или COM. Попробуйте простой EXE. |
| `ошибка компиляции` | Используйте точно указанные флаги; убедитесь, что MinGW‑w64 поддерживает `-static-pie`. |
| `антивирус ругается` | Это поведение ожидаемо для упаковщиков; используйте в изолированной среде. |
| `ошибка чтения файла` | Проверьте права доступа в выходной директории. |
| `не расшифровывается` | Не изменяйте загрузчик отдельно; собирайте оба компонента из одного коммита. |

---

<div align="center">

**[⬆ Back to Top](#-peldr)**

*PE Packing & Reflective Loading for Windows*

</div>
