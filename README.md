# 👾 peldr


<div align="center">

[![Platform](https://img.shields.io/badge/platform-Windows-blue?logo=windows&logoColor=white)](https://www.microsoft.com/en-us/windows)
[![Language](https://img.shields.io/badge/language-C%2FC%2B%2B-00599C?logo=c%2B%2B)](https://en.cppreference.com/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

*Compress, Encrypt, Fileless Execute — One binary, zero traces.*

</div>

---

> [!WARNING]
> This tool is intended **only** for educational purposes and authorized security auditing.  
> The author assumes no liability for any misuse or damage.

---

## 📖 Table of Contents | Оглавление

- [English](#english)
  - [📋 Overview](#-overview)
  - [✨ Features](#-features)
  - [🔒 Complete Packing Pipeline](#-complete-packing-pipeline)
  - [🚀 Quick Start](#-quick-start)
  - [⚙️ Build-time Configuration Flags](#️-build-time-configuration-flags)
  - [⚙️ Technical Highlights](#️-technical-highlights)
  - [📁 Output](#-output)
  - [⚠️ Requirements](#️-requirements)
  - [🔧 Troubleshooting](#-troubleshooting)

- [Русский](#русский)
  - [📋 Обзор](#-обзор)
  - [✨ Возможности](#-возможности)
  - [🔒 Полный конвейер упаковки](#-полный-конвейер-упаковки)
  - [🚀 Быстрый старт](#-быстрый-старт)
  - [⚙️ Флаги конфигурации времени сборки](#️-флаги-конфигурации-времени-сборки)
  - [⚙️ Технические особенности](#️-технические-особенности)
  - [📁 Результат](#-результат)
  - [⚠️ Требования](#️-требования)
  - [🔧 Устранение неполадок](#-устранение-неполадок)

---

# English

## 📋 Overview

**PELDR** — is an advanced PE packer and reflective loader that transforms standard Windows executables (EXE/DLL) into self‑contained, encrypted, fileless‑executing binaries.  
It combines efficient compression, strong encryption, and a fully reflective loader stub written in pure C — no CRT, no imports, all APIs resolved dynamically.

The loader never writes the original image to disk: it reads its own overlay, decrypts and decompresses the payload directly in memory, maps it reflectively, and transfers execution. The result is a single executable that hides the original code and evades common static and dynamic analysis.

### Key Components

| Component | Description |
|-----------|-------------|
| **Reflective Loader** | Pure C, no standard libraries; all functions resolved via hashing |
| **API Hashing** | Pre‑computed hashes eliminate plaintext import names |
| **Compression** | Efficient algorithm reduces payload size significantly |
| **Encryption** | Stream cipher with variable key and internal state |
| **Runtime Protection** | Optional anti‑analysis and environmental checks |
| **Fileless Execution** | Everything happens in memory — no disk writes of the original PE |

## ✨ Features

### Core Packing

| Feature | Description |
|---------|-------------|
| 🗜️ **Compression** | Reduces size by 20‑50% on typical PE files |
| 🔐 **Encryption** | Stream cipher with feedback — each byte depends on all previous |
| 🔍 **API Hashing** | Imports resolved without plaintext strings |
| 🧠 **Reflective Loading** | Full PE mapping: relocations, imports, TLS, exception handling |

### Compilation & Linking

| Feature | Description |
|---------|-------------|
| 🏗️ **Minimal Environment** | `-nostdlib -nostartfiles -ffreestanding` — no CRT |
| 🧹 **Stripped Binary** | `--gc-sections`, no symbols, minimal footprint |
| 📦 **Static PIE** | Position‑independent loader works from any base address |

### Runtime Protection

| Feature | Description |
|---------|-------------|
| 🛡️ **Anti‑analysis** | Detects debugging and virtualised environments |
| 🔒 **Memory Guard** | Prevents certain types of memory scanning |
| 🧹 **Self‑cleaning** | Sensitive pointers are zeroed after use |
| 🗑️ **Header Erasure** | Optional removal of PE signatures from memory |

## 🔒 Complete Packing Pipeline

```
PHASE 1: PE VALIDATION
├── Checks signatures (MZ, PE)
├── Confirms x86‑64 architecture
└── Verifies structural integrity

PHASE 2: COMPRESSION
├── Efficient run‑length encoding
└── Typical size reduction: 20‑50%

PHASE 3: ENCRYPTION
├── Random key generation
├── Stream cipher with internal state
└── Feedback makes decryption dependent on all previous bytes

PHASE 4: STUB ASSEMBLY
├── Loader stub (embedded as byte array)
├── Key, compressed + encrypted payload appended
├── Overlay length stored for runtime reading
└── Optional GUI subsystem flag (-w)

PHASE 5: RUNTIME (Loader Execution)
├── Reads overlay from its own file
├── Decrypts and decompresses payload in memory
├── Allocates image, maps sections, resolves relocations/imports
├── Handles TLS and exception directory
├── Applies runtime protection (if enabled)
├── Sets final memory permissions
└── Jumps to entry point (or calls DllMain for DLL)
```

## 🚀 Quick Start

### 📥 Download

Pre‑built binaries are available on the [Releases](https://github.com/vk-candpython/peldr/releases/tag/v1.0.0) page.

Or clone and build from source:

```bash
git clone https://github.com/vk-candpython/peldr.git
cd peldr
```

### 📦 Build

The builder is a single C++ file with the loader stub already embedded.

```bash
g++ -o peldr.exe peldr.c                                                        ^
    -m64 -static                                                                ^
    -Wl,--sort-common,--nxcompat,--dynamicbase,--no-seh,-x                      ^
    -s -g0 -O3 -Wl,-O2                                                          ^
    -fipa-pta -fno-strict-aliasing -fvisibility=hidden -fomit-frame-pointer     ^
    -fmerge-all-constants -ffunction-sections -fdata-sections -Wl,--gc-sections ^
    -Wl,--build-id=none -fno-ident -fno-builtin -fno-common                     ^
    -fno-stack-check -fno-stack-protector -fno-stack-clash-protection           ^
    -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables
```

> **Note:** The loader stub is pre‑compiled. If you modify `loader.c` / `loader.h`, you must regenerate the stub array (see [Rebuilding the stub](#rebuilding-the-stub)).

<details>
<summary><b>Rebuilding the stub</b></summary>

```bash
gcc -o loader.exe loader.c                                                      ^
    -m64 -nostdlib -nostartfiles -ffreestanding                                 ^
    -Wl,--sort-common,--nxcompat,--dynamicbase,--no-seh,-x                      ^
    -s -g0 -O3 -Wl,-O2                                                          ^
    -fipa-pta -fno-strict-aliasing -fvisibility=hidden -fomit-frame-pointer     ^
    -fno-reorder-blocks-and-partition                                           ^
    -fmerge-all-constants -ffunction-sections -fdata-sections -Wl,--gc-sections ^
    -Wl,--build-id=none -fno-ident -fno-builtin -fno-common -fno-stack-check    ^
    -fno-stack-protector -fno-stack-clash-protection -fno-exceptions            ^
    -fno-unwind-tables -fno-asynchronous-unwind-tables
```

Convert `loader.exe` to a C array (e.g., using `xxd -i loader.exe > stub.h`) and update `STUB_EXE[]` in `peldr.c`. Then rebuild the builder.
</details>

### 🏃 Usage

```bash
# Pack an executable (console subsystem by default)
peldr.exe myapp.exe

# Pack with GUI subsystem (no console window)
peldr.exe -w myapp.exe

# Pack multiple files
peldr.exe app1.exe app2.dll
```

**Output example:**
```
Start processing -> C:\Users\...\myapp.exe

[*] compressed    :  142144 -> 89123 bytes  |  saved: 53021 bytes (37.2%)
[+] output file   :  ./peldr-myapp.exe (123456 bytes)
[*] elapsed time  :  0.01s

End of processing -> C:\Users\...\myapp.exe
```

## ⚙️ Build-time Configuration Flags

The loader (`loader.h`) exposes three compile‑time switches that control its behaviour:

```c
#define  USING_ANTI_VM           FALSE
#define  USING_ANTI_DEBUG        FALSE
#define  USING_ERASE_PE_HEADERS  FALSE
```

| Flag | Default | Description |
|------|---------|-------------|
| **`USING_ANTI_VM`** | `FALSE` | Enables detection of virtualised environments |
| **`USING_ANTI_DEBUG`** | `FALSE` | Enables anti‑debugging checks and memory guard |
| **`USING_ERASE_PE_HEADERS`** | `FALSE` | Erases DOS/NT headers from memory after loading |

> Changing any flag requires rebuilding the loader stub and re‑embedding it into the builder.

## ⚙️ Technical Highlights

- **API Hashing** – all NT functions are resolved by walking `ntdll.dll`’s export table and comparing pre‑computed hashes. No plain‑text import names exist in the stub.
- **Reflective Loading** – the payload is mapped, relocated, and executed entirely from memory. The original executable is never written to disk.
- **Compression & Encryption** – a custom RLE algorithm reduces size; a stream cipher with variable key length and internal state protects the payload.
- **Runtime Protection** – optional measures help to detect debugging and common analysis environments, without relying on easily hooked API calls.
- **Self‑cleaning** – after use, all resolved function pointers are set to `NULL`, minimising in‑memory artifacts.

## 📁 Output

```
original.exe  →  peldr-original.exe
```

- Single executable containing loader + encrypted payload
- No imports, symbols, or plaintext strings
- Executes completely in memory
- Typical size reduction: **20‑50%**

## ⚠️ Requirements

| Requirement | Version | Notes |
|-------------|---------|-------|
| **Builder OS** | Windows | Build and tested on Windows |
| **Target OS** | Windows 7+ | NT API required |
| **Architecture** | x86_64 | 64‑bit only |
| **Compiler** | MinGW‑w64 (GCC/G++) | `-nostdlib` support needed |

## 🔧 Troubleshooting

| Issue | Solution |
|-------|----------|
| `packed binary crashes` | Original may require specific DLLs/COM. Try a simple executable first. |
| `compilation fails` | Use the exact flags shown. Ensure MinGW‑w64 is correctly installed. |
| `antivirus alert` | Packers and loaders are often flagged. Use in an isolated environment. |
| `file access error` | Check read/write permissions for the output folder. |
| `decryption failure` | Do not mix loader stub and builder from different versions. |

---

# Русский

## 📋 Обзор

**PELDR** — это продвинутый упаковщик PE‑файлов с рефлективной загрузкой. Он превращает стандартные исполняемые файлы Windows в автономные, зашифрованные, бесфайлово‑исполняемые бинарники.  
В основе лежат эффективное сжатие, стойкое шифрование и загрузчик на чистом C, не требующий CRT и разрешающий API динамически.

Загрузчик никогда не сохраняет исходный образ на диск: расшифровка и распаковка происходят прямо в памяти, после чего образ отображается и запускается. Результат — один исполняемый файл, скрывающий оригинальный код.

### Ключевые компоненты

| Компонент | Описание |
|-----------|----------|
| **Рефлективный загрузчик** | Чистый C, все функции разрешаются через хеширование |
| **Хеширование API** | Нет открытых имён импортируемых функций |
| **Сжатие** | Уменьшает размер на 20‑50% |
| **Шифрование** | Потоковый шифр с внутренним состоянием |
| **Защита времени выполнения** | Опциональные проверки окружения и отладки |
| **Бесфайловое выполнение** | Никакой записи оригинального PE на диск |

## ✨ Возможности

*(Полный список см. в английской версии)*

## 🔒 Полный конвейер упаковки

*(Идентичен английской версии)*

## 🚀 Быстрый старт

```bash
git clone https://github.com/vk-candpython/peldr.git
cd peldr
# Сборка упаковщика (stub уже встроен)
g++ -m64 -static ... -o peldr.exe peldr.c
# Упаковка файла
peldr.exe myapp.exe
./peldr-myapp.exe
```

При необходимости пересобрать заглушку загрузчика (`loader.c`), следуйте инструкции в английской секции [Rebuilding the stub](#rebuilding-the-stub).

## ⚙️ Флаги конфигурации времени сборки

```c
#define  USING_ANTI_VM           FALSE
#define  USING_ANTI_DEBUG        FALSE
#define  USING_ERASE_PE_HEADERS  FALSE
```

| Флаг | Описание |
|------|----------|
| **`USING_ANTI_VM`** | Включает детект виртуальных машин |
| **`USING_ANTI_DEBUG`** | Включает защиту от отладки и страничную ловушку |
| **`USING_ERASE_PE_HEADERS`** | Затирает PE‑заголовки образа в памяти после загрузки |

## ⚙️ Технические особенности

- **Хеширование API** – все функции извлекаются из `ntdll.dll` с помощью предвычисленных хешей. В заглушке нет строк‑имён.
- **Рефлективная загрузка** – образ отображается, перемещается и запускается целиком в памяти.
- **Сжатие и шифрование** – оригинальный RLE и потоковый шифр с обратной связью.
- **Защита времени выполнения** – опциональные меры против отладки и виртуализации.
- **Самоочистка** – указатели функций зануляются после завершения работы.

## 📁 Результат

```
оригинал.exe  →  peldr-оригинал.exe
```

## ⚠️ Требования

| Требование | Версия | Примечания |
|------------|--------|------------|
| **ОС сборщика** | Windows | |
| **Целевая ОС** | Windows 7+ | |
| **Архитектура** | x86_64 | |
| **Компилятор** | MinGW‑w64 (GCC/G++) | |

## 🔧 Устранение неполадок

*(См. английскую секцию Troubleshooting)*

---

<div align="center">

**[⬆ Back to Top](#-peldr-advanced-pe-packing--reflective-loader)**

*PE Packing & Reflective Loading for Windows*

</div>
