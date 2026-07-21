/*
 * Author   : Vladislav Khudash
 * Source   : https://github.com/vk-candpython/peldr/blob/main/loader.h
 * Compiler : MinGW-w64 (w64devkit)
 * Platform : Windows x64 (PE32+)
 * Summary  : Core configuration header, custom NT structures, and basic utilities.
*/


#pragma once


/********************
 *     INCLUDES     *
 ********************/


/* Compiler ASM intrinsics */
#include <intrin.h>


/* Native API environment
   and NT status codes */
#include <winternl.h>
#include <ntstatus.h>




/*************************************
 *     BUILD-TIME FEATURE CONFIG     *
 *************************************/


#define USING_ANTI_VM          FALSE
#define USING_ANTI_DEBUG       FALSE
#define USING_ERASE_PE_HEADERS FALSE




/*********************************
 *     CONSTANT-DECLARATIONS     *
 *********************************/


#define DAT_KEY_SZ sizeof(BYTE)   // Size of key size field (BYTE)
#define DAT_LEN_SZ sizeof(UINT32) // Size of length fields (UINT32)

#define RLE_MAX_RUN 127 // Maximum encoded run length
#define RLE_FLG_RUN 128 // High-bit marker for run blocks


#define PAGE_SIZE 0x1000 // Standard memory page size

#define MAX_PATH_LEN 1024 // Maximum length of a full file path
#define MAX_NAME_LEN 128  // Maximum length of a module name


#define NT_CUR_PROCESS ((HANDLE)-1LL) // Current process pseudo-handle


#define PEB64_GS_OFFSET 0x60 // PEB64 offset in GS segment

#define KUSER_SHARED_DATA         0x7FFE0000ULL                   // Base address of structure KUSER_SHARED_DATA
#define KUSER_INTERRUPT_TIME      (KUSER_SHARED_DATA + 0x0008ULL) // KUSER_SHARED_DATA::InterruptTime
#define KUSER_KD_DEBUGGER_ENABLED (KUSER_SHARED_DATA + 0x02D4ULL) // KUSER_SHARED_DATA::KdDebuggerEnabled


/* Mask for section memory access permissions
   (Read, Write, Execute) */
#define SECTION_PROT_MASK \
    (IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_EXECUTE)


#if (USING_ANTI_DEBUG)
    /* Enable memory protection trap,
       The first page is reserved as a guard page
       before the mapped image */
    #define PAGE_GUARD_SIZE PAGE_SIZE

    /* NT Virtual Memory allocation flags */
    #define NT_ALLOC_FLG \
        (MEM_COMMIT|MEM_RESERVE|MEM_TOP_DOWN)
#else
    /* Disable memory protection trap */
    #define PAGE_GUARD_SIZE 0

    /* NT Virtual Memory allocation flags */
    #define NT_ALLOC_FLG \
        (MEM_COMMIT|MEM_RESERVE)
#endif




/*****************************
 *     ALIASES & HELPERS     *
 *****************************/


/* Compiler attribute wrapper helper */
#define _DEC_ATTR(...) \
    __attribute__((__VA_ARGS__))



/* Stack buffer alignment helper */
#define DEC_ALIGN_BUF \
    _DEC_ATTR(aligned(16))

/* Unaligned type wrapper */
#define DEC_UNALIGNED(TYPE) \
    TYPE _DEC_ATTR(aligned(sizeof(BYTE)))



/* Const-qualified pointer helper
   (const data and const pointer) */
#define CONST_PTR(TYPE) \
    const TYPE *const

/* Restrict-qualified pointer helper
   (guarantees no memory aliasing) */
#define RESTR_PTR(TYPE) \
    TYPE *restrict



/* Branch prediction hints for compiler optimization */

#define _UNLIKELY(x) __builtin_expect(!!(x), 0) // Cold path
#define _LIKELY(x)   __builtin_expect(!!(x), 1) // Hot path


/* Check for NTSTATUS failure */
#define NT_FAIL(status) \
    _UNLIKELY((NTSTATUS)(status) < STATUS_SUCCESS)


/* Optimized branch control macros */

#define IF_LIKE(expr)     if (_LIKELY(expr))
#define IF_UNLIKE(expr)   if (_UNLIKELY(expr))
#define IF_NTFAIL(status) if (NT_FAIL(status))


/* Optimized loop control macros */

#define WHILE_LIKE(expr) \
    while (_LIKELY(expr))

#define FOR_LIKE(init, cond, post) \
    for (init; _LIKELY(cond); post)



/* Function declaration helper */
#define DEC_FUNC(TYPE) \
    static inline _DEC_ATTR(always_inline) TYPE


/* Initialize OBJECT_ATTRIBUTES with case‑insensitive access */
#define DEC_OBJATTR_CASE_INSENSITIVE(pPath) {                 \
    .Length                   = sizeof(OBJECT_ATTRIBUTES),    \
    .RootDirectory            = NULL,                         \
    .ObjectName               = (pPath),                      \
    .Attributes               = OBJ_CASE_INSENSITIVE,         \
    .SecurityDescriptor       = NULL,                         \
    .SecurityQualityOfService = NULL                          \
}




/******************************
 *     PE-IMAGE UTILITIES     *
 ******************************/


typedef BOOL (WINAPI *DllMain_t)(
    HINSTANCE    hinstDLL,
    DWORD        fdwReason,
    LPVOID       lpvReserved
);



/* Get current process PEB pointer */
#define GET_PTR_PEB() \
    ((PMN_PEB)__readgsqword(PEB64_GS_OFFSET))


/* Copy memory block */
#define MEMCPY(dst, src, sz) \
    __movsb((PBYTE)(dst), (const BYTE*)(src), (SIZE_T)(sz))

/* Fill memory with zeros */
#define ZEROS(dst, sz) \
    __stosb((PBYTE)(dst), 0, (SIZE_T)(sz))


/* Check if the PE image is a DLL */
#define PE_IS_DLL(hdFl) \
    ((BOOLEAN)((hdFl)->Characteristics & IMAGE_FILE_DLL))



/* Case‑folding mask for a single character */
#define ASCII_FOLD_MASK(chr) \
    ((BYTE)(((BYTE)((chr) - 'A') <= (BYTE)('Z' - 'A')) << 5))



/* Convert RVA to typed pointer */
#define RVA(TYPE, base, addr) \
    ((TYPE)((PBYTE)(base) + (addr)))


/* Extract e_lfanew from DOS header */
#define DOS_LFANEW(base) \
    (((PIMAGE_DOS_HEADER)(base))->e_lfanew)


/* Number of relocation entries in a block */
#define RELOC_ENTRY_COUNT(reloc)                              \
    (((reloc)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)    \
     ) / sizeof(WORD))

/* True if relocation entry requests
   64-bit absolute fixup */
#define RELOC_IS_DIR64(entry) \
    (((entry) >> 12) == IMAGE_REL_BASED_DIR64)

/* Get intra‑page offset from relocation entry */
#define RELOC_BLOCK_OFFSET(entry) \
    ((entry) & 0x0FFF)


/* Extracts PE section protection index
   from Characteristics (bits 29–31) */
#define SECTION_PROT_IDX(attr) \
    ((BYTE)(((attr) & SECTION_PROT_MASK) >> 29))




/*******************************
 *     ANTI-VM DEFINITIONS     *
 *******************************/


/* CPUID-based hypervisor detection */
#define AVM_STAGE_CPUID 1

/* PCI vendor ID scan via registry enumeration */
#define AVM_STAGE_PCIVEN 2



/* Stage: CPUID definitions */

#define CPUID_REG_COUNT 4 // (EAX, EBX, ECX, EDX)
#define CPUID_REG_ECX   2

#define CPUID_LEAF_FEATURES  0x01
#define CPUID_HYPERVISOR_BIT 31



/* Stage: PCIVEN definitions */

/* Stack initializer for PCI registry path,
   Packed as Little-endian UINT64 (WCHAR):
L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\PCI" */
#define PCI_INIT_REG_PATH(pBuf) do {                   \
    volatile UINT64 *_p = (PUINT64)(pBuf);             \
    *_p++ = 0x006700650052005CULL; /* \  R  e  g */    \
    *_p++ = 0x0072007400730069ULL; /* i  s  t  r */    \
    *_p++ = 0x0061004D005C0079ULL; /* y  \  M  a */    \
    *_p++ = 0x006E006900680063ULL; /* c  h  i  n */    \
    *_p++ = 0x00590053005C0065ULL; /* e  \  S  Y */    \
    *_p++ = 0x004D004500540053ULL; /* S  T  E  M */    \
    *_p++ = 0x007200750043005CULL; /* \  C  u  r */    \
    *_p++ = 0x0074006E00650072ULL; /* r  e  n  t */    \
    *_p++ = 0x0074006E006F0043ULL; /* C  o  n  t */    \
    *_p++ = 0x0053006C006F0072ULL; /* r  o  l  S */    \
    *_p++ = 0x0045005C00740065ULL; /* e  t  \  E */    \
    *_p++ = 0x005C006D0075006EULL; /* n  u  m  \ */    \
    *_p   = 0x0000004900430050ULL; /* P  C  I \0 */    \
} while (0)

/* Length of PCI registry path in WCHARs
   (including null-terminator) */
#define PCI_REG_PATH_LEN 52


/* Minimum byte size of
   a PCI vendor ID substring L"VEN_XXXX&" */
#define PCI_MIN_ID_SZ 18

/* Byte offset to the vendor ID part
   (skips L"VEN_" = 4 WCHARs = 8 bytes) */
#define PCI_SIG_OFFSET_SZ 8


/* PCI vendor IDs packed as Little-endian UINT64 (WCHAR) */

#define PCI_VENID_VBOX      0x0045004500300038ULL // L"80EE"
#define PCI_VENID_VMWARE    0x0044004100350031ULL // L"15AD"

#define PCI_VENID_QEMU      0x0034004600410031ULL // L"1AF4"
#define PCI_VENID_QEMU_BRG  0x0036003300420031ULL // L"1B36"
#define PCI_VENID_QEMU_VGA  0x0034003300320031ULL // L"1234"

#define PCI_VENID_XEN       0x0033003500380035ULL // L"5853"
#define PCI_VENID_HYPER_V   0x0034003100340031ULL // L"1414"
#define PCI_VENID_PARALLELS 0x0038004200410031ULL // L"1AB8"


/* Registry definitions (for NtEnumerateKey) */

typedef enum {
    KeyBasicInformation
} KEY_INFORMATION_CLASS;

typedef struct {
    LARGE_INTEGER    Reserved1; // LastWriteTime
    ULONG            Reserved2; // TitleIndex
    ULONG            NameLength;
    WCHAR            Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;




/**********************************
 *     ANTI-DEBUG DEFINITIONS     *
 **********************************/


/* Pre-API check of the KUSER_SHARED_DATA and PEB */
#define ADB_STAGE_PREAPI 1

/* Verification via Native API */
#define ADB_STAGE_NTAPI 2

/* Memory protection trap setup for the mapped image */
#define ADB_STAGE_GUARD 3




/***********************************
 *     NTDLL PARSING CONSTANTS     *
 ***********************************/


/* Size of L"ntdll.dll" in bytes */
#define NTDLL_NAME_SZ 18

/* Little-endian UINT64 (WCHAR) for L"ntdl" */
#define NTDLL_NAME_HASH 0x006C00640074006EULL

/* Bitmask to force lowercase via OR (|) */
#define NTDLL_NAME_FOLD_MASK 0x0020002000200020ULL




/*********************************************
 *     PRECOMPUTED NTDLL FUNCTION HASHES     *
 *********************************************/


/*
 * Script for generating hashes:
 * https://github.com/vk-candpython/peldr/blob/main/hash.py
*/


#define HASH_STR_SEED 1993U

#define HASH_NtTerminateProcess         0x596F6B0DU
#define HASH_NtClose                    0x98FDEA49U
#define HASH_NtAllocateVirtualMemory    0x34F08840U
#define HASH_NtProtectVirtualMemory     0xD4210E8CU
#define HASH_NtFreeVirtualMemory        0x80EF4D11U
#define HASH_NtOpenKey                  0x7F770326U
#define HASH_NtEnumerateKey             0xCE8F062AU
#define HASH_NtOpenFile                 0x77F8F075U
#define HASH_NtReadFile                 0x8ED84F11U
#define HASH_NtQueryInformationFile     0xDE09D22FU
#define HASH_NtQueryInformationProcess  0x4AAEEB8CU
#define HASH_LdrLoadDll                 0x2140CC9DU
#define HASH_LdrGetProcedureAddress     0xD39545C6U
#define HASH_RtlAddFunctionTable        0x2BB97A56U


/* NTDLL function entry for API hashing */
typedef struct {
    const DWORD     Hash; // Precomputed hash of function name
    PVOID          *Func; // Pointer to the resolved function pointer
} NT_PFUNC_ENTRY;




/**********************************
 *     INTERNAL NT STRUCTURES     *
 **********************************/


typedef struct {
    PVOID             Reserved1[2]; // InLoadOrderLinks
    LIST_ENTRY        InMemoryOrderLinks;
    PVOID             Reserved2[2]; // InInitializationOrderLinks
    PVOID             DllBase;
    PVOID             Reserved3[2]; // EntryPoint, SizeOfImage
    UNICODE_STRING    Reserved4;    // FullDllName
    UNICODE_STRING    BaseDllName;
} MN_LDR_DATA_TABLE_ENTRY;


typedef struct {
    ULONG    Reserved1[3]; // MaximumLength, Length, Flags
    ULONG    DebugFlags;
} *PMN_RTL_USER_PROCESS_PARAMETERS;

typedef struct {
    BYTE                               Reserved1[2]; // InheritedAddressSpace, ReadImageFileExecOptions
    BOOLEAN                            BeingDebugged;
    BYTE                               Reserved2[1]; // BitField
    PVOID                              Reserved3[1]; // Mutant
    PVOID                              ImageBaseAddress;
    PPEB_LDR_DATA                      Ldr;
    PMN_RTL_USER_PROCESS_PARAMETERS    ProcessParameters;
} MN_PEB, *PMN_PEB;




/*************************************
 *     NTDLL FUNCTION PROTOTYPES     *
 *************************************/


typedef NTSTATUS (NTAPI *NtTerminateProcess_t)(
    HANDLE      ProcessHandle,
    NTSTATUS    ExitStatus
);

typedef NTSTATUS (NTAPI *NtClose_t)(
    HANDLE    Handle
);


typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE        ProcessHandle,
    PVOID        *BaseAddress,
    ULONG_PTR     ZeroBits,
    PSIZE_T       RegionSize,
    ULONG         AllocationType,
    ULONG         PageProtection
);

typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    HANDLE      ProcessHandle,
    PVOID      *BaseAddress,
    PSIZE_T     RegionSize,
    ULONG       NewProtection,
    PULONG      OldProtection
);

typedef NTSTATUS (NTAPI *NtFreeVirtualMemory_t)(
    HANDLE      ProcessHandle,
    PVOID      *BaseAddress,
    PSIZE_T     RegionSize,
    ULONG       FreeType
);


typedef NTSTATUS (NTAPI *NtOpenKey_t)(
    PHANDLE               KeyHandle,
    ACCESS_MASK           DesiredAccess,
    POBJECT_ATTRIBUTES    ObjectAttributes
);

typedef NTSTATUS (NTAPI *NtEnumerateKey_t)(
    HANDLE                   KeyHandle,
    ULONG                    Index,
    KEY_INFORMATION_CLASS    KeyInformationClass,
    PVOID                    KeyInformation,
    ULONG                    Length,
    PULONG                   ResultLength
);


typedef NTSTATUS (NTAPI *NtOpenFile_t)(
    PHANDLE                     FileHandle,
    ACCESS_MASK                 DesiredAccess,
    const OBJECT_ATTRIBUTES    *ObjectAttributes,
    PIO_STATUS_BLOCK            IoStatusBlock,
    ULONG                       ShareAccess,
    ULONG                       OpenOptions
);

typedef NTSTATUS (NTAPI *NtReadFile_t)(
    HANDLE              FileHandle,
    HANDLE              Event,
    PIO_APC_ROUTINE     ApcRoutine,
    PVOID               ApcContext,
    PIO_STATUS_BLOCK    IoStatusBlock,
    PVOID               Buffer,
    ULONG               Length,
    PLARGE_INTEGER      ByteOffset,
    PULONG              Key
);

typedef NTSTATUS (NTAPI *NtQueryInformationFile_t)(
    HANDLE                    FileHandle,
    PIO_STATUS_BLOCK          IoStatusBlock,
    PVOID                     FileInformation,
    ULONG                     Length,
    FILE_INFORMATION_CLASS    FileInformationClass
);


typedef NTSTATUS (NTAPI *NtQueryInformationProcess_t)(
    HANDLE              ProcessHandle,
    PROCESSINFOCLASS    ProcessInformationClass,
    PVOID               ProcessInformation,
    ULONG               ProcessInformationLength,
    PULONG              ReturnLength
);


typedef NTSTATUS (NTAPI *LdrLoadDll_t)(
    PCWSTR               DllPath,
    PULONG               DllCharacteristics,
    PCUNICODE_STRING     DllName,
    PVOID               *DllHandle
);

typedef NTSTATUS (NTAPI *LdrGetProcedureAddress_t)(
    PVOID             DllHandle,
    PCANSI_STRING     ProcedureName,
    ULONG             ProcedureNumber,
    PVOID            *ProcedureAddress
);

typedef BOOLEAN (NTAPI *RtlAddFunctionTable_t)(
    PRUNTIME_FUNCTION    FunctionTable,
    ULONG                EntryCount,
    ULONG64              BaseAddress
);
