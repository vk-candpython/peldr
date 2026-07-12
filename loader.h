/*=================================*/
// [ OWNER ]
//     CREATOR  : Vladislav Khudash
//     AGE      : 17
//     LOCATION : Ukraine
//
// [ PINFO ]
//     DATE     : 12.07.2026
//     PROJECT  : PE-LOADER-HEADER
//     PLATFORM : WIN64
/*=================================*/




#pragma once


/* Compiler ASM intrinsics */
#include <intrin.h>

/* Native API environment
   and status codes */
#include <winternl.h>
#include <ntstatus.h>




/*=====/BUILD-TIME FEATURE CONFIGURATION\=====*/
#define USING_ANTI_VM/*------------>*/FALSE
#define USING_ANTI_DEBUG/*--------->*/FALSE
#define USING_ERASE_PE_HEADERS/*--->*/FALSE
/*==/END OF BUILD-TIME FEATURE CONFIGURATION\==*/




#define DAT_KEY_SZ sizeof(BYTE)   // Size of key size field (BYTE)
#define DAT_LEN_SZ sizeof(UINT32) // Size of length fields (UINT32)

#define RLE_MAX_RUN 127 // Maximum encoded run length
#define RLE_FLG_RUN 128 // High-bit marker for run blocks


#define NT_CUR_PROCESS ((HANDLE)-1LL) // Current process pseudo-handle

#define PAGE_SIZE 0x1000 // Standard memory page size

#define MAX_PATH_LEN 1024 // Maximum length of a full file path
#define MAX_NAME_LEN 128  // Maximum length of a module name

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




/* Const-qualified pointer helper
   (const data and const pointer) */
#define CONST_PTR(TYPE) \
    const TYPE *const


/* Function declaration helper */
#define DEC_FUNC(TYPE) \
    static inline __attribute__((always_inline, hot)) TYPE


/* Initialize OBJECT_ATTRIBUTES with case‑insensitive access */
#define DEC_OBJATTR_CASE_INSENSITIVE(pPath) {                 \
    .Length                   = sizeof(OBJECT_ATTRIBUTES),    \
    .RootDirectory            = NULL,                         \
    .ObjectName               = (pPath),                      \
    .Attributes               = OBJ_CASE_INSENSITIVE,         \
    .SecurityDescriptor       = NULL,                         \
    .SecurityQualityOfService = NULL                          \
}



/* Case‑folding mask for a single character */
#define ASCII_FOLD_MASK(sym) \
    ((((sym) - 'A') <= ('Z' - 'A')) << 5)


/* Convert RVA to typed pointer */
#define RVA(TYPE, base, addr) \
    ((TYPE)((PBYTE)(base) + (addr)))


/* Extract e_lfanew from DOS header */
#define DOS_LFANEW(base) \
    (((PIMAGE_DOS_HEADER)(base))->e_lfanew)


/* Number of relocation entries in a block */
#define RELOC_ENTRY_COUNT(blk)                              \
    (((blk)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)    \
     ) / sizeof(WORD))


/* True if relocation entry requests
   64-bit absolute fixup */
#define RELOC_IS_DIR64(entry) \
    (((entry) >> 12) == IMAGE_REL_BASED_DIR64)


/* Get intra‑page offset from relocation entry */
#define RELOC_BLK_OFFSET(entry) \
    ((entry) & 0x0FFF)


/* Extracts PE section protection index
   from Characteristics (bits 29–31) */
#define SECTION_PROT_IDX(c) \
    ((BYTE)(((c) & SECTION_PROT_MASK) >> 29))


/* Check if the PE image is a DLL */
#define PE_IS_DLL(hdFl) \
    ((BOOLEAN)((hdFl)->Characteristics & IMAGE_FILE_DLL))



/* Copy memory block */
#define MEMCPY(dst, src, sz) \
    __movsb((PBYTE)(dst), (const BYTE*)(src), (SIZE_T)(sz))


/* Fill memory with zeros */
#define ZEROS(dst, sz) \
    __stosb((PBYTE)(dst), 0, (SIZE_T)(sz))


/* Get current process PEB pointer */
#define GET_PTR_PEB() \
    ((PMN_PEB)__readgsqword(PEB64_GS_OFFSET))




/* ANTI-VM DEFINITIONS */

/* CPUID-based hypervisor detection */
#define AVM_STAGE_CPUID 1

/* PCI vendor ID scan via registry enumeration */
#define AVM_STAGE_PCI 2



/* Stage: CPUID definitions */

#define CPUID_REG_COUNT      4 // (EAX, EBX, ECX, EDX)
#define CPUID_LEAF_FEATURES  0x01
#define CPUID_REG_ECX        2
#define CPUID_HYPERVISOR_BIT 31



/* Stage: PCI definitions */

/* Registry key for PCI vendor enumeration:
L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\PCI" */
#define PCI_REG_KEY {L'\\',L'R',L'e',L'g',L'i',L's',L't',L'r',L'y',L'\\',L'M',L'a',L'c',L'h',L'i',L'n',L'e',L'\\',L'S',L'Y',L'S',L'T',L'E',L'M',L'\\',L'C',L'u',L'r',L'r',L'e',L'n',L't',L'C',L'o',L'n',L't',L'r',L'o',L'l',L'S',L'e',L't',L'\\',L'E',L'n',L'u',L'm',L'\\',L'P',L'C',L'I',L'\0'}


/* Minimum byte length of
   a PCI vendor key name L"VEN_XXXX&" */
#define PCI_MIN_NAME_LEN 18

/* Offset in WCHARs to
   the ID part of L"VEN_" */
#define PCI_SIG_OFFSET 4


/* PCI vendor IDs packed as Little-endian UINT64 (WCHAR) */
#define PCI_SIG_QEMU      0x0034004600410031ULL // 1A F4
#define PCI_SIG_VBOX      0x0045004500300038ULL // 80 EE
#define PCI_SIG_VMWARE    0x0044004100350031ULL // 15 AD
#define PCI_SIG_HYPER_V   0x0034003100340031ULL // 14 14
#define PCI_SIG_PARALLELS 0x0038004200410031ULL // 1A B8


typedef enum {
    KeyBasicInformation
} KEY_INFORMATION_CLASS;

typedef struct {
    LARGE_INTEGER    Reserved1; // LastWriteTime
    ULONG            Reserved2; // TitleIndex
    ULONG            NameLength;
    WCHAR            Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;




/* ANTI-DEBUGGING DEFINITIONS */

/* Pre-API check of the KUSER_SHARED_DATA and PEB */
#define ADB_STAGE_PREAPI 1

/* Verification via Native API */
#define ADB_STAGE_NTAPI 2

/* Memory protection trap setup for the mapped image */
#define ADB_STAGE_GUARD 3




/* NTDLL module name matching constants */
#define NTDLL_NAME_LEN  18                    // Size of L"ntdll.dll" in bytes
#define NTDLL_NAME_HASH 0x006C00640074006EULL // Little-endian UINT64 (WCHAR) for L"ntdl"
#define NTDLL_NAME_MASK 0x0020002000200020ULL // Bitmask to force lowercase via OR (|)




/* Precomputed NTDLL function hashes
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
} NT_FUNC_ENTRY;




/* Internal NT loader structures */

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




typedef BOOL (WINAPI *DllMain_t)(
    HINSTANCE    hinstDLL,
    DWORD        fdwReason,
    LPVOID       lpvReserved
);




/* NTDLL function prototypes */

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
