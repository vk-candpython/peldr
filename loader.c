/*====================================*/
// [ OWNER ]
//     CREATOR  : Vladislav Khudash
//     AGE      : 17
//     LOCATION : Ukraine
//
// [ PINFO ]
//     DATE     : 12.07.2026
//     PROJECT  : REFLECTIVE-PE-LOADER
//     PLATFORM : WIN64
/*====================================*/




/* REQUIREMENTS (
       compiler : MinGW-w64 (w64devkit: https://github.com/niXman/mingw-builds-binaries/releases)
       for-file : PE32+
   )


https://github.com/vk-candpython/peldr/blob/main/loader.h

INTERNAL LOADER DECLARATIONS */
#include "loader.h"




/* Compile-time validation of feature flags */

#define _FLAG_IS_BOOLEAN(FLAG) _Static_assert(                     \
    ((FLAG) == FALSE) || ((FLAG) == TRUE),                         \
    "Build flag: '" #FLAG "', must be either (FALSE) or (TRUE)"    \
)


_FLAG_IS_BOOLEAN(  USING_ANTI_VM           );
_FLAG_IS_BOOLEAN(  USING_ANTI_DEBUG        );
_FLAG_IS_BOOLEAN(  USING_ERASE_PE_HEADERS  );


#undef _FLAG_IS_BOOLEAN




/* Function pointers resolved from NTDLL exports */

static  NtTerminateProcess_t         pNtTerminateProcess         ;
static  NtClose_t                    pNtClose                    ;

static  NtAllocateVirtualMemory_t    pNtAllocateVirtualMemory    ;
static  NtProtectVirtualMemory_t     pNtProtectVirtualMemory     ;
static  NtFreeVirtualMemory_t        pNtFreeVirtualMemory        ;

#if (USING_ANTI_VM)
static  NtOpenKey_t                  pNtOpenKey                  ;
static  NtEnumerateKey_t             pNtEnumerateKey             ;
#endif

static  NtOpenFile_t                 pNtOpenFile                 ;
static  NtReadFile_t                 pNtReadFile                 ;
static  NtQueryInformationFile_t     pNtQueryInformationFile     ;

static  NtQueryInformationProcess_t  pNtQueryInformationProcess  ;

static  LdrLoadDll_t                 pLdrLoadDll                 ;
static  LdrGetProcedureAddress_t     pLdrGetProcedureAddress     ;
static  RtlAddFunctionTable_t        pRtlAddFunctionTable        ;




/* Terminate current process with status code */
#define NT_EXIT(s) \
    pNtTerminateProcess(NT_CUR_PROCESS, (s))


/* Universal NT String Initializer
   using compiler type deduction */
#define NT_INIT_STR(dst, src) do {                           \
    typeof(dst) _d = (dst);                                  \
    typeof(src) _s = (src);                                  \
    typeof(src) _p = _s;                                     \
                                                             \
    while (*_p) ++_p;                                        \
    const USHORT _ln = (USHORT)((_p - _s) * sizeof(*_s));    \
                                                             \
    _d->Buffer        = (typeof(_d->Buffer))_s;              \
    _d->Length        = _ln;                                 \
    _d->MaximumLength = _ln + sizeof(*_s);                   \
} while (0)




/* Calculate case-insensitive string hash */
DEC_FUNC(DWORD) HashStr(PCSTR s) {
    DWORD h = HASH_STR_SEED;
    BYTE  c;


    while ((c = (BYTE)*s++)) {
        /* ASCII case-folding */
        c |= ASCII_FOLD_MASK(c);

        /* DJB15 iterative hash step */
        h = ((h << 4) - h) + c;
    }


    return h;
}




/* Get NTDLL base address from PEB module list */
DEC_FUNC(HMODULE) GetNtdllAddr(CONST_PTR(MN_PEB) peb) {
    CONST_PTR(LIST_ENTRY) mdl = &peb->Ldr->InMemoryOrderModuleList;


    for (const LIST_ENTRY *e = mdl->Flink;  e != mdl;  e = e->Flink) {
        CONST_PTR(MN_LDR_DATA_TABLE_ENTRY) rc =
            CONTAINING_RECORD(e, MN_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);


        if (rc->BaseDllName.Length == NTDLL_NAME_LEN) {
            /* Read first 8 bytes of DLL name as hash/integer */
            const UINT64 nm = *(PUINT64)rc->BaseDllName.Buffer;

            if ((nm | NTDLL_NAME_MASK) == NTDLL_NAME_HASH)
                return (HMODULE)rc->DllBase;
        }
    }


    return NULL;
}




/* Resolve NTDLL exports
   and initialize function table */
DEC_FUNC(BOOLEAN) InitNtdllFunctions(
    const HMODULE                   hmd,
    CONST_PTR(IMAGE_DATA_DIRECTORY) exdr,
    NT_FUNC_ENTRY *const            ent,
    const BYTE                      eSz
) {
    const DWORD exBeg = exdr->VirtualAddress,
                exEnd = exBeg + exdr->Size;

    CONST_PTR(IMAGE_EXPORT_DIRECTORY) extb =
        RVA(PIMAGE_EXPORT_DIRECTORY, hmd, exBeg);


    CONST_PTR(DWORD) func = RVA(PDWORD, hmd, extb->AddressOfFunctions   );
    const     DWORD *addr = RVA(PDWORD, hmd, extb->AddressOfNames       );
    const     WORD  *ordd = RVA(PWORD,  hmd, extb->AddressOfNameOrdinals);


    CONST_PTR(DWORD) addrEnd = addr + extb->NumberOfNames;
    BYTE             left    = eSz;

    for (;  left && (addr < addrEnd);  addr++, ordd++) {
        const DWORD hs = HashStr(RVA(PCSTR, hmd, *addr));

        for (BYTE j = 0;  j < eSz;  j++) {
            if (ent[j].Hash != hs) continue;


            const DWORD frv = func[*ordd];

            /* Forwarded exports are not supported */
            if ((frv >= exBeg) && (frv < exEnd))
                return FALSE;


            /* Store resolved function address */
            *ent[j].Func = RVA(PVOID, hmd, frv);

            --left;
            break;
        }
    }


    /* TRUE if all functions resolved */
    return !left;
}




/* Initialize required NTDLL exports from the PEB */
DEC_FUNC(BOOLEAN) InitNtdApi(HMODULE *hNtdll, CONST_PTR(MN_PEB) peb) {
    const HMODULE h = GetNtdllAddr(peb);
    if (!h) return FALSE;

    /* Save NTDLL handle */
    *hNtdll = h;


    CONST_PTR(IMAGE_NT_HEADERS64) hdNt =
        RVA(PIMAGE_NT_HEADERS64, h, DOS_LFANEW(h));

    CONST_PTR(IMAGE_DATA_DIRECTORY) exdr =
        &hdNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];


    NT_FUNC_ENTRY ent[] = {
{ HASH_NtTerminateProcess        , (PVOID*)&pNtTerminateProcess        },
{ HASH_NtClose                   , (PVOID*)&pNtClose                   },

{ HASH_NtAllocateVirtualMemory   , (PVOID*)&pNtAllocateVirtualMemory   },
{ HASH_NtProtectVirtualMemory    , (PVOID*)&pNtProtectVirtualMemory    },
{ HASH_NtFreeVirtualMemory       , (PVOID*)&pNtFreeVirtualMemory       },

#if (USING_ANTI_VM)
{ HASH_NtOpenKey                 , (PVOID*)&pNtOpenKey                 },
{ HASH_NtEnumerateKey            , (PVOID*)&pNtEnumerateKey            },
#endif

{ HASH_NtOpenFile                , (PVOID*)&pNtOpenFile                },
{ HASH_NtReadFile                , (PVOID*)&pNtReadFile                },
{ HASH_NtQueryInformationFile    , (PVOID*)&pNtQueryInformationFile    },

{ HASH_NtQueryInformationProcess , (PVOID*)&pNtQueryInformationProcess },

{ HASH_LdrLoadDll                , (PVOID*)&pLdrLoadDll                },
{ HASH_LdrGetProcedureAddress    , (PVOID*)&pLdrGetProcedureAddress    },
{ HASH_RtlAddFunctionTable       , (PVOID*)&pRtlAddFunctionTable       },
    };


    return InitNtdllFunctions(h, exdr, ent, sizeof(ent) / sizeof(*ent));
}




/* Load a DLL via LdrLoadDll */
DEC_FUNC(HMODULE) LoadDll(PCWSTR nm) {
    PVOID          h = NULL;
    UNICODE_STRING s;

    NT_INIT_STR(&s, nm);

    pLdrLoadDll(NULL, NULL, &s, &h);
    return (HMODULE)h;
}


/* Resolve exported procedure address */
DEC_FUNC(FARPROC) GetProcedureAddr(
    const HMODULE hmd,
    PCSTR         nm,
    const ULONG   ord
) {
    PVOID p = NULL;

    if (ord) {
        pLdrGetProcedureAddress(hmd, NULL, ord, &p);
    }
    else {
        ANSI_STRING s;
        NT_INIT_STR(&s, nm);
        pLdrGetProcedureAddress(hmd, &s, 0, &p);
    }

    return (FARPROC)p;
}




/* Copy PE image data into allocated memory */
DEC_FUNC(VOID) CopyImageData(
    const PVOID                   img,
    const PVOID                   buf,
    CONST_PTR(IMAGE_NT_HEADERS64) hdNt
) {
    /* Copy PE headers */
    MEMCPY(img, buf, hdNt->OptionalHeader.SizeOfHeaders);


    const IMAGE_SECTION_HEADER *sn =
        IMAGE_FIRST_SECTION(hdNt);

    CONST_PTR(IMAGE_SECTION_HEADER) se =
        sn + hdNt->FileHeader.NumberOfSections;

    /* Copy each section */
    for (;  sn < se;  sn++) {
        const DWORD vrSz = sn->Misc.VirtualSize,
                    rwSz = sn->SizeOfRawData;

        /* Skip virtual-only sections
           with no data */
        if (!vrSz) continue;


        const PVOID     dst = RVA(PVOID, img, sn->VirtualAddress  );
        CONST_PTR(VOID) src = RVA(PVOID, buf, sn->PointerToRawData);
        const DWORD     sz  = min(vrSz, rwSz);


        /* Copy section data to image */
        if (sz) MEMCPY(dst, src, sz);

        /* Zero out the rest of the section */
        if (vrSz > rwSz) ZEROS((PBYTE)dst + rwSz, vrSz - rwSz);
    }
}




/* Apply base relocations to the mapped image */
DEC_FUNC(VOID) ApplyImageRelocations(
    const PVOID                        img,
    CONST_PTR(IMAGE_OPTIONAL_HEADER64) hdOpt
) {
    /* Relocation delta actual
       load address offset from ImageBase */
    const ULONGLONG dlt = (ULONGLONG)img - hdOpt->ImageBase;


    CONST_PTR(IMAGE_DATA_DIRECTORY) ldr =
        &hdOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    /* Skip if no base relocation table is present */
    if (!ldr->VirtualAddress) return;


    const IMAGE_BASE_RELOCATION *rl =
        RVA(PIMAGE_BASE_RELOCATION, img, ldr->VirtualAddress);

    CONST_PTR(IMAGE_BASE_RELOCATION) rlEnd =
        RVA(PIMAGE_BASE_RELOCATION, rl, ldr->Size);


    /* Process each relocation block */
    while (rl < rlEnd) {
        const PBYTE     blkVA = RVA(PBYTE, img, rl->VirtualAddress);
        const WORD     *it    = (PWORD)(rl + 1);
        CONST_PTR(WORD) itEnd = it + RELOC_ENTRY_COUNT(rl);


        /* Apply all fixups in this block */
        for (;  it < itEnd;  it++)
            if (RELOC_IS_DIR64(*it)) *(PULONGLONG)(
                blkVA + RELOC_BLK_OFFSET(*it)
            ) += dlt;


        /* Advance to next relocation block */
        rl = RVA(PIMAGE_BASE_RELOCATION, rl, rl->SizeOfBlock);
    }
}




/* Resolve imports for the mapped image */
DEC_FUNC(BOOLEAN) ProcessImageImports(
    const PVOID                        img,
    CONST_PTR(IMAGE_OPTIONAL_HEADER64) hdOpt
) {
    CONST_PTR(IMAGE_DATA_DIRECTORY) imdr =
        &hdOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    /* No imports to process */
    if (!imdr->VirtualAddress) return TRUE;


    const IMAGE_IMPORT_DESCRIPTOR *ids =
        RVA(PIMAGE_IMPORT_DESCRIPTOR, img, imdr->VirtualAddress);


    WCHAR libName[MAX_NAME_LEN];

    while (ids->Name) {
    {//* INITIALIZE LIBRARY NAME
        const CHAR *_s = RVA(PCHAR, img, ids->Name);
        PWCHAR      _p = libName;

        while (*_s) *_p++ = (WCHAR)*_s++;
        *_p = L'\0';
    }//* INITIALIZE LIBRARY NAME


        const HMODULE hLib = LoadDll((PCWSTR)libName);
        if (!hLib) return FALSE;
        const DWORD   lAtr = ids->Characteristics;


        IMAGE_THUNK_DATA
            *tnk = RVA(PIMAGE_THUNK_DATA, img, ids->FirstThunk),
            *otk = lAtr? RVA(PIMAGE_THUNK_DATA, img, lAtr) : tnk;


        /* Resolve each import thunk pair */
        while (tnk->u1.AddressOfData && otk->u1.AddressOfData)
    {//* while
        /* Resolve by ordinal */
        if (otk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
            const ULONG fOrd = (ULONG)((UINT16)otk->u1.Ordinal);

            const FARPROC fAdr = GetProcedureAddr(hLib, NULL, fOrd);
            if (!fAdr) return FALSE;

            tnk->u1.Function = (ULONGLONG)fAdr;
        }
        /* Resolve by name */
        else {
            CONST_PTR(IMAGE_IMPORT_BY_NAME) fnm =
                RVA(PIMAGE_IMPORT_BY_NAME, img, otk->u1.AddressOfData);

            const FARPROC fAdr = GetProcedureAddr(hLib, (PCSTR)fnm->Name, 0);
            if (!fAdr) return FALSE;

            tnk->u1.Function = (ULONGLONG)fAdr;
        }

        ++tnk; ++otk;
    }//* end of while
        ++ids;
    }


    return TRUE;
}




/* Register exception handlers for the mapped image */
DEC_FUNC(BOOLEAN) InitImageExceptionTable(
    const PVOID                        img,
    CONST_PTR(IMAGE_OPTIONAL_HEADER64) hdOpt
) {
    CONST_PTR(IMAGE_DATA_DIRECTORY) ldr =
        &hdOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];


    if (ldr->VirtualAddress)
        return pRtlAddFunctionTable(
            RVA(PRUNTIME_FUNCTION, img, ldr->VirtualAddress),
            (ULONG)(ldr->Size / sizeof(RUNTIME_FUNCTION)),
            (ULONG64)img
        );

    return TRUE;
}




/* Initialize security cookie from load config */
DEC_FUNC(VOID) InitImageSecurityCookie(
    const PVOID                        img,
    CONST_PTR(IMAGE_OPTIONAL_HEADER64) hdOpt
) {
    CONST_PTR(IMAGE_DATA_DIRECTORY) lcd =
        &hdOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

    /* No load config to process */
    if (!lcd->VirtualAddress) return;


    CONST_PTR(IMAGE_LOAD_CONFIG_DIRECTORY64) lc =
        RVA(PIMAGE_LOAD_CONFIG_DIRECTORY64, img, lcd->VirtualAddress);

    if (lc->SecurityCookie) {
        PULONGLONG ckAdr = (PULONGLONG)lc->SecurityCookie;
        *ckAdr = (ULONGLONG)img ^ *(volatile const ULONGLONG*)KUSER_INTERRUPT_TIME;
    }
}




/* Set memory protection for image sections */
DEC_FUNC(BOOLEAN) SetImageSectionsPermission(
    const PVOID                   img,
    CONST_PTR(IMAGE_NT_HEADERS64) hdNt
) {
{//* Protect PE headers as read-only
    ULONG  hdOlp;
    PVOID  hdAdr = img;
    SIZE_T hdSz  = (SIZE_T)hdNt->OptionalHeader.SizeOfHeaders;

    if (pNtProtectVirtualMemory(NT_CUR_PROCESS,
        &hdAdr, &hdSz, PAGE_READONLY, &hdOlp)
    ) return FALSE;
}//* PE headers



    /* Section permission lookup table */
    const ULONG ProtTab[] = {
        PAGE_NOACCESS,     PAGE_EXECUTE,
        PAGE_READONLY,     PAGE_EXECUTE_READ,
        PAGE_READWRITE,    PAGE_EXECUTE_READWRITE,
        PAGE_READWRITE,    PAGE_EXECUTE_READWRITE
    };


    const IMAGE_SECTION_HEADER *scCur =
        IMAGE_FIRST_SECTION(hdNt);

    CONST_PTR(IMAGE_SECTION_HEADER) scEnd =
        scCur + hdNt->FileHeader.NumberOfSections;


    /* Apply protection to each section */
    for (;  scCur < scEnd;  scCur++) {
        ULONG  olp;
        SIZE_T vsz = (SIZE_T)scCur->Misc.VirtualSize;
        PVOID  adr = RVA(PVOID, img, scCur->VirtualAddress);

        const BYTE idx = SECTION_PROT_IDX(scCur->Characteristics);

        if (pNtProtectVirtualMemory(NT_CUR_PROCESS,
            &adr, &vsz, ProtTab[idx], &olp)
        ) return FALSE;
    }



    /* All permissions applied */
    return TRUE;
}




/* Execute TLS callbacks from PE image (if present) */
DEC_FUNC(VOID) ExecuteImageTLS(
    const PVOID                        img,
    CONST_PTR(IMAGE_OPTIONAL_HEADER64) hdOpt
) {
    CONST_PTR(IMAGE_DATA_DIRECTORY) tdr =
        &hdOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

    /* Skip if TLS directory is missing */
    if (!tdr->VirtualAddress) return;


    CONST_PTR(IMAGE_TLS_DIRECTORY64) tls =
        RVA(PIMAGE_TLS_DIRECTORY64, img, tdr->VirtualAddress);

    if (!tls->AddressOfCallBacks) return;


    PIMAGE_TLS_CALLBACK *fcb =
        (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;

    /* Invoke each callback */
    while (*fcb) (*fcb++)(img, DLL_PROCESS_ATTACH, NULL);
}




/* Stateful byte mixing (keyed XOR + rotation + state update) */
#define DEC_BYTE(b, idx, stt, key, msk) ({                  \
    const UINT32 _j   =  (*(idx))++;                        \
    const BYTE   _s   =  *(stt);                            \
                                                            \
    const BYTE   _k1  =  (key)[ _j       & (msk)];          \
    const BYTE   _k2  =  (key)[(_j >> 3) & (msk)];          \
                                                            \
    const BYTE   _y   =  ((_k1 << 1) | (     _k2 >> 7))     \
                      ^  ((BYTE)_j   ^ (BYTE)(_j >> 8));    \
    const BYTE   _m   =  _y ^ (_y >> 4);                    \
                                                            \
    const BYTE   _v   =  ((b) ^ _m) - (_s ^ _k1);           \
    const BYTE   _r   =  _rotr8(_v, 3);                     \
                                                            \
    *(stt)            =  (_r + _k2) ^ (_s >> 1);            \
                                                            \
    /* Return decrypt byte */                               \
    _r;                                                     \
})


/* Decode encrypted RLE-compressed data */
DEC_FUNC(VOID) UnPackData(
    PBYTE           dst, const UINT32 dstSz,
    const BYTE     *src, const UINT32 srcSz,
    CONST_PTR(BYTE) key, const BYTE   msk
) {
    UINT32 idx = 0;
    BYTE   stt = *key;

    CONST_PTR(BYTE) dstEnd = dst + dstSz;
    CONST_PTR(BYTE) srcEnd = src + srcSz;

    BYTE l;


    while ((dst < dstEnd) && (src < srcEnd)) {
        const BYTE c = DEC_BYTE(*src++, &idx, &stt, key, msk);

        if (c & RLE_FLG_RUN) {
            if (src >= srcEnd) return;

            l = c & RLE_MAX_RUN;
            const BYTE v = DEC_BYTE(*src++, &idx, &stt, key, msk);

            while (l-- && (dst < dstEnd))
                *dst++ = v;
        }
        else {
            if (c > (srcEnd - src)) return;

            l = c;

            while (l-- && (dst < dstEnd))
                *dst++ = DEC_BYTE(*src++, &idx, &stt, key, msk);
        }
    }
}




/* Release and nullify a virtual memory buffer */
DEC_FUNC(VOID) FreeBuf(PVOID *buf) {
    SIZE_T zr = 0;
    pNtFreeVirtualMemory(NT_CUR_PROCESS, buf, &zr, MEM_RELEASE);
    *buf = NULL;
}




/* Extracts the appended payload overlay
   from the current process image file */
DEC_FUNC(const BYTE*) ReadOverLay(VOID) {
    /* Initialize with size marker length
       for the initial read */
    UINT32 tlLn = DAT_LEN_SZ;


    PVOID           buf   = NULL;
    HANDLE          hFile = NULL;
    PUNICODE_STRING fPath;


    BYTE  pthBuf[MAX_PATH_LEN + sizeof(UNICODE_STRING)];
    ULONG pthBln;



    /* Retrieve the native NT path
       of the current executable */
    if (pNtQueryInformationProcess(
        NT_CUR_PROCESS, ProcessImageFileName,
        pthBuf, sizeof(pthBuf), &pthBln
    )) goto _ret;

    fPath = (PUNICODE_STRING)pthBuf;



    IO_STATUS_BLOCK   io;
    OBJECT_ATTRIBUTES attr = DEC_OBJATTR_CASE_INSENSITIVE(fPath);


    if (pNtOpenFile(
        &hFile,
        FILE_READ_DATA|SYNCHRONIZE,
        &attr, &io,
        FILE_SHARE_READ,
        FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE
    )) goto _ret;



    FILE_STANDARD_INFORMATION fsi;

    if (pNtQueryInformationFile(
        hFile,
        &io, &fsi, sizeof(fsi),
        FileStandardInformation
    )) goto _ret;


    UINT32 fSz = (UINT32)fsi.EndOfFile.QuadPart;

    /* Enforce minimum size for a valid PE image */
    if (fSz < (sizeof(IMAGE_DOS_HEADER) +
               sizeof(IMAGE_NT_HEADERS64))
    ) goto _ret;


    /* Calculate file offset
       to the beginning of the encrypted data */
    LARGE_INTEGER offS = {.QuadPart = (LONGLONG)(fSz - tlLn)};

    /* Read overlay data length directly
       into the length variable */
    if (pNtReadFile(
        hFile,
        NULL, NULL, NULL,
        &io,  &tlLn,
        tlLn, &offS,
        NULL
    )) goto _ret;


    /* Account for the size marker itself
       and verify bounds */
    tlLn += DAT_LEN_SZ;
    if (tlLn > fSz) goto _ret;



    /* Allocate virtual memory buffer
       to hold the complete overlay structure */
    SIZE_T bsz = (SIZE_T)tlLn;

    if (pNtAllocateVirtualMemory(
        NT_CUR_PROCESS,
        &buf, 0, &bsz,
        NT_ALLOC_FLG,
        PAGE_READWRITE
    )) goto _ret;

    /* Store overlay size at buffer start
       for unpacker parsing */
    *(PUINT32)buf = tlLn;



    /* Reset the file offset
       to the beginning of the complete overlay data */
    offS.QuadPart = (LONGLONG)(fSz - tlLn);

    /* Read the remainder of the payload from disk,
       skipping the total length header slot */
    if (pNtReadFile(
        hFile,
        NULL, NULL, NULL,
        &io,               (PBYTE)buf + DAT_LEN_SZ,
        tlLn - DAT_LEN_SZ, &offS,
        NULL
    )) FreeBuf(&buf);



    _ret:
        if (hFile) pNtClose(hFile);
        return (const BYTE*)buf;
}




/* Anti-VM Engine:
   Returns TRUE if virtual machine is DETECTED */
#if (USING_ANTI_VM)
DEC_FUNC(BOOLEAN) AntiVmStage(const BYTE stage) {
    /* CPUID hypervisor present bit check */
    if (stage == AVM_STAGE_CPUID) {
        INT regs[CPUID_REG_COUNT];

        __cpuid(regs, CPUID_LEAF_FEATURES);

        return _bittest(
            (const LONG*)&regs[CPUID_REG_ECX],
            CPUID_HYPERVISOR_BIT
        );
    }
    /* PCI vendor enumeration via registry */
    else if (stage == AVM_STAGE_PCI) {
        const WCHAR PciKey[] = PCI_REG_KEY;


        UNICODE_STRING PciPath = {
            .Length        = sizeof(PciKey) - sizeof(WCHAR),
            .MaximumLength = sizeof(PciKey),
            .Buffer        = (PWSTR)PciKey
        };

        OBJECT_ATTRIBUTES attr = DEC_OBJATTR_CASE_INSENSITIVE(&PciPath);


        HANDLE hPci = NULL;

        /* Assume VM if PCI key cannot be opened */
        if (pNtOpenKey(&hPci, KEY_ENUMERATE_SUB_KEYS, &attr))
            return TRUE;


        BYTE  buf[MAX_NAME_LEN + sizeof(KEY_BASIC_INFORMATION)];
        ULONG bln;

        /* Enumerate PCI keys
           and match known VM vendor IDs */
        for (ULONG idx = 0;  ;  idx++) {
            if (pNtEnumerateKey(
                hPci, idx,
                KeyBasicInformation,
                buf, sizeof(buf), &bln
            )) break;


            CONST_PTR(KEY_BASIC_INFORMATION) pKey =
                (PKEY_BASIC_INFORMATION)buf;

            if (pKey->NameLength < PCI_MIN_NAME_LEN)
                continue;


            /* Extract vendor ID as UINT64 */
            const UINT64 venId = *(PUINT64)(
                pKey->Name + PCI_SIG_OFFSET);

            switch (venId) {
                case PCI_SIG_QEMU      :
                case PCI_SIG_VBOX      :
                case PCI_SIG_VMWARE    :
                case PCI_SIG_HYPER_V   :
                case PCI_SIG_PARALLELS :
                    pNtClose(hPci);
                    return TRUE;
            }
        }


        pNtClose(hPci);
        return FALSE;
    }
    /* Unknown stage interpreted as anomaly */
    return TRUE;
}
#endif




/* Anti-Debug Engine:
   Returns TRUE if debug/anomaly is DETECTED */
#if (USING_ANTI_DEBUG)
DEC_FUNC(BOOLEAN) AntiDebugStage(
    const BYTE        stage,
    CONST_PTR(MN_PEB) peb,
    const PVOID       img
) {
    /* Pre-API Raw Structures Check */
    if (stage == ADB_STAGE_PREAPI) {
        return
            *(volatile const BOOLEAN*)KUSER_KD_DEBUGGER_ENABLED
            ||
            peb->BeingDebugged ||
            peb->ProcessParameters->DebugFlags
        ;
    }
    /* Native API Checks */
    else if (stage == ADB_STAGE_NTAPI) {
        HANDLE prt, hdl;

        /* Assume Debugger if cannot be queried */

        pNtQueryInformationProcess(
            NT_CUR_PROCESS, ProcessDebugPort,
            &prt, sizeof(prt), NULL
        );

        pNtQueryInformationProcess(
            NT_CUR_PROCESS, ProcessDebugObjectHandle,
            &hdl, sizeof(hdl), NULL
        );


        return prt || hdl;
    }
    /* Memory Protection Trap Setup */
    else if (stage == ADB_STAGE_GUARD) {
        PVOID  gAdr = img;
        SIZE_T gSz  = PAGE_GUARD_SIZE;
        ULONG  gOlp;

        return pNtProtectVirtualMemory(
            NT_CUR_PROCESS,
            &gAdr, &gSz,
            PAGE_NOACCESS,
            &gOlp
        ) != STATUS_SUCCESS;
    }
    /* Unknown stage interpreted as anomaly */
    return TRUE;
}
#endif




/*
/==================\
 LOADER-ENTRY-POINT
/==================\
*/
NTSTATUS Main(VOID) {
    ULONGLONG AddrOfEntryPoint;

{//* MAIN
    PMN_PEB peb = GET_PTR_PEB();


#if (USING_ANTI_DEBUG)
    if (AntiDebugStage(ADB_STAGE_PREAPI, peb, NULL))
        return STATUS_ACCESS_VIOLATION;
#endif

#if (USING_ANTI_VM)
    if (AntiVmStage(AVM_STAGE_CPUID))
        return STATUS_NOT_SUPPORTED;
#endif



    HMODULE hNtdll;

    if (!InitNtdApi(&hNtdll, peb))
        return STATUS_DLL_NOT_FOUND;


#if (USING_ANTI_DEBUG)
{//* Verify PEB Integrity
    PROCESS_BASIC_INFORMATION pbi;

    pNtQueryInformationProcess(
        NT_CUR_PROCESS, ProcessBasicInformation,
        &pbi, sizeof(pbi), NULL
    );

    if ((PVOID)pbi.PebBaseAddress != (PVOID)peb)
        /* Integrity violation detected */
        NT_EXIT(STATUS_INVALID_PARAMETER);
}//* PEB

    if (AntiDebugStage(ADB_STAGE_NTAPI, NULL, NULL))
        NT_EXIT(STATUS_ACCESS_VIOLATION);
#endif

#if (USING_ANTI_VM)
    if (AntiVmStage(AVM_STAGE_PCI))
        NT_EXIT(STATUS_NOT_SUPPORTED);
#endif



    /* Overlay layout
        1: total_len : DAT_LEN_SZ
        2: key_size  : DAT_KEY_SZ
        3: key       : PE_KEY
        4: raw_len   : DAT_LEN_SZ
        5: payload   : PE_EXE
    */
    const BYTE *PE_DAT = ReadOverLay();
    if (!PE_DAT) NT_EXIT(STATUS_FILE_CORRUPT_ERROR);


    const UINT32 PE_DAT_SZ = *(PUINT32)PE_DAT;
    const BYTE   PE_KEY_SZ = *(PE_DAT + DAT_LEN_SZ);


    const UINT32 RW_EXE_SZ = *(PUINT32)(
        (PE_DAT     + DAT_LEN_SZ) +
        (DAT_KEY_SZ + PE_KEY_SZ )
    );

    const UINT32 DT_EXE_SZ = PE_DAT_SZ - (
        (DAT_LEN_SZ + DAT_KEY_SZ) +
        (PE_KEY_SZ  + DAT_LEN_SZ)
    );

    const UINT32 PE_EXE_SZ = max(DT_EXE_SZ, RW_EXE_SZ);


    const BYTE
        *PE_KEY = (PBYTE)(PE_DAT + (DAT_LEN_SZ + DAT_KEY_SZ)),
        *PE_EXE = (PBYTE)(PE_KEY + (PE_KEY_SZ  + DAT_LEN_SZ));



    PVOID buf = NULL;
{//* ALLOCATE DATA BUFFER
    SIZE_T bsz = (SIZE_T)PE_EXE_SZ;

    if (pNtAllocateVirtualMemory(
        NT_CUR_PROCESS,
        &buf, 0, &bsz,
        NT_ALLOC_FLG,
        PAGE_READWRITE
    )) NT_EXIT(STATUS_MEMORY_NOT_ALLOCATED);


    UnPackData(
        (PBYTE)buf, PE_EXE_SZ,
        PE_EXE,     DT_EXE_SZ,
        PE_KEY,     PE_KEY_SZ - 1 // Key size to mask for power-of-two indexing
    );

    /* Release unpacked file data buffer */
    FreeBuf((PVOID*)&PE_DAT);
}//* ALLOCATE DATA BUFFER



    CONST_PTR(IMAGE_NT_HEADERS64) hdNt =
        RVA(PIMAGE_NT_HEADERS64, buf, DOS_LFANEW(buf));

    CONST_PTR(IMAGE_OPTIONAL_HEADER64) hdOpt =
        &hdNt->OptionalHeader;


    const BOOLEAN IS_DLL_IMAGE = PE_IS_DLL(&hdNt->FileHeader);



    PVOID img = NULL;
{//* ALLOCATE IMAGE
    SIZE_T isz = (SIZE_T)(PAGE_GUARD_SIZE + hdOpt->SizeOfImage);

    if (pNtAllocateVirtualMemory(
        NT_CUR_PROCESS,
        &img, 0, &isz,
        NT_ALLOC_FLG,
        PAGE_READWRITE
    )) NT_EXIT(STATUS_MEMORY_NOT_ALLOCATED);
}//* ALLOCATE IMAGE


#if (USING_ANTI_DEBUG)
    if (AntiDebugStage(ADB_STAGE_GUARD, NULL, img))
        NT_EXIT(STATUS_ACCESS_VIOLATION);
#endif



    /* Advance past guard page to image base */
    img = RVA(PVOID, img, PAGE_GUARD_SIZE);


    CopyImageData(img, buf, hdNt);
    ApplyImageRelocations(img, hdOpt);

    if (!ProcessImageImports(img, hdOpt))
        NT_EXIT(STATUS_INVALID_IMAGE_FORMAT);

    if (!InitImageExceptionTable(img, hdOpt))
        NT_EXIT(STATUS_UNHANDLED_EXCEPTION);

    InitImageSecurityCookie(img, hdOpt);


    /* Update PEB with new image base */
    peb->ImageBaseAddress = img;



#if (USING_ERASE_PE_HEADERS)
{//* ERASE PE HEADERS
    PIMAGE_NT_HEADERS64 _nt =
        RVA(PIMAGE_NT_HEADERS64, img, DOS_LFANEW(img));

    ZEROS(img, _nt->OptionalHeader.SizeOfHeaders);
}//* ERASE PE HEADERS
#endif



    if (!SetImageSectionsPermission(img, hdNt))
        NT_EXIT(STATUS_SECTION_PROTECTION);


    /* Calculate entry point virtual address */
    AddrOfEntryPoint = RVA(ULONGLONG, img, hdOpt->AddressOfEntryPoint);


    ExecuteImageTLS(img, hdOpt);



    /* Release unpacked image buffer */
    FreeBuf(&buf);


    /* Scrub resolved function pointers from memory */

    pNtClose                   = NULL;

    pNtAllocateVirtualMemory   = NULL;
    pNtProtectVirtualMemory    = NULL;
    pNtFreeVirtualMemory       = NULL;

#if (USING_ANTI_VM)
    pNtOpenKey                 = NULL;
    pNtEnumerateKey            = NULL;
#endif

    pNtOpenFile                = NULL;
    pNtReadFile                = NULL;
    pNtQueryInformationFile    = NULL;

    pNtQueryInformationProcess = NULL;

    pLdrLoadDll                = NULL;
    pLdrGetProcedureAddress    = NULL;
    pRtlAddFunctionTable       = NULL;



    /* Call DllMain for DLL images */
    if (IS_DLL_IMAGE) NT_EXIT((

        ((DllMain_t)AddrOfEntryPoint)(
            (HINSTANCE)img, DLL_PROCESS_ATTACH, NULL)

    )? STATUS_SUCCESS : STATUS_DLL_INIT_FAILED);



    pNtTerminateProcess = NULL;
}//* MAIN

    /* Transfer control to the loaded executable */
    __asm__ volatile (
        "andq $-16, %%rsp\n\t" // Align stack to 16-byte boundary
        "subq $40,  %%rsp\n\t" // Reserve 32-byte shadow space + 8 for alignment

        "jmpq *%0\n\t"         // Jump to the loaded image entry point

        : : "r"(AddrOfEntryPoint)
        : "memory"
    );
    return STATUS_SUCCESS;
}
