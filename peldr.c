/*=================================*/
// [ OWNER ]
//     CREATOR  : Vladislav Khudash
//     AGE      : 17
//     LOCATION : Ukraine
//
// [ PINFO ]
//     DATE     : 11.07.2026
//     PROJECT  : PELDR-BUILDER
//     PLATFORM : WIN64
/*=================================*/




/* https://github.com/vk-candpython/peldr

Reflective PE-Loader Builder


Utility for building and configuring
reflective loader images.

Automates the build process, embeds required
components, applies build time configuration,
and generates the final output binary.


Usage:
    peldr.exe <exe|dll> [exe|dll ...]

*/




/* Variable arguments, Windows API
   and Unicode command line parsing */
#include <stdarg.h>
#include <windows.h>
#include <shellapi.h>




/* Supported key sizes (powers of two) */
static const BYTE KEY_SZ[] = {16, 32, 64, 128};


/* Embedded executable stub */
static BYTE STUB_EXE[] = {0};


/* Prefix for generated executables */
static PCWSTR FILE_PREF = L"./peldr-";




/* Const-qualified pointer helper
   (const data and const pointer) */
#define CONST_PTR(TYPE) \
    const TYPE *const


/* Function declaration helper */
#define DEC_FUNC(TYPE) \
    static inline __attribute__((always_inline, hot)) TYPE


/* Check for GUI subsystem flag (-w) */
#define IS_FLAG_GUI(argv, idx) (      \
    ((argv)[(idx)][0] == L'-' ) &&    \
    ((argv)[(idx)][1] == L'w' ) &&    \
    ((argv)[(idx)][2] == L'\0')       \
)


/* Store a 32-bit integer into a byte buffer */
#define CAST_INT32(buf, val) \
    (*(PUINT32)(buf) = (UINT32)(val))




/* RLE constants */
#define RLE_MIN_RUN 3   // Minimum run length for compression
#define RLE_MAX_RUN 127 // Maximum encoded run length
#define RLE_LIT_MAX 126 // Maximum literal block length
#define RLE_FLG_RUN 128 // High-bit marker for run blocks


/* Worst-case compressed buffer size */
#define RLE_BUF_SZ(sz) (                           \
    ((((sz) + (RLE_LIT_MAX - 1)) / RLE_LIT_MAX)    \
    * RLE_MAX_RUN) + RLE_MIN_RUN                   \
)




/* Centralized informational message strings */
#define INF_START    L"Start processing -> %s\n"
#define INF_COMP     L"[*] compressed    :  %u -> %u bytes  |  saved: %d bytes (%d.%d%%)"
#define INF_OUT      L"[+] output file   :  %s (%u bytes)"
#define INF_TIME     L"[*] elapsed time  :  %d.%02ds"
#define INF_END      L"\nEnd of processing -> %s"


/* Centralized error message string constants */
#define ERR_PROC      L"\nFailed to process -> %s"
#define ERR_NOFILE    L"[-] input file does not exist"
#define ERR_OS        L"[-] Win32 API call failed"
#define ERR_MIN_SZ    L"[-] file size is below minimum PE threshold"
#define ERR_MAX_SZ    L"[-] file size exceeds maximum supported limit"
#define ERR_IS_PE     L"[-] file is not valid EXE or DLL binary"
#define ERR_PE_ST     L"[-] invalid PE-file structure"
#define ERR_ARCH      L"[-] PE-file architecture is not x64"




/* Main process heap handle */
static HANDLE hHeap;




/* Run-length compression handler */
DEC_FUNC(VOID) compress(
    const BYTE *dt, const SIZE_T dtSz,
    PBYTE      out, PSIZE_T     outSz
) {
    CONST_PTR(BYTE) beg = out;       // Initial output pointer
    CONST_PTR(BYTE) end = dt + dtSz; // Input boundary



    while (dt < end) {
        const BYTE c = *dt; // Current byte
        BYTE       r = 1;   // Run length


        /* Limit the maximum run length */
        const SIZE_T u = min(RLE_MAX_RUN, (SIZE_T)(end - dt));

        /* Count matching bytes */
        while ((r < u) && (*(dt + r) == c)) ++r;


        if (r >= RLE_MIN_RUN) {
            *out++ = r | RLE_FLG_RUN; // Write run header
            *out++ = c;               // Write repeated byte
            dt    += r;               // Advance input
        }
        else {
            CONST_PTR(BYTE) s = dt; // Literal block start


            /* Limit the literal block length */
            const SIZE_T lim = min(RLE_LIT_MAX, (SIZE_T)(end - s));

            /* Scan until the next run */
            while (
                ((SIZE_T)(dt - s)         < lim) && !(
                ((dt + (RLE_MIN_RUN - 1)) < end) &&
            /* Check for a RLE_MIN_RUN-byte run */
                (*dt == *(dt + 1)) &&
                (*dt == *(dt + 2))
            )) ++dt;


            const BYTE l = dt - s; // Literal length

            if (l) {
                *out++ = l;            // Write literal length
                CopyMemory(out, s, l); // Copy literal bytes
                out   += l;            // Advance output
            }
        }
    }



    /* Return the compressed size */
    *outSz = (SIZE_T)(out - beg);
}




/* Stateful stream cipher based on
   rotating key material and feedback */
DEC_FUNC(VOID) encrypt(
    PBYTE           dt,  const SIZE_T dtSz,
    CONST_PTR(BYTE) key, const SIZE_T keySz
) {
    const BYTE msk = (BYTE)(keySz - 1); // Power-of-two key mask
    BYTE       stt = key[0];            // Rolling cipher state


    PBYTE           ptr = dt;        // Current input pointer
    CONST_PTR(BYTE) end = dt + dtSz; // Input boundary
    SIZE_T          j   = 0;         // Stream position counter



    while (ptr < end) {
        /* Derive key bytes */
        const BYTE k1 = key[ j       & msk];
        const BYTE k2 = key[(j >> 3) & msk];


        /* Generate mixing mask */
        const BYTE t = j ^ (j >> 8);
        const BYTE y = (((k1 << 1) | (k2 >> 7))) ^ t;
        const BYTE m = y ^ (y >> 4);


        /* Encrypt the current byte */
        const BYTE b  = *ptr;
        BYTE       r  = (b << 3) | (b >> 5);
                   r += stt ^ k1;
                   r ^= m;


        /* Update the cipher state */
        stt    = (b + k2) ^ (stt >> 1);
        *ptr++ = r;
        ++j;
    }
}




/* Generates pseudo-random key
   using system uptime */
DEC_FUNC(PBYTE) gen_key(PBYTE keyLn) {
    DWORD seed = GetTickCount();


    /* Select key length */
    const BYTE ln = KEY_SZ[seed % sizeof(KEY_SZ)];
    *keyLn        = ln;

    PBYTE key = (PBYTE)HeapAlloc(hHeap, 0, ln);
    if (!key) return NULL;


    /* Fill key using Xorshift PRNG */
    for (BYTE i = 0;  i < ln;  i++) {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;

        key[i] = (BYTE)((seed >> (i & 24)) ^ ~i);
    }


    return key;
}




/* Console output helper */
static VOID cout(PCWSTR s) {
    /* Cache the standard output handle */
    static HANDLE h = NULL;

    if (!h) {
        h = GetStdHandle(STD_OUTPUT_HANDLE);

        if (h == INVALID_HANDLE_VALUE)
            ExitProcess(1);
    }


    DWORD n;

    WriteConsoleW(h, s,     (DWORD)lstrlenW(s), &n, NULL); // Write string
    WriteConsoleW(h, L"\n", 1,                  &n, NULL); // Append new line
}




/* Formatted console output helper */
static VOID coutfmt(PCWSTR fmt, ...) {
    /* Reusable formatting buffer */
    static WCHAR buf[MAX_PATH * sizeof(WCHAR)];


    va_list va;
    va_start(va, fmt);

    /* Format the output string */
    wvsprintfW(buf, fmt, va);

    va_end(va);


    /* Write the formatted string */
    cout(buf);
}




/* Console error output helper */
#define cerr(s) do {    \
    cout(s);            \
    return FALSE;       \
} while (0)




/* Load file contents into heap memory */
DEC_FUNC(BOOLEAN) read_file(
    PCWSTR fpath,
    PBYTE *out, PSIZE_T outSz
) {
    /* Open the input file for reading */
    const HANDLE hFile = CreateFileW(fpath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);


    if (hFile == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();

        if (err == ERROR_FILE_NOT_FOUND ||
            err == ERROR_PATH_NOT_FOUND
        ) cerr(ERR_NOFILE);

        cerr(ERR_OS);
    }



    /* Retrieve the total file size */
    LARGE_INTEGER li;

    if (!GetFileSizeEx(hFile, &li)) {
        CloseHandle(hFile);
        cerr(ERR_OS);
    }


    /* Guard against empty files */
    if (!li.QuadPart) {
        CloseHandle(hFile);
        cerr(ERR_MIN_SZ);
    }

    /* Verify the file size limit */
    else if (li.QuadPart > MAXDWORD) {
        CloseHandle(hFile);
        cerr(ERR_MAX_SZ);
    }


    /* Set file size */
    const SIZE_T fsz = (SIZE_T)li.QuadPart;



    /* Allocate a buffer for file contents */
    PBYTE buf = (PBYTE)HeapAlloc(hHeap, 0, fsz);

    if (!buf) {
        CloseHandle(hFile);
        cerr(ERR_OS);
    }


    /* Read the entire file into memory */
    DWORD n;

    if (!ReadFile(hFile, buf, (DWORD)fsz, &n, NULL) || (n != (DWORD)fsz)) {
        HeapFree(hHeap, 0, buf);
        CloseHandle(hFile);
        cerr(ERR_OS);
    }


    CloseHandle(hFile);



    /* Return the buffer and its size */
    *out   = buf;
    *outSz = fsz;

    return TRUE;
}




/* Validate PE file structure and
   basic header integrity */
DEC_FUNC(BOOLEAN) is_valid_pe_file(
    CONST_PTR(BYTE) dt, const SIZE_T dtSz
) {
    /* Check baseline size for PE headers */
    if (dtSz < (sizeof(IMAGE_DOS_HEADER) +
                sizeof(IMAGE_NT_HEADERS64))
    ) cerr(ERR_MIN_SZ);



    /* Map DOS header */
    CONST_PTR(IMAGE_DOS_HEADER) hdDos = (PIMAGE_DOS_HEADER)dt;


    /* Verify DOS magic signature ("MZ") */
    if (hdDos->e_magic != IMAGE_DOS_SIGNATURE)
        cerr(ERR_IS_PE);

    /* Guard against overlapping NT headers and DOS header */
    else if (hdDos->e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER))
        cerr(ERR_PE_ST);

    /* Guard against malformed e_lfanew
       pointer overflowing file boundary */
    else if (dtSz < ((SIZE_T)hdDos->e_lfanew +
                     sizeof(IMAGE_NT_HEADERS64))
    ) cerr(ERR_PE_ST);



    /* Advance to the NT headers offset */
    CONST_PTR(IMAGE_NT_HEADERS64) hdNt =
        (PIMAGE_NT_HEADERS64)(dt + hdDos->e_lfanew);


    /* Verify PE file signature ("PE\0\0") */
    if (hdNt->Signature != IMAGE_NT_SIGNATURE)
        cerr(ERR_IS_PE);



    /* Localize reference to the COFF File Header */
    CONST_PTR(IMAGE_FILE_HEADER) hdFl = &hdNt->FileHeader;

    /* Localize reference to the 64-bit Optional Header */
    CONST_PTR(IMAGE_OPTIONAL_HEADER64) hdOpt = &hdNt->OptionalHeader;


    /* Enforce strict 64-bit architecture (PE32+ magic validation) */
    if (hdOpt->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        cerr(ERR_ARCH);

    /* Enforce strict image type validation
       (must be EXE or DLL) */
    else if (
        !(hdFl->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) ||
        (hdOpt->Subsystem      == IMAGE_SUBSYSTEM_NATIVE     )
    ) cerr(ERR_IS_PE);



    /* Structural and alignment integrity guard */
    if (
!hdOpt->SizeOfImage      || // Missing virtual image size
!hdOpt->FileAlignment    || // Missing file alignment value
!hdOpt->SectionAlignment || // Missing section alignment value

(hdOpt->FileAlignment    & (hdOpt->FileAlignment    - 1)) || // File alignment is not a power of two
(hdOpt->SectionAlignment & (hdOpt->SectionAlignment - 1)) || // Section alignment is not a power of two

(hdOpt->SectionAlignment < hdOpt->FileAlignment         ) || // Section alignment must be >= file alignment
(hdOpt->ImageBase        & (hdOpt->SectionAlignment - 1)) || // ImageBase must be aligned to section boundary
(hdOpt->SizeOfHeaders    > dtSz                         )    // Headers exceed physical file size
    ) cerr(ERR_PE_ST);



    /* File passed all PE validation checks */
    return TRUE;
}




/* Builds prefixed output file name from a full path */
DEC_FUNC(PCWSTR) get_file_name(PCWSTR fpath) {
    static WCHAR buf[MAX_PATH + 1];
    PCWSTR name = fpath;


    /* Locate the file name within the full path */
    while (*fpath) {
        if ((*fpath == L'\\') || (*fpath == L'/'))
            name = fpath + 1;

        ++fpath;
    }


    /* Prepend FILE_PREF to the file name */
    wsprintfW(buf, L"%s%s", FILE_PREF, name);
    return buf;
}




/* Builds the output executable */
DEC_FUNC(SIZE_T) build_exe(
    PCWSTR     fileName, const UINT32 rawSz,
    CONST_PTR(BYTE) out, const UINT32 outSz,
    CONST_PTR(BYTE) key, const BYTE   kln
) {
    /* Create the output file */
    const HANDLE hFile = CreateFileW(fileName, GENERIC_WRITE, 0,
        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
        cerr(ERR_OS);


    DWORD n;                    // Number of bytes written
    BYTE  szBuf[sizeof(rawSz)]; // Buffer for packed integer values



    /* Write the loader stub */
    WriteFile(hFile, STUB_EXE, sizeof(STUB_EXE), &n, NULL);


    /* Write the encryption key */
    WriteFile(hFile, &kln, sizeof(kln), &n, NULL);
    WriteFile(hFile, key,  (DWORD)kln,  &n, NULL);


    /* Write the original payload size */
    CAST_INT32(szBuf, rawSz);
    WriteFile(hFile, szBuf, sizeof(szBuf), &n, NULL);


    /* Write the encrypted payload */
    WriteFile(hFile, out, outSz, &n, NULL);


    /* Write the appended data size */
    const UINT32 tlLn = (sizeof(kln  ) + (UINT32)kln) +
                        (sizeof(rawSz) + outSz      );

    CAST_INT32(szBuf, tlLn);
    WriteFile(hFile, szBuf, sizeof(szBuf), &n, NULL);



    FlushFileBuffers(hFile);


    /* Query the resulting file size */
    LARGE_INTEGER fsz;

    if (!GetFileSizeEx(hFile, &fsz)) {
        CloseHandle(hFile);
        cerr(ERR_OS);
    }


    CloseHandle(hFile);



    /* Verify the resulting file size */
    const UINT32 tlFsz = sizeof(STUB_EXE) + (sizeof(tlLn) + tlLn);

    if (fsz.QuadPart != (LONGLONG)tlFsz)
        cerr(ERR_OS);


    /* Return the final file size */
    return (SIZE_T)fsz.QuadPart;
}




/* Processes the target executable
   and builds the output loader */
DEC_FUNC(BOOLEAN) setup(PCWSTR fpath) {
    /* Capture execution start time */
    const DWORD _ts = GetTickCount();
    coutfmt(INF_START, fpath);



    PCWSTR fileName = get_file_name(fpath);
    PBYTE   fileDt;
    SIZE_T  fileSz;


    /* Read the target PE-file into memory */
    if (!read_file(fpath, &fileDt, &fileSz))
        return FALSE;

    /* Validate PE headers and file structure */
    if (!is_valid_pe_file(fileDt, fileSz)) {
        HeapFree(hHeap, 0, fileDt);
        return FALSE;
    }



    /* Allocate buffer for the compressed payload */
    PBYTE  out = (PBYTE)HeapAlloc(hHeap, 0, RLE_BUF_SZ(fileSz));
    SIZE_T outSz;

    if (!out) {
        HeapFree(hHeap, 0, fileDt);
        cerr(ERR_OS);
    }



    /* Compress PE binary */
    compress(fileDt, fileSz, out, &outSz);


    {//* OUTPUT COMPRESSED
        UINT32 saved = (UINT32)(fileSz - outSz);
        UINT32 pct10 = (UINT32)((saved * 1000) / fileSz);

        coutfmt(INF_COMP,
            (UINT32)fileSz, (UINT32)outSz,
            saved,
            pct10 / 10,     pct10 % 10
        );
    }//* OUTPUT COMPRESSED


    /* Free file data buffer */
    HeapFree(hHeap, 0, fileDt);



    /* Generate encryption key */
    BYTE  kln;
    PBYTE key = gen_key(&kln);

    if (!key) {
        HeapFree(hHeap, 0, out);
        cerr(ERR_OS);
    }


    /* Encrypt the compressed payload */
    encrypt(out, outSz, key, kln);



    /* Build the final output executable */
    const SIZE_T fsz = build_exe(
        fileName, (UINT32)fileSz,
        out,      (UINT32)outSz,
        key,      kln
    );
    if (fsz) coutfmt(INF_OUT, fileName, fsz);



    /* Clean up key and payload buffers */
    HeapFree(hHeap, 0, key);
    HeapFree(hHeap, 0, out);



    /* Report total processing time */
    DWORD elapsed = GetTickCount() - _ts;

    coutfmt(INF_TIME,
        elapsed / 1000,
        (elapsed % 1000) / 10
    );



    /* Report processing result */
    if (fsz) coutfmt(INF_END, fpath);
    return fsz != 0;
}




INT main(VOID) {
    /* Initialize process heap */
    hHeap = GetProcessHeap();


    /* Parse command-line arguments */
    INT     argc;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    if (!argv) {
        cout(ERR_OS);
        return 1;
    }



    /* Display usage information */
    if ((argc < 2) || ((argc == 2) && IS_FLAG_GUI(argv, 1))) {
        cout(
            L"\n(C) Vladislav Khudash, 2026"
            L"\n(P) GitHub: https://github.com/vk-candpython/peldr"
            L"\n(!) Only for PE32+\n"

            L"\n\n(Usage):\n"
            L"  peldr.exe <exe|dll> [exe|dll ...]\n"

            L"\n\n(Flags):\n"
            L"  -w -> Set GUI Subsystem (Default: Console)\n"

            L"\n\n(Features):\n"
            L"  - RLE compression\n"
            L"  - XOR stream cipher\n"
            L"  - Fileless execution\n"
            L"  - More features on GitHub"
        );

        LocalFree(argv);
        return 1;
    }



    /* Set the stub subsystem to GUI if requested */
    for (INT i = 1;  i < argc;  i++)
        if (IS_FLAG_GUI(argv, i)) {
            PIMAGE_DOS_HEADER   ds = (PIMAGE_DOS_HEADER)STUB_EXE;
            PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(STUB_EXE + ds->e_lfanew);

            nt->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
            break;
        }



    /* Process each input file */
    BOOLEAN sep = FALSE;
    cout(L""); // Put new line

    for (INT i = 1;  i < argc;  i++) {
        if (IS_FLAG_GUI(argv, i)) continue;


        /* Print block separator */
        if (sep) cout(L"\n\n");
        sep = TRUE;


        /* Process the current file */
        if (!setup(argv[i]))
            coutfmt(ERR_PROC, argv[i]);
    }



    LocalFree(argv);
    return 0;
}
