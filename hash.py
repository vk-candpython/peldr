#=================================#
# [ OWNER ]
#     CREATOR  : Vladislav Khudash
#     AGE      : 17
#     LOCATION : Ukraine
#
# [ PINFO ]
#     DATE     : 16.05.2026
#     PROJECT  : EXEOBF-HASH
#     PLATFORM : ANY
#=================================#




from sys     import argv  
from os.path import basename 




def HashStr(s: bytes, k: int, *, _A=b'A'[0], _Z=b'Z'[0]) -> str:
    h = k

    for c in s:
        if _A <= c <= _Z: c |= 0x20   
        h = (( (h << 4) - h ) + c) & 0xFFFFFFFF

    return f'0x{h:08X}'




def main():
    try:
        k = int(argv[1]) & 0xFFFFFFFF
    except (IndexError, ValueError):
        print(
            f'Usage: python {basename(__file__)} <int:hash_key>'
            '  <->  '
            'Generate #define Hash-Functions For loader.c'
        )
        return
    


    print(f'#define KEY_HASH_STR {"":<20} {k}')

    for n in (
        b'EtwEventWrite', 
        b'NtAllocateVirtualMemory', 
        b'NtFreeVirtualMemory', 
        b'NtProtectVirtualMemory', 
        b'LdrLoadDll', 
        b'LdrGetProcedureAddress', 
        b'RtlAddFunctionTable', 
        b'NtQueryInformationProcess', 
        b'NtSetInformationProcess', 
        b'NtSetInformationThread', 
        b'NtOpenFile', 
        b'NtReadFile', 
        b'NtClose', 
        b'NtQueryInformationFile', 
        b'NtTerminateProcess'
    ): print(f'#define HASH_{n.decode():<28} {HashStr(n, k)}')

    


if __name__ == '__main__': main()
