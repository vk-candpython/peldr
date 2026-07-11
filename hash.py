#=================================#
# [ OWNER ]
#     CREATOR  : Vladislav Khudash
#     AGE      : 17
#     LOCATION : Ukraine
#
# [ PINFO ]
#     DATE     : 11.07.2026
#     PROJECT  : PELDR-HASH
#     PLATFORM : ANY
#=================================#




'''
PELDR-HASH Generator


Pre-computes case-insensitive 32-bit hashes
for Windows Native API names.

Generates C-style #define macros
for compile-time string masking to assist
with dynamic symbol resolution in loader.h


Usage:
    python hash.py <int:hash_key>
'''




from sys     import argv  
from os.path import basename 




# Generate a seeded, case-insensitive 32-bit hash
# for loader.h API and function names
def HashStr(s: bytes, k: int,
    *, _A=b'A'[0], _Z=b'Z'[0]) -> str:
    # Initialize hash with the user-defined seed
    h = k


    for c in s:
        # Convert ASCII uppercase to lowercase
        if _A <= c <= _Z: c |= 0x20

        # Mix the current character
        # into the 32-bit hash value
        h = (( (h << 4) - h ) + c) & 0xFFFFFFFF


    # Return the final 32-bit hash
    # as a C-style hexadecimal constant
    return f'0x{h:08X}'




def main():
    try:
        # Get the initial 32-bit hash seed from argv
        k = int(argv[1]) & 0xFFFFFFFF
    except (IndexError, ValueError):
        # Display usage information if the seed is missing
        # or cannot be parsed as an integer
        print(
            f'Usage: python {basename(__file__)} <int:hash_key>'
            '  <->  '
            'Generate #define Hash-Functions For loader.h'
        )
        return


    print('\n')


    # Emit the hash seed used by loader.h
    print(f'#define HASH_STR_SEED {k}U\n')

    # Generate hash definitions for all required APIs
    for n in (
        b'NtTerminateProcess',
        b'NtClose',
        b'NtAllocateVirtualMemory',
        b'NtProtectVirtualMemory',
        b'NtFreeVirtualMemory',
        b'NtOpenKey',
        b'NtEnumerateKey',
        b'NtOpenFile',
        b'NtReadFile',
        b'NtQueryInformationFile',
        b'NtQueryInformationProcess',
        b'LdrLoadDll',
        b'LdrGetProcedureAddress',
        b'RtlAddFunctionTable',
    ):
        print(f'#define HASH_{n.decode():<26} {HashStr(n, k)}U')


    print('\n')




if __name__ == '__main__': main()
