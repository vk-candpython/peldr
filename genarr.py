#=================================#
# [ OWNER ]
#     CREATOR  : Vladislav Khudash
#     AGE      : 17
#     LOCATION : Ukraine
#
# [ PINFO ]
#     DATE     : 21.05.2026
#     PROJECT  : PELDR-GENARR
#     PLATFORM : ANY
#=================================#




'''
PELDR-GENARR Utility


Converts any binary file
into a raw C-style byte array initializer {x,y,z}.

Optimized for performance
via block buffering and disabled GC.


Usage:
    python genarr.py <file>
'''




from sys     import argv, stdout
from gc      import disable
from os      import stat
from os.path import basename




# Stream binary file contents
# as a raw C-style array initializer
def genarr(
    fp: str,
    *,
    # Cache ASCII byte values (0-255)
    # to eliminate runtime string allocation
    _tab=tuple(str(i).encode('ascii')
               for i in range(256)).__getitem__
) -> None:
    with open(fp, 'rb') as f:
        # Cache methods to local scope for speed
        rd = f.read
        wt = stdout.buffer.write

        sp = b''
        cm = b','

        jn = cm.join
        mp = map


        wt(b'{')

        # Read and convert file data
        # in stable 4KB blocks
        while ck := rd(4096):
            wt(sp)               # Write block separator
            wt(jn(mp(_tab, ck))) # Convert and write chunk
            sp=cm                # Set comma for next blocks

        wt(b'}')




def main() -> int:
    if len(argv) != 2:
        # Enforce proper usage
        print(
            f'Usage: python {basename(argv[0])} <file>'
        '  <->  '
            'Make bin file into C byte array'
        )
        return 1



    # Get target file path
    _fp=argv[1]

    try:

        # Check if file is empty
        if not stat(_fp).st_size:
            print(f'[-] file({_fp}) is empty')
            return 1

    except OSError as e:
        print(f'[-] cannot open file({_fp})  |  errno({e.errno}): {e}')
        return 1 



    print('\n')

    disable()   # Disable GC to prevent stutter
    genarr(_fp) # Generate C-style byte array

    print('\n\n')



    # Flush remaining data to stdout
    stdout.buffer.flush()
    return 0




if __name__ == '__main__': 
    c = main() # Return code for exit
    raise SystemExit(c)
