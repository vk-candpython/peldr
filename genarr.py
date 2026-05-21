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




from sys     import argv, stdout
from gc      import disable
from os      import stat
from os.path import basename




def genarr(
    fp: str,
    *,
    _tab=tuple(str(i).encode('ascii') 
               for i in range(256)).__getitem__
) -> None:
    with open(fp, 'rb') as f:
        rd = f.read
        wt = stdout.buffer.write

        sp = b''
        cm = b','

        jn = cm.join
        mp = map


        wt(b'{')

        while ck := rd(4096):
            wt(sp)
            wt(jn(mp(_tab, ck)))
            sp=cm

        wt(b'}')




def main() -> int:
    if len(argv) != 2:
        print(
            f'Usage: python {basename(argv[0])} <file>'
        '  <->  '
            'Make bin file into C byte array'
        )
        return 1


    
    _fp=argv[1]

    try:
        if not stat(_fp).st_size:
            print(f'[-] file({_fp}) is empty')
            return 1
    except OSError as e:
        print(f'[-] cannot open file({_fp})  |  errno({e.errno}): {e}')
        return 1 



    print('\n')

    disable()
    genarr(_fp)

    print('\n\n')



    stdout.buffer.flush()
    return 0




if __name__ == '__main__': 
    c = main()
    raise SystemExit(c)
