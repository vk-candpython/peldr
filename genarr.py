#=================================#
# [ OWNER ]
#     CREATOR  : Vladislav Khudash
#     AGE      : 17
#     LOCATION : Ukraine
#
# [ PINFO ]
#     DATE     : 20.05.2026
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
) -> memoryview:
    buf = bytearray()


    with open(fp, 'rb') as f:
        rd = f.read
        au = buf.extend
        cm = b','
        jn = cm.join
        mp = map


        au(b'{')

        while ck := rd(4096):
            au(jn(mp(_tab, ck)))
            au(cm)

        ptr = memoryview(buf)
        ptr[-1 :] = b'}'


    return ptr




def main() -> int:
    if len(argv) != 2:
        print(
            f'Usage: python {basename(argv[0])} <file>'
        '  <->  '
            'Make bin file into C byte array'
        )
        return 1



    _fp=argv[1]
    _wt=stdout.buffer.write
    disable()


    try:
        if not stat(_fp).st_size:
            print(f'[-] file({_fp}) is empty')
            return 1
    except OSError as e:
        print(f'[-] cannot open file({_fp})  |  errno({e.errno}): {e}')
        return 1 


    _wt(b'\n\n')
    _wt(genarr(_fp))
    _wt(b'\n\n')


    stdout.buffer.flush()
    return 0




if __name__ == '__main__': 
    c = main()
    raise SystemExit(c)
