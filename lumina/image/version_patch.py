
from pathlib import Path
from sigmak_search import ManualMapper, find_signature

import sys

CURRENT_DIRECTORY = Path(__file__).parent

LUMINA_SERVER_PATH = CURRENT_DIRECTORY.joinpath('lumina_server')

def main(argv):

    if LUMINA_SERVER_PATH.exists():
        lumina_server = ManualMapper(LUMINA_SERVER_PATH)
        lumina_server.load()

        address = find_signature(
            lumina_server.memory, lumina_server.image_size,
            [ 0xDE, 0xC6, 0x44 ],
            [ 0b11100000 ],
            -0x14,
            [
                ( 0x0, True, 0x6, 0x2, 0x4, 0x0 ),
                ( -0x24, True, 0x5, 0x1, 0x4, 0x0 ),
                ( -0x21, True, 0x2, 0x1, 0x1, 0x3 )
            ]
        )

        if address:
            print(f'Found address: {address:#x}')
            lumina_server.memory[address + 2] = 0x06 # Protocol 6
            print('Patched!')

        lumina_server.save(LUMINA_SERVER_PATH)
        lumina_server.unmap()

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
