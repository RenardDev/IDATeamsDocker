
from pathlib import Path
from sigmak_search import ManualMapper, find_signature

import sys

CURRENT_DIRECTORY = Path(__file__).parent

LICENSE_SERVER_PATH = CURRENT_DIRECTORY.joinpath('license_server')

def main(argv):

    if LICENSE_SERVER_PATH.exists():
        license_server = ManualMapper(LICENSE_SERVER_PATH)
        license_server.load()

        address = find_signature(
            license_server.memory, license_server.image_size,
            [ 0x64, 0x24, 0x76 ],
            [ 0b11010000 ],
            -0xd,
            [
                ( 0x3f, True, 0x5, 0x1, 0x4, 0x0 ),
                ( 0x3b, True, 0x5, 0x1, 0x4, -0x1c )
            ]
        )

        if address:
            print(f'Found address: {address:#x}')
            license_server.memory[address:address + 6] = b'\x90\xE9\xCE\x00\x00\x00'
            print('Patched!')

        license_server.save(LICENSE_SERVER_PATH)
        license_server.unmap()

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
