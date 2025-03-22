
from pathlib import Path
from sigmak_search import ManualMapper, find_signature

import sys

CURRENT_DIRECTORY = Path(__file__).parent

LICENSE_SERVER_PATH = CURRENT_DIRECTORY.joinpath('license_server')
VAULT_SERVER_PATH = CURRENT_DIRECTORY.joinpath('vault_server')
LUMINA_SERVER_PATH = CURRENT_DIRECTORY.joinpath('lumina_server')

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

    if VAULT_SERVER_PATH.exists():
        vault_server = ManualMapper(VAULT_SERVER_PATH)
        vault_server.load()

        address = find_signature(
            vault_server.memory, vault_server.image_size,
            [ 0x70, 0x0F, 0x8F ],
            [ 0b10110000 ],
            -0x14
        )

        if address:
            print(f'Found address: {address:#x}')
            vault_server.memory[address:address + 6] = b'\x90' * 6
            print('Patched!')

        address = find_signature(
            vault_server.memory, vault_server.image_size,
            [ 0x70, 0x0F, 0x8F ],
            [ 0b10110000 ],
            0x2
        )

        if address:
            print(f'Found address: {address:#x}')
            vault_server.memory[address:address + 6] = b'\x90' * 6
            print('Patched!')

        address = find_signature(
            vault_server.memory, vault_server.image_size,
            [ 0xD2, 0x59, 0x5E ],
            [ 0b11100000 ],
            -0x37,
            [
                ( 0x0, True, 0x2, 0x1, 0x1, 0x0 ),
                ( 0x3e, True, 0x6, 0x2, 0x4, 0x0 ),
                ( -0xb, True, 0x5, 0x1, 0x4, -0x22 )
            ]
        )

        if address:
            print(f'Found address: {address:#x}')
            vault_server.memory[address:address + 6] = b'\x90\xE9\xE2\x01\x00\x00'
            print('Patched!')

        vault_server.save(VAULT_SERVER_PATH)
        vault_server.unmap()

    if LUMINA_SERVER_PATH.exists():
        lumina_server = ManualMapper(LUMINA_SERVER_PATH)
        lumina_server.load()

        address = find_signature(
            lumina_server.memory, lumina_server.image_size,
            [ 0x2A, 0xD2 ],
            [ 0b10100000 ],
            0x11,
            [
                ( 0, True, 0x2, 0x1, 0x1, 0x1f )
            ]
        )

        if address:
            print(f'Found address: {address:#x}')
            lumina_server.memory[address] = 0xEB
            print('Patched!')

        lumina_server.save(LUMINA_SERVER_PATH)
        lumina_server.unmap()

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
