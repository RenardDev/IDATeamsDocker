
# Imports

import platform
import sys
import hashlib
import json

from pathlib import Path
from random import randint
from datetime import datetime

# General

CURRENT_DIRECTORY = Path(__file__).parent
OS_NAME = platform.system()

ORIGINAL_ROOT_CA_CERTIFICATE = bytes.fromhex('2D2D2D2D2D424547494E2043455254494649434154452D2D2D2D2D0A4D4949463054434341376D6741774942416749554C7A4B74454F50395137562F4C2F4734526E76344C3376712F6845774451594A4B6F5A496876634E4151454E0A425141775644454C4D416B474131554542684D43516B5578447A414E42674E564241634D426B78707736686E5A5445564D424D47413155454367774D534756340A4C564A6865584D67553045754D5230774777594456515144444252495A586774556D46356379425451533467556D39766443424451544165467730794D4441310A4D4451784D5441794D446861467730304D4441304D6A6B784D5441794D4468614D465178437A414A42674E5642415954416B4A464D51387744515944565151480A44415A4D61634F6F5A3255784654415442674E5642416F4D4445686C6543315359586C7A49464E424C6A45644D4273474131554541777755534756344C564A680A65584D675530457549464A766233516751304577676749694D4130474353714753496233445145424151554141344943447741776767494B416F4943415144420A727345683438564E796A4350524F53597A773576694163664475426F4441486533624952594D61476D3261366F6D5358537A54303252416970536C4F366E4A5A0A2F50674E4569706158594C6245586D727247646E5364427538756235317431374164476347597A7A506A534970495648356D5832694F624864533367794E7A700A4A4B4A515543444D3646644A61385A637A744B772B6258734E3166744B615A437A4863755542633850356C6B6952476375596662694872693543303270476F310A3379344F7A3939536F74384B5566774E6842794F4F474F77655979666E394E676D6871686B427532372B367278706D7552376D48794F68666E4C732B707351300A796A4536627A756C32696C5746724F53614C41784B6268424C4C5144574359654276586D4530497A6D5A56626F32447154552B4E575245553661766D5252427A0A36526E5A484655686C324C56624A354172343542617752333862524E726F36564E4354713839724258564665436E6B394A613676345A416F576D6A4A757048430A70585449786F65626B6F655741774943757A36336357735268317932617164675136763979564572413634476867436B704A4F383248447441395369716765330A542B7267556E6A3170636C6C474B6778414659634B686C434C6C342B626D306F686C784630574638564D68472F54424C4E48334D6C4A466A6C4D6F4277516E6C0A4150686545675A576F5153456A416B7A524C55725277376B566B2F51743847356846474C6233556A4538534B44504B5259534241554E2F75503859484B46716F0A3261727054436931444F345371583872367A717A736C565466367557546971384D4E6B5A2F2B374E5972312F4A50543235694D6C7736736136673447555070510A7A685261507931396F62476534337534766A7079736539673576715839703375394D49313478336B36514944415141426F3447614D4947584D423047413155640A4467515742425161784E6163664D37584B6A4B4975744948726336746A6945394454416642674E5648534D454744415767425161784E6163664D37584B6A4B490A75744948726336746A6945394454415042674E5648524D4241663845425441444151482F4D41344741315564447745422F77514541774942686A413042674E560A485238454C5441724D436D674A36416C68694E6F644852774F69387659334A734C6D686C6543317959586C7A4C6D4E76625339796232393058324E684C6D4E790A6244414E42676B71686B6947397730424151304641414F4341674541644B7034496E70526B357A30426A50733643634A53674B624348304D585A7162742F454D0A2F34644A50766D4136744165784A7076396539426D542F444F423834514232787A516C45694E4F42372F56346A336F44696A356D4D77527971594C32346C33670A4841617677632B644C72707A582F3534755A6D4839624B7337796A33666B2F7655336537746837323041724C322F595A6A485632577830424D63732B595669740A70687647326D7875313644547069646D733370436A3235654549534A76586665385845664B4F503146784743706D4B7878367150486C4E41534F70357A6477560A6945696D6B677555777A43736D6D5049357245574C58644C52786330436B66666D62734E6D734638535A7A333843697775526C6963684444645A754A586A69370A6A6E5A46376830344D6F32414B507436774A392B36367259714469677650397348474B70517035687231444D756B46476E656933533968354B703865446852580A593234792F434A564E4F307278596F4650556E4F77625355463346777534665833457A71356557374E304E6C37733058484578622F5039666D685078514256310A677772363635696E71355A77443848397577474556703349425439634852753869655A7251444D49315571504F792B3245574E507459344B786D6765725462630A4E3056483442754538746478544755636B67344A5462734E525562717853586D534C396A4131644C425436336C624D4C49553036644964714E627078453447560A4D674F4C777177782F42462B465A6751547474646A6D7065786D6C364E49445647444278667945434A3576647778624B4D4952666F376670306A52706A5A70500A3862773442506E783059344E704D7A4B78695753306937726539694561666468364774704E796E4B55304A46534B7249776D4965634B462B5A345A55452F314B0A2B742F464F67493D0A2D2D2D2D2D454E442043455254494649434154452D2D2D2D2D0A00')
ORIGINAL_ROOT_CA_CERTIFICATE_WITHOUT_HEADERS = bytes.fromhex('4D4949463054434341376D6741774942416749554C7A4B74454F50395137562F4C2F4734526E76344C3376712F6845774451594A4B6F5A496876634E4151454E425141775644454C4D416B474131554542684D43516B5578447A414E42674E564241634D426B78707736686E5A5445564D424D47413155454367774D534756344C564A6865584D67553045754D5230774777594456515144444252495A586774556D46356379425451533467556D39766443424451544165467730794D4441314D4451784D5441794D446861467730304D4441304D6A6B784D5441794D4468614D465178437A414A42674E5642415954416B4A464D513877445159445651514844415A4D61634F6F5A3255784654415442674E5642416F4D4445686C6543315359586C7A49464E424C6A45644D4273474131554541777755534756344C564A6865584D675530457549464A766233516751304577676749694D4130474353714753496233445145424151554141344943447741776767494B416F494341514442727345683438564E796A4350524F53597A773576694163664475426F4441486533624952594D61476D3261366F6D5358537A54303252416970536C4F366E4A5A2F50674E4569706158594C6245586D727247646E5364427538756235317431374164476347597A7A506A534970495648356D5832694F624864533367794E7A704A4B4A515543444D3646644A61385A637A744B772B6258734E3166744B615A437A4863755542633850356C6B6952476375596662694872693543303270476F313379344F7A3939536F74384B5566774E6842794F4F474F77655979666E394E676D6871686B427532372B367278706D7552376D48794F68666E4C732B70735130796A4536627A756C32696C5746724F53614C41784B6268424C4C5144574359654276586D4530497A6D5A56626F32447154552B4E575245553661766D5252427A36526E5A484655686C324C56624A354172343542617752333862524E726F36564E4354713839724258564665436E6B394A613676345A416F576D6A4A7570484370585449786F65626B6F655741774943757A36336357735268317932617164675136763979564572413634476867436B704A4F38324844744139536971676533542B7267556E6A3170636C6C474B6778414659634B686C434C6C342B626D306F686C784630574638564D68472F54424C4E48334D6C4A466A6C4D6F4277516E6C4150686545675A576F5153456A416B7A524C55725277376B566B2F51743847356846474C6233556A4538534B44504B5259534241554E2F75503859484B46716F3261727054436931444F345371583872367A717A736C565466367557546971384D4E6B5A2F2B374E5972312F4A50543235694D6C7736736136673447555070517A685261507931396F62476534337534766A7079736539673576715839703375394D49313478336B36514944415141426F3447614D4947584D423047413155644467515742425161784E6163664D37584B6A4B4975744948726336746A6945394454416642674E5648534D454744415767425161784E6163664D37584B6A4B4975744948726336746A6945394454415042674E5648524D4241663845425441444151482F4D41344741315564447745422F77514541774942686A413042674E56485238454C5441724D436D674A36416C68694E6F644852774F69387659334A734C6D686C6543317959586C7A4C6D4E76625339796232393058324E684C6D4E796244414E42676B71686B6947397730424151304641414F4341674541644B7034496E70526B357A30426A50733643634A53674B624348304D585A7162742F454D2F34644A50766D4136744165784A7076396539426D542F444F423834514232787A516C45694E4F42372F56346A336F44696A356D4D77527971594C32346C33674841617677632B644C72707A582F3534755A6D4839624B7337796A33666B2F7655336537746837323041724C322F595A6A485632577830424D63732B5956697470687647326D7875313644547069646D733370436A3235654549534A76586665385845664B4F503146784743706D4B7878367150486C4E41534F70357A6477566945696D6B677555777A43736D6D5049357245574C58644C52786330436B66666D62734E6D734638535A7A333843697775526C6963684444645A754A586A69376A6E5A46376830344D6F32414B507436774A392B36367259714469677650397348474B70517035687231444D756B46476E656933533968354B70386544685258593234792F434A564E4F307278596F4650556E4F77625355463346777534665833457A71356557374E304E6C37733058484578622F5039666D68507851425631677772363635696E71355A77443848397577474556703349425439634852753869655A7251444D49315571504F792B3245574E507459344B786D6765725462634E3056483442754538746478544755636B67344A5462734E525562717853586D534C396A4131644C425436336C624D4C49553036644964714E627078453447564D674F4C777177782F42462B465A6751547474646A6D7065786D6C364E49445647444278667945434A3576647778624B4D4952666F376670306A52706A5A70503862773442506E783059344E704D7A4B78695753306937726539694561666468364774704E796E4B55304A46534B7249776D4965634B462B5A345A55452F314B2B742F464F67493D00')
ORIGINAL_PUBLIC_MODULUS = bytes.fromhex('EDFD425CF978546E8911225884436C57140525650BCF6EBFE80EDBC5FB1DE68F4C66C29CB22EB668788AFCB0ABBB718044584B810F8970CDDF227385F75D5DDDD91D4F18937A08AA83B28C49D12DC92E7505BB38809E91BD0FBD2F2E6AB1D2E33C0C55D5BDDD478EE8BF845FCEF3C82B9D2929ECB71F4D1B3DB96E3A8E7AAF93')

PRIVATE_KEY = bytes.fromhex('77C86ABBB7F3BB134436797B68FF47BEB1A5457816608DBFB72641814DD464DD640D711D5732D3017A1C4E63D835822F00A4EAB619A2C4791CF33F9F57F9C2AE4D9EED9981E79AC9B8F8A411F68F25B9F0C05D04D11E22A3A0D8D4672B56A61F1532282FF4E4E74759E832B70E98B9D102D07E9FB9BA8D15810B144970029874')
NEW_PUBLIC_MODULUS = bytes.fromhex('EDFD42CBF978546E8911225884436C57140525650BCF6EBFE80EDBC5FB1DE68F4C66C29CB22EB668788AFCB0ABBB718044584B810F8970CDDF227385F75D5DDDD91D4F18937A08AA83B28C49D12DC92E7505BB38809E91BD0FBD2F2E6AB1D2E33C0C55D5BDDD478EE8BF845FCEF3C82B9D2929ECB71F4D1B3DB96E3A8E7AAF93')

HAVE_NEW_ROOT_CA_CERTIFICATE = False
if CURRENT_DIRECTORY.joinpath('CA').joinpath('CA.pem').exists():
    NEW_ROOT_CA_CERTIFICATE = b''
    with open(CURRENT_DIRECTORY.joinpath('CA').joinpath('CA.pem'), 'rb') as f:
        NEW_ROOT_CA_CERTIFICATE += f.read()
        NEW_ROOT_CA_CERTIFICATE += b'\x00'

    NEW_ROOT_CA_CERTIFICATE_WITHOUT_HEADERS = NEW_ROOT_CA_CERTIFICATE \
        .replace(b'-----BEGIN CERTIFICATE-----', b'')                 \
        .replace(b'-----END CERTIFICATE-----', b'')                   \
        .replace(b'\r\n', b'')                                        \
        .replace(b'\r', b'')                                          \
        .replace(b'\n', b'')

    if len(NEW_ROOT_CA_CERTIFICATE) > len(ORIGINAL_ROOT_CA_CERTIFICATE) or \
       len(NEW_ROOT_CA_CERTIFICATE_WITHOUT_HEADERS) > len(ORIGINAL_ROOT_CA_CERTIFICATE_WITHOUT_HEADERS):
        print('New CA certificate is too big!')
    else:
        NEW_ROOT_CA_CERTIFICATE += b'\x00' * (len(ORIGINAL_ROOT_CA_CERTIFICATE) - len(NEW_ROOT_CA_CERTIFICATE))
        NEW_ROOT_CA_CERTIFICATE_WITHOUT_HEADERS += b'\x00' * (len(ORIGINAL_ROOT_CA_CERTIFICATE_WITHOUT_HEADERS) - len(NEW_ROOT_CA_CERTIFICATE_WITHOUT_HEADERS))

        HAVE_NEW_ROOT_CA_CERTIFICATE = True

# Crypto functions

def bytes_to_bigint(data: bytes) -> int:
    return int.from_bytes(data, byteorder='little')

def bigint_to_bytes(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, byteorder='little')

def decrypt_message(message: bytes, public_key: int, exponent: int = 0x13) -> bytes:
    decrypted = pow(bytes_to_bigint(message), exponent, public_key)
    decrypted = bigint_to_bytes(decrypted)
    return decrypted[::-1]

def encrypt_message(message: bytes, private_key: int, public_key: int) -> bytes:
    encrypted = pow(bytes_to_bigint(message[::-1]), private_key, public_key)
    encrypted = bigint_to_bytes(encrypted)
    return encrypted

# License

#  IDAPRO     - IDA Pro
#  IDAEDU     - IDA Educational
#  IDAPC      - IDA Home for Intel x64
#  IDAARM     - IDA Home for ARM
#  IDAPPC     - IDA Home for PowerPC
#  IDAMIPS    - IDA Home for MIPS
#  IDAM68K    - IDA Home for Motorola 68K
#  IDABASE    - Hex-Rays Base
#  IDACORE    - Hex-Rays Core
#  IDAULT     - Hex-Rays Ultra

# code
#  HEXX64     - x64 Decompiler
#  HEXX86     - x86 Decompiler
#  HEXARM64   - ARM64 Decompiler
#  HEXARM     - ARM Decompiler
#  HEXPPC64   - PowerPC64 Decompiler
#  HEXPPC     - PowerPC Decompiler
#  HEXMIPS64  - MIPS64 Decompiler
#  HEXMIPS    - MIPS Decompiler
#  HEXRV64    - RISC-V64 Decompiler
#  HEXRV      - RISC-V Decompiler
#  HEXARC     - ARC Decompiler
#  HEXARC64   - ARC64 Decompiler
#  HEXCX64    - x64 Decompiler (cloud)
#  HEXCX86    - x86 Decompiler (cloud)
#  HEXCARM64  - ARM64 Decompiler (cloud)
#  HEXCARM    - ARM Decompiler (cloud)
#  HEXCPPC64  - PowerPC64 Decompiler (cloud)
#  HEXCPPC    - PowerPC Decompiler (cloud)
#  HEXCMIPS64 - MIPS64 Decompiler (cloud)
#  HEXCMIPS   - MIPS Decompiler (cloud)
#  HEXCRV64   - RISC-V64 Decompiler (cloud)
#  HEXCRV     - RISC-V Decompiler (cloud)
#  HEXCARC    - ARC Decompiler (cloud)
#  HEXCARC64  - ARC64 Decompiler (cloud)
#  LUMINA     - Lumina Server
#  TEAMS      - Vault Server

def generate_add_on(code: str, owner: str, start_date: str, end_date: str, id: str) -> dict:
    data = {
        'code': code,
        'owner': owner,
        'start_date': start_date,
        'end_date': end_date,
        'id': id
    }

    return data

# product_id
#  IDAPRO
#  IDAHOME
#  IDAFREE
#  TEAMS_SERVER
#  LUMINA_SERVER
#  LICENSE_SERVER

# edition_id:
#  ida-pro
#  ida-pro-classroom
#  ida-home-pc
#  ida-home-arm
#  ida-home-mips
#  ida-home-ppc
#  ida-home-riscv
#  ida-free
#  teams-server
#  lumina-server
#  license-server

def generate_license(license_type: str, product_id: str, edition_id: str, description: str, seats: int, start_date: str, end_date: str, issued_on: str, owner: str, add_ons: list, features: list, id: str) -> dict:
    data = {
        'license_type': license_type,
        'product_id': product_id,
        'edition_id': edition_id,
        'description': description,
        'seats': seats,
        'start_date': start_date,
        'end_date': end_date,
        'issued_on': issued_on,
        'owner': owner,
        'add_ons': add_ons,
        'features': features,
        'id': id
    }

    return data

def generate_license_package(version: int, name: str, email: str, licenses: list) -> dict:
    if version == 1:
        data = {
            'header': { 'version': version },
            'payload': {
                'name': name,
                'email': email,
                'licenses': licenses
            }
        }

        return data

def to_alphabetical_json(d: dict) -> str:
    return json.dumps(d, sort_keys=True, separators=(',', ':'))

def from_alphabetical_json(s: str) -> dict:
    return json.loads(s)

def sign_license_package(license: dict, private_key: int, public_key: int) -> str:
    data = { 'payload': license['payload'] }
    data_str = to_alphabetical_json(data)

    buffer = bytearray(128)

    # First 33 bytes are random
    for i in range(33):
        buffer[i] = 0x42

    # Compute sha256 of the data
    sha256 = hashlib.sha256()
    sha256.update(data_str.encode())
    digest = sha256.digest()

    # Copy the sha256 digest to the buffer
    for i in range(32):
        buffer[33 + i] = digest[i]

    # Encrypt the buffer
    encrypted = encrypt_message(buffer, private_key, public_key)

    return encrypted.hex().upper()

# Patch

def patch_file(file_path: Path) -> bool:
    data = None

    if file_path.exists():
        with open(file_path, 'rb') as f:
            data = f.read()

        backup_file_path = file_path.parent / (file_path.name + '.bak')
        
        if not backup_file_path.exists():
            with open(backup_file_path, 'wb') as sf:
                sf.write(data)
        else:
            with open(backup_file_path, 'rb') as sf:
                data = sf.read()

    if data:
        if HAVE_NEW_ROOT_CA_CERTIFICATE:
            if data.find(NEW_PUBLIC_MODULUS[:6]) != -1 or data.find(NEW_ROOT_CA_CERTIFICATE) != -1 or data.find(NEW_ROOT_CA_CERTIFICATE_WITHOUT_HEADERS) != -1:
                print(f'INFO: `{file_path.name}` already has a patch.')
                return False

            if data.find(ORIGINAL_PUBLIC_MODULUS[:6]) == -1 and data.find(ORIGINAL_ROOT_CA_CERTIFICATE) == -1 and data.find(ORIGINAL_ROOT_CA_CERTIFICATE_WITHOUT_HEADERS) == -1:
                print(f'ERROR: Patch for `{file_path.name}` is not supported!')
                return False
        else:
            if data.find(NEW_PUBLIC_MODULUS[:6]) != -1:
                print(f'INFO: `{file_path.name}` already has a patch.')
                return False

            if data.find(ORIGINAL_PUBLIC_MODULUS[:6]) == -1:
                print(f'ERROR: Patch for `{file_path.name}` is not supported!')
                return False

        data = data.replace(ORIGINAL_PUBLIC_MODULUS[:6], NEW_PUBLIC_MODULUS[:6])

        if HAVE_NEW_ROOT_CA_CERTIFICATE:
            data = data.replace(ORIGINAL_ROOT_CA_CERTIFICATE, NEW_ROOT_CA_CERTIFICATE)
            data = data.replace(ORIGINAL_ROOT_CA_CERTIFICATE_WITHOUT_HEADERS, NEW_ROOT_CA_CERTIFICATE_WITHOUT_HEADERS)

        with open(file_path, 'wb') as f:
            f.write(data)

        print(f'INFO: `{file_path.name}` successful patched.')

# Main

def generate_id(ID_0: int = randint(0x00, 0xFF), ID_1: int = randint(0x00, 0xFF),
                ID_2: int = randint(0x00, 0xFF), ID_3: int = randint(0x00, 0xFF),
                ID_4: int = randint(0x00, 0xFF), ID_5: int = randint(0x00, 0xFF)) -> list:
    return [ID_0, ID_1, ID_2, ID_3, ID_4, ID_5]

def format_id(id:list) -> str:
    return f'{id[0]:02X}-{id[1]:02X}{id[2]:02X}-{id[3]:02X}{id[4]:02X}-{id[5]:02X}'

def main(argv: list) -> int:

    private_key = bytes_to_bigint(PRIVATE_KEY)
    public_key = bytes_to_bigint(NEW_PUBLIC_MODULUS)

    if 'ida-pro' in argv:
        if OS_NAME == 'Linux':
            files = [
                'hv',
                'hvui',
                'lsadmin',
                'libida.so',
                'libida32.so',
                'dbgsrv/linux_server',
                'dbgsrv/linux_server32',
                'dbgsrv/mac_server',
                'dbgsrv/mac_server32',
                'dbgsrv/mac_server_arm',
                'dbgsrv/mac_server_arme',
                'dbgsrv/win32_remote32',
                'dbgsrv/win64_remote.exe',
                'plugins/armlinux_stub.so',
                'plugins/arm_mac_stub.so',
                'plugins/dalvik_user.so',
                'plugins/gdb_user.so',
                'plugins/ios_user.so',
                'plugins/linux_stub.so',
                'plugins/mac_stub.so',
                'plugins/pin_user.so',
                'plugins/win32_stub.so',
                'plugins/xnu_user.so',
            ]

            for file in files:
                patch_file(CURRENT_DIRECTORY.joinpath(file))
                
        elif OS_NAME == 'Windows':
            files = [
                'hv.exe',
                'hvui.exe',
                'lsadmin.exe',
                'ida.dll',
                'ida32.dll',
                'dbgsrv/linux_server',
                'dbgsrv/linux_server32',
                'dbgsrv/mac_server',
                'dbgsrv/mac_server32',
                'dbgsrv/mac_server_arm',
                'dbgsrv/mac_server_arme',
                'dbgsrv/win32_remote32',
                'dbgsrv/win64_remote.exe',
                'plugins/armlinux_stub.dll',
                'plugins/arm_mac_stub.dll',
                'plugins/dalvik_user.dll',
                'plugins/gdb_user.dll',
                'plugins/ios_user.dll',
                'plugins/linux_stub.dll',
                'plugins/mac_stub.dll',
                'plugins/pin_user.dll',
                'plugins/win32_stub.dll',
                'plugins/xnu_user.dll',
            ]

            for file in files:
                patch_file(CURRENT_DIRECTORY.joinpath(file))

        elif OS_NAME == 'iOS':
            files = [
                'hv',
                'hvui',
                'lsadmin',
                'libida.dylib',
                'libida32.dylib',
                'dbgsrv/linux_server',
                'dbgsrv/linux_server32',
                'dbgsrv/mac_server',
                'dbgsrv/mac_server32',
                'dbgsrv/mac_server_arm',
                'dbgsrv/mac_server_arme',
                'dbgsrv/win32_remote32',
                'dbgsrv/win64_remote.exe',
                'plugins/armlinux_stub.dylib',
                'plugins/arm_mac_stub.dylib',
                'plugins/dalvik_user.dylib',
                'plugins/gdb_user.dylib',
                'plugins/ios_user.dylib',
                'plugins/linux_stub.dylib',
                'plugins/mac_stub.dylib',
                'plugins/pin_user.dylib',
                'plugins/win32_stub.dylib',
                'plugins/xnu_user.dylib',
            ]

            for file in files:
                patch_file(CURRENT_DIRECTORY.joinpath(file))

        license_path = CURRENT_DIRECTORY.joinpath('idapro.hexlic')
        is_valid_license = False
        if license_path.exists():
            with open(license_path, 'r') as f:
                license_package = from_alphabetical_json(f.read())
                if sign_license_package(license_package, private_key, public_key) == license_package['signature']:
                    is_valid_license = True
        if is_valid_license:
            return 0

        # Set up

        start_date = datetime.now().strftime('%Y-%m-%d')
        issued_on  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        end_date   = '2038-01-18' # '2038-01-19 03:14:07'
        owner      = 'RenardDev'
        name       = 'RenardDev'
        email      = 'zeze839@gmail.com'

        license_id = generate_id(ID_5=0x00)

        # Add-ons

        add_ons_list = [
            'HEXX86',
            'HEXX64',
            'HEXARM',
            'HEXARM64',
            'HEXMIPS',
            'HEXMIPS64',
            'HEXPPC',
            'HEXPPC64',
            'HEXRV64',
            'HEXARC',
            'HEXARC64',

            #'HEXCX86',
            #'HEXCX64',
            #'HEXCARM',
            #'HEXCARM64',
            #'HEXCMIPS',
            #'HEXCMIPS64',
            #'HEXCPPC',
            #'HEXCPPC64',
            #'HEXCRV64',
            #'HEXCARC',
            #'HEXCARC64'
        ]

        add_ons = []
        for idx, add_on in enumerate(add_ons_list):
            license_id_copy = license_id.copy()
            license_id_copy[5] += idx + 1
            add_ons.append(generate_add_on(add_on, format_id(license_id), start_date, end_date, format_id(license_id_copy)))

        # Licenses

        licenses = [
            generate_license('named', 'IDAPRO', 'ida-pro', 'Licensed by RenardDev', 1, start_date, end_date, issued_on, owner, add_ons, [], format_id(license_id))
        ]

        # Package

        license_package = generate_license_package(1, name, email, licenses)
        license_package['signature'] = sign_license_package(license_package, private_key, public_key)

        # File

        serialized = to_alphabetical_json(license_package)
        with open(license_path, 'w') as f:
            f.write(serialized)
            print('INFO: License generated!')

    if 'hexvault' in argv:
        if OS_NAME == 'Linux':
            patch_file(CURRENT_DIRECTORY.joinpath('vault_server'))

        license_path = CURRENT_DIRECTORY.joinpath('teams_server.hexlic')
        is_valid_license = False
        if license_path.exists():
            with open(license_path, 'r') as f:
                license_package = from_alphabetical_json(f.read())
                if sign_license_package(license_package, private_key, public_key) == license_package['signature']:
                    is_valid_license = True
        if is_valid_license:
            return 0

        # Set up

        start_date = datetime.now().strftime('%Y-%m-%d')
        issued_on  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        end_date   = '2038-01-18' # '2038-01-19 03:14:07'
        seats      = 32767
        owner      = '00:00:00:00:00:00'
        name       = 'RenardDev'
        email      = 'zeze839@gmail.com'

        license_id = generate_id(ID_5=0x00)

        # Add-ons

        add_ons_list = [
            'TEAMS'
        ]

        add_ons = []
        for idx, add_on in enumerate(add_ons_list):
            license_id_copy = license_id.copy()
            license_id_copy[5] += idx + 1
            add_ons.append(generate_add_on(add_on, format_id(license_id), start_date, end_date, format_id(license_id_copy)))

        # Licenses

        licenses = [
            generate_license('named', 'TEAMS_SERVER', 'teams-server', 'Licensed by RenardDev', seats, start_date, end_date, issued_on, owner, add_ons, [], format_id(license_id))
        ]

        # Package

        license_package = generate_license_package(1, name, email, licenses)
        license_package['signature'] = sign_license_package(license_package, private_key, public_key)

        # File

        serialized = to_alphabetical_json(license_package)
        with open(license_path, 'w') as f:
            f.write(serialized)
            print('INFO: License generated!')

    if 'lumina' in argv:
        if OS_NAME == 'Linux':
            patch_file(CURRENT_DIRECTORY.joinpath('lumina_server'))
            patch_file(CURRENT_DIRECTORY.joinpath('lc'))

        license_path = CURRENT_DIRECTORY.joinpath('lumina_server.hexlic')
        is_valid_license = False
        if license_path.exists():
            with open(license_path, 'r') as f:
                license_package = from_alphabetical_json(f.read())
                if sign_license_package(license_package, private_key, public_key) == license_package['signature']:
                    is_valid_license = True
        if is_valid_license:
            return 0

        # Set up

        start_date = datetime.now().strftime('%Y-%m-%d')
        issued_on  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        end_date   = '2038-01-18' # '2038-01-19 03:14:07'
        seats      = 32767
        owner      = '00:00:00:00:00:00'
        name       = 'RenardDev'
        email      = 'zeze839@gmail.com'

        license_id = generate_id(ID_5=0x00)

        # Add-ons

        add_ons_list = [
            'LUMINA'
        ]

        add_ons = []
        for idx, add_on in enumerate(add_ons_list):
            license_id_copy = license_id.copy()
            license_id_copy[5] += idx + 1
            add_ons.append(generate_add_on(add_on, format_id(license_id), start_date, end_date, format_id(license_id_copy)))

        # Licenses

        licenses = [
            generate_license('named', 'LUMINA_SERVER', 'lumina-server', 'Licensed by RenardDev', seats, start_date, end_date, issued_on, owner, add_ons, [], format_id(license_id))
        ]

        # Package

        license_package = generate_license_package(1, name, email, licenses)
        license_package['signature'] = sign_license_package(license_package, private_key, public_key)

        # File

        serialized = to_alphabetical_json(license_package)
        with open(license_path, 'w') as f:
            f.write(serialized)
            print('INFO: License generated!')

    if 'hexlicsrv' in argv:
        if OS_NAME == 'Linux':
            patch_file(CURRENT_DIRECTORY.joinpath('license_server'))
            patch_file(CURRENT_DIRECTORY.joinpath('lsadm'))

        license_path = CURRENT_DIRECTORY.joinpath('license_server.hexlic')
        is_valid_license = False
        if license_path.exists():
            with open(license_path, 'r') as f:
                license_package = from_alphabetical_json(f.read())
                if sign_license_package(license_package, private_key, public_key) == license_package['signature']:
                    is_valid_license = True
        if is_valid_license:
            return 0

        # Set up

        start_date      = datetime.now().strftime('%Y-%m-%d')
        issued_on       = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        end_date        = '2038-01-18' # '2038-01-19 03:14:07'
        seats           = 32767
        owner_hexlicsrv = '00:00:00:00:00:00'
        owner           = 'RenardDev'
        name            = 'RenardDev'
        email           = 'zeze839@gmail.com'

        hexlicsrv_license_id = generate_id(ID_5=0x00)
        license_id           = generate_id(ID_5=0x00)

        # Add-ons

        add_ons_list = [
            'HEXX86',
            'HEXX64',
            'HEXARM',
            'HEXARM64',
            'HEXMIPS',
            'HEXMIPS64',
            'HEXPPC',
            'HEXPPC64',
            'HEXRV64',
            'HEXARC',
            'HEXARC64',

            #'HEXCX86',
            #'HEXCX64',
            #'HEXCARM',
            #'HEXCARM64',
            #'HEXCMIPS',
            #'HEXCMIPS64',
            #'HEXCPPC',
            #'HEXCPPC64',
            #'HEXCRV64',
            #'HEXCARC',
            #'HEXCARC64'
        ]

        add_ons = []
        for idx, add_on in enumerate(add_ons_list):
            license_id_copy = license_id.copy()
            license_id_copy[5] += idx + 1
            add_ons.append(generate_add_on(add_on, format_id(license_id), start_date, end_date, format_id(license_id_copy)))

        # Licenses

        licenses = [
            generate_license('named', 'LICENSE_SERVER', 'license-server', 'Licensed by RenardDev', seats, start_date, end_date, issued_on, owner_hexlicsrv, add_ons, [], format_id(hexlicsrv_license_id)),
            generate_license('floating', 'IDAPRO', 'ida-pro', 'Licensed by RenardDev', seats, start_date, end_date, issued_on, owner, add_ons, [], format_id(license_id))
        ]

        # Package

        license_package = generate_license_package(1, name, email, licenses)
        license_package['signature'] = sign_license_package(license_package, private_key, public_key)

        # File

        serialized = to_alphabetical_json(license_package)
        with open(license_path, 'w') as f:
            f.write(serialized)
            print('INFO: License generated!')

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
