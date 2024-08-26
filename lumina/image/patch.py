
import json
import hashlib
import os
import sys

ROOT_CA_CERTIFICATE = bytes.fromhex('2D2D2D2D2D424547494E2043455254494649434154452D2D2D2D2D0A4D4949463054434341376D6741774942416749554C7A4B74454F50395137562F4C2F4734526E76344C3376712F6845774451594A4B6F5A496876634E4151454E0A425141775644454C4D416B474131554542684D43516B5578447A414E42674E564241634D426B78707736686E5A5445564D424D47413155454367774D534756340A4C564A6865584D67553045754D5230774777594456515144444252495A586774556D46356379425451533467556D39766443424451544165467730794D4441310A4D4451784D5441794D446861467730304D4441304D6A6B784D5441794D4468614D465178437A414A42674E5642415954416B4A464D51387744515944565151480A44415A4D61634F6F5A3255784654415442674E5642416F4D4445686C6543315359586C7A49464E424C6A45644D4273474131554541777755534756344C564A680A65584D675530457549464A766233516751304577676749694D4130474353714753496233445145424151554141344943447741776767494B416F4943415144420A727345683438564E796A4350524F53597A773576694163664475426F4441486533624952594D61476D3261366F6D5358537A54303252416970536C4F366E4A5A0A2F50674E4569706158594C6245586D727247646E5364427538756235317431374164476347597A7A506A534970495648356D5832694F624864533367794E7A700A4A4B4A515543444D3646644A61385A637A744B772B6258734E3166744B615A437A4863755542633850356C6B6952476375596662694872693543303270476F310A3379344F7A3939536F74384B5566774E6842794F4F474F77655979666E394E676D6871686B427532372B367278706D7552376D48794F68666E4C732B707351300A796A4536627A756C32696C5746724F53614C41784B6268424C4C5144574359654276586D4530497A6D5A56626F32447154552B4E575245553661766D5252427A0A36526E5A484655686C324C56624A354172343542617752333862524E726F36564E4354713839724258564665436E6B394A613676345A416F576D6A4A757048430A70585449786F65626B6F655741774943757A36336357735268317932617164675136763979564572413634476867436B704A4F383248447441395369716765330A542B7267556E6A3170636C6C474B6778414659634B686C434C6C342B626D306F686C784630574638564D68472F54424C4E48334D6C4A466A6C4D6F4277516E6C0A4150686545675A576F5153456A416B7A524C55725277376B566B2F51743847356846474C6233556A4538534B44504B5259534241554E2F75503859484B46716F0A3261727054436931444F345371583872367A717A736C565466367557546971384D4E6B5A2F2B374E5972312F4A50543235694D6C7736736136673447555070510A7A685261507931396F62476534337534766A7079736539673576715839703375394D49313478336B36514944415141426F3447614D4947584D423047413155640A4467515742425161784E6163664D37584B6A4B4975744948726336746A6945394454416642674E5648534D454744415767425161784E6163664D37584B6A4B490A75744948726336746A6945394454415042674E5648524D4241663845425441444151482F4D41344741315564447745422F77514541774942686A413042674E560A485238454C5441724D436D674A36416C68694E6F644852774F69387659334A734C6D686C6543317959586C7A4C6D4E76625339796232393058324E684C6D4E790A6244414E42676B71686B6947397730424151304641414F4341674541644B7034496E70526B357A30426A50733643634A53674B624348304D585A7162742F454D0A2F34644A50766D4136744165784A7076396539426D542F444F423834514232787A516C45694E4F42372F56346A336F44696A356D4D77527971594C32346C33670A4841617677632B644C72707A582F3534755A6D4839624B7337796A33666B2F7655336537746837323041724C322F595A6A485632577830424D63732B595669740A70687647326D7875313644547069646D733370436A3235654549534A76586665385845664B4F503146784743706D4B7878367150486C4E41534F70357A6477560A6945696D6B677555777A43736D6D5049357245574C58644C52786330436B66666D62734E6D734638535A7A333843697775526C6963684444645A754A586A69370A6A6E5A46376830344D6F32414B507436774A392B36367259714469677650397348474B70517035687231444D756B46476E656933533968354B703865446852580A593234792F434A564E4F307278596F4650556E4F77625355463346777534665833457A71356557374E304E6C37733058484578622F5039666D685078514256310A677772363635696E71355A77443848397577474556703349425439634852753869655A7251444D49315571504F792B3245574E507459344B786D6765725462630A4E3056483442754538746478544755636B67344A5462734E525562717853586D534C396A4131644C425436336C624D4C49553036644964714E627078453447560A4D674F4C777177782F42462B465A6751547474646A6D7065786D6C364E49445647444278667945434A3576647778624B4D4952666F376670306A52706A5A70500A3862773442506E783059344E704D7A4B78695753306937726539694561666468364774704E796E4B55304A46534B7249776D4965634B462B5A345A55452F314B0A2B742F464F67493D0A2D2D2D2D2D454E442043455254494649434154452D2D2D2D2D0A00')
ROOT_CA_CERTIFICATE_WITHOUT_HEADERS = bytes.fromhex('4D4949463054434341376D6741774942416749554C7A4B74454F50395137562F4C2F4734526E76344C3376712F6845774451594A4B6F5A496876634E4151454E425141775644454C4D416B474131554542684D43516B5578447A414E42674E564241634D426B78707736686E5A5445564D424D47413155454367774D534756344C564A6865584D67553045754D5230774777594456515144444252495A586774556D46356379425451533467556D39766443424451544165467730794D4441314D4451784D5441794D446861467730304D4441304D6A6B784D5441794D4468614D465178437A414A42674E5642415954416B4A464D513877445159445651514844415A4D61634F6F5A3255784654415442674E5642416F4D4445686C6543315359586C7A49464E424C6A45644D4273474131554541777755534756344C564A6865584D675530457549464A766233516751304577676749694D4130474353714753496233445145424151554141344943447741776767494B416F494341514442727345683438564E796A4350524F53597A773576694163664475426F4441486533624952594D61476D3261366F6D5358537A54303252416970536C4F366E4A5A2F50674E4569706158594C6245586D727247646E5364427538756235317431374164476347597A7A506A534970495648356D5832694F624864533367794E7A704A4B4A515543444D3646644A61385A637A744B772B6258734E3166744B615A437A4863755542633850356C6B6952476375596662694872693543303270476F313379344F7A3939536F74384B5566774E6842794F4F474F77655979666E394E676D6871686B427532372B367278706D7552376D48794F68666E4C732B70735130796A4536627A756C32696C5746724F53614C41784B6268424C4C5144574359654276586D4530497A6D5A56626F32447154552B4E575245553661766D5252427A36526E5A484655686C324C56624A354172343542617752333862524E726F36564E4354713839724258564665436E6B394A613676345A416F576D6A4A7570484370585449786F65626B6F655741774943757A36336357735268317932617164675136763979564572413634476867436B704A4F38324844744139536971676533542B7267556E6A3170636C6C474B6778414659634B686C434C6C342B626D306F686C784630574638564D68472F54424C4E48334D6C4A466A6C4D6F4277516E6C4150686545675A576F5153456A416B7A524C55725277376B566B2F51743847356846474C6233556A4538534B44504B5259534241554E2F75503859484B46716F3261727054436931444F345371583872367A717A736C565466367557546971384D4E6B5A2F2B374E5972312F4A50543235694D6C7736736136673447555070517A685261507931396F62476534337534766A7079736539673576715839703375394D49313478336B36514944415141426F3447614D4947584D423047413155644467515742425161784E6163664D37584B6A4B4975744948726336746A6945394454416642674E5648534D454744415767425161784E6163664D37584B6A4B4975744948726336746A6945394454415042674E5648524D4241663845425441444151482F4D41344741315564447745422F77514541774942686A413042674E56485238454C5441724D436D674A36416C68694E6F644852774F69387659334A734C6D686C6543317959586C7A4C6D4E76625339796232393058324E684C6D4E796244414E42676B71686B6947397730424151304641414F4341674541644B7034496E70526B357A30426A50733643634A53674B624348304D585A7162742F454D2F34644A50766D4136744165784A7076396539426D542F444F423834514232787A516C45694E4F42372F56346A336F44696A356D4D77527971594C32346C33674841617677632B644C72707A582F3534755A6D4839624B7337796A33666B2F7655336537746837323041724C322F595A6A485632577830424D63732B5956697470687647326D7875313644547069646D733370436A3235654549534A76586665385845664B4F503146784743706D4B7878367150486C4E41534F70357A6477566945696D6B677555777A43736D6D5049357245574C58644C52786330436B66666D62734E6D734638535A7A333843697775526C6963684444645A754A586A69376A6E5A46376830344D6F32414B507436774A392B36367259714469677650397348474B70517035687231444D756B46476E656933533968354B70386544685258593234792F434A564E4F307278596F4650556E4F77625355463346777534665833457A71356557374E304E6C37733058484578622F5039666D68507851425631677772363635696E71355A77443848397577474556703349425439634852753869655A7251444D49315571504F792B3245574E507459344B786D6765725462634E3056483442754538746478544755636B67344A5462734E525562717853586D534C396A4131644C425436336C624D4C49553036644964714E627078453447564D674F4C777177782F42462B465A6751547474646A6D7065786D6C364E49445647444278667945434A3576647778624B4D4952666F376670306A52706A5A70503862773442506E783059344E704D7A4B78695753306937726539694561666468364774704E796E4B55304A46534B7249776D4965634B462B5A345A55452F314B2B742F464F67493D00')

'''
openssl req -x509 -newkey rsa:4096 -sha512 -keyout CA.key -out CA.pem -days 365 -nodes -subj "/C=BE/L=Liège/O=Hex-Rays SA./CN=Hex-Rays SA. Root CA"
'''

NEW_ROOT_CA_CERTIFICATE = b''
with open('CA/CA.pem', 'rb') as f:
    NEW_ROOT_CA_CERTIFICATE += f.read()
    NEW_ROOT_CA_CERTIFICATE += b'\x00'

NEW_ROOT_CA_CERTIFICATE_WITHOUT_HEADERS = NEW_ROOT_CA_CERTIFICATE \
    .replace(b'-----BEGIN CERTIFICATE-----', b'')                 \
    .replace(b'-----END CERTIFICATE-----', b'')                   \
    .replace(b'\r\n', b'')                                        \
    .replace(b'\r', b'')                                          \
    .replace(b'\n', b'')

if len(NEW_ROOT_CA_CERTIFICATE) > len(ROOT_CA_CERTIFICATE):
    print('New CA certificate is too big!')
    sys.exit(1)

if len(NEW_ROOT_CA_CERTIFICATE_WITHOUT_HEADERS) > len(ROOT_CA_CERTIFICATE_WITHOUT_HEADERS):
    print('New CA certificate is too big!')
    sys.exit(1)

NEW_ROOT_CA_CERTIFICATE += b'\x00' * (len(ROOT_CA_CERTIFICATE) - len(NEW_ROOT_CA_CERTIFICATE))
NEW_ROOT_CA_CERTIFICATE_WITHOUT_HEADERS += b'\x00' * (len(ROOT_CA_CERTIFICATE_WITHOUT_HEADERS) - len(NEW_ROOT_CA_CERTIFICATE_WITHOUT_HEADERS))

''' TLS chain generation (replace <DOMAIN>)
openssl req -newkey rsa:2048 -keyout server.key -out server.csr -nodes -subj "/CN=<DOMAIN>"
openssl x509 -req -in server.csr -CA CA.pem -CAkey CA.key -CAcreateserial -out server.crt -days 365 -sha512 -extfile <(cat <<EOF
[req]
distinguished_name=req_distinguished_name
[req_distinguished_name]
[ v3_req ]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = <DOMAIN>
EOF
)

cat server.crt rootCA.crt > server_chain.crt

chmod 640 server_chain.crt # (From IDA docs)
'''

license = {
    'header': { 'version': 1 },
    'payload': {
        'name': 'RenardDev',
        'email': 'zeze839@gmail.com',
        'licenses': [
            {
                'id': '48-3137-ACAB-99',
                'license_type': 'named',
                'product': 'IDA',
                'seats': 1,
                'start_date': '2024-08-13 00:00:00',
                'end_date': '2038-01-19 03:14:07',
                'issued_on': '2024-08-13 00:00:00',
                'owner': 'RenardDev',
                'add_ons': [],
                'features': [],
            }, {
                'id': '48-3137-ACAB-98',
                'license_type': 'named',
                'product': 'TEAMSSRV',
                'seats': 32767,
                'start_date': '2024-08-13 00:00:00',
                'end_date': '2038-01-19 03:14:07',
                'issued_on': '2024-08-13 00:00:00',
                'owner': '00:00:00:00:00:00',
                'add_ons': [],
                'features': [],
            }, {
                'id': '48-3137-ACAB-97',
                'license_type': 'named',
                'product': 'LUMINASRV',
                'seats': 32767,
                'start_date': '2024-08-13 00:00:00',
                'end_date': '2038-01-19 03:14:07',
                'issued_on': '2024-08-13 00:00:00',
                'owner': '00:00:00:00:00:00',
                'add_ons': [],
                'features': [],
            }
        ],
    },
}

def add_every_addon(license_index, start_license_index, license):
    platforms = [
        'W',  # Windows
        'L',  # Linux
        'M',  # MacOS
    ]

    addons = [
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
        # Cloud
        # 'HEXCX86',
        # 'HEXCX64',
        # 'HEXCARM',
        # 'HEXCARM64',
        # 'HEXCMIPS',
        # 'HEXCMIPS64',
        # 'HEXCPPC',
        # 'HEXCPPC64',
        # 'HEXCRV',
        # 'HEXCRV64',
        # 'HEXCARC',
        # 'HEXCARC64',
    ]

    i = start_license_index
    for addon in addons:
        i += 1
        license['payload']['licenses'][license_index]['add_ons'].append(
            {
                'id': f'48-3137-ACAB-{i:02X}',
                'code': addon,
                'owner': license['payload']['licenses'][license_index]['id'],
                'start_date': '2024-08-13 00:00:00',
                'end_date': '2038-01-19 03:14:07',
            }
        )

add_every_addon(0, 0, license)
add_every_addon(1, 0, license)
add_every_addon(2, 0, license)

def json_stringify_alphabetical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'))

def buf_to_bigint(buf):
    return int.from_bytes(buf, byteorder='little')


def bigint_to_buf(i):
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder='little')

pub_modulus_hexrays = buf_to_bigint(
    bytes.fromhex(
        'edfd425cf978546e8911225884436c57140525650bcf6ebfe80edbc5fb1de68f4c66c29cb22eb668788afcb0abbb718044584b810f8970cddf227385f75d5dddd91d4f18937a08aa83b28c49d12dc92e7505bb38809e91bd0fbd2f2e6ab1d2e33c0c55d5bddd478ee8bf845fcef3c82b9d2929ecb71f4d1b3db96e3a8e7aaf93'
    )
)

pub_modulus_patched = buf_to_bigint(
    bytes.fromhex(
        'edfd42cbf978546e8911225884436c57140525650bcf6ebfe80edbc5fb1de68f4c66c29cb22eb668788afcb0abbb718044584b810f8970cddf227385f75d5dddd91d4f18937a08aa83b28c49d12dc92e7505bb38809e91bd0fbd2f2e6ab1d2e33c0c55d5bddd478ee8bf845fcef3c82b9d2929ecb71f4d1b3db96e3a8e7aaf93'
    )
)

private_key = buf_to_bigint(
    bytes.fromhex(
        '77c86abbb7f3bb134436797b68ff47beb1a5457816608dbfb72641814dd464dd640d711d5732d3017a1c4e63d835822f00a4eab619a2c4791cf33f9f57f9c2ae4d9eed9981e79ac9b8f8a411f68f25b9f0c05d04d11e22a3a0d8d4672b56a61f1532282ff4e4e74759e832b70e98b9d102d07e9fb9ba8d15810b144970029874'
    )
)

def decrypt(message):
    decrypted = pow(buf_to_bigint(message), exponent, pub_modulus_patched)
    decrypted = bigint_to_buf(decrypted)
    return decrypted[::-1]

def encrypt(message):
    encrypted = pow(buf_to_bigint(message[::-1]), private_key, pub_modulus_patched)
    encrypted = bigint_to_buf(encrypted)
    return encrypted

exponent = 0x13

def sign_hexlic(payload: dict) -> str:
    data = {'payload': payload}
    data_str = json_stringify_alphabetical(data)

    buffer = bytearray(128)
    # first 33 bytes are random
    for i in range(33):
        buffer[i] = 0x42

    # compute sha256 of the data
    sha256 = hashlib.sha256()
    sha256.update(data_str.encode())
    digest = sha256.digest()

    # copy the sha256 digest to the buffer
    for i in range(32):
        buffer[33 + i] = digest[i]

    # encrypt the buffer
    encrypted = encrypt(buffer)

    return encrypted.hex().upper()

def generate_patched_executable(filename):
    if not os.path.exists(filename):
        print(f'Didn\'t find {filename}, skipping patch generation')
        return

    with open(filename, 'rb') as f:
        data = f.read()

        if data.find(bytes.fromhex('EDFD42CBF978')) != -1 or \
            data.find(NEW_ROOT_CA_CERTIFICATE) != -1 or \
                data.find(NEW_ROOT_CA_CERTIFICATE_WITHOUT_HEADERS) != -1:
            print(f'{filename} looks to be already patched.')
            return

        if data.find(bytes.fromhex('EDFD425CF978')) == -1 and \
            data.find(ROOT_CA_CERTIFICATE) == -1 and \
                data.find(ROOT_CA_CERTIFICATE_WITHOUT_HEADERS) == -1:
            print(f'{filename} doesn\'t contain the original modulus.')
            return

        data = data.replace(
            bytes.fromhex('EDFD425CF978'), bytes.fromhex('EDFD42CBF978')
        )

        data = data.replace(
            ROOT_CA_CERTIFICATE, NEW_ROOT_CA_CERTIFICATE
        )

        data = data.replace(
            ROOT_CA_CERTIFICATE_WITHOUT_HEADERS, NEW_ROOT_CA_CERTIFICATE_WITHOUT_HEADERS
        )

        patched_filename = f'{filename}.patched'
        with open(patched_filename, 'wb') as f:
            f.write(data)

        print(f'Generated patch to {patched_filename}! To apply the patch, replace the original file with the patched file')

license['signature'] = sign_hexlic(license['payload'])

serialized = json_stringify_alphabetical(license)

# write to ida.hexlic
filename = 'ida.hexlic'

with open(filename, 'w') as f:
    f.write(serialized)

print(f'Saved new license to {filename}!')

filename = 'teamssrv.hexlic'

with open(filename, 'w') as f:
    f.write(serialized)

print(f'Saved new license to {filename}!')

filename = 'luminasrv.hexlic'

with open(filename, 'w') as f:
    f.write(serialized)

print(f'Saved new license to {filename}!')

# Windows

# move /Y "C:\Program Files\IDA Professional 9.0\ida.dll.patched" "C:\Program Files\IDA Professional 9.0\ida.dll"
# move /Y "C:\Program Files\IDA Professional 9.0\ida64.dll.patched" "C:\Program Files\IDA Professional 9.0\ida64.dll"
# move /Y "C:\Program Files\IDA Professional 9.0\hv.exe.patched" "C:\Program Files\IDA Professional 9.0\hv.exe"
# move /Y "C:\Program Files\IDA Professional 9.0\hvui.exe.patched" "C:\Program Files\IDA Professional 9.0\hvui.exe"
# move /Y "C:\Program Files\IDA Professional 9.0\dbgsrv\linux_server.patched" "C:\Program Files\IDA Professional 9.0\dbgsrv\linux_server"
# move /Y "C:\Program Files\IDA Professional 9.0\dbgsrv\linux_server64.patched" "C:\Program Files\IDA Professional 9.0\dbgsrv\linux_server64"
# move /Y "C:\Program Files\IDA Professional 9.0\dbgsrv\mac_server.patched" "C:\Program Files\IDA Professional 9.0\dbgsrv\mac_server"
# move /Y "C:\Program Files\IDA Professional 9.0\dbgsrv\mac_server64.patched" "C:\Program Files\IDA Professional 9.0\dbgsrv\mac_server64"
# move /Y "C:\Program Files\IDA Professional 9.0\dbgsrv\mac_server_arm64.patched" "C:\Program Files\IDA Professional 9.0\dbgsrv\mac_server_arm64"
# move /Y "C:\Program Files\IDA Professional 9.0\dbgsrv\mac_server_arm64e.patched" "C:\Program Files\IDA Professional 9.0\dbgsrv\mac_server_arm64e"
# move /Y "C:\Program Files\IDA Professional 9.0\dbgsrv\win32_remote.exe.patched" "C:\Program Files\IDA Professional 9.0\dbgsrv\win32_remote.exe"
# move /Y "C:\Program Files\IDA Professional 9.0\dbgsrv\win64_remote64.exe.patched" "C:\Program Files\IDA Professional 9.0\dbgsrv\win64_remote64.exe"
# move /Y "C:\Program Files\IDA Professional 9.0\plugins\armlinux_stub64.dll.patched" "C:\Program Files\IDA Professional 9.0\plugins\armlinux_stub64.dll"
# move /Y "C:\Program Files\IDA Professional 9.0\plugins\arm_mac_stub64.dll.patched" "C:\Program Files\IDA Professional 9.0\plugins\arm_mac_stub64.dll"
# move /Y "C:\Program Files\IDA Professional 9.0\plugins\dalvik_user64.dll.patched" "C:\Program Files\IDA Professional 9.0\plugins\dalvik_user64.dll"
# move /Y "C:\Program Files\IDA Professional 9.0\plugins\gdb_user64.dll.patched" "C:\Program Files\IDA Professional 9.0\plugins\gdb_user64.dll"
# move /Y "C:\Program Files\IDA Professional 9.0\plugins\ios_user64.dll.patched" "C:\Program Files\IDA Professional 9.0\plugins\ios_user64.dll"
# move /Y "C:\Program Files\IDA Professional 9.0\plugins\linux_stub64.dll.patched" "C:\Program Files\IDA Professional 9.0\plugins\linux_stub64.dll"
# move /Y "C:\Program Files\IDA Professional 9.0\plugins\mac_stub64.dll.patched" "C:\Program Files\IDA Professional 9.0\plugins\mac_stub64.dll"
# move /Y "C:\Program Files\IDA Professional 9.0\plugins\pin_user64.dll.patched" "C:\Program Files\IDA Professional 9.0\plugins\pin_user64.dll"
# move /Y "C:\Program Files\IDA Professional 9.0\plugins\win32_stub64.dll.patched" "C:\Program Files\IDA Professional 9.0\plugins\win32_stub64.dll"
# move /Y "C:\Program Files\IDA Professional 9.0\plugins\xnu_user64.dll.patched" "C:\Program Files\IDA Professional 9.0\plugins\xnu_user64.dll"

generate_patched_executable('ida.dll')
generate_patched_executable('ida64.dll')
generate_patched_executable('hv.exe')
generate_patched_executable('hvui.exe')
generate_patched_executable('dbgsrv/linux_server')
generate_patched_executable('dbgsrv/linux_server64')
generate_patched_executable('dbgsrv/mac_server')
generate_patched_executable('dbgsrv/mac_server64')
generate_patched_executable('dbgsrv/mac_server_arm64')
generate_patched_executable('dbgsrv/mac_server_arm64e')
generate_patched_executable('dbgsrv/win32_remote.exe')
generate_patched_executable('dbgsrv/win64_remote64.exe')
generate_patched_executable('plugins/armlinux_stub64.dll')
generate_patched_executable('plugins/arm_mac_stub64.dll')
generate_patched_executable('plugins/dalvik_user64.dll')
generate_patched_executable('plugins/gdb_user64.dll')
generate_patched_executable('plugins/ios_user64.dll')
generate_patched_executable('plugins/linux_stub64.dll')
generate_patched_executable('plugins/mac_stub64.dll')
generate_patched_executable('plugins/pin_user64.dll')
generate_patched_executable('plugins/win32_stub64.dll')
generate_patched_executable('plugins/xnu_user64.dll')

# Linux

# mv "/opt/idapro-9.0/ida.so.patched" "/opt/idapro-9.0/ida.so"
# mv "/opt/idapro-9.0/ida64.so.patched" "/opt/idapro-9.0/ida64.so"
# mv "/opt/idapro-9.0/hv.exe.patched" "/opt/idapro-9.0/hv.exe"
# mv "/opt/idapro-9.0/hvui.exe.patched" "/opt/idapro-9.0/hvui.exe"
# mv "/opt/idapro-9.0/dbgsrv/linux_server.patched" "/opt/idapro-9.0/dbgsrv/linux_server"
# mv "/opt/idapro-9.0/dbgsrv/linux_server64.patched" "/opt/idapro-9.0/dbgsrv/linux_server64"
# mv "/opt/idapro-9.0/dbgsrv/mac_server.patched" "/opt/idapro-9.0/dbgsrv/mac_server"
# mv "/opt/idapro-9.0/dbgsrv/mac_server64.patched" "/opt/idapro-9.0/dbgsrv/mac_server64"
# mv "/opt/idapro-9.0/dbgsrv/mac_server_arm64.patched" "/opt/idapro-9.0/dbgsrv/mac_server_arm64"
# mv "/opt/idapro-9.0/dbgsrv/mac_server_arm64e.patched" "/opt/idapro-9.0/dbgsrv/mac_server_arm64e"
# mv "/opt/idapro-9.0/dbgsrv/win32_remote.exe.patched" "/opt/idapro-9.0/dbgsrv/win32_remote.exe"
# mv "/opt/idapro-9.0/dbgsrv/win64_remote64.exe.patched" "/opt/idapro-9.0/dbgsrv/win64_remote64.exe"
# mv "/opt/idapro-9.0/plugins/armlinux_stub64.so.patched" "/opt/idapro-9.0/plugins/armlinux_stub64.so"
# mv "/opt/idapro-9.0/plugins/arm_mac_stub64.so.patched" "/opt/idapro-9.0/plugins/arm_mac_stub64.so"
# mv "/opt/idapro-9.0/plugins/dalvik_user64.so.patched" "/opt/idapro-9.0/plugins/dalvik_user64.so"
# mv "/opt/idapro-9.0/plugins/gdb_user64.so.patched" "/opt/idapro-9.0/plugins/gdb_user64.so"
# mv "/opt/idapro-9.0/plugins/ios_user64.so.patched" "/opt/idapro-9.0/plugins/ios_user64.so"
# mv "/opt/idapro-9.0/plugins/linux_stub64.so.patched" "/opt/idapro-9.0/plugins/linux_stub64.so"
# mv "/opt/idapro-9.0/plugins/mac_stub64.so.patched" "/opt/idapro-9.0/plugins/mac_stub64.so"
# mv "/opt/idapro-9.0/plugins/pin_user64.so.patched" "/opt/idapro-9.0/plugins/pin_user64.so"
# mv "/opt/idapro-9.0/plugins/win32_stub64.so.patched" "/opt/idapro-9.0/plugins/win32_stub64.so"
# mv "/opt/idapro-9.0/plugins/xnu_user64.so.patched" "/opt/idapro-9.0/plugins/xnu_user64.so"

generate_patched_executable('libida.so')
generate_patched_executable('libida64.so')
generate_patched_executable('hv')
generate_patched_executable('hvui')
generate_patched_executable('dbgsrv/linux_server')
generate_patched_executable('dbgsrv/linux_server64')
generate_patched_executable('dbgsrv/mac_server')
generate_patched_executable('dbgsrv/mac_server64')
generate_patched_executable('dbgsrv/mac_server_arm64')
generate_patched_executable('dbgsrv/mac_server_arm64e')
generate_patched_executable('dbgsrv/win32_remote.exe')
generate_patched_executable('dbgsrv/win64_remote64.exe')
generate_patched_executable('plugins/armlinux_stub64.so')
generate_patched_executable('plugins/arm_mac_stub64.so')
generate_patched_executable('plugins/dalvik_user64.so')
generate_patched_executable('plugins/gdb_user64.so')
generate_patched_executable('plugins/ios_user64.so')
generate_patched_executable('plugins/linux_stub64.so')
generate_patched_executable('plugins/mac_stub64.so')
generate_patched_executable('plugins/pin_user64.so')
generate_patched_executable('plugins/win32_stub64.so')
generate_patched_executable('plugins/xnu_user64.so')

# MacOS

# mv "/opt/idapro-9.0/ida.dylib.patched" "/opt/idapro-9.0/ida.dylib"
# mv "/opt/idapro-9.0/ida64.dylib.patched" "/opt/idapro-9.0/ida64.dylib"
# mv "/opt/idapro-9.0/hv.exe.patched" "/opt/idapro-9.0/hv.exe"
# mv "/opt/idapro-9.0/hvui.exe.patched" "/opt/idapro-9.0/hvui.exe"
# mv "/opt/idapro-9.0/dbgsrv/linux_server.patched" "/opt/idapro-9.0/dbgsrv/linux_server"
# mv "/opt/idapro-9.0/dbgsrv/linux_server64.patched" "/opt/idapro-9.0/dbgsrv/linux_server64"
# mv "/opt/idapro-9.0/dbgsrv/mac_server.patched" "/opt/idapro-9.0/dbgsrv/mac_server"
# mv "/opt/idapro-9.0/dbgsrv/mac_server64.patched" "/opt/idapro-9.0/dbgsrv/mac_server64"
# mv "/opt/idapro-9.0/dbgsrv/mac_server_arm64.patched" "/opt/idapro-9.0/dbgsrv/mac_server_arm64"
# mv "/opt/idapro-9.0/dbgsrv/mac_server_arm64e.patched" "/opt/idapro-9.0/dbgsrv/mac_server_arm64e"
# mv "/opt/idapro-9.0/dbgsrv/win32_remote.exe.patched" "/opt/idapro-9.0/dbgsrv/win32_remote.exe"
# mv "/opt/idapro-9.0/dbgsrv/win64_remote64.exe.patched" "/opt/idapro-9.0/dbgsrv/win64_remote64.exe"
# mv "/opt/idapro-9.0/plugins/armlinux_stub64.dylib.patched" "/opt/idapro-9.0/plugins/armlinux_stub64.dylib"
# mv "/opt/idapro-9.0/plugins/arm_mac_stub64.dylib.patched" "/opt/idapro-9.0/plugins/arm_mac_stub64.dylib"
# mv "/opt/idapro-9.0/plugins/dalvik_user64.dylib.patched" "/opt/idapro-9.0/plugins/dalvik_user64.dylib"
# mv "/opt/idapro-9.0/plugins/gdb_user64.dylib.patched" "/opt/idapro-9.0/plugins/gdb_user64.dylib"
# mv "/opt/idapro-9.0/plugins/ios_user64.dylib.patched" "/opt/idapro-9.0/plugins/ios_user64.dylib"
# mv "/opt/idapro-9.0/plugins/linux_stub64.dylib.patched" "/opt/idapro-9.0/plugins/linux_stub64.dylib"
# mv "/opt/idapro-9.0/plugins/mac_stub64.dylib.patched" "/opt/idapro-9.0/plugins/mac_stub64.dylib"
# mv "/opt/idapro-9.0/plugins/pin_user64.dylib.patched" "/opt/idapro-9.0/plugins/pin_user64.dylib"
# mv "/opt/idapro-9.0/plugins/win32_stub64.dylib.patched" "/opt/idapro-9.0/plugins/win32_stub64.dylib"
# mv "/opt/idapro-9.0/plugins/xnu_user64.dylib.patched" "/opt/idapro-9.0/plugins/xnu_user64.dylib"

generate_patched_executable('libida.dylib')
generate_patched_executable('libida64.dylib')
generate_patched_executable('hv')
generate_patched_executable('hvui')
generate_patched_executable('dbgsrv/linux_server')
generate_patched_executable('dbgsrv/linux_server64')
generate_patched_executable('dbgsrv/mac_server')
generate_patched_executable('dbgsrv/mac_server64')
generate_patched_executable('dbgsrv/mac_server_arm64')
generate_patched_executable('dbgsrv/mac_server_arm64e')
generate_patched_executable('dbgsrv/win32_remote.exe')
generate_patched_executable('dbgsrv/win64_remote64.exe')
generate_patched_executable('plugins/armlinux_stub64.dylib')
generate_patched_executable('plugins/arm_mac_stub64.dylib')
generate_patched_executable('plugins/dalvik_user64.dylib')
generate_patched_executable('plugins/gdb_user64.dylib')
generate_patched_executable('plugins/ios_user64.dylib')
generate_patched_executable('plugins/linux_stub64.dylib')
generate_patched_executable('plugins/mac_stub64.dylib')
generate_patched_executable('plugins/pin_user64.dylib')
generate_patched_executable('plugins/win32_stub64.dylib')
generate_patched_executable('plugins/xnu_user64.dylib')

# Servers

# mv "/opt/hexvault/vault_server.patched" "/opt/hexvault/vault_server"
# mv "/opt/lumina/lumina_server_teams.patched" "/opt/lumina/lumina_server_teams"
# mv "/opt/lumina/lc.patched" "/opt/lumina/lc"

generate_patched_executable('vault_server')
generate_patched_executable('lumina_server_teams')
generate_patched_executable('lc')
