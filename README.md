# IDATeamsDocker
Docker configuration (and only docker configuration) files for hosting self-hosted Hexvault, Lumina and Hexlicsrv. The installation files should be in `./image` folders.

Supported version:
1. [IDA 9.0.240925 September 30, 2024](https://docs.hex-rays.com/release-notes/9_0)

# CA (NOTE)
Before you start doing anything, you need to generate your own CA certificate. This can be done like this:
```bash
openssl req -x509 -newkey rsa:4096 -sha512 \
    -keyout CA.key -out CA.pem -days 3650 -nodes \
    -subj "/C=BE/L=Liège/O=Hex-Rays SA./CN=Hex-Rays SA. Root CA"
```
Now you have two files (the key and the certificate itself), you need to place these two files in the CA folders (`./CA`). Also you need to replace the CA in IDA itself, which is done in another step below.

# IDA preparing
1. Create a CA folder in the root (`C:\Program Files\IDA Professional 9.0\CA`)
2. Copy `CA.key` and `CA.pem` to the previously created folder
3. Copy the Python script (`license_patch.py`) to the root
4. Run script as administrator (`python3 license_patch.py ida-pro`)
5. Enjoy

# Hexvault hosting
1. `cd ./hexvault`
2. Copy `hexvault90_x64linux.run` into `./image`
3. Copy `CA.key` and `CA.pem` to the CA folder (`./CA`)
4. Edit `docker-compose.yml`. (You need to edit `VAULT_HOST` for TLS)
5. `sudo docker-compose up -d`
6. Enjoy

# Lumina hosting
1. `cd ./lumina`
2. Copy `lumina90_x64linux.run` into `./image`
3. Copy `CA.key` and `CA.pem` to the CA folder (`./CA`)
4. Edit `docker-compose.yml`. (You need to edit `LUMINA_HOST` for TLS)
5. `sudo docker-compose up -d`
6. Enjoy

# Hexlicsrv hosting
1. `cd ./hexlicsrv`
2. Copy `hexlicsrv90_x64linux.run` into `./image`
3. Copy `CA.key` and `CA.pem` to the CA folder (`./CA`)
4. Edit `docker-compose.yml`. (You need to edit `LICENSE_HOST` for TLS)
5. `sudo docker-compose up -d`
6. Enjoy

# NOTE
The *_schema.lock flag file is an indicator to the container when it is time to run a schema recreate using --recreate-schema. As long as this file exists, the container will not run a schema recreate.

# shell.reg
This file adds support for opening IDA with the right mouse button in Windows.
