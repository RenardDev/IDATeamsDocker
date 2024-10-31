# IDATeamsDocker
Docker configuration (and only docker configuration) files for hosting self-hosted Hexvault, Lumina and Hexlicsrv. The installation files should be in `./image` folders.

Supported version: [IDA 9.0.240925 September 30, 2024](https://docs.hex-rays.com/release-notes/9_0)

# Note
Before you start doing anything, you need to generate your own CA certificate. This can be done like this:
```bash
openssl req -x509 -newkey rsa:4096 -sha512 \
    -keyout CA.key -out CA.pem -days 365 -nodes \
        -subj "/C=BE/L=Liège/O=Hex-Rays SA./CN=Hex-Rays SA. Root CA"
```
Now you have two files (the key and the certificate itself), you need to place these two files in the CA folders (`./CA`). Also you need to replace the CA in IDA itself, which is done in another step below.

# IDA preparing
1. Create a CA folder in the root (`C:\Program Files\IDA Professional 9.0\CA`)
2. Copy `CA.key` and `CA.pem` to the previously created folder
4. Copy the Python script (`patch.py`) to the root
5. Run script as administrator
6. Enjoy

# Hexvault hosting
1. `cd ./hexvault`
2. Copy `hexvault90_x64linux.run` into `./image`
3. `chmod +x ./image/entrypoint.sh`
4. Copy `CA.key` and `CA.pem` to the CA folder (`./CA`)
5. Edit `docker-compose.yml`. (You need to edit `VAULT_HOST` for TLS)
6. `sudo docker-compose up -d`
7. Enjoy

# Lumina hosting
11. `cd ./lumina`
2. Copy `lumina90_x64linux.run` into `./image`
3. `chmod +x ./image/entrypoint.sh`
4. Copy `CA.key` and `CA.pem` to the CA folder (`./CA`)
5. Edit `docker-compose.yml`. (You need to edit `LUMINA_HOST` for TLS)
6. `sudo docker-compose up -d`
7. Enjoy

# Hexlicsrv hosting
1. `cd ./hexlicsrv`
2. Copy `hexlicsrv90_x64linux.run` into `./image`
3. `chmod +x ./image/entrypoint.sh`
4. Copy `CA.key` and `CA.pem` to the CA folder (`./CA`)
5. Edit `docker-compose.yml`. (You need to edit `LICENSE_HOST` for TLS)
6. `sudo docker-compose up -d`
7. Enjoy
