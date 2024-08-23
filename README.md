# IDATeamsDocker
Docker configuration (and only docker configuration) files for hosting self-hosted Lumina and Hexvault. The installation files should be in ./image folders.

# Note
Before you start doing anything, you need to generate your own CA certificate. This can be done like this:
```bash
openssl req -x509 -newkey rsa:4096 -sha512 \
    -keyout CA.key -out CA.pem -days 365 -nodes \
    -subj "/C=BE/L=Liège/O=Hex-Rays SA./CN=Hex-Rays SA. Root CA"
```
Now you have two files (the key and the certificate itself), you need to place these two files in the CA folders (./data/CA). Also you need to replace the CA in IDA itself, which is done in another step below.

# IDA preparing
1. Create a CA folder in the root (for example `C:\Program Files\IDA Professional 10.0\CA`)
2. Copy CA.key and CA.pem to the previously created folder
4. Copy the Python script to the root.
5. Run script as administrator.
6. Enjoy.

# Hexvault hosting
1. `cd ./hexvault`
2. Copy CA.key and CA.pem to the CA folder (./data/CA)
3. `sudo docker-compose up -d`
4. Enjoy

# Lumina hosting
Lumina requires hexvault because it stores all the file history (similar to SVN from Hex-Rays) and also stores accounts.
1. `cd ./lumina`
2. Copy CA.key and CA.pem to the CA folder (./data/CA)
3. `sudo docker-compose up -d`
4. Enjoy

# How to set up Lumina client on IDA
You need to apply these registry values.
```
[HKEY_CURRENT_USER\SOFTWARE\Hex-Rays\IDA\Lumina]
"Primary"="<hexvault username>:<hexvault passwords>@reversing.example.com"
```
