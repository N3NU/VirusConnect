# VirusConnect.py
VirusConnect.py connects to the VirusTotal v3 API to pull data.
Currently, VirusConnect.py pulls data on hashes and IP Addresses.
# Download
`git clone https://github.com/N3NU/VirusConnect.git`
# Setup
Insert your VirusTotal API key in the API_KEY variable.
```
#VirusTotal API Key
API_KEY = " "           ###### PUT API KEY HERE ######
```
# Usage
```
$ ./VirusConnect.py -h
usage: VirusConnect.py [-h] [-H HASH] [-ip IP]

options:
  -h, --help            show this help message and exit
  -H HASH, --hash HASH  Hash for scanning
  -ip IP, --IP IP       IP Address for scanning
```
## Scanning a Hash
`$ ./VirusConnect.py -H <hash>`
## Scanning an IP Address
`$ ./VirusConnect.py -ip <ip>`
# Example
```
$ ./VirusConnect.py -H d1f7832035c3e8a73cc78afd28cfd7f4cece6d20
==========================================================================================
                                SECURITY VENDORS' ANALYSIS                                
==========================================================================================
Total Vendors                 72
Malicious                     59
Undetected                    13
==========================================================================================
                                     BASIC PROPERTIES                                     
==========================================================================================
Name                          mimikatz.exe
md5                           e930b05efe23891d19bc354a4209be3e
sha1                          d1f7832035c3e8a73cc78afd28cfd7f4cece6d20
sha256                        92804faaab2175dc501d73e814663058c78c0a042675a8937266357bcfb96c50
Vhash                         016066651d15556515d2z1a2z8a4d0922z30300270c0105001303dz
Authentihash                  71c140fa4c5cfe126234823cfb4aad51e6ce1b6acf77d56ef7a998ef6847f3f0
Imphash                       1355327f6ca3430b3ddbe6e0acda71ea
Rich PE header hash           1c6070ab2c7665b88b0631b164393a12
SSDEEP                        24576:zLrEjqXg4NiXcmHVjIhlIyEeQ37uV3Ugmf4Yl0Q0V7FCR:zLZo1jFyjFJhmf4YlHWk
TLSH                          T142452941A7E940A8F1B79AB49EF19117DBB378D61934C30F02A48B5B1F73F619D29322
Type                          file
Type Description              Win32 EXE
Magic                         PE32+ executable for MS Windows (console) Mono/.Net assembly
File size                     1250056 bytes
==========================================================================================
                                         HISTORY                                          
==========================================================================================
Creation Time                 2020-02-29 05:13:55
First Seen In The Wild        2020-02-29 08:13:55
First Submission Date         2020-03-01 10:39:45
Last Submission Date          2022-10-15 06:15:46
Last Analysis Date            2022-10-12 06:12:40
```
