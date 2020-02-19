#!/bin/bash
# bash script for netcat TCP port scanning process
# darksh3llRU 2017

#define netcat path
nc=/tmp/nctool

#define where to store scanning logs
logs=/tmp/scanlogs/

#create dir for logs
mkdir $logs

#define port list, default nmap top 1000
#change /,/ to // with sed: sed 's/,/ /g' port_list_commas.txt > port_list_spaces.txt
ports=(1 3 4 6 7 9 13 17 19 20 21 22 23 24 25 26 30 32 33 37 42 43 49 53 70 79 80 81 82 83 84 85 88 89 90 99 100 106 109 110 111 113 119 125 135 139 143 144 146 161 163 179 199 211 212 222 254 255 256 259 264 280 301 306 311 340 366 389 406 407 416 417 425 427 443 444 445 458 464 465 481 497 500 512 513 514 515 524 541 543 544 545 548 554 555 563 587 593 616 617 625 631 636 646 648 666 667 668 683 687 691 700 705 711 714 720 722 726 749 765 777 783 787 800 801 808 843 873 880 888 898 900 901 902 903 911 912 981 987 990 992 993 995 999 1000 1001 1002 1007 1009 1010 1011 1021 1022 1023 1024 1025 1026 1027 1028 1029 1030 1031 1032 1033 1034 1035 1036 1037 1038 1039 1040 1041 1042 1043 1044 1045 1046 1047 1048 1049 1050 1051 1052 1053 1054 1055 1056 1057 1058 1059 1060 1061 1062 1063 1064 1065 1066 1067 1068 1069 1070 1071 1072 1073 1074 1075 1076 1077 1078 1079 1080 1081 1082 1083 1084 1085 1086 1087 1088 1089 1090 1091 1092 1093 1094 1095 1096 1097 1098 1099 1100 1102 1104 1105 1106 1107 1108 1110 1111 1112 1113 1114 1117 1119 1121 1122 1123 1124 1126 1130 1131 1132 1137 1138 1141 1145 1147 1148 1149 1151 1152 1154 1163 1164 1165 1166 1169 1174 1175 1183 1185 1186 1187 1192 1198 1199 1201 1213 1216 1217 1218 1233 1234 1236 1244 1247 1248 1259 1271 1272 1277 1287 1296 1300 1301 1309 1310 1311 1322 1328 1334 1352 1417 1433 1434 1443 1455 1461 1494 1500 1501 1503 1521 1524 1533 1556 1580 1583 1594 1600 1641 1658 1666 1687 1688 1700 1717 1718 1719 1720 1721 1723 1755 1761 1782 1783 1801 1805 1812 1839 1840 1862 1863 1864 1875 1900 1914 1935 1947 1971 1972 1974 1984 1998 1999 2000 2001 2002 2003 2004 2005 2006 2007 2008 2009 2010 2013 2020 2021 2022 2030 2033 2034 2035 2038 2040 2041 2042 2043 2045 2046 2047 2048 2049 2065 2068 2099 2100 2103 2105 2106 2107 2111 2119 2121 2126 2135 2144 2160 2161 2170 2179 2190 2191 2196 2200 2222 2251 2260 2288 2301 2323 2366 2381 2382 2383 2393 2394 2399 2401 2492 2500 2522 2525 2557 2601 2602 2604 2605 2607 2608 2638 2701 2702 2710 2717 2718 2725 2800 2809 2811 2869 2875 2909 2910 2920 2967 2968 2998 3000 3001 3003 3005 3006 3007 3011 3013 3017 3030 3031 3052 3071 3077 3128 3168 3211 3221 3260 3261 3268 3269 3283 3300 3301 3306 3322 3323 3324 3325 3333 3351 3367 3369 3370 3371 3372 3389 3390 3404 3476 3493 3517 3527 3546 3551 3580 3659 3689 3690 3703 3737 3766 3784 3800 3801 3809 3814 3826 3827 3828 3851 3869 3871 3878 3880 3889 3905 3914 3918 3920 3945 3971 3986 3995 3998 4000 4001 4002 4003 4004 4005 4006 4045 4111 4125 4126 4129 4224 4242 4279 4321 4343 4443 4444 4445 4446 4449 4550 4567 4662 4848 4899 4900 4998 5000 5001 5002 5003 5004 5009 5030 5033 5050 5051 5054 5060 5061 5080 5087 5100 5101 5102 5120 5190 5200 5214 5221 5222 5225 5226 5269 5280 5298 5357 5405 5414 5431 5432 5440 5500 5510 5544 5550 5555 5560 5566 5631 5633 5666 5678 5679 5718 5730 5800 5801 5802 5810 5811 5815 5822 5825 5850 5859 5862 5877 5900 5901 5902 5903 5904 5906 5907 5910 5911 5915 5922 5925 5950 5952 5959 5960 5961 5962 5963 5987 5988 5989 5998 5999 6000 6001 6002 6003 6004 6005 6006 6007 6009 6025 6059 6100 6101 6106 6112 6123 6129 6156 6346 6389 6502 6510 6543 6547 6565 6566 6567 6580 6646 6666 6667 6668 6669 6689 6692 6699 6779 6788 6789 6792 6839 6881 6901 6969 7000 7001 7002 7004 7007 7019 7025 7070 7100 7103 7106 7200 7201 7402 7435 7443 7496 7512 7625 7627 7676 7741 7777 7778 7800 7911 7920 7921 7937 7938 7999 8000 8001 8002 8007 8008 8009 8010 8011 8021 8022 8031 8042 8045 8080 8081 8082 8083 8084 8085 8086 8087 8088 8089 8090 8093 8099 8100 8180 8181 8192 8193 8194 8200 8222 8254 8290 8291 8292 8300 8333 8383 8400 8402 8443 8500 8600 8649 8651 8652 8654 8701 8800 8873 8888 8899 8994 9000 9001 9002 9003 9009 9010 9011 9040 9050 9071 9080 9081 9090 9091 9099 9100 9101 9102 9103 9110 9111 9200 9207 9220 9290 9415 9418 9485 9500 9502 9503 9535 9575 9593 9594 9595 9618 9666 9876 9877 9878 9898 9900 9917 9929 9943 9944 9968 9998 9999 10000 10001 10002 10003 10004 10009 10010 10012 10024 10025 10082 10180 10215 10243 10566 10616 10617 10621 10626 10628 10629 10778 11110 11111 11967 12000 12174 12265 12345 13456 13722 13782 13783 14000 14238 14441 14442 15000 15002 15003 15004 15660 15742 16000 16001 16012 16016 16018 16080 16113 16992 16993 17877 17988 18040 18101 18988 19101 19283 19315 19350 19780 19801 19842 20000 20005 20031 20221 20222 20828 21571 22939 23502 24444 24800 25734 25735 26214 27000 27352 27353 27355 27356 27715 28201 30000 30718 30951 31038 31337 32768 32769 32770 32771 32772 32773 32774 32775 32776 32777 32778 32779 32780 32781 32782 32783 32784 32785 33354 33899 34571 34572 34573 35500 38292 40193 40911 41511 42510 44176 44442 44443 44501 45100 48080 49152 49153 49154 49155 49156 49157 49158 49159 49160 49161 49163 49165 49167 49175 49176 49400 49999 50000 50001 50002 50003 50006 50300 50389 50500 50636 50800 51103 51493 52673 52822 52848 52869 54045 54328 55055 55056 55555 55600 56737 56738 57294 57797 58080 60020 60443 61532 61900 62078 63331 64623 64680 65000 65129 65389)

#define array of targets
#to create a list of targets in the subnet: for i in {1..254}; do echo -n "172.30.0.$i " >> /tmp/targets.txt; done
targets=(172.30.0.1 172.30.0.2 172.30.0.3 172.30.0.4 172.30.0.5 172.30.0.6 172.30.0.7 172.30.0.8 172.30.0.9 172.30.0.10 172.30.0.11 172.30.0.12 172.30.0.13 172.30.0.14 172.30.0.15 172.30.0.16 172.30.0.17 172.30.0.18 172.30.0.19 172.30.0.20 172.30.0.21 172.30.0.22 172.30.0.23 172.30.0.24 172.30.0.25 172.30.0.26 172.30.0.27 172.30.0.28 172.30.0.29 172.30.0.30 172.30.0.31 172.30.0.32 172.30.0.33 172.30.0.34 172.30.0.35 172.30.0.36 172.30.0.37 172.30.0.38 172.30.0.39 172.30.0.40 172.30.0.41 172.30.0.42 172.30.0.43 172.30.0.44 172.30.0.45 172.30.0.46 172.30.0.47 172.30.0.48 172.30.0.49 172.30.0.50 172.30.0.51 172.30.0.52 172.30.0.53 172.30.0.54 172.30.0.55 172.30.0.56 172.30.0.57 172.30.0.58 172.30.0.59 172.30.0.60 172.30.0.61 172.30.0.62 172.30.0.63 172.30.0.64 172.30.0.65 172.30.0.66 172.30.0.67 172.30.0.68 172.30.0.69 172.30.0.70 172.30.0.71 172.30.0.72 172.30.0.73 172.30.0.74 172.30.0.75 172.30.0.76 172.30.0.77 172.30.0.78 172.30.0.79 172.30.0.80 172.30.0.81 172.30.0.82 172.30.0.83 172.30.0.84 172.30.0.85 172.30.0.86 172.30.0.87 172.30.0.88 172.30.0.89 172.30.0.90 172.30.0.91 172.30.0.92 172.30.0.93 172.30.0.94 172.30.0.95 172.30.0.96 172.30.0.97 172.30.0.98 172.30.0.99 172.30.0.100 172.30.0.101 172.30.0.102 172.30.0.103 172.30.0.104 172.30.0.105 172.30.0.106 172.30.0.107 172.30.0.108 172.30.0.109 172.30.0.110 172.30.0.111 172.30.0.112 172.30.0.113 172.30.0.114 172.30.0.115 172.30.0.116 172.30.0.117 172.30.0.118 172.30.0.119 172.30.0.120 172.30.0.121 172.30.0.122 172.30.0.123 172.30.0.124 172.30.0.125 172.30.0.126 172.30.0.127 172.30.0.128 172.30.0.129 172.30.0.130 172.30.0.131 172.30.0.132 172.30.0.133 172.30.0.134 172.30.0.135 172.30.0.136 172.30.0.137 172.30.0.138 172.30.0.139 172.30.0.140 172.30.0.141 172.30.0.142 172.30.0.143 172.30.0.144 172.30.0.145 172.30.0.146 172.30.0.147 172.30.0.148 172.30.0.149 172.30.0.150 172.30.0.151 172.30.0.152 172.30.0.153 172.30.0.154 172.30.0.155 172.30.0.156 172.30.0.157 172.30.0.158 172.30.0.159 172.30.0.160 172.30.0.161 172.30.0.162 172.30.0.163 172.30.0.164 172.30.0.165 172.30.0.166 172.30.0.167 172.30.0.168 172.30.0.169 172.30.0.170 172.30.0.171 172.30.0.172 172.30.0.173 172.30.0.174 172.30.0.175 172.30.0.176 172.30.0.177 172.30.0.178 172.30.0.179 172.30.0.180 172.30.0.181 172.30.0.182 172.30.0.183 172.30.0.184 172.30.0.185 172.30.0.186 172.30.0.187 172.30.0.188 172.30.0.189 172.30.0.190 172.30.0.191 172.30.0.192 172.30.0.193 172.30.0.194 172.30.0.195 172.30.0.196 172.30.0.197 172.30.0.198 172.30.0.199 172.30.0.200 172.30.0.201 172.30.0.202 172.30.0.203 172.30.0.204 172.30.0.205 172.30.0.206 172.30.0.207 172.30.0.208 172.30.0.209 172.30.0.210 172.30.0.211 172.30.0.212 172.30.0.213 172.30.0.214 172.30.0.215 172.30.0.216 172.30.0.217 172.30.0.218 172.30.0.219 172.30.0.220 172.30.0.221 172.30.0.222 172.30.0.223 172.30.0.224 172.30.0.225 172.30.0.226 172.30.0.227 172.30.0.228 172.30.0.229 172.30.0.230 172.30.0.231 172.30.0.232 172.30.0.233 172.30.0.234 172.30.0.235 172.30.0.236 172.30.0.237 172.30.0.238 172.30.0.239 172.30.0.240 172.30.0.241 172.30.0.242 172.30.0.243 172.30.0.244 172.30.0.245 172.30.0.246 172.30.0.247 172.30.0.248 172.30.0.249 172.30.0.250 172.30.0.251 172.30.0.252 172.30.0.253 172.30.0.254)

for host in ${!targets[*]}
do
	echo "Scan of ${targets[$host]} started" > $logs/${targets[$host]}
	for port in ${!ports[*]}
	do
		$nc -n -v -z -w 1 ${targets[$host]} ${ports[$port]} 2>&1 | grep open >> $logs/${targets[$host]} 2>&1
	done
	echo "Scan of ${targets[$host]} finished" >> $logs/${targets[$host]}
	sleep 2
done