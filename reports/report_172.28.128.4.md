
# Shennina Exploitation Report

## Target: `172.28.128.4`

#### The target has been compromised using the following:


## Exploit: `exploit/multi/elasticsearch/script_mvel_rce`

## Exploit Details

### Name

```
ElasticSearch Dynamic Script Arbitrary Java Execution
```

### Description

```
This module exploits a remote command execution (RCE) vulnerability in ElasticSearch, exploitable by default on ElasticSearch prior to 1.2.0. The bug is found in the REST API, which does not require authentication, where the search function allows dynamic scripts execution. It can be used for remote attackers to execute arbitrary Java code. This module has been tested successfully on ElasticSearch 1.1.1 on Ubuntu Server 12.04 and Windows XP SP3.
```

### References

```
CVE-2014-3120
OSVDB-106949
EDB-33370
http://bouk.co/blog/elasticsearch-rce/
https://www.found.no/foundation/elasticsearch-security/#staying-safe-while-developing-with-elasticsearch
```

## Shell Type: `meterpreter`

## Payload: `payload/java/meterpreter/reverse_tcp`



---

# Data Obtained From Target via Exfiltration Server
### env

```

Name                           Value                                           
----                           -----                                           
ALLUSERSPROFILE                C:\ProgramData                                  
APPDATA                        C:\Windows\system32\config\systemprofile\AppD...
ChocolateyInstall              C:\ProgramData\chocolatey                       
CLASSPATH                      .;                                              
CommonProgramFiles             C:\Program Files\Common Files                   
CommonProgramFiles(x86)        C:\Program Files (x86)\Common Files             
CommonProgramW6432             C:\Program Files\Common Files                   
COMPUTERNAME                   METASPLOITABLE3                                 
ComSpec                        C:\Windows\system32\cmd.exe                     
CYGWIN                         mintty                                          
FP_NO_HOST_CHECK               NO                                              
JAVA_HOME                      C:\Program Files\Java\jdk1.8.0_211              
LOCALAPPDATA                   C:\Windows\system32\config\systemprofile\AppD...
NUMBER_OF_PROCESSORS           2                                               
OS                             Windows_NT                                      
Path                           C:\tools\ruby23\bin;C:\Program Files (x86)\Co...
PATHEXT                        .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;....
PROCESSOR_ARCHITECTURE         AMD64                                           
PROCESSOR_IDENTIFIER           Intel64 Family 6 Model 142 Stepping 10, Genui...
PROCESSOR_LEVEL                6                                               
PROCESSOR_REVISION             8e0a                                            
ProgramData                    C:\ProgramData                                  
ProgramFiles                   C:\Program Files                                
ProgramFiles(x86)              C:\Program Files (x86)                          
ProgramW6432                   C:\Program Files                                
PSModulePath                   WindowsPowerShell\Modules;C:\ProgramData\Boxs...
PUBLIC                         C:\Users\Public                                 
SystemDrive                    C:                                              
SystemRoot                     C:\Windows                                      
TEMP                           C:\Windows\TEMP                                 
TMP                            C:\Windows\TEMP                                 
USERDOMAIN                     WORKGROUP                                       
USERNAME                       METASPLOITABLE3$                                
USERPROFILE                    C:\Windows\system32\config\systemprofile        
windir                         C:\Windows                                      
windows_tracing_flags          3                                               
windows_tracing_logfile        C:\BVTBin\Tests\installpackage\csilogfile.log   



```

### Username

```
METASPLOITABLE3$
```

### COMPUTERNAME

```
METASPLOITABLE3
```

### USERPROFILE

```
C:\Windows\system32\config\systemprofile
```

### USERDOMAIN

```
WORKGROUP
```

### USERNAME

```
METASPLOITABLE3$
```

### Path

```
C:\tools\ruby23\bin;C:\Program Files (x86)\Common Files\Oracle\Java\javapath;C:\ProgramData\Boxstarter;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Program Files\OpenSSH\bin;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\ProgramData\chocolatey\bin;C:\Program Files\Java\jdk1.8.0_211\bin;
```

### ipconfig

```

Windows IP Configuration

   Host Name . . . . . . . . . . . . : metasploitable3-win2k8
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Local Area Connection 2:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Desktop Adapter #2
   Physical Address. . . . . . . . . : 08-00-27-E8-86-4A
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::ccd4:30bb:640a:782%14(Preferred) 
   IPv4 Address. . . . . . . . . . . : 172.28.128.4(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 
   DHCPv6 IAID . . . . . . . . . . . : 319291431
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-24-BC-A8-BD-08-00-27-E1-EE-BB
   DNS Servers . . . . . . . . . . . : fec0:0:0:ffff::1%1
                                       fec0:0:0:ffff::2%1
                                       fec0:0:0:ffff::3%1
   NetBIOS over Tcpip. . . . . . . . : Enabled

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Desktop Adapter
   Physical Address. . . . . . . . . : 08-00-27-E1-EE-BB
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::6c72:416a:5c79:9680%11(Preferred) 
   IPv4 Address. . . . . . . . . . . : 10.0.2.15(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Lease Obtained. . . . . . . . . . : Tuesday, October 15, 2019 11:56:50 AM
   Lease Expires . . . . . . . . . . : Wednesday, October 16, 2019 11:56:53 AM
   Default Gateway . . . . . . . . . : 10.0.2.2
   DHCP Server . . . . . . . . . . . : 10.0.2.2
   DHCPv6 IAID . . . . . . . . . . . : 235405351
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-24-BC-A8-BD-08-00-27-E1-EE-BB
   DNS Servers . . . . . . . . . . . : 10.0.2.3
   NetBIOS over Tcpip. . . . . . . . : Enabled

Tunnel adapter isatap.{501DF89C-22DB-4782-9151-634C06421220}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes

Tunnel adapter isatap.{4D23D7F7-1902-46C7-B795-EF3585D13827}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter #2
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes

```

### logged_in_users

```

username
--------
        



```

### running_processes

```

Handles  NPM(K)    PM(K)      WS(K) VM(M)   CPU(s)     Id  SI ProcessName      
-------  ------    -----      ----- -----   ------     --  -- -----------      
     28       5     2200       1428    21     0.00   1420   0 cmd              
     29       5     2144        200    21     0.00   2044   0 cmd              
     43       6     2124        200    25     0.02   3152   0 cmd              
     29       5     2040       2560    18     0.02   5276   0 cmd              
     29       5     2040       2560    18     0.00   5752   0 cmd              
     34       5     1008        400    26     0.02   1220   0 conhost          
     33       5      972        416    26     0.00   1320   0 conhost          
     34       5     1020        396    26     0.02   1428   0 conhost          
     34       5     1024        376    26     0.02   1536   0 conhost          
     36       5     1028        380    26     0.03   1704   0 conhost          
     32       5     1008        368    26     0.00   1908   0 conhost          
     32       4      944        224    22     0.02   2120   0 conhost          
     32       5     1008        368    26     0.02   2216   0 conhost          
     64       6      952        364    23     0.00   3088   0 conhost          
     32       5     1012        504    26     0.00   3216   0 conhost          
     32       5      952        372    26     0.02   3260   0 conhost          
     32       4      888       2508    22     0.00   3956   0 conhost          
     32       4      888       2492    22     0.02   4364   0 conhost          
     32       4      892       2504    22     0.02   5200   0 conhost          
     32       4      892       2484    22     0.00   5664   0 conhost          
     32       4      888       2508    22     0.02   5896   0 conhost          
     32       4      888       2512    22     0.00   6052   0 conhost          
   1452      19     2256       1996    54     0.44    324   0 csrss            
     71       8     1696        388    42     0.08    388   1 csrss            
    100       7     7692        944   549     0.02   2248   0 cygrunsrv        
     83      10     2040       1308    35     0.03   1824   0 dcnotification...
     43       7     1084       1660    42     0.00   1880   0 dcrotatelogs     
     43       7     1084       1832    42     0.00   2204   0 dcrotatelogs     
    109      22     4988       1244    58     0.83   1872   0 dcserverhttpd    
    533      93    16680       5780   158     0.92   2088   0 dcserverhttpd    
    157      24    23692       2804   491     0.08   1228   0 domain1Service   
    677      86   396252     262772  2515    12.63   1312   0 elasticsearch-...
    126      19     7272        484    69     0.06   3436   0 httpd            
    173      33     8952        568    83     0.03   3604   0 httpd            
      0       0        0         24     0               0   0 Idle             
    142      15    77932      17724  1898     0.13    476   0 java             
    228      18    66368       1544   730     0.30   1032   0 java             
    243      18   102864       2976  1929     2.27   1476   0 java             
   1392      76   544000     464980   867   148.86   1600   0 java             
   1257      56   459036     361076  2153    52.67   2096   0 java             
    690      41   343272      57512  2029    18.34   3612   0 java             
    205      19    83064      30092  1906     0.50   4440   0 java             
    231      20    83288      37472  1908     0.56   5944   0 java             
    414      50    62580      31108   673     6.63   1376   0 jenkins          
    263      42    59856      26088   560     3.84   1676   0 jmx              
    147      23    12936       9872    90     0.36    808   1 LogonUI          
    565      19     3988       4296    44     0.45    484   0 lsass            
    185      10     2768       1612    30     0.02    492   0 lsm              
    146      18     3424       7608    60     0.02   5588   0 msdtc            
    518      14   183316       3640   237     0.17   3584   0 mysqld           
    322      18     3904       2480   599     0.11   3204   0 postgres         
    273      10     3408        464   594     0.02   3280   0 postgres         
    271      10     3632       8136   590     0.03   3460   0 postgres         
    270      10     3608       2208   590     0.02   3468   0 postgres         
    270      10     3604        436   590     0.02   3476   0 postgres         
    271      10     4592       2088   592     0.05   3484   0 postgres         
    271      10     3344        736   590     0.02   3492   0 postgres         
    272      10     3668       1108   590     0.13   3500   0 postgres         
    574      12     8236       1356   607     2.19   3572   0 postgres         
    397      11     6488       1296   602     0.08   5024   0 postgres         
    731      12    10720     107828   609   387.72   5032   0 postgres         
    397      11     6420       1368   602     0.08   5040   0 postgres         
    619      12     8436      21220   607     1.97   5048   0 postgres         
    301      11     5016       1188   601     0.03   5056   0 postgres         
    580      12     8692      87352   607   243.53   5064   0 postgres         
    301      11     5020       1184   601     0.03   5072   0 postgres         
    374      35    74712      80024   634     1.34   4488   0 powershell       
    269      14     4888       3864    40     0.28    468   0 services         
     30       2      440        236     5     0.09    252   0 smss             
    262      18     6032       9016    80     0.05   1060   0 spoolsv          
    154       8     2360       4940    36     0.70   4616   0 sppsvc           
    113      10     6872       3580   558     0.03   3252   0 sshd             
    314      33    10384       7120    55     0.34    460   0 svchost          
    355      14     3548       3220    45     0.16    596   0 svchost          
    226      16     3244       3208    36     0.23    728   0 svchost          
    316      15     8764       6380    48     0.81    788   0 svchost          
    931      40    15788      20156   370     1.02    868   0 svchost          
    272      22     6000       8204    63     0.27    916   0 svchost          
    132      10     2064       2684    51     0.03    964   0 svchost          
    432      29    12116       5872   355     0.80   1008   0 svchost          
     92      10     4504       1748    41     0.05   1092   0 svchost          
    143      16     4648       2776    44     0.03   1352   0 svchost          
     48       4      924        348    13     0.00   3164   0 svchost          
    145      13     7012       6544    46     0.11   3920   0 svchost          
     68       7     1580       4432    33     0.03   4312   0 svchost          
    234      13     2456       1656    38     0.03   4412   0 svchost          
     98      11     2244       1104    34     0.02   4860   0 svchost          
    631       0      112         76     3     5.94      4   0 System           
    435      56   297968     120804  1756    21.14   3228   0 tomcat8          
    123      10     2236       1792    52     0.19    660   0 VBoxService      
     79      10     1460        828    48     0.08    368   0 wininit          
     75       6     1464        788    25     0.05    424   1 winlogon         
     47       6     1020       1400    22     0.03   3576   0 wlms             
    151      12     2780       7488    40     0.02    724   0 WmiPrvSE         
    255      19     2652       4060    57     0.13   1116   0 wrapper          



```

