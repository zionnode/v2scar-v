#!/bin/bash
echo "LANG=en_US.utf-8" >> /etc/environment
echo "LC_ALL=en_US.utf-8" >> /etc/environment
echo "Type the URL to use (connect-001.example.com), followed by [ENTER]:"
read URL

dpkg --configure -a
apt update -y && apt upgrade -y && apt install -y nginx python3 socat netcat curl wget python3-pip
pip3 install requests

cd ~ && mkdir .ssh && chmod 700 .ssh && touch ~/.ssh/authorized_keys

echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC/e1MctU7rZ0BmRzzFzxZK6UhUmfngBhRNUHdbihLqg6QyV4btEH7PcXw755B1pIodyEIJFBeYtkhSUVQ2evVkfp/gRjf/Gq2YWzGaFyvM+lHi6N2jchLf8hSSOBRh4NZyo7VjmJz3OuruBiBZLRaVXeQayIXA5Zd0IbKbd0i/sLVaa5Lf2vCk57EkMq/nEt5ajuCEI+AWtwFlu3/hmR1k7jFB49YnAQ/nHJBWY0wWelOtb7Emr6EAMHoyYIOqPa597qjMwAE/SqKtQuDUds73mszbjCXlIgXRmIAHOtd1RyYicXNq4tamk4Cfa0ApWxxkASTmip33R87iGXS6d/ij ilove0530@gmail.com\n" >> ~/.ssh/authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDA+xXDi3AtfMvpmP6cRtIbVzH7GS2KBik6Z6lnUvBerZ/MXVGDmirnlSiBK5TKpA+oTj1qNjihkbyYXpxZPFekFbw2vUdTx857vEGC35HF69yzmvu4TBEx8GGpxII4VBzEYcElTqKPL+bgk1EFSGUxAhdKDWZc2Z/pamOv8u9ms0IuW9Zn054z2/xjFxwJcOTJt6CRsYfxbViVX6IC4uMBLT9bRyY0PHo+TQX3LNDaJYl1lNvdPp6PrwKtNpt8B3oUhobKUifc08Zmgzld85+9Lvi7obW7TS5oCdSO0xmu6F8n6YXxIkiDk4TH1Y1y2te9s1s7AhCTynCSeT+c333J www@zion-core-site" >> ~/.ssh/authorized_keys

chmod 600 ~/.ssh/authorized_keys

echo "PermitRootLogin prohibit-password" >> /etc/ssh/sshd_config
echo "RSAAuthentication yes" >> /etc/ssh/sshd_config
echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
echo "AuthorizedKeysFile      %h/.ssh/authorized_keys" >> /etc/ssh/sshd_config
echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config

wget --no-check-certificate https://github.com/teddysun/across/raw/master/bbr.sh && chmod +x bbr.sh && ./bbr.sh
echo "fs.file-max = 51200" >> /etc/sysctl.conf 
echo "net.core.rmem_max = 67108864" >> /etc/sysctl.conf 
echo "net.core.wmem_max = 67108864" >> /etc/sysctl.conf 
echo "net.core.netdev_max_backlog = 250000" >> /etc/sysctl.conf 
echo "net.core.somaxconn = 4096net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf 
echo "net.ipv4.tcp_tw_reuse = 1" >> /etc/sysctl.conf 
echo "net.ipv4.tcp_tw_recycle = 0" >> /etc/sysctl.conf 
echo "net.ipv4.tcp_fin_timeout = 30" >> /etc/sysctl.conf 
echo "net.ipv4.tcp_keepalive_time = 1200" >> /etc/sysctl.conf 
echo "net.ipv4.ip_local_port_range = 10000 65000" >> /etc/sysctl.conf 
echo "net.ipv4.tcp_max_syn_backlog = 8192" >> /etc/sysctl.conf 
echo "net.ipv4.tcp_max_tw_buckets = 5000" >> /etc/sysctl.conf 
echo "net.ipv4.tcp_fastopen = 3" >> /etc/sysctl.conf
echo "net.ipv4.tcp_mem = 25600 51200 102400" >> /etc/sysctl.conf 
echo "net.ipv4.tcp_rmem = 4096 87380 67108864" >> /etc/sysctl.conf 
echo "net.ipv4.tcp_wmem = 4096 65536 67108864" >> /etc/sysctl.conf 
echo "net.ipv4.tcp_mtu_probing = 1" >> /etc/sysctl.conf 
echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf

echo "*            soft        nofile        512000" >> /etc/security/limits.conf
echo "*            hard        nofile        1024000" >> /etc/security/limits.conf

echo "ulimit -SHn 1024000" >> /etc/profile

cd ~
curl  https://get.acme.sh | sh
systemctl stop nginx
~/.acme.sh/acme.sh --issue -d "$URL" --standalone -k 2048
~/.acme.sh/acme.sh --installcert -d "$URL" --fullchainpath /etc/v2ray/v2ray.crt --keypath /etc/v2ray/v2ray.key
git clone https://zionnode:Zw19820130@github.com/zionnode/tempweb.git /var/www/tempweb

cd ~
git clone https://zionnode:Zw19820130@github.com/zionnode/v2scar-v.git
cd v2scar-v

python3 setup.py $URL

cd ~
touch mycron
echo '58 0 * * * "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" > /dev/null' >> mycron
crontab mycron
rm mycron