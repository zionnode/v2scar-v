#!/usr/bin/env python
import os
import sys
import base64
import dns.resolver
import requests

from cf_ddns import init_node, reset_nginx

url = sys.argv[1]
apiurl = sys.argv[2]
admin = sys.argv[3]
port = sys.argv[4]

token = base64.b64encode(bytes(f'{admin}+{port}', 'utf8')).decode()

def get_current_ip():
    try:
        r = requests.get('http://ipv4.icanhazip.com/')
        ip = r.content.rstrip().decode('utf-8')
    except:
        r = requests.get('http://ip-api.com/json')
        ip = r.json()['query']
    return ip

def resolve_domain_ip(address):
    cloudflare_dns = dns.resolver.Resolver()
    cloudflare_dns.nameservers = ['1.1.1.1']
    try:
        ip_resolved = str(cloudflare_dns.query(address)[0])
    except:
        raise ValueError(f'Cannot resolve the domain: {address}')
    return ip_resolved

def hash_ip_to_node_id(ip):
    ip_splitted = ip.split('.')
    num_to_hash = 256 * 256 * 256 * int(ip_splitted[0]) + 256 * 256 * int(
        ip_splitted[1]) + 256 * int(ip_splitted[2]) + int(ip_splitted[3])
    return 256 * 256 * 256 * 256 - num_to_hash


server_current_ip = get_current_ip()
domain_resolved_ip = resolve_domain_ip(url)

if server_current_ip != domain_resolved_ip:
    print(f'Server current IP is not same as domain resolved ip! Continue? y - Yes, n - No')
    string_input = sys.stdin.readline().rstrip('\n')
    if not string_input in ['y', 'Y', 'Yes', 'yes', 'YES', 'True', 'true', 'TRUE']:
        exit()

node_address, port = init_node()
if node_address != url:
    print(f'The address of the node from API is not same as the url provided! Continue? y - Yes, n - No')
    string_input = sys.stdin.readline().rstrip('\n')
    if not string_input in ['y', 'Y', 'Yes', 'yes', 'YES', 'True', 'true', 'TRUE']:
        exit()

if domain_resolved_ip is not None:
    node_ip = domain_resolved_ip
else:
    node_ip = server_current_ip

node_id = hash_ip_to_node_id(node_ip)

v2ray_string = f'''version: "3"

services:
    v2ray:
        image: v2fly/v2fly-core:latest
        container_name: v2ray
        restart: always
        volumes:
            - ./v2ray-config.json:/etc/v2ray/config.json
        ports:
            - {port}:{port}
        command: ["v2ray","-config={apiurl}/api/vmess_server_config/{node_id}/?token={token}"]

    v2scar:
        container_name: v2scar
        image: ehco1996/v2scar
        restart: always
        depends_on:
            - v2ray
        links:
            - v2ray
        environment:
            V2SCAR_SYNC_TIME: 60
            V2SCAR_API_ENDPOINT: "{apiurl}/api/user_vmess_config/{node_id}/?token={token}"
            V2SCAR_GRPC_ENDPOINT: "v2ray:8080"'''

with open('/root/v2scar-v/docker-compose.yml', 'w+') as file:
    file.write(v2ray_string)

reset_nginx(url)
# nginx_string = f'''server
# {{
#     listen 80;
#     listen [::]:80;
#     server_name {url};
#     if ($http_user_agent ~* "qihoobot|Baiduspider|Googlebot|Googlebot-Mobile|Googlebot-Image|Mediapartners-Google|Adsbot-Google|Feedfetcher-Google|Yahoo! Slurp|Yahoo! Slurp China|YoudaoBot|Sosospider|Sogou spider|Sogou web spider|MSNBot|ia_archiver|Tomato Bot") 
#     {{ 
#         return 403; 
#     }} 
#         location / {{
#         return 301 https://{url}$request_uri; 
#         }}
# }}
# server {{
#     listen  443 ssl;
#     ssl on;
#     ssl_certificate       /root/v2ray.crt;
#     ssl_certificate_key   /root/v2ray.key;
#     ssl_protocols         TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
#     ssl_ciphers           HIGH:!aNULL:!MD5;
#     root /var/www/tempweb;
#     index index.html;

#     server_name           {url};
#     location / {{
#       proxy_max_temp_file_size 0;
#     }}
#     location /clientarea {{ 
#     proxy_redirect off;
#     proxy_pass http://127.0.0.1:{port};
#     proxy_http_version 1.1;
#     proxy_set_header Upgrade $http_upgrade;
#     proxy_set_header Connection "upgrade";
#     proxy_set_header Host $http_host;

#     # Show realip in v2ray access.log
#     proxy_set_header X-Real-IP $remote_addr;
#     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#     }}
# }}
# '''

# with open('/root/v2scar-v/https.conf', 'w+') as file:
#     file.write(nginx_string)