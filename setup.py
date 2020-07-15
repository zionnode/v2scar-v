#!/usr/bin/env python
import os
import sys
import base64
import dns.resolver
import requests

url = sys.argv[1]

print('Input the API url of the node (ex: http://api.examle.com):')
apiurl = sys.stdin.readline().rstrip('\n')

print('Input the ADMIN email (ex: examle@gmail.com):')
admin = sys.stdin.readline().rstrip('\n')

print('Input the admin PORT (ex: 8080):')
port = sys.stdin.readline().rstrip('\n')

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

if domain_resolved_ip is not None:
    node_ip = domain_resolved_ip
else:
    node_ip = server_current_ip

node_id = hash_ip_to_node_id(node_ip)

file_string = f'''version: "3"

services:
    v2ray:
        image: v2fly/v2fly-core:latest
        container_name: v2ray
        restart: always
        volumes:
            - ./v2ray-config.json:/etc/v2ray/config.json
        ports:
            - 20086:20086
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
    file.write(file_string)
