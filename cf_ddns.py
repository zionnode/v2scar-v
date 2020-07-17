#! /usr/bin/env python
# place cf-ddns.py and cf-ddns.conf on your server (e.g. /usr/local/bin/ or ~/)
# run this command:
# chmod +x /PATH_TO_FILE/cf-ddns.sh
# open cf-ddns.conf in a text editor and set the necessary parameters.
# (minimum config: one domain name, one host name, email address and api_key)
# run `crontab -e` and append this line to it:
# 0 */5 * * * * /PATH_TO_FILE/cf_ddns.py >/dev/null 2>&1
import json
import base64
import sys
import os
import socket

from urllib.request import urlopen
from urllib.request import Request
from urllib.error import URLError
from urllib.error import HTTPError

config_file_name = '/root/v2scar-v/cf_ddns.conf'

def get_public_ip():
    try:
        public_ipv4 = urlopen(
            Request('http://116.202.55.106')).read().rstrip().decode('utf-8')
        print(f"Got public ip: {public_ipv4}")
        return public_ipv4
    except URLError as e:
        return None

def get_headers(config):
    return {'X-Auth-Email': config['cloudflare_api']['email'],
            'X-Auth-Key': config['cloudflare_api']['api_key'],
            'Content-type': 'application/json'}

def get_base_url():
    return 'https://api.cloudflare.com/client/v4/zones/'


def hash_ip_to_node_id(ip):
    ip_splitted = ip.split('.')
    num_to_hash = 256 * 256 * 256 * int(ip_splitted[0]) + 256 * 256 * int(
        ip_splitted[1]) + 256 * int(ip_splitted[2]) + int(ip_splitted[3])
    return 256 * 256 * 256 * 256 - num_to_hash

def get_node_id():
    ip = get_public_ip()
    node_id = hash_ip_to_node_id(ip)
    print(f"Got node_id: {node_id}")
    return node_id

def get_token(config):
    try:
        token = base64.b64encode(
            bytes('{}+{}'.format(config['admin']['email'], config['admin']['port']), 'utf8')).decode()
    except:
        token = base64.b64encode(
            bytes('{}+{}'.format(config['username'], config['port']))).decode()
    return token


def get_node_info(config):
    try:
        apiurl = config['apiurl']
        node_id = get_node_id()
        token = get_token(config)
        header = {'token': token, 'Content-type': 'application/json'}
        api_endpoint = f'{apiurl}/api/nodeinfo/{node_id}/'
        api_req = Request(api_endpoint, headers=header)
        api_resp = urlopen(api_req)
        return json.loads(api_resp.read().decode('utf-8'))
    except:
        return {'message': 'Failed to get node_info'}


def update_or_get_dns_zone_id(config, domain):
    content_header = get_headers(config)
    base_url = get_base_url()
    if not domain:
        return config, False

    if config['domain']['name'] != domain:
        try:
            zone_id_req = Request(base_url, headers=content_header)
            zone_id_resp = urlopen(zone_id_req)
            for d in json.loads(zone_id_resp.read().decode('utf-8'))['result']:
                if domain == d['name']:
                    config['domain']['name'] = d['name']
                    config['domain']['id'] = d['id']
                    print('* zone id for "{0}" is'
                          ' {1}'.format(config['domain']['name'], config['domain']['id']))
                    return config, True
        except HTTPError as e:
            pass
        print('* could not get zone id for: {0}'.format(domain))
        print('* possible causes: wrong domain and/or auth credentials')
        return config, False

    if config['domain']['id']:
        try:
            zone_id_req = Request(base_url, headers=content_header)
            zone_id_resp = urlopen(zone_id_req)
            for d in json.loads(zone_id_resp.read().decode('utf-8'))['result']:
                if domain == d['name']:
                    if config['domain']['id'] == d['id'] and config['domain']['name'] == domain:
                        return config, False
                    else:
                        config['domain']['id'] = d['id']
                        config['domain']['name'] = domain
                        return config, True
        except:
            pass
        print('* could not get zone id for: {0}'.format(domain))
        print('* possible causes: wrong domain and/or auth credentials')
        return config, False

    config['domain']['name'] = ''
    return update_or_get_dns_zone_id(config, domain)


def get_dns_zone_id(config):
    content_header = get_headers(config)
    base_url = get_base_url()
    domain = '.'.join(config['domain']['name'].split('.')[1:])
    
    try:
        domain_id_req = Request(base_url, headers=content_header)
        domain_id_resp = urlopen(domain_id_req)
        for d in json.loads(domain_id_resp.read().decode('utf-8'))['result']:
            if domain == d['name']:
                if config['domain']['domain_id'] != d['id']:
                    config['domain']['domain_id'] = d['id']
                    save_config(config)
                return config, True
        return config, False
    except:
        return config, False


    if not config['domain']['name']:
        print('* missing domain name')
        return config


def query_ddns(config):
    content_header = get_headers(config)
    base_url = get_base_url()
    query_req = Request(
        f'{base_url}{config["domain"]["domain_id"]}/dns_records?type=A&name={config["domain"]["name"]}',
        headers=content_header)
    try:
        query_resp = json.loads(urlopen(query_req).read().decode('utf-8'))['result']
        if len(query_resp) == 1:
            return query_resp[0]
    except:
        pass
    return None


def save_config(config):
    with open(config_file_name, 'w') as config_file: 
        json.dump(config, config_file, indent=1, sort_keys=True)

def update_dynamic_ip():
    with open(config_file_name, 'r') as config_file:
        try:
            config = json.loads(config_file.read())
        except ValueError:
            print('* problem with the config file')
            exit(0)
    if not config['dynamic']:
        return
    public_ip = get_public_ip()
    if config['domain']['ipv4'] == public_ip:
        return
    update_ddns(config, public_ip)


def update_ddns(config, ip):
    content_header = get_headers(config)
    base_url = get_base_url()
    data = json.dumps({
        'type': 'A',
        'name': config['domain']['name'],
        'content': ip,
        'priority': 5,
        'ttl': 120,
        'proxied': False
    })
    update_req = Request(
        f"{base_url}{config['domain']['domain_id']}/dns_records/{config['domain']['id']}",
        headers=content_header,
        data=data.encode('utf-8'))
    update_req.get_method = lambda: 'PUT'
    update_resp = json.loads(urlopen(update_req).read().decode('utf-8'))
    if update_resp['success']:
        config['domain']['ipv4'] = update_resp['result']['content']
        save_config(config)


def init_node():
    print("Input the API url (ex: api.example.com), follwed by [ENTER]:")
    apirul = sys.stdin.readline().rstrip('\n')
    if not apirul.startswith('http'):
        apirul = 'http://' + apirul
    
    print("Input the ADMIN mail (ex: admin@example.com), followed by [ENTER]:")
    admin = sys.stdin.readline().rstrip('\n')

    print("Input the admin PORT (ex: 8080), followed by [ENTER]:")
    port = sys.stdin.readline().rstrip('\n')

    config = {
        'domain': {
            'domain_id': '',
            'ipv4': '',
            'id': '',
            'name': '',
        },
        'cloudflare_api': {
            'api_key': '37b78ed9890b7e577aa141fbedd474211b35a',
            'email': 'wzhang@zionladder.com'
        },
        'admin': {
            'email': admin,
            'port': port
        },
        'apiurl': apirul,
        'dynamic': '',
        'node_type': ''
    }
    save_config(config)
    node_info = get_node_info(config)
    if 'message' in node_info:
        print(f'ERROR: {node_info["message"]}')
        exit(0)
    print(node_info)
    config =  update_config(config, node_info)
    if 'port' in node_info and 'node_type' in node_info and node_info['node_type'] == 'v2ray':
        set_v2ray_node(config, node_info)
    if 'node_type' in node_info and node_info['node_type'] == 'ssr':
        set_ssr_node()
    if 'node_type' in node_info and node_info['node_type'] == 'ss':
        set_ssr_node()
    if 'dynamic' in node_info and node_info['dynamic']:
        create_crontab_dynamic_ip()

def update_config(config, node_info):
    if 'prefix' in node_info and node_info['prefix']:
        config['domain']['name'] = f"{node_info['prefix']}.{node_info['domain']}"
        config['dynamic'] = node_info['dynamic']
        config['node_type'] = node_info['node_type']
        save_config(config)
        config, updated = get_dns_zone_id(config)
        if updated:
            print('SUCCESS: update domain ID for cloudflare ddns')
            ddns_result = query_ddns(config)
            if ddns_result['content'] != get_public_ip():
                ask_for_continue("WRANNING: IP fron cloudflare is not same as your current IP!")
            config['domain']['id'] = query_ddns(config)['id']
            config['domain']['ipv4'] = query_ddns(config)['content']
            save_config(config)
        else:
            ask_for_continue('WRANNING: failed to get domain ID from cloudfalre ddns!')
        os.system('curl https://get.acme.sh | sh')
        create_tls_keys(config['domain']['name'], node_info)
        return config

def create_crontab_dynamic_ip():
    os.system('crontab -l > mycron')
    os.system('echo "*/10 * * * * python3 /root/v2scar-v/cf_ddns.py update_dynamic_ip > /dev/null 2>&1" >> mycron')
    os.system('crontab mycron')
    os.system('rm crontab')

def set_v2ray_node(config, node_info):
    v2ray_config = get_v2scar_config(config, node_info['port'])
    with open('/root/v2scar-v/docker-compose.yml', 'w+') as file:
        file.write(v2ray_config)
    os.system('cd /root/v2scar-v && docker-compose up -d')

def set_ss_node():
    pass

def set_ssr_node():
    pass

def get_v2scar_config(config, port):
    apiurl = config['apiurl']
    node_id = get_node_id()
    token = get_token(config)
    return f'''version: "3"

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


def ask_for_continue(message):
    print(message)
    print('Continue? y - Yes, n - No')
    string_input = sys.stdin.readline().rstrip('\n')
    if not string_input in ['y', 'Y', 'Yes', 'yes', 'YES', 'True', 'true', 'TRUE']:
        exit(0)


def create_tls_keys(address, node_info):
    port = node_info['port'] if 'port' in node_info else 8000
    os.system('systemctl stop nginx')
    os.system(f'~/.acme.sh/acme.sh --issue -d {address} --standalone -k 2048')
    os.system(f'~/.acme.sh/acme.sh --installcert -d {address} --fullchainpath /root/v2ray.crt --keypath /root/v2ray.key')
    reset_nginx(address, port)


def update_node():
    with open(config_file_name, 'r') as config_file:
        try:
            config = json.loads(config_file.read())
        except ValueError:
            print('* problem with the config file')
            exit(0)
    node_info = get_node_info(config)
    config = update_config(config, node_info)
    if 'message' in node_info:
        print(f'ERROR: {node_info["message"]}')
        exit(0)
    if 'prefix' in node_info and node_info['prefix']:
        address = f'{node_info["prefix"]}.{node_info["domain"]}'
        if address != config['domain']['name']:
            create_tls_keys(address, node_info)
            config['domain']['name'] = address
        config['dynamic'] = node_info["dynamic"]
        save_config(config)


def reset_nginx(url, port):
    nginx_string = f'''server
{{
    listen 80;
    listen [::]:80;
    server_name {url};
    if ($http_user_agent ~* "qihoobot|Baiduspider|Googlebot|Googlebot-Mobile|Googlebot-Image|Mediapartners-Google|Adsbot-Google|Feedfetcher-Google|Yahoo! Slurp|Yahoo! Slurp China|YoudaoBot|Sosospider|Sogou spider|Sogou web spider|MSNBot|ia_archiver|Tomato Bot") 
    {{ 
        return 403; 
    }} 
        location / {{
        return 301 https://{url}$request_uri; 
        }}
}}
server {{
    listen  443 ssl;
    ssl on;
    ssl_certificate       /root/v2ray.crt;
    ssl_certificate_key   /root/v2ray.key;
    ssl_protocols         TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_ciphers           HIGH:!aNULL:!MD5;
    root /var/www/tempweb;
    index index.html;

    server_name           {url};
    location / {{
      proxy_max_temp_file_size 0;
    }}
    location /clientarea {{ 
    proxy_redirect off;
    proxy_pass http://127.0.0.1:{port};
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $http_host;

    # Show realip in v2ray access.log
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }}
}}
'''
    with open('/root/v2scar-v/https.conf', 'w+') as file:
        file.write(nginx_string)
    os.system('rm -rf /etc/nginx/sites-available/https.conf')
    os.system('rm -rf /etc/nginx/sites-enabled/https.conf')
    os.system('ln -s /root/v2scar-v/https.conf /etc/nginx/sites-available/')
    os.system('ln -s /etc/nginx/sites-available/https.conf /etc/nginx/sites-enabled/')
    os.system('systemctl restart nginx')

def check_run_func():
    os.system('echo "Hello World"')


func_dict = {
    'get_public_ip': get_public_ip,
    'init_node': init_node,
    'check_run_func': check_run_func,
    'update_node': update_node,
    'update_dynamic_ip': update_dynamic_ip,
    'init_node': init_node,
}

if __name__ == '__main__':
    func_dict[sys.argv[1]]()

