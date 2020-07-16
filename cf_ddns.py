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

from urllib.request import urlopen
from urllib.request import Request
from urllib.error import URLError
from urllib.error import HTTPError

config_file_name = '/root/v2scar-v/cf_ddns.conf'

def get_public_ip():
    try:
        public_ipv4 = urlopen(
            Request('http://116.202.55.106')).read().rstrip().decode('utf-8')
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

def get_token(config):
    try:
        token = base64.b64encode(
            bytes('{}+{}'.format(config['admin']['email'], config['admin']['port']), 'utf8')).decode()
    except:
        token = base64.b64encode(
            bytes('{}+{}'.format(config['username'], config['port']))).decode()
    return token


def get_node_info(config, ip, apiurl):
    try:
        node_id = hash_ip_to_node_id(ip)
        token = get_token(config)
        header = {'token': token, 'Content-type': 'application/json'}
        api_endpoint = f'{apiurl}/api/nodeinfo/{node_id}/vtwo/'
        api_req = Request(api_endpoint, headers=header)
        api_resp = urlopen(api_req)
        return json.loads(api_resp.read().decode('utf-8'))
    except:
        return None


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


def get_dns_zone_id(config, domain):
    content_header = get_headers(config)
    base_url = get_base_url()

    if not config['domain']['name']:
        print('* missing domain name')
        return config

    # get domain zone id from CloudFlare if missing
    if not config['domain']['domain_id']:
        try:
            print(
                '* zone id for "{0}" is missing. attempting to '
                'get it from cloudflare...'.format(config['domain']['name']))
            zone_id_req = Request(base_url, headers=content_header)
            zone_id_resp = urlopen(zone_id_req)
            for d in json.loads(zone_id_resp.read().decode('utf-8'))['result']:
                if domain == d['name']:
                    config['domain']['domain_id'] = d['id']
                    print('* zone id for "{0}" is'
                          ' {1}'.format(config['domain']['name'], config['domain']['id']))
                    return config, True
        except HTTPError as e:
            print(
                '* could not get zone id for: {0}'.format(config['domain']['name']))
            print('* possible causes: wrong domain and/or auth credentials')
    return config, False


def create_or_update_prefix(config, node_info, update):
    public_ip = get_public_ip()
    prefix = node_info['prefix']


def create_prefix(config, node_info, update):
    public_ip = get_public_ip()
    prefix = node_info['prefix']
    if prefix and public_ip and config['domain']['id']:
        content_header = get_headers(config)
        base_url = get_base_url()
        try:
            print('creating name!')
            data = json.dumps({
                'type': 'A',
                'name': prefix,
                'content': public_ip,
                'ttl': 120,
                'priority': 10,
                'proxied': False
            })
            print(data)
            create_req = Request(
                '{}{}/dns_records'.format(base_url, config['domain']['id']),
                headers=content_header,
                data=data.encode('utf-8')
            )
            create_req.get_method = lambda: 'POST'
            create_resp = json.loads(
                urlopen(create_req).read().decode('utf-8'))
            print(create_resp)
            config['domain']['host']['ipv4'] = public_ip
            config['domain']['host']['name'] = prefix
            config['domain']['host']['id'] = create_resp['result']['id']
            return config, True
        except:
            print('creating failed!')
    print('prefix or public_ip or domain_id not provided')
    return config, update


def query_ddns(config):
    content_header = get_headers(config)
    base_url = get_base_url()
    print('{base_url}{zion_id}/dns_records?type={qtype}&name={name}'.format(
            base_url=base_url,
            zion_id=config['domain']['id'],
            qtype='A',
            name=config['domain']['host']['name']+'.'+config['domain']['name']))
    query_req = Request(
        '{base_url}{zion_id}/dns_records?type={qtype}&name={name}'.format(
            base_url=base_url,
            zion_id=config['domain']['id'],
            qtype='A',
            name=config['domain']['host']['name']+'.'+config['domain']['name']),
        headers=content_header)
    try:
        query_resp = json.loads(urlopen(query_req).read().decode('utf-8'))['result']
        if len(query_resp) == 1:
            return query_resp[0]
    except:
        pass
    return None


def update_prefix(config, node_info, update):
    public_ip = get_public_ip()
    prefix = node_info['prefix']
    if prefix and public_ip and config['domain']['id']:
        if config['domain']['host']['id']:
            if config['domain']['host']['ipv4'] == public_ip:
                print('no ip changed, no update')
                return config, update
            try:
                content_header = get_headers(config)
                base_url = get_base_url()
                data = json.dumps({
                    'type': 'A',
                    'name': prefix,
                    'content': public_ip,
                    'priority': 5,
                    'ttl': 120,
                    'proxied': False
                })
                update_req = Request(
                    '{}{}/dns_records/{}'.format(
                        base_url, config['domain']['id'], config['domain']['host']['id']),
                    headers=content_header,
                    data=data.encode('utf-8')
                )
                update_req.get_method = lambda: 'PUT'
                update_resp = json.loads(
                    urlopen(update_req).read().decode('utf-8'))
                if update_resp['success']:
                    print('update success !')
                    config['domain']['host']['ipv4'] = update_resp['result']['content']
                    return config, True
            except:
                pass
    return config, update


def update_public_ip(config, update):
    content_header = get_headers(config)
    base_url = get_base_url()
    data = json.dumps({
        'type': 'A',
        'name': config['domain']['host']['name'],
        'content': get_public_ip(),
        'priority': 5,
        'ttl': 120,
        'proxied': False
    })
    update_req = Request(
        '{base_url}{zion_id}/dns_records/{name_id}'.format(
            base_url=base_url,
            zion_id=config['domain']['id'],
            name_id=config['domain']['host']['id']),
        headers=content_header,
        data=data.encode('utf-8'))
    update_req.get_method = lambda: 'PUT'
    try:
        update_resp = json.loads(urlopen(update_req).read().decode('utf-8'))
        config['domain']['host']['ipv4'] = update_resp['result']['content']
        return config, True
    except:
        pass
    return config, False

def init_node():
    with open(config_file_name, 'r') as config_file:
        try:
            config = json.loads(config_file.read())
        except ValueError:
            print('* problem with the config file')
            exit(0)
    public_ip = get_public_ip()
    node_info = get_node_info(config, public_ip, config['apiurl'])
    if 'port' in node_info:
        config, update = get_dns_zone_id(config, node_info['domain'])
        print(config, update)
        if update:
            with open(config_file_name, 'w') as config_file: 
                json.dump(config, config_file, indent=1, sort_keys=True)
        return (f'{node_info["prefix"]}.{node_info["domain"]}', node_info['port'])

def update_node():
    with open(config_file_name, 'r') as config_file:
        try:
            config = json.loads(config_file.read())
        except ValueError:
            print('* problem with the config file')
            exit(0)
        public_ip = get_public_ip()
        node_info = get_node_info(config, public_ip, config['apiurl'])
        if 'prefix' in node_info:
            address = f'{node_info["prefix"]}.{node_info["domain"]}'
            if address != config['domain']['name']:
                os.system('systemctl stop nginx')
                os.system(f'~/.acme.sh/acme.sh --issue -d {address} --standalone -k 2048')
                os.system(f'~/.acme.sh/acme.sh --installcert -d {address} --fullchainpath /root/v2ray.crt --keypath /root/v2ray.key')
                reset_nginx(address, node_info['port'])
                with open(config_file_name, 'w') as config_file:
                    config['domain']['name'] = address
                    json.dump(config, config_file, indent=1, sort_keys=True)

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
    os.system('systemctl restart nginx')

def check_run_func():
    os.system('echo "Hello World"')


func_dict = {
    'get_public_ip': get_public_ip,
    'init_node': init_node,
    'check_run_func': check_run_func,
    'update_node': update_node,
}

if __name__ == '__main__':
    func_dict[sys.argv[1]]()


# with open(config_file_name, 'r') as config_file:
#     try:
#         config = json.loads(config_file.read())
#     except ValueError:
#         print('* problem with the config file')
#         exit(0)

# if not config['cloudflare_api']['email'] or not config['cloudflare_api']['api_key']:
#     print('* missing CloudFlare auth credentials')
#     exit(0)

# if not config['apiurl']:
#     print('* missing core_api address')
#     exit(0)

# if config['dynamic'] in ['True', 'TRUE']:
#     is_dynamic = True
# else:
#     is_dynamic = False

# public_ip = None
# update = False

# public_ip = get_public_ip()
# if not public_ip:
#     print('* Failed to get any public IP address')
#     exit(0)

# node_info = get_node_info(config, public_ip, config['apiurl'])
# print(node_info)

# if is_dynamic:
#     pass
# else:
#     if hasattr(node_info, 'port'):
#         port = node_info.port





# if not 'domain' in node_info:
#     # 查不到 node_info 但node 曾经注册过 core, 可能1: core 更改了对应的node 2. 此 node 的公网IP 更改过
#     if config['domain']['host']['ipv4'] and config['domain']['host']['id'] and config['domain']['id'] and config['domain']['name'] and config['domain']['host']['name']:
#         if public_ip != config['domain']['host']['ipv4']:
#             ddns = query_ddns(config)
#             print(ddns['id'], ddns['content'])
#             print(config['domain']['host']['id'], config['domain']['host']['ipv4'])
#             if ddns and ddns['id'] == config['domain']['host']['id'] and ddns['content'] == config['domain']['host']['ipv4']:
#                 # 查询到该 node 的 DDNS 记录，且IP与该node 上存储的一致，说明core 未主动更改 IP, 是该node IP地址自动变化
#                 print('updating name')
#                 config, update = update_public_ip(config, update)


# if 'prefix' in node_info:
#     if not config['domain']['id'] or config['domain']['name'] != node_info['domain']:
#         # 首次登录该 node
#         config, update = update_or_get_dns_zone_id(config, node_info['domain'])
#         print(config)
#     if not config['domain']['host']['name'] or config['domain']['host']['name'] != node_info['prefix']:
#         print(node_info['prefix'])
#         config['domain']['host']['name'] = node_info['prefix']
#         ddns = query_ddns(config)
#         print(ddns)
#         if ddns['content'] == get_public_ip():
#             config['domain']['host']['id'] = ddns['id']
#             config['domain']['host']['ipv4'] = get_public_ip()
#             update = True


# # node_info 查询失败，返回{'message': ''}
# if 'message' in node_info:
#     # 该node 尚未进行任何设置，core也未添加该node. 该node保持ready状态
#     if not config['domain']['host']['id'] and not config['domain']['host']['name']:
#         exit(0)

#     # 1. core 主动修改IP地址，删除该node 或 2. 该 node ip 地址自行变更
#     if config['domain']['host']['ipv4'] and config['domain']['host']['id'] and config['domain']['id'] and config['domain']['name'] and config['domain']['host']['name']:
#         # 对比上一次设置与ddns当前设置 确认是 core 主动修改IP 地址 还是 node ip 地址自行变更:
#         query_ddns(config, config['domain']['name'])


# if config['domain']['host']['ipv4'] != public_ip and config['domain']['host']['id'] and config['domain']['id'] and config['domain']['name'] and config['domain']['host']['name']:
#     print('change_node_info')
#     node_info['prefix'] = config['domain']['host']['name']
#     node_info['domain'] = config['domain']['name']
# elif not 'domain' in node_info:
#     print('* Failed to get node info from core server')
#     exit(0)


# if 'domain' in node_info:
#     if config['domain']['id'] and config['domain']['name'] and config['domain']['name'] != node_info['domain']:
#         print('find conflict, stop update')
#         exit(0)
#     config, update = update_or_get_dns_zone_id(config, node_info['domain'])
#     if config['domain']['host']['id']:
#         config, update = update_prefix(config, node_info, update)
#     else:
#         config, update = create_prefix(config, node_info, update)
# else:
#     config['domain']['host']['ipv4'] = ''
#     update = True

# if any records were updated, update the config file accordingly
# if update:
#     print('* updates completed. bye.')
#     with open(config_file_name, 'w') as config_file:
#         json.dump(config, config_file, indent=1, sort_keys=True)
# else:
#     print('* nothing to update. bye.')