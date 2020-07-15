#! /usr/bin/env python
# place cf-ddns.py and cf-ddns.conf on your server (e.g. /usr/local/bin/ or ~/)
# run this command:
# chmod +x /PATH_TO_FILE/cf-ddns.sh
# open cf-ddns.conf in a text editor and set the necessary parameters.
# (minimum config: one domain name, one host name, email address and api_key)
# run `crontab -e` and append this line to it:
# 0 */5 * * * * /PATH_TO_FILE/cf-ddns.py >/dev/null 2>&1

try:
    # For Python 3.0 and later
    from urllib.request import urlopen
    from urllib.request import Request
    from urllib.error import URLError
    from urllib.error import HTTPError
    # import urllib.parse
except ImportError:
    # Fall back to Python 2's urllib2
    from urllib2 import urlopen
    from urllib2 import Request
    from urllib2 import HTTPError
    from urllib2 import URLError

import json
import base64


config_file_name = '/root/v2scar-v/cf-ddns.conf'
# config_file_name = 'cf-ddns.conf'


def get_public_ip():
    try:
        public_ipv4 = urlopen(
            Request('http://116.202.55.106')).read().rstrip().decode('utf-8')
        return public_ipv4
    except URLError as e:
        return None


def get_headers(config):
    return {'X-Auth-Email': config['user']['email'],
            'X-Auth-Key': config['user']['api_key'],
            'Content-type': 'application/json'}


def get_base_url():
    return 'https://api.cloudflare.com/client/v4/zones/'


def get_node_id(ip):
    ip_splitted = ip.split('.')
    num_to_hash = 256 * 256 * 256 * int(ip_splitted[0]) + 256 * 256 * int(
        ip_splitted[1]) + 256 * int(ip_splitted[2]) + int(ip_splitted[3])
    return 256 * 256 * 256 * 256 - num_to_hash


def get_token(config):
    try:
        print(config['username'], config['port'])
        token = base64.b64encode(
            bytes('{}+{}'.format(config['username'], config['port']), 'utf8')).decode()
    except:
        token = base64.b64encode(
            bytes('{}+{}'.format(config['username'], config['port']))).decode()
    print(token)
    return token


def get_node_info(config, ip, api_url):
    # api 可能回复
    # 1. 尚未上线, 或者ip已经更换, 返回{'message':'no_such_node'}, 直接退出
    # 2. 初次查询, config prefix空，可查到node_id, 返回prefix, domain, api
    # 3. 非初次查询, config prifix非空，可查到node_id, 返回prefix, domain, api
    try:
        node_id = get_node_id(ip)
        token = get_token(config)
        header = {'token': token, 'Content-type': 'application/json'}
        apiurl = '{api_url}/api/nodeinfo/{node_id}'.format(
            api_url=api_url, node_id=node_id)
        api_req = Request(apiurl, headers=header)
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
    if not config['domain']['id']:
        try:
            print(
                '* zone id for "{0}" is missing. attempting to '
                'get it from cloudflare...'.format(config['domain']['name']))
            zone_id_req = Request(base_url, headers=content_header)
            zone_id_resp = urlopen(zone_id_req)
            for d in json.loads(zone_id_resp.read().decode('utf-8'))['result']:
                if config['domain']['name'] == d['name']:
                    config['domain']['id'] = d['id']
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

    # for d in query_resp['result']:
    #     if d['id'] == config['domain']['host']['id']:
    #         return


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


with open(config_file_name, 'r') as config_file:
    try:
        config = json.loads(config_file.read())
    except ValueError:
        print('* problem with the config file')
        exit(0)

if not config['user']['email'] or not config['user']['api_key']:
    print('* missing CloudFlare auth credentials')
    exit(0)

if not config['coreapi']:
    print('* missing core_api address')
    exit(0)

public_ip = None
update = False

public_ip = get_public_ip()
if not public_ip:
    print('* Failed to get any public IP address')
    exit(0)

node_info = get_node_info(config, public_ip, config['coreapi'])
print(node_info)


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


if not 'domain' in node_info:
    # 查不到 node_info 但node 曾经注册过 core, 可能1: core 更改了对应的node 2. 此 node 的公网IP 更改过
    if config['domain']['host']['ipv4'] and config['domain']['host']['id'] and config['domain']['id'] and config['domain']['name'] and config['domain']['host']['name']:
        if public_ip != config['domain']['host']['ipv4']:
            ddns = query_ddns(config)
            print(ddns['id'], ddns['content'])
            print(config['domain']['host']['id'], config['domain']['host']['ipv4'])
            if ddns and ddns['id'] == config['domain']['host']['id'] and ddns['content'] == config['domain']['host']['ipv4']:
                # 查询到该 node 的 DDNS 记录，且IP与该node 上存储的一致，说明core 未主动更改 IP, 是该node IP地址自动变化
                print('updating name')
                config, update = update_public_ip(config, update)


if 'prefix' in node_info:
    if not config['domain']['id'] or config['domain']['name'] != node_info['domain']:
        # 首次登录该 node
        config, update = update_or_get_dns_zone_id(config, node_info['domain'])
        print(config)
    if not config['domain']['host']['name'] or config['domain']['host']['name'] != node_info['prefix']:
        print(node_info['prefix'])
        config['domain']['host']['name'] = node_info['prefix']
        ddns = query_ddns(config)
        print(ddns)
        if ddns['content'] == get_public_ip():
            config['domain']['host']['id'] = ddns['id']
            config['domain']['host']['ipv4'] = get_public_ip()
            update = True


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
if update:
    print('* updates completed. bye.')
    with open(config_file_name, 'w') as config_file:
        json.dump(config, config_file, indent=1, sort_keys=True)
else:
    print('* nothing to update. bye.')