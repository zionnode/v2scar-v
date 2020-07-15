#!/usr/bin/env python
import os
import sys
import yaml

file_string =
'''version: "3"

services:
    v2ray:
        image: v2fly/v2fly-core:latest
        container_name: v2ray
        restart: always
        volumes:
            - ./v2ray-config.json:/etc/v2ray/config.json
        ports:
            - 20086:20086
        env_file: 
            - env.v2ray
        command: ["v2ray","-config=http://34.89.127.171:8000/api/vmess_server_config/3717607258/?token=aWxvdmUwNTMwQGdtYWlsLmNvbSsxMDAwMQ%3D%3D"]

    v2scar:
        container_name: v2scar
        image: ehco1996/v2scar
        restart: always
        depends_on:
            - v2ray
        links:
            - v2ray
        env_file: 
            - env.v2scar'''

with open('/root/v2scar-v/docker-compose.yml', 'w+') as file:
    file.write(file_string)
