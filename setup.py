#!/usr/bin/env python
import os
import sys
import yaml

os.system('echo "haha"')

dict_file = [
    {'version':'3'},
    {'services':
        [
            {
                'v2ray': [
                    'image',
                    'container_name'
                    ]
            },
            {
                'web': [
                    'image',
                    'container_name'
                ]
            }
            
        ]
    }
    ]
with open('/root/v2scar-v/docker-compose.yml', 'w+') as file:
    yaml.dump(dict_file, file)