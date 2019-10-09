#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2013-2014, Epic Games, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# zabbix_TMPL derived from zabbix_group; (c) 2019 sysfive.com GmbH

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'sysfive'}

DOCUMENTATION = '''
---
module: zabbix_TMPL
short_description: Zabbix TMPL
description:
   - Create TMPL if they dont exist
   - Delete TMPL if they exist.
version_added: "2.8"
author:
    - "(@cove)"
    - "Tony Minfei Ding"
    - "Harrison Gu (@harrisongu)"
    - "TMPL"
requirements:
    - "python >= 2.7"
    - zabbix-api
options:
    state:
        description:
            - Create or delete TMPL
        required: false
        default: "present"
        choices: [ "present", "absent" ]
    TMPLvar1:
        description:
            - TMPL to create or delete.
        required: true

extends_documentation_fragment:
    - zabbix

'''

EXAMPLES = '''
# create an TMPL
- name: Create TMPL
  local_action:
    module: zabbix_TMPL
    server_url: http://monitor.example.com
    login_user: api_user
    login_password: api_user_pass
    state: present
    TMPL: TMPLvalue
'''

try:
    from zabbix_api import ZabbixAPI, ZabbixAPISubClass
    from zabbix_api import Already_Exists

    HAS_ZABBIX_API = True
except ImportError:
    HAS_ZABBIX_API = False

from ansible.module_utils.basic import AnsibleModule


def main():
    module = AnsibleModule(
        argument_spec=dict(
            server_url=dict(type='str', required=True, aliases=['url']),
            login_user=dict(type='str', required=True),
            login_password=dict(type='str', required=True, no_log=True),
            http_login_user=dict(type='str', required=False, default=None),
            http_login_password=dict(type='str', required=False, default=None, no_log=True),
            validate_certs=dict(type='bool', required=False, default=True),
            TMPL=dict(type='str', required=True)
            state=dict(default="present", choices=['present', 'absent']),
            timeout=dict(type='int', default=10)
        ),
        supports_check_mode=False
    )

    if not HAS_ZABBIX_API:
        module.fail_json(msg="Missing required zabbix-api module (check docs or install with: pip install zabbix-api)")

    server_url = module.params['server_url']
    #api login
    login_user = module.params['login_user']
    login_password = module.params['login_password']
    #basic auth login?
    http_login_user = module.params['http_login_user']
    http_login_password = module.params['http_login_password']
    validate_certs = module.params['validate_certs']
    TMPL = module.params['TMPL']
    state = module.params['state']
    timeout = module.params['timeout']

    zbx = None

    # login to zabbix
    try:
        zbx = ZabbixAPI(server_url, timeout=timeout, user=http_login_user, passwd=http_login_password,
                        validate_certs=validate_certs)
        zbx.login(login_user, login_password)
    except Exception as e:
        module.fail_json(msg="Failed to connect to Zabbix server: {server} with {exception}".format(server=server_url, exception=e))

    # rather a WIP/debug-fallthrough:
    module.exit_json(changed=True, result="This module should not exit this way!")
if __name__ == '__main__':
    main()
