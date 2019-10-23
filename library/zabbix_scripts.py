#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2013-2014, Epic Games, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# zabbix_scripts derived from zabbix_group; (c) 2019 sysfive.com GmbH

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'sysfive'}

DOCUMENTATION = '''
---
module: zabbix_scripts
short_description: Zabbix scripts
description:
   - Create scripts if they dont exist
   - Delete scripts if they exist.
version_added: "2.8"
author:
    - "(@cove)"
    - "Tony Minfei Ding"
    - "Harrison Gu (@harrisongu)"
    - "Alina Riebe"
requirements:
    - "python >= 2.7"
    - zabbix-api
options:
    state:
        description:
            - Create or delete scripts
        required: false
        default: "present"
        choices: [ "present", "absent" ]
    scriptsvar1:
        description:
            - scripts to create or delete.
        required: true

extends_documentation_fragment:
    - zabbix

'''

EXAMPLES = '''
# create an scripts
- name: Create scripts
  local_action:
    module: zabbix_scripts
    server_url: http://monitor.example.com
    login_user: api_user
    login_password: api_user_pass
    state: present
    scripts: scriptsvalue
'''

try:
    from zabbix_api import ZabbixAPI, ZabbixAPISubClass
    from zabbix_api import Already_Exists

    HAS_ZABBIX_API = True
except ImportError:
    HAS_ZABBIX_API = False

from ansible.module_utils.basic import AnsibleModule

class zbxScripts(object):
    def __init__(self, module, zbx):
        self._module = module
        self._zapi = zbx

    def script_exists(self, data):
        method = "create"
        exists = self._zapi.script.get({
            'filter': {'name': data['name']}
        })
        if len(exists) > 0 and 'scriptid' in exists[0]:
            method = "update"
            filterdata = data.copy()
            #we can't filter by description anyway
            #I hate the if thing here
            if 'description' in filterdata: filterdata.pop('description')
            scriptparams = self._zapi.script.get(
                {
                    'filter': filterdata
                }
            )

            if len(scriptparams) > 0:
                #self._module.exit_json(changed=False, result="scriptparams: {}, xxx data: {}".format(scriptparams, data))
                # compare description
                # I hate the if thing here too
                if 'description' in data:
                    if data['description'] == scriptparams[0]['description']:
                        method = "exists"
                else:
                    method = "exists"

        return method

    def create_or_update(self, method, data):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            if method == "create":
                self._zapi.script.create(data)
                self._module.exit_json(
                    changed=True,
                    result="Created script {}".format(data['name'])
                )
            elif method == "update":
                result = self._zapi.script.get({'filter': {'name': data['name']}})
                data['scriptid'] = result[0]['scriptid']
                self._zapi.script.update(data)
                self._module.exit_json(
                    changed=True,
                    result="Updated script {}".format(data['name'])
                 )
            else:
                self._module.fail_json(
                    changed=False,
                    msg="unknown method {} to create_or_update".format(method)
                )
        except Exception as e:
            self._module.fail_json(msg="Failed to {} script {}".format(method, e))

    def delete(self, name):
        method = "delete"
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)

            result = self._zapi.script.get({
                'filter': {'name': name}
            })
            if len(result) > 0 and 'scriptid' in result[0]:
                self._zapi.script.delete([result[0]['scriptid']])
                self._module.exit_json(
                    changed=True,
                    result="Deleted script {}".format(name)
                )
            else:
                self._module.exit_json(changed=False, result="Script {} not found so no need to delete it...".format(name))
        except Exception as e:
            self._module.fail_json(msg="Failed to {} script {}".format(method, e))

def main():
    module = AnsibleModule(
        argument_spec=dict(
            server_url=dict(type='str', required=True, aliases=['url']),
            login_user=dict(type='str', required=True),
            login_password=dict(type='str', required=True, no_log=True),
            http_login_user=dict(type='str', required=False, default=None),
            http_login_password=dict(type='str', required=False, default=None, no_log=True),
            validate_certs=dict(type='bool', required=False, default=True),
            state=dict(default="present", choices=['present', 'absent']),
            timeout=dict(type='int', default=10),
            name=dict(type='str', required=True),
            command=dict(type='str', required=True),
            confirmation=dict(type='str', required=False),
            description=dict(type='str', required=False),
            execute_on=dict(type='int', default=2, choices=[0, 1, 2]), #0 agent, 1 server, 2 server (proxy)
            groupid=dict(type='int', default=0), #0 all hostgroups
            host_access=dict(type='int', default=2), #2 read, 3 write
            type=dict(type='int', default=0), #0 script, 1 IPMI
            usrgrpid=dict(type='str', default='0') #0 all usergroups, no idea why this is string
        ),
        supports_check_mode=False
    )

    if not HAS_ZABBIX_API:
        module.fail_json(msg="Missing required zabbix-api module (check docs or install with: pip install zabbix-api)")

    zbx = None
    # login to zabbix
    try:
        zbx = ZabbixAPI(
                module.params['server_url'],
                timeout=module.params['timeout'],
                user=module.params['http_login_user'],
                passwd=module.params['http_login_password'],
                validate_certs=module.params['validate_certs'])
        zbx.login( module.params['login_user'],  module.params['login_password'])
    except Exception as e:
        module.fail_json(msg="Failed to connect to Zabbix server: {server} with {exception}".format(server=server_url, exception=e))

    scripts = zbxScripts(module, zbx)

    scriptdata = {}
    scriptdata['name'] = module.params['name']
    scriptdata['command'] = module.params['command']

    if module.params['confirmation'] is not None: scriptdata['confirmation'] = module.params['confirmation']
    if module.params['description'] is not None: scriptdata['description'] = module.params['description']
    if module.params['execute_on'] is not None: scriptdata['execute_on'] = module.params['execute_on']
    if module.params['groupid'] is not None: scriptdata['groupid'] = module.params['groupid']
    if module.params['host_access'] is not None: scriptdata['host_access'] = module.params['host_access']
    if module.params['type'] is not None: scriptdata['type'] = module.params['type']
    if module.params['usrgrpid'] is not None: scriptdata['usrgrpid'] = module.params['usrgrpid']

    method = scripts.script_exists(scriptdata)

    if module.params['state'] == "absent":
        scripts.delete(scriptdata['name'])
    elif method == "exists":
        module.exit_json(changed=False, result="Script {} exists as specified".format(scriptdata['name']))
    else:
        scripts.create_or_update(method, scriptdata)


    # rather a WIP/debug-fallthrough:
    module.exit_json(changed=True, result="This module should not exit this way!")
if __name__ == '__main__':
    main()
