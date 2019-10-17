#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# (c) 2013-2014, Epic Games, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# zabbix_usergroup derived from zabbix_group; (c) 2019 sysfive.com GmbH

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'sysfive'}

DOCUMENTATION = '''
---
module: zabbix_usergroup
short_description: Zabbix usergroup
description:
   - Create usergroup if it doesn't exist.
   - Update usergroup if it exists.
   - Delete usergroup if it exists.
version_added: "2.8"
author:
    - "(@cove)"
    - "Tony Minfei Ding"
    - "Harrison Gu (@harrisongu)"
    - "Alina Riebe"
requirements:
    - "python >= 3.5"
    - zabbix-api
options:
    state:
        description:
            - Create or delete usergroup
        required: false
        default: "present"
        choices: [ "present", "absent" ]
    name:
        description:
            - name of usergroup to create, update or delete.
        required: true

extends_documentation_fragment:
    - zabbix

'''

EXAMPLES = '''
# create a usergroup
- name: Create/Update usergroup
   local_action:
    module: zabbix_usergroup
    server_url: http://monitor.example.com
    login_user: api_user
    login_password: api_user_pass
    state: present
    name: "test group 123"
    gui_access: 0
    debug_mode: 0
    users_status: 0
    rights:
        - {'permission': '2', 'id': '1'}
    tag_filters:
        - {'groupid': '2', 'tag': 'idk', 'value': 'wtf'}
- name: Delete usergroup
  local_action:
    module: zabbix_usergroup
    server_url: http://monitor.example.com
    login_user: api_user
    login_password: api_user_pass
    state: absent
    name: "test group 123"
'''

try:
    from zabbix_api import ZabbixAPI, ZabbixAPISubClass
    from zabbix_api import Already_Exists

    HAS_ZABBIX_API = True
except ImportError:
    HAS_ZABBIX_API = False

from ansible.module_utils.basic import AnsibleModule

class zbxUserGroup(object):
    def __init__(self, module, zbx):
        self._module = module
        self._zapi = zbx

    def usergroup_exists(self, data):
        method = "create"
        exists = self._zapi.usergroup.get({'filter': {'name': data['name']}})
        if len(exists) > 0 and 'usrgrpid' in exists[0]:
            method = "update"
            usergroupparams = self._zapi.usergroup.get(
                {
                    'selectTagFilters': 1,
                    'selectUsers': 1,
                    'selectRights': 1,
                    'filter': {
                        'name': data['name'],
                        'gui_access': data['gui_access'],
                        'users_status': data['users_status'],
                        'debug_mode': data['debug_mode']
                    }
                }
            )
            #oh well...
            #I ruined it to death
            if len(usergroupparams) > 0:
                sorted_usergroupparam_rights = 0
                sorted_data_rights = 0
                sorted_data_tag_filters = 0
                sorted_usergroupparam_tag_filters = 0
                if data['rights']:
                    #compare rights
                    sorted_usergroupparam_rights = sorted(usergroupparams[0]['rights'], key=lambda k: k['id'])
                    sorted_data_rights = sorted(data['rights'], key=lambda k: k['id'])

                if data['tag_filters']:
                    #compare tag_filters
                    sorted_usergroupparam_tag_filters = sorted(sorted(sorted(usergroupparams[0]['tag_filters'], key=lambda k: k['value']), key=lambda k: k['tag']), key=lambda k: k['groupid'])
                    sorted_data_tag_filters = sorted(sorted(sorted(data['tag_filters'], key=lambda k: k['value']), key=lambda k: k['tag']), key=lambda k: k['groupid'])
                if not data['rights'] and not data['tag_filters']:
                    method = "exists"
                elif sorted_usergroupparam_tag_filters == sorted_data_tag_filters and sorted_usergroupparam_rights == sorted_data_rights:
                    method = "exists"
                else:
                    method = "update"
        return method

    def create_or_update(self, method, data):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            data = dict(filter(lambda elem: elem[1] != None,data.items()))
            if len(data) > 1:
                if method == "create":
                    self._zapi.usergroup.create(data)
                    self._module.exit_json(
                        changed=True,
                        result="Created usergroup {}".format(data['name'])
                    )
                if method == "update":
                    result = self._zapi.usergroup.get({
                        'filter': {'name': data['name']}
                    })
                    data['usrgrpid'] = result[0]['usrgrpid']
                    self._zapi.usergroup.update(data)
                    self._module.exit_json(
                        changed=True,
                        result="Updated usergroup {}".format(data['name'])
                    )
                else:
                    self._module.fail_json(
                        changed=False,
                        msg="unknown method '{}' to create_or_update".format(method)
                    )
            else:
                self._module.exit_json(changed=False, msg="No usergroup data/parameters found!")
        except Exception as e:
            self._module.fail_json(msg="Failed to {} usergroup {}: {}".format(method, data['name'], e))

    def delete(self, name):
        method = "delete"
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)

            result = self._zapi.usergroup.get({
                'filter': {'name': name}
            })
            #self._module.exit_json(changed=False, result="{}".format(result))
            if len(result) > 0 and 'usrgrpid' in result[0]:
                #self._module.exit_json(changed=False, result="{}".format(result))
                self._zapi.usergroup.delete([result[0]['usrgrpid']])
                self._module.exit_json(
                    changed=True,
                    result="Deleted usergroup {}".format(name)
                )
            else:
                self._module.exit_json(changed=False, result="Usergroup {} not found so no need to delete it...".format(name))
        except Exception as e:
            self._module.fail_json(msg="Failed to {} usergroup {}: {}".format(method, name, e))

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
            debug_mode=dict(type='int', default=0, choices=[0, 1]), #0 disabled, 1 enabled
            gui_access=dict(type='int', default=0, choices=[0, 1, 2, 3]),
            users_status=dict(type='int', default=0, choices=[0, 1]), #0 enabled, 1 disabled
            rights=dict(type='list', required=False), #weird part of the documentation
            tag_filters=dict(type='list', required=False)
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
    state = module.params['state']
    timeout = module.params['timeout']

    usergroupparams = {}
    usergroupparams['name'] = module.params['name']
    usergroupparams['debug_mode'] = module.params['debug_mode']
    usergroupparams['gui_access'] = module.params['gui_access']
    usergroupparams['users_status'] = module.params['users_status']
    usergroupparams['rights'] = module.params['rights']
    usergroupparams['tag_filters'] = module.params['tag_filters']

    zbx = None

    # login to zabbix
    try:
        zbx = ZabbixAPI(server_url, timeout=timeout, user=http_login_user, passwd=http_login_password,
                        validate_certs=validate_certs)
        zbx.login(login_user, login_password)
    except Exception as e:
        module.fail_json(msg="Failed to connect to Zabbix server: {server} with {exception}".format(server=server_url, exception=e))

    usergroup = zbxUserGroup(module, zbx)
    method = usergroup.usergroup_exists(usergroupparams)

    if state == "absent":
        usergroup.delete(usergroupparams['name'])
    elif method == "exists":
        module.exit_json(changed=False, result="Usergroup {} exists as specified".format((usergroupparams['name'])))
    else:
        usergroup.create_or_update(method, usergroupparams)

    # rather a WIP/debug-fallthrough:
    module.exit_json(changed=True, result="This module should not exit this way!")
if __name__ == '__main__':
    main()
