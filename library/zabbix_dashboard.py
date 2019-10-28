#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2013-2014, Epic Games, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# zabbix_dashboard derived from zabbix_group; (c) 2019 sysfive.com GmbH

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'sysfive'}

DOCUMENTATION = '''
---
module: zabbix_dashboard
short_description: Zabbix dashboard
description:
   - Create dashboard if it doesn't exist
   - Delete dashboard if it exists.
   - Dump dashboard to file (will be overwritten)
   - Import dashboard from file
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
            - Create or delete dashboard
        required: false
        default: "present"
        choices: [ "present", "absent", "dump", "import" ]
    name:
        description:
            - name dashboard to create or delete.
        required: true
    dump_name:
        description:
            - name of dump file
    private:
        description:
            - 0 is public, 1 is private
        choices: [0, 1]
    userid:
        description:
            - dashboard owner user id
    users:
        description:
            - list of dashboard permissions based on users
    userGroups:
        description:
            - list of dashboard permissions based on user groups
    widgets:
        description:
            - list of widgets...

extends_documentation_fragment:
    - zabbix

'''

EXAMPLES = '''
# create an dashboard
- name: Create dashboard
  local_action:
    module: zabbix_dashboard
    server_url: http://monitor.example.com
    login_user: api_user
    login_password: api_user_pass
    state: present
    name: "just call me dashboard"
    private: 1
    userid: '1'
    users:
        - {'userid': '5', 'permission': '2'}
        - {'userid': '7', 'permission': '3'}
    userGroups:
        - {'permission': '3', 'usrgrpid': '22'}
        - {'permission': '2', 'usrgrpid': '21'}
    widgets:
        - {'type': 'problems', 'name': 'dashboard of problems', 'x': '0', 'y': '0', 'width': '12', 'height': '5', 'view_mode': '0', 'fields': []}

- name: Delete dashboard
  local_action:
    module: zabbix_dashboard
    server_url: http://monitor.example.com
    login_user: api_user
    login_password: api_user_pass
    state: absent
    name: "nobody ever liked this dashboard"

- name: Dump dashboard to file
  local_action:
    module: zabbix_dashboard
    server_url: http://monitor.example.com
    login_user: api_user
    login_password: api_user_pass
    state: dump
    name: "very good dashboard, someone should make a dump of it"
    dump_name: such_a_good_dump

- name: Import dashboard
  local_action:
    module: zabbix_dashboard
    server_url: http://monitor.example.com
    login_user: api_user
    login_password: api_user_pass
    state: import
    name: "dashboard, I dumped to a file earlier"
    dump_name: thing
'''

try:
    from zabbix_api import ZabbixAPI, ZabbixAPISubClass
    from zabbix_api import Already_Exists
    import json

    HAS_ZABBIX_API = True
except ImportError:
    HAS_ZABBIX_API = False

class zbxDashboard(object):
    def __init__(self, module, zbx):
        self._module = module
        self._zapi = zbx

    def sort_widgets(self, widgets):
        keys = []
        for k in widgets[0]:
            keys.append(k)
        keys = sorted(keys)
        for i in keys[::-1]:
            widgets=sorted(widgets, key=lambda k: k[i])
        return widgets

    def dashboard_exists(self, data):
        method = "create"
        exists = self._zapi.dashboard.get({'filter': {'name': data['name']}})
        if len(exists) > 0 and 'dashboardid' in exists[0]:
            method = "update"
            filterdata = data.copy()
            if 'widgets' in filterdata: filterdata.pop('widgets')
            if 'users' in filterdata: filterdata.pop('users')
            if 'userGroups' in filterdata: filterdata.pop('userGroups')
            dashboardparams = self._zapi.dashboard.get(
                {
                    'selectWidgets': 'extend',
                    'selectUsers': 'extend',
                    'selectUserGroups': 'extend',
                    'filter': filterdata
                }
            )
            #compare widgets, users, userGroups
            if len(dashboardparams) > 0:
                sorted_dp_ug = 0
                sorted_data_ug = 0
                sorted_dp_u = 0
                sorted_data_u = 0
                sorted_dp_w = 0
                sorted_data_w = 0
                if 'widgets' in data:
                    for w in dashboardparams[0]['widgets']:
                        w.pop('widgetid')
                    sorted_dp_w = self.sort_widgets(dashboardparams[0]['widgets'])
                    sorted_data_w = self.sort_widgets(data['widgets'])
                    #self._module.exit_json(changed=False, result="{} XXXXXXXXXXXXXXXXXXXXXXXXX {}".format(sorted_dp_w, sorted_data_w))
                if 'users' in data:
                    sorted_dp_u = sorted(dashboardparams[0]['users'], key=lambda k: k['userid'])
                    sorted_data_u = sorted(data['users'], key=lambda k: k['userid'])
                if 'userGroups' in data:
                    sorted_dp_ug = sorted(dashboardparams[0]['userGroups'], key=lambda k: k['usrgrpid'])
                    sorted_data_ug = sorted(data['userGroups'], key=lambda k: k['usrgrpid'])

                if sorted_data_ug == sorted_dp_ug and sorted_dp_u == sorted_data_u and sorted_dp_w == sorted_data_w:
                    method = "exists"
                if not 'widgets' in data and not 'users' in data and not 'userGroups' in data:
                    method = "exists"
        return method

    def create_or_update(self, method, data):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            if method == "create":
                self._zapi.dashboard.create(data)
                self._module.exit_json(
                    changed=True,
                    result="Created dashboard {}".format(data['name'])
                )
            elif method == "update":
                result = self._zapi.dashboard.get({'filter': {'name': data['name']}})
                data['dashboardid'] = result[0]['dashboardid']
                self._zapi.dashboard.update(data)
                self._module.exit_json(
                    changed=True,
                    result="Updated dashboard {}".format(data['name'])
                )
            else:
                self._module.fail_json(
                    changed=False,
                    msg="unknown method {} to create_or_update".format(method)
                )
        except Exception as e:
            self._module.fail_json(msg="Failed to {} dashboard {}: {}".format(method, data['name'], e))

    def delete(self, name):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            result = self._zapi.dashboard.get({
                'filter': {'name': name}
            })
            if len(result) > 0 and 'dashboardid' in result[0]:
                self._zapi.dashboard.delete([result[0]['dashboardid']])
                self._module.exit_json(
                    changed=True,
                    result="Deleted dashboard {}".format(name)
                )
            else:
                self._module.exit_json(changed=False, result="Dashboard {} not found so no need to delete it...".format(name))
        except Exception as e:
            module.fail_json(msg="Failed to delete dashboard {}: {}".format(name, e))

    def dump(self, name, name_of_dump):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        try:
            #should test if exists at some point...
            dump = self._zapi.dashboard.get({
                'selectWidgets': 'extend',
                'selectUsers': 'extend',
                'selectUserGroups': 'extend',
                'filter': {'name': name}
            })
            #need to be careful with overwriting dumps and fuuu...
            with open('{}.json'.format(name_of_dump), 'w+') as f:
                json.dump(dump, f, indent=4)
            self._module.exit_json(changed=True, result="Dumped dashboard {} to file {}.json".format(name, name_of_dump))
        except Exception as e:
            module.fail_json(msg="Failed to dump dashboard {}: {}".format(name, e))

    def import_dump(self, name_of_dump):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        try:
            with open('{}.json'.format(name_of_dump)) as json_data:
                d = json.load(json_data)
                d[0].pop('dashboardid')
                if 'widgets' in d[0]:
                    for w in d[0]['widgets']:
                        w.pop('widgetid')
                method = self.dashboard_exists(d[0])
                #self._module.exit_json(changed=False, result="here's d: {}".format(d))
                if method in ["create", "update"]:
                    self.create_or_update(method, d[0])
                elif method == "exists":
                    self._module.exit_json(changed=False, result="Dashboard from dump '{}' exists as specified".format(name_of_dump))
                else:
                    self._module.fail_json(msg="Found method {}, what are you trying to do?".format(method))
        except Exception as e:
            self._module.fail_json(msg="Failed to import dump {}: {}".format(name_of_dump, e))

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
            state=dict(default="present", choices=['present', 'absent', 'dump', 'import']),
            timeout=dict(type='int', default=10),
            name=dict(type='str', required=True),
            userid=dict(type='str', default='1'),
            private=dict(type='int', choices=[0, 1], default=1), #0 public, 1 private
            widgets=dict(type='list'),
            users=dict(type='list'),
            userGroups=dict(type='list'),
            dump_name=dict(type='str', required=False)
        ),
        supports_check_mode=False
    )

    if not HAS_ZABBIX_API:
        module.fail_json(msg="Missing required zabbix-api module (check docs or install with: pip install zabbix-api)")

    zbx = None

    # login to zabbix
    try:
        zbx = ZabbixAPI(module.params['server_url'], timeout=module.params['timeout'], user=module.params['http_login_user'], passwd=module.params['http_login_password'],
                        validate_certs=module.params['validate_certs'])
        zbx.login(module.params['login_user'], module.params['login_password'])
    except Exception as e:
        module.fail_json(msg="Failed to connect to Zabbix server: {server} with {exception}".format(server=module.params['server_url'], exception=e))

    dashboard = zbxDashboard(module, zbx)

    dashboarddata = {}
    dashboarddata['name'] = module.params['name']
    if module.params['userid'] is not None: dashboarddata['userid'] = module.params['userid']
    if module.params['private'] is not None: dashboarddata['private'] = module.params['private']
    if module.params['widgets'] is not None: dashboarddata['widgets'] = module.params['widgets']
    if module.params['users'] is not None: dashboarddata['users'] = module.params['users']
    if module.params['userGroups'] is not None: dashboarddata['userGroups'] = module.params['userGroups']

    method = dashboard.dashboard_exists(dashboarddata)

    if module.params['state'] == "dump":
        dashboard.dump(module.params['name'], module.params['dump_name'])
    elif module.params['state'] == "import":
        dashboard.import_dump(module.params['dump_name'])
    elif module.params['state'] == "absent":
        dashboard.delete(module.params['name'])
    elif method == "exists":
        module.exit_json(changed=False, result="Dashboard {} exists as specified".format(module.params['name']))
    else:
        dashboard.create_or_update(method, dashboarddata)

    # rather a WIP/debug-fallthrough:
    module.exit_json(changed=True, result="This module should not exit this way!")
if __name__ == '__main__':
    main()
