#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2013-2014, Epic Games, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# zabbix_user derived from zabbix_group; (c) 2019 sysfive.com GmbH

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: zabbix_user
short_description: Zabbix user creates/deletes/updates
description:
   - Create user if they do not exist.
   - Change/Update user if they do exist.
   - Delete user if they exist.
version_added: "2.8"
author:
    - "(@cove)"
    - "Tony Minfei Ding"
    - "Harrison Gu (@harrisongu)"
    - "Philipp Buehler"
requirements:
    - "python >= 2.6"
    - zabbix-api
options:
 #XXX: missing: user_medias, usergroups-by-name
    state:
        description:
            - Create or update or delete user
        required: false
        default: "present"
        choices: [ "present", "absent" ]
    username:
        description:
            - Users login/accountname
        required: true
        aliases: [ "alias" ]
    passwd:
        description:
            - Password for user's account (only 'create')
        required: false
    name:
        description:
            - First name of the user
        required: false
    surname:
        description:
            - Family name of the user
        required: false
    autologin:
        description:
            - en/disable autologin (1=enabled)
        required: false
        choices: [ 0, 1 ]
        default: 0
    autologout:
        description:
            - logout after idle time
        required: false
        default: "15m"
    lang:
        description:
            - Language code for this user
        required: false
        default: "en_GB"
    refresh:
        description:
            - automatic refresh of webpages
        required: false
        default: "30s"
    rows:
        description:
            - object rows per webpage
        required: false
        default: 50
        aliases: [ "rows_per_page" ]
    theme:
        description:
            - webpage theme for this user
        required: false
        default: "default"
        choices: [ "blue-theme", "dark-theme", "default" ]
    type:
        description:
            - (privilege) type (0=user,1=admin,2=super admin)
        required: false
        default: 0
        choices: [ 0, 1, 2 ]
    url:
        description:
            - redirect to this URL after login
        required: false
    usergroups:
        description:
            - list of Usergroup IDs
        required: false

extends_documentation_fragment:
    - zabbix

'''

EXAMPLES = '''
# create an user
- name: Create User
  local_action:
    module: zabbix_user
    server_url: http://monitor.example.com
    login_user: api_user
    login_password: api_user_pass
    state: present
    username: johndoe
    name: "John"
    surname: "Doe"
    passwd: "supersecret"
    usergroups:
      - 8
'''

try:
    from zabbix_api import ZabbixAPI, ZabbixAPISubClass
    from zabbix_api import Already_Exists

    HAS_ZABBIX_API = True
except ImportError:
    HAS_ZABBIX_API = False

from ansible.module_utils.basic import AnsibleModule

class zbxUser(object):
    def __init__(self, module, zbx):
        self._module = module
        self._zapi = zbx

    def user_exists(self, alias, userdata):
        method = "create"
        exists = self._zapi.user.get({'filter': {'alias': alias}})
        if len(exists) > 0 and 'userid' in exists[0]:
          method = "update"
          # lets check for all parameters - except passwd..
          # XXX: expand this list to all API properties for UserObject
          userparams = self._zapi.user.get({'filter': {'alias': alias,
            'autologin': userdata['autologin'],
            'autologout': userdata['autologout'],
            'lang': userdata['lang'],
            'name': userdata['name'],
            'refresh': userdata['refresh'],
            'rows_per_page': userdata['rows'],
            'surname': userdata['surname'],
            'theme': userdata['theme'],
            'type': userdata['type'],
            'url': userdata['url'],
          }})
          # XXX: need to check usergroups!
          if len(userparams) > 0:
            method = "exists"

        return method

    def check_usergroup_exists(self, group_names):
        for group_name in group_names:
            result = self._zapi.usergroup.get({'filter': {'usrgrpid': group_name}})
            if not result:
                self._module.fail_json(msg="Usergroup not found: '%s'" % group_name)
        return True

    def create_or_update(self, method, alias, data):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)

            # we could just use 'data', but this preparation
            # to insert additional data from other lookups
            parameters = {}
            parameters['alias'] = alias
            for item in data:
                if data[item]:
                   parameters[item] = data[item]
                   if 'usrgrps' in parameters:
                      groupids = []
                      for group in parameters['usrgrps']:
                         groupids.append({'usrgrpid': group})
                      parameters['usrgrps'] = groupids

            if len(parameters) > 1:
                if method == "update":
                   result = self._zapi.user.get({
                     'filter': {'alias': alias} })
                   parameters['userid'] = result[0]['userid']
                   self._zapi.user.update(parameters)
                   self._module.exit_json(
                       changed=True,
                       result="Updated user %s" % alias
                   )
                if method == "create":
                   self._zapi.user.create(parameters)
                   self._module.exit_json(
                       changed=True,
                       result="Created user %s" % alias
                   )
                else:
                   self._module.fail_json(
                       changed=False,
                       msg="unknown method '%s' to create_or_update" % method
                   )
            else:
                self._module.exit_json(changed=False, msg="No user data/parameters found!")
        except Exception as e:
            self._module.fail_json(msg="XX Failed to %s user %s: %s" %
                                       (method, alias, e))


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
            username=dict(type='str', required=True, aliases=['alias']),
            name=dict(type='str', required=False),
            surname=dict(type='str', required=False),
            passwd=dict(type='str', required=True, aliases=['password'], no_log=True),
            autologin=dict(type='int', required=False),
            autologout=dict(type='str', required=False),
            lang=dict(type='str', required=False),
            refresh=dict(type='str', required=False),
            rows=dict(type='int', required=False, aliases=['rows_per_page']),
            theme=dict(type='str', required=False),
            type=dict(type='int', required=False),
            url=dict(type='str', required=False),
            usergroups=dict(type='list', default=[7]),
        ),
        supports_check_mode=False
    )

    if not HAS_ZABBIX_API:
        module.fail_json(msg="!! Missing required zabbix-api module (check docs or install with: pip install zabbix-api)")

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
    username = module.params['username']
    name = module.params['name']
    surname = module.params['surname']
    passwd = module.params['passwd']
    autologin = module.params['autologin']
    autologout = module.params['autologout']
    lang = module.params['lang']
    refresh = module.params['refresh']
    rows = module.params['rows']
    theme = module.params['theme']
    type = module.params['type']
    url = module.params['url']
    usergroups = module.params['usergroups']

    zbx = None

    # login to zabbix
    try:
        zbx = ZabbixAPI(server_url, timeout=timeout, user=http_login_user, passwd=http_login_password,
                        validate_certs=validate_certs)
        zbx.login(login_user, login_password)
    except Exception as e:
        module.fail_json(msg="Failed to connect to Zabbix server: {server} with {exception}".format(server=server_url, exception=e))

    user = zbxUser(module, zbx)

    userdata = {}
    # the key in brackets must match the API object properties
    userdata['alias'] = username
    userdata['name'] = name
    userdata['surname'] = surname
    userdata['passwd'] = passwd
    userdata['autologin'] = autologin
    userdata['autologout'] = autologout
    userdata['lang'] = lang
    userdata['refresh'] = refresh
    userdata['rows'] = rows
    userdata['theme'] = theme
    userdata['type'] = type
    userdata['url'] = url
    userdata['usrgrps'] = usergroups

    method = user.user_exists(username, userdata)
    group_ids = user.check_usergroup_exists(usergroups)

    if method == "exists":
        if state == "absent":
            user.delete(alias)
        else:
            module.exit_json(changed=False, result="User %s exists as specified" % username)
    else:
        user.create_or_update(method, username, userdata)

    # fallthru error
    module.fail_json(changed=True, result="This module should not exit this way!")
if __name__ == '__main__':
    main()
