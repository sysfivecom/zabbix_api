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
            - list of Usergroup Names, Default value is "Guests"
        required: false
    media:
        description:
            - list of trigger media definitions
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
      - usrgrpid: "Admin"
# add/change media settings
- name: Create User
  local_action:
    module: zabbix_user
    server_url: http://monitor.example.com
    login_user: api_user
    login_password: api_user_pass
    state: present
    username: johndoe
    media:
      - mediatypeid: "1"
        sendto:
          - "foo@example.com"
        severity: 24
        period: "1-7,00:00-24:00"
      - mediatypeid: "1"
        sendto:
          -"all@example.com"
        severity: 63
'''

from ansible.module_utils.basic import AnsibleModule

try:
    from zabbix_api import ZabbixAPI, ZabbixAPISubClass
    from zabbix_api import Already_Exists

    HAS_ZABBIX_API = True
except ImportError:
    HAS_ZABBIX_API = False


class zbxUser(object):
    def __init__(self, module, zbx):
        self._module = module
        self._zapi = zbx


    def get_usergroups(self, usergroupnames):
        groups = []
        for groupname in usergroupnames:
            try:
                groupid = self._zapi.usergroup.get({'filter': {'name': groupname}})[0]['usrgrpid']
                groups.append({'usrgrpid': groupid})
            except Exception as e:
                self._module.fail_json(msg="Failed to find usergroup {} on server.".format(groupname))
        return groups

    def compareListParams(self, param, sortkey, requested, current):
        sorted_current = sorted(current[param], key=lambda k: k[sortkey])
        sorted_requested = sorted(requested[param], key=lambda k: k[sortkey])
        return sorted_current == sorted_requested

    def compareUserMedias(self, requested, current):
        if len(requested) != len(current):
           return False
        sorted_current = sorted(current, key=lambda k: k['sendto'])
        sorted_requested = sorted(requested, key=lambda k: k['sendto'])
        result = True
        for i in range(len(sorted_current)):
            result = result and (sorted_requested[i]['mediatypeid'] == sorted_current[i]['mediatypeid'])
            result = result and (str(sorted_requested[i]['active']) == sorted_current[i]['active'])
            result = result and (sorted_requested[i]['period'] == sorted_current[i]['period'])
            result = result and (str(sorted_requested[i]['severity']) == sorted_current[i]['severity'])
            result = result and (sorted_requested[i]['sendto'] == sorted_current[i]['sendto'])
        return result

    def user_exists(self, userdata):
        method = "create"
        exists = self._zapi.user.get({'filter': {'alias': userdata['alias']}})
        if len(exists) > 0 and 'userid' in exists[0]:
            method = "update"
            # before trying to filter, remove those keys that don't work in filters
            filterdata = userdata.copy()
            filterdata.pop('passwd')
            filterdata.pop('usrgrps')
            if 'user_medias' in filterdata: filterdata.pop('user_medias')
            userparams = self._zapi.user.get(
                    {
                        'selectUsrgrps': 1,
                        'selectMedias': 'extend',
                        'getAccess': 1,
                        'filter': filterdata
                    }
                )
            # usergroups and medias need more checking(Filter in API does not work for these)
            if len(userparams) > 0:
                # a user with the filter parameters exist - need to compare media and usergroups to be sure
                # it is configured correctly
                if self.compareListParams('usrgrps', 'usrgrpid', userdata, userparams[0]):
                    if 'user_medias' in userdata:
                        if self.compareUserMedias(userdata['user_medias'], userparams[0]['medias']):
                            method = "exists"
                        #self._module.exit_json(changed=False, result="%s \n%s  %s" % (userdata['user_medias'], userparams[0]['medias'], method))
                    else:
                        method = "update"
                else:
                    method = "update"
        return method


    def delete(self, userdata):
        name = userdata['alias']
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)

            result = self._zapi.user.get({
                'filter': {'alias': name}
            })
            if len(result) > 0 and 'userid' in result[0]:
                self._zapi.user.delete([result[0]['userid']])
                self._module.exit_json(
                    changed=True,
                    result="Deleted user {}".format(name)
                )
            else:
                self._module.exit_json(changed=False, result="User {} not found so no need to delete it...".format(name))
        except Exception as e:
            self._module.fail_json(msg="Failed to delete user {}: {}".format(name, e))


    def create_or_update(self, method, userdata):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            if method == "create":
                self._zapi.user.create(userdata)
                self._module.exit_json(
                        changed=True,
                        result="Created user %s" % userdata['alias']
                    )
            elif method == "update":
                result = self._zapi.user.get({'filter': {'alias': userdata['alias']}})
                userdata['userid'] = result[0]['userid']
                self._zapi.user.update(userdata)
                self._module.exit_json(
                        changed=True,
                        result="Updated user %s" % userdata['alias']
                    )
            else:
                self._module.fail_json(
                        changed=False,
                        msg="unknown method '%s' to create_or_update" % method
                    )
        except Exception as e:
            self._module.fail_json(msg="XX Failed to %s user %s: %s" %
                                       (method, userdata['alias'], e))


def main():
    module = AnsibleModule(
        argument_spec=dict(
            # connection parameters
            server_url=dict(type='str', required=True, aliases=['url']),
            login_user=dict(type='str', required=True),
            login_password=dict(type='str', required=True, no_log=True),
            http_login_user=dict(type='str', required=False, default=None),
            http_login_password=dict(type='str', required=False, default=None, no_log=True),
            validate_certs=dict(type='bool', required=False, default=True),
            timeout=dict(type='int', default=10),
            # payload parameters
            state=dict(default="present", choices=['present', 'absent']),
            username=dict(type='str', required=True, aliases=['alias']),
            passwd=dict(type='str', required=True, aliases=['password'], no_log=True),
            usergroups=dict(type='list', default=["Guests"]),
            name=dict(type='str', required=False),
            surname=dict(type='str', required=False),
            autologin=dict(type='int', required=False),
            autologout=dict(type='str', required=False),
            lang=dict(type='str', required=False),
            refresh=dict(type='str', required=False),
            rows=dict(type='int', required=False, aliases=['rows_per_page']),
            theme=dict(type='str', required=False),
            type=dict(type='int', required=False),
            url=dict(type='str', required=False),
            media=dict(type='list', required=False),
        ),
        supports_check_mode=False
    )

    if not HAS_ZABBIX_API:
        module.fail_json(
                msg="!! Missing required zabbix-api module \
                        (check docs or install with: pip install zabbix-api)")


    # login to zabbix
    zbx = None
    try:
        zbx = ZabbixAPI(
                module.params['server_url'],
                timeout=module.params['timeout'],
                user=module.params['http_login_user'],
                passwd=module.params['http_login_password'],
                validate_certs=module.params['validate_certs'])
        zbx.login(module.params['login_user'], module.params['login_password'])
    except Exception as e:
        module.fail_json(
                msg="Failed to connect to Zabbix server: {server} with {exception}".format(
                    server=module.params['server_url'], exception=e))

    # create instance of Zabbix User Class, which does the actual work
    user = zbxUser(module, zbx)

    # extract/convert existing parameters for further usage
    userdata = {}
    # these are required/default values and exist for sure
    userdata['alias']  = module.params['username']
    userdata['passwd'] = module.params['passwd']
    # only copy existing params for the next steps
    if module.params['name']       is not None: userdata['name']          = module.params['name']
    if module.params['surname']    is not None: userdata['surname']       = module.params['surname']
    if module.params['autologin']  is not None: userdata['autologin']     = module.params['autologin']
    if module.params['autologout'] is not None: userdata['autologout']    = module.params['autologout']
    if module.params['lang']       is not None: userdata['lang']          = module.params['lang']
    if module.params['refresh']    is not None: userdata['refresh']       = module.params['refresh']
    if module.params['rows']       is not None: userdata['rows_per_page'] = module.params['rows']
    if module.params['theme']      is not None: userdata['theme']         = module.params['theme']
    if module.params['type']       is not None: userdata['type']          = module.params['type']
    if module.params['url']        is not None: userdata['url']           = module.params['url']
    if module.params['media']      is not None: userdata['user_medias']   = module.params['media']
    # we most convert user group names to IDs
    userdata['usrgrps'] = user.get_usergroups(module.params['usergroups'])

    method = user.user_exists(userdata)

    if module.params['state'] == "absent":
        user.delete(userdata)
    elif method == "exists":
        module.exit_json(changed=False, result="User %s exists as specified" % userdata['alias'])
    else:
        user.create_or_update(method, userdata)

    # fallthru error
    module.fail_json(msg="This module should not exit this way!")


if __name__ == '__main__':
    main()
