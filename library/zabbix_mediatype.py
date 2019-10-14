#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# (c) 2013-2014, Epic Games, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# zabbix_mediatype derived from zabbix_group; (c) 2019 sysfive.com GmbH

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'sysfive'}

DOCUMENTATION = '''
---
module: zabbix_mediatype
short_description: Zabbix mediatype
description:
   - Create mediatype if it does not exist.
   - Delete mediatype if it exists.
   - Update mediatype if it exists.
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
            - Create or delete mediatype
        required: false
        default: "present"
        choices: [ "present", "absent" ]
    name:
        description:
            - name of mediatype.
        required: true
    type:
        description:
            - 0 Email, 1 Script, 2 SMS, 4 Webhook
        required: true

extends_documentation_fragment:
    - zabbix

'''

EXAMPLES = '''
# create a mediatype
- name: Create mediatype Email (Type 0)
  local_action:
    module: zabbix_mediatype
    server_url: http://monitor.example.com
    login_user: api_user
    login_password: api_user_pass
    state: present
    type: 0
    name: "Mail Type..."
    smtp_server: "localhost"
    smtp_helo: "localhost"
    smtp_email: "zabbix@localhost"
    smtp_port: 25

- name: Create mediatype Script (Type 1)
  local_action:
    module: zabbix_mediatype
    server_url: http://monitor.example.com
    login_user: api_user
    login_password: api_user_pass
    state: present
    type: 1
    name: "Script Type..."
    exec_path: "/path/to/script"
    exec_params: "{ALERT.SENDTO}\n{ALERT.SUBJECT}\n{ALERT.MESSAGE}\n"

- name: Create mediatype SMS (Type 2)
  local_action:
    module: zabbix_mediatype
    server_url: http://monitor.example.com
    login_user: api_user
    login_password: api_user_pass
    state: present
    name: "SMS Type..."
    type: 2
    gsm_modem: "/dev/ttyS0"

- name: Create mediatype Webhook (Type 4)
  local_action:
    module: zabbix_mediatype
    server_url: http://monitor.example.com
    login_user: api_user
    login_password: api_user_pass
    state: present
    type: 4
    name: "Webhook Type..."
    script: "irgendwas mit script"
    parameters: [
        {'name': 'foo', 'value': '1'},
        {'name': 'bar', 'value': 'abc'}
    ]
'''

try:
    from zabbix_api import ZabbixAPI, ZabbixAPISubClass
    from zabbix_api import Already_Exists

    HAS_ZABBIX_API = True
except ImportError:
    HAS_ZABBIX_API = False

from ansible.module_utils.basic import AnsibleModule

class zbxMediaType(object):
    def __init__(self, module, zbx):
        self._module = module
        self._zapi = zbx

    def mediatype_exists(self, name, mediatypedata):
        method = "create"
        exists = self._zapi.mediatype.get({'filter': {'name': name,
            'type': mediatypedata['type']}})
        if len(exists) > 0 and 'mediatypeid' in exists[0]:
            method = "update"
            mediatypeparams = self._zapi.mediatype.get({'filter': {'name': name,
                'type': mediatypedata['type'],
                'smtp_server': mediatypedata['smtp_server'],
                'smtp_helo': mediatypedata['smtp_helo'],
                'smtp_email': mediatypedata['smtp_email'],
                'exec_path': mediatypedata['exec_path'],
                'gsm_modem': mediatypedata['gsm_modem'],
                'username': mediatypedata['username'],
                'status': mediatypedata['status'],
                'smtp_port': mediatypedata['smtp_port'],
                'smtp_security': mediatypedata['smtp_security'],
                'smtp_verify_peer': mediatypedata['smtp_verify_peer'],
                'smtp_verify_host': mediatypedata['smtp_verify_host'],
                'smtp_authentication': mediatypedata['smtp_authentication'],
                'exec_params': mediatypedata['exec_params'],
                'maxsessions': mediatypedata['maxsessions'],
                'maxattempts': mediatypedata['maxattempts'],
                'attempt_interval': mediatypedata['attempt_interval'],
                'content_type': mediatypedata['content_type'],
                'script': mediatypedata['script'],
                'timeout': mediatypedata['timeout'],
                'process_tags': mediatypedata['process_tags'],
                'show_event_menu': mediatypedata['show_event_menu'],
                'event_menu_url': mediatypedata['event_menu_url'],
                'event_menu_name': mediatypedata['event_menu_name'],
                #can't update parameters, I tried...
                'parameters': mediatypedata['parameters']
            }})
            if len(mediatypeparams) > 0:
                method = "exists"
        #self._module.exit_json(changed=False, msg="mediatypeparams: %s, method %s" % (mediatypeparams, method))
        return method

    def create_or_update(self, method, name, data):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)

            #sorry, this is required...
            #need to sort out None values to avoid weird API errors when creating media types...
            data = dict(filter(lambda elem: elem[1] != None,data.items()))
            if len(data) > 1:
                if method == "create":
                    self._zapi.mediatype.create(data)
                    self._module.exit_json(
                        changed=True,
                        result="Created media type %s" % name
                    )
                if method == "update":
                    result = self._zapi.mediatype.get({
                        'filter': {'name': name,
                        'type': data['type']} })
                    data['mediatypeid'] = result[0]['mediatypeid']
                    self._zapi.mediatype.update(data)
                    self._module.exit_json(
                        changed=True,
                        result="Updated mediatype %s" % name
                    )
                else:
                    self._module.fail_json(
                        changed=False,
                        msg="unknown method '%s' to create_or_update" % method
                    )
            else:
                self._module.exit_json(changed=False, msg="No media type data/parameters found!")
        except Exception as e:
            self._module.fail_json(msg="XX Failed to %s media type %s: %s %s" %
                                        (method, name, e, data))

    def delete(self, name, type):
        method = "delete"
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)

            result = self._zapi.mediatype.get({
                'filter': {'name': name,
                'type': type} })
            if len(result) > 0 and 'mediatypeid' in result[0]:
                mediatypeid = result[0]['mediatypeid']
                self._zapi.mediatype.delete([mediatypeid])
                self._module.exit_json(
                    changed=True,
                    result="Deleted media type %s" % name
                )
            else:
                self._module.exit_json(changed=False, result="Media type {} not found so no need to delete it...".format(name))
        except Exception as e:
            self._module.fail_json(msg="XX Failed to %s media type %s: %s %s" %
                                        (method, name, e, result))

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
            type=dict(type='int', required=True, choices=[0, 1, 2, 4]),
            name=dict(type='str', required=True),
            description=dict(type='str', required=False),
            smtp_server=dict(type='str', required=False), #required for email
            smtp_helo=dict(type='str', required=False), #required for email
            smtp_email=dict(type='str', required=False), #required for email
            exec_path=dict(type='str', required=False), #required for script
            gsm_modem=dict(type='str', required=False), #required for sms
            username=dict(type='str', required=False),
            passwd=dict(type='str', required=False, no_log=True),
            status=dict(type='int', default=0, choices=[0, 1]), #0 enabled, 1 disabled
            smtp_port=dict(type='int', default=25), #0 to 65535, required for email
            smtp_security=dict(type='int', default=0, choices=[0, 1, 2]), #0 None, 1 STARTTLS, 2 SSL/TLS
            smtp_verify_peer=dict(type='int', default=0, choices=[0, 1]), #0 No, 1 Yes
            smtp_verify_host=dict(type='int', default=0, choices=[0, 1]), #0 No, 1 Yes
            smtp_authentication=dict(type='int', default=0),
            exec_params=dict(type='str', required=False), #needed for script
            maxsessions=dict(type='int', default=1), #0-100
            maxattempts=dict(type='int', default=3), #1-10
            attempt_interval=dict(type='str', default='10s'), #0-60s
            content_type=dict(type='int', default=1, choices=[0, 1]), #0 plain text, 1 html
            script=dict(type='str', required=False), #required for webhook
            timeout_param=dict(type='str', default='30s'), #1-60s
            process_tags=dict(type='int', default=0, choices=[0, 1]), #0 ignore, 1 process
            show_event_menu=dict(type='int', default=0, choices=[0, 1]), #0 don't add urls, # 1 add urls
            event_menu_url=dict(type='str', required=False),
            event_menu_name=dict(type='str', required=False),
            parameters=dict(type='list', required=False)
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
    name = module.params['name']

    zbx = None

    # login to zabbix
    try:
        zbx = ZabbixAPI(server_url, timeout=timeout, user=http_login_user, passwd=http_login_password,
                        validate_certs=validate_certs)
        zbx.login(login_user, login_password)
    except Exception as e:
        module.fail_json(msg="Failed to connect to Zabbix server: {server} with {exception}".format(server=server_url, exception=e))

    mediatype = zbxMediaType(module, zbx)

    method = mediatype.mediatype_exists(name, module.params)

    if state == "absent":
        mediatype.delete(module.params['name'], module.params['type'])
    elif method == "exists":
        module.exit_json(changed=False, result="Media type %s exists as specified" % name)
    else:
        mediatype.create_or_update(method, name, module.params)

    # rather a WIP/debug-fallthrough:
    module.exit_json(changed=True, result="This module should not exit this way!")
if __name__ == '__main__':
    main()
