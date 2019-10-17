# Setup
You can test/debug these modules by changing inventory files
to point to an existing Zabbix API endpoint or create
a playground as follows.

## Dependencies
This relies on python library zabbix-api, install by:
```pip3 install zabbix-api```.

## Vagrant (small)
A quick option is to create a VM with the cookbook in
ssfn1_v_zabbixserver. See README.md there on how to this
(esp. setup_zabbix_db.sh).
If unchanged, the existing inventory will "just work".

## Vagrant (large)
If it's needed to test in a "full cluster", please
```vagrant up``` in git:tools/manage-zabbix-cluster
Adapt a new inventory as needed.

## Test the kit
```ansible-playbook -i vagrant_inventory testkit.yml```

# Development
Before creating new modules, please check back if the
intended API-functionality isn't already implemented,
e.g. ```ansible-doc -l |grep zabbix``` or look at
https://docs.ansible.com/ansible/latest/modules/list_of_monitoring_modules.html

## "template"
Please start from `__template_zbx_module.py' provided
in this directory.
It's a slightly commented `bare things' module that is
integrating into ansible module loader and creates an
authenticated session (zapi.login) which all further
calls will need

## exit/fail
Any codepath must end with a `modules.exit_json()'
or `modules.fail_json()' before exiting the module
or ansible might produce very confusing error messages.

## debug
To gather POSTed JSON to the API or/and HTTP headers,
run the nginx play. To enable both:
```
ansible-playbook -i vagrant_inventory -t headers,postdata nginx.yml
```
Logged headers (and way more) is noisy and for all
requests (e.g. webUI). As so, use this only to debug e.g.
basic-auth problems.
The rpc-postdata.log is for the API only, best to read:
```
sed 's/\\x22/"/g' /var/log/nginx/rpc-postdata.log | jq .
```
