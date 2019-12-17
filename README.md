OU Libraries Zabbix
=========

Rudimentary Zabbix zerver role for CentOS 7.
See the [Zabbix 4.0 documentation](https://www.zabbix.com/documentation/4.0/manual).

Requirements
------------

This role requires:

- [OULibraries.centos7](https://github.com/OULibraries/ansible-role-centos7)
- [OULibraries.mariadb](https://github.com/OULibraries/ansible-role-mariadb)
- [OULibraries.apache2](https://github.com/OULibraries/ansible-role-apache2)


Role Variables
--------------

The following variables are defined:

```
# Domain name suffix to the hostname. hostname + dn_suffix == fqdn.
httpd_dn_suffix: 'example.com'

# DB admin user for creating zabbix db 
mariadb_host: "localhost"
mariadb_port: "3306"
mariadb_root_user: 'root'
mariadb_root_pw: 'root'

# Zabbix db and credentials
zabbix_db: 'zabbix'
zabbix_db_user: 'zabbix'
zabbix_db_pass: 'zabbix'

zabbix_tz: "America/Chicago"



# TLD to use with zabbix, prepended to base dn from Apache role
zabbix_hostname: 'monitor'

```
License
-------

[MIT](https://github.com/OULibraries/ansible-role-zabbix/blob/master/LICENSE)
