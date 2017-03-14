#!/usr/bin/env python

import csv
import ldap
import yaml
import sys
import re

# Load settings
with open("/opt/oulib/zabbix/etc/check_ldap.yml", 'r') as ymlfile:
  secrets = yaml.load(ymlfile)

if len(sys.argv) < 2:
    print 'Must supply ldap target!'
    sys.exit(1)
  
ldap_target = sys.argv[1]
  
# loop through ldap targets specified in secrets
for secret in secrets['zabbix_check_ldap']:

  # Skip to the next ldap if this isn't the requested one
  if ldap_target != secret['target']:
    continue

  # Collect details needed for bind
  l = ldap.initialize(secret['target'])
  basedn = secret['basedn']
  binddn = secret['binddn']
  pw = secret['bindpw']

  # Collect details needed for search and auth
  search_account = secret['search_account']
  search_pass = secret['search_pass']
  
  # We're on AD
  ldap.set_option(ldap.OPT_REFERRALS, 0)
  ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, 0)
  
  # Bind to the server
  
  try:
      l.protocol_version = ldap.VERSION3
      l.simple_bind_s(binddn, pw) 
  
      account_name = l.whoami_s()
  
      print 'Successfully bound as %s' % account_name
  
  # Search AD for username
  
      search_result=l.search_s(basedn,ldap.SCOPE_SUBTREE,'(sAMAccountName=%s)' % search_account)
  
  # Make the LDAP data a printable string
  
      search_result = repr(search_result)
  
  # Search LDAP data for account OU data
  
      user_dn = re.search('^\[\(\'(.+?)\',\s', search_result)
  
      if user_dn:
          print 'Account name %s found:' % search_account
  
      else:
          print 'Account name %s not found.' % search_account
          sys.exit(1)
  
      print user_dn.group(1)
  
  # Authenticate using search results
  
      check_name = user_dn.group(1)
      check_pass = search_pass
  
      l.simple_bind_s(check_name, check_pass)
  
      new_name = l.whoami_s()
  
      print 'Successfully bound as %s' % new_name
  
  # If all else fails, abaondon ship
  
  except ldap.INVALID_CREDENTIALS:
      print "Your username or password is incorrect."
      sys.exit(1)
  
  except ldap.SERVER_DOWN:
      print"The server appears to be down."
      sys.exit(1)
  
  except ldap.LDAPError, e:
      if type(e.message) == dict and e.message.has_key('desc'):
          print e.message['desc']
          sys.exit(1)
      else: 
          print e
          sys.exit(1)
  
  sys.exit(0)
  
  l.unbind_s()
