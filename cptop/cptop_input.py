#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import re
import logging


           
def create_input_file(input_file):
    ''' Create sample input file '''
    
    lines = ('# SNMP Version - Default version=0',
            '# 0 = auto, 1 = SNMPv1, 2 = SNMPv2c, 3 = SNMPv3', '#',
            '# SNMP string1 and string2 - Default string1 and string2=public',
            '# string1 = v1 v2 string or v3 auth string',
            '# string2 = v3 priv string', '#',
            '# SNMP v3 user - Default user=user',
            '# user = user', '#',
            '# SNMP v3 auth mode - Default auth_mode=2',
            '# 0 = noAuthNoPriv, 1 = authNoPriv, 2 = authPriv', '#',
            '# SNMP v3 auth protocol - Default auth_proto=0',
            '# 0 = MD5, 1 = SHA', '#',
            '# SNMP v3 priv protocol - Default priv_proto=1',
            '# 0 = AES, 1 = DES', '#',
            '# host, version, string1, string2, user, auth_mode, auth_proto, priv_proto, comment',
            '# 192.168.1.254,3,public,public,user,2,1,0,sample comment')
            
    with open(input_file, 'w') as f:
        for row in lines:
            f.write('%s \n' % row )

        
def main(input_file):   
    ''' 
    Checks for input file 
    If not exists it creates a sample file for user to edit   
    '''
    logger = logging.getLogger(__name__)
   
    if not os.path.isfile(input_file):
        logger.debug('Creating sample input file %s', input_file)
        try:
            #create_sample(input_file)
            create_input_file(input_file)
        except Exception, err:
            sys.stderr.write('ERROR: Failed to create input file, %s' % str(err))
            sys.exit(1)
        else:
            logger.info('Successfully created input file %s', input_file)
