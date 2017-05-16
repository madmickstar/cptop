#!/usr/bin/env python


import sys
import os
import csv

from _version import __version__
import cptop_tools 
import cptop_log
import cptop_input

import logging
import logging.config
import logging.handlers
import ConfigParser

import argparse                                # import cli argument
from argparse import RawTextHelpFormatter      # Formatting help

from pysnmp.entity.rfc3413.oneliner import cmdgen



def process_cli():
    # processes cli arguments and usage guide
    parser = argparse.ArgumentParser(prog='cptop',
    description='''         SNMP tool for grabbing checkpoint fleet IP and interface details,\n \
        this assists when locating clients, servers and services when updating \n \
        firewall rules''',
    epilog='''Command line examples \n\n \
        POSIX Users \n \
        python -m cptop \n \
        python -m cptop other/dir/input.txt \n \
         \n \
        Windows Users \n \
        python -m cptop \n \
        python -m cptop other\\dir\\input.txt''',
    formatter_class=RawTextHelpFormatter)
#    parser.add_argument('-wd', '--dir',
#        default=working_dir,
#        type=str,
#        metavar=('{dir path}'),
#        help='Directory to find input file, default = %s' % working_dir)
    parser.add_argument('-f', '--file',
        default='input.txt',
        type=str,
        metavar=('{filename}'),
        help='Input file name, default = input.txt')
    parser.add_argument('-d', '--debug',
        action="store_true",
        help='Enable debug output to console')
    parser.add_argument('--version',
        action='version',
        version='%(prog)s v'+__version__)

    args = parser.parse_args()
    return args




def snmp_host():

    cmdGen = cmdgen.CommandGenerator()
    errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
        cmdgen.CommunityData('public', mpModel=0),
        cmdgen.UdpTransportTarget(('192.168.1.253', 161),timeout=2,retries=1),
    #    '1.3.6.1.2.1.1'
        '1.3.6.1.2.1.1.1.0',
        '1.3.6.1.2.1.1.2.0',
        '1.3.6.1.2.1.1.3.0',
        '1.3.6.1.2.1.1.4.0',    
        '1.3.6.1.2.1.1.5.0'
#    errorIndication, errorStatus, errorIndex, varBinds = cmdGen.nextCmd(
#        cmdgen.UsmUserData('user', 'public', 'public'),
#        cmdgen.UsmUserData('user', 'public', 'public',
#                               authProtocol=cmdgen.usmHMACSHAAuthProtocol,
#                               privProtocol=cmdgen.usmAesCfb128Protocol),
#        cmdgen.UdpTransportTarget(('192.168.1.254', 161),timeout=2,retries=1),
#         '1.3.6.1.4.1.2620.1.1.27.1.2',
#         '1.3.6.1.2.1.2.2.1.2'
    )
    
    # Check for errors and print out results
    if errorIndication:
        print(errorIndication)
    else:
        if errorStatus:
            print('%s at %s' % (
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex)-1] or '?'
                )
            )
        else:
            for name, val in varBinds:
                print('%s = %s' % (name, val))
#            for varBindTableRow in varBinds:
#                for name, val in varBindTableRow:
#                    print('%s = %s' % (name, val))    
     
        
        
def process_csv():
    fp = open('samples.csv')
    rdr = csv.DictReader(filter(lambda row: row[0]!='#', fp))
    for row in rdr:
        print(row)
    fp.close()
    

def main():
    '''
    The main entry point of the application
    '''
    
    working_dir = cptop_tools.process_working_dir()

    # process arguments from cli
    args = process_cli()

    # load the logging configuration
    logging_file = cptop_log.main(working_dir, args)
    try:
        logging.config.fileConfig(logging_file, disable_existing_loggers=False)
    except Exception, err:
        sys.stderr.write('ERROR: log config file - %s' % str(err))
        sys.exit(1)
    logger = logging.getLogger(__name__)

    logger.debug('CLI Arguments %s', args)
    
    # check write permissions
    try:
        input_file, current_working_dir = cptop_tools.permissions(args)
    except Exception, err:
        logger.error(str(err))
        sys.exit(1)
   
    # create input file
    cptop_input.main(input_file)
    snmp_host()

if __name__ == "__main__":
    main()     