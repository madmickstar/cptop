#!/usr/bin/env python


import sys
import os
import csv

from _version import __version__
import cptop_tools
import cptop_log
import cptop_input
from cptop_snmp import snmpengine


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
    parser.add_argument('-o', '--out-file',
        default='output.csv',
        type=str,
        metavar=('{filename}'),
        help='Ouput file name, default = output.csv')
    parser.add_argument('-i', '--in-file',
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


def process_input(process_input):
    '''
    read in lines from CSV input file that do not start with #
    '''
    logger = logging.getLogger(__name__)
    alive_hosts = []

    with open(process_input, 'rb') as csvfile:
        rdr = csv.reader(filter(lambda row: row[0]!='#', csvfile))
        for row in rdr:
            oid = None
            timeout = None
            retry = None
            #oid = '1.3.6.1.2.1.1.5.0'
            #timeout = 2
            #retry = 1

            if (len(row) < 3):
                logger.error('%s arguments supplied from csv line %s', len(row), row)
                logger.error('Expect min 3 arguments for SNMPv1 or 2, and min 7 for SNMPv3')
                continue

            if row[1] in ['1', '2']:
                query_profile = {'Host': row[0],
                                 'Version': row[1],
                                 'Community': row[2],
                                 'OID': oid,
                                 'Timeout': timeout,
                                 'Retry': retry}
            else:
                if (len(row) < 7):
                    logger.error('Expecting min 7 arguments for SNMPv3, %s supplied from row %s', len(row), row)
                    continue
                query_profile = {'Host': row[0],
                                 'Version': row[1],
                                 'AuthKey': row[2],
                                 'PrivKey': row[3],
                                 'User': row[4],
                                 'AuthProto': row[5],
                                 'PrivProto': row[6],
                                 'OID': oid,
                                 'Timeout': timeout,
                                 'Retry': retry}

            logger.debug('Row is SNMPv%s %s', row[1], query_profile)
            logger.info('Processing %s', query_profile['Host'])

            try:
                b = snmpengine(query_profile)
            except Exception, err:
                logger.error('Initialising host failed with an exception, skipping host')
                logger.error('Error returned - %s', err)
                continue

            logger.debug('Checking %s is alive', query_profile['Host'])
            try:
                error, value = b.get_host()
            except Exception, err:
                logger.error('Checking host is alive failed with an exception, skipping host')
                logger.error('Error returned - %s', err)
                continue

            if error:
                #logger.info('SNMP Response Errors:- %s', value)
                #continue
                logger.error('Checking host is alive returned an error, skipping host')
                logger.error('Error returned - %s', error)
                continue

            logger.info('Host is alive - %s', value)
            query_profile['Hostname'] = value
            #query_profile['Hostname'] = str(value)
            alive_hosts.append(query_profile)

    return alive_hosts


def index_hosts(dic):
    '''
    index interfaces of live hosts
    '''
    logger = logging.getLogger(__name__)

    final_index_file = []
    oid_list = []
    # final OIDs
    oid_list.append('1.3.6.1.4.1.2620.1.1.27.1.2')
    oid_list.append('1.3.6.1.2.1.2.2.1.2')
    
    # testing OIDs
    #oid_list.append('1.3.6.1.2.1.2.2.1.2')
    #oid_list.append('1.3.6.1.2.1.2.2.1.2')
    counter = 0
    logger.debug('Indexing host %s', dic['Hostname'])

    for i in oid_list:
        dic['OID'] = i
        counter += 1

        try:
            b = snmpengine(dic)
        except Exception, err:
            logger.error('Initialising host failed with an exception, skipping host')
            logger.error('Error returned - %s', err)
            break

        logger.debug('Walking OID %s', dic['OID'])
        try:
            error, value = b.walk_host()
        except Exception, err:
            logger.error('Walking host failed with an exception, skipping host')
            logger.error('Error returned - %s', err)
            break

        if error:
            logger.error('Walking host returned an error, skipping host')
            logger.error('Error returned - %s', error)
            break

        if len(value) <= 0:
            logger.error('Index failed, %s returned empty result', dic['OID'])
            break

        logger.debug('Successfully indexed loop %s oid %s', counter, dic['OID'])

        # if first loop, preserve value
        if counter == 1:
            tmp_index_file = value
            logger.debug('Index 1 %s', tmp_index_file)
            #for index_1 in tmp_index_file:
            #    logger.debug('Index 1 %s = %s', index_1['Index'], index_1['Result'])
        elif counter == 2:
            for index_2 in value:
               logger.debug('Index 2 %s = %s', index_2['Index'], index_2['Result'])
               for index_1 in tmp_index_file:
                   # if Result matches from both indexes combine the result
                   if index_1['Result'] == index_2['Result']:
                       #logger.debug('Index 1 %s = %s', index_1['Index'], index_1['Result'])
                       index_3 = {'Index_1': index_1['Index'][-2],
                                  'IntName': index_1['Result'],
                                  'Index_2': index_2['Index'][-1]}
                       final_index_file.append(index_3)
                       logger.debug('Index %s = %s = %s', index_3['Index_1'], index_3['IntName'], index_3['Index_2'])
                       break
        else:
            logger.debug('Oops, looped more than twice, counter = %s', counter)

    return final_index_file


def get_int_details(dic, final_index_file):
    '''
    Get details of interfaces
    '''
    logger = logging.getLogger(__name__)

    all_interfaces = []
    logger.debug('Grabbing interface details for host %s', dic['Hostname'])

    for i in final_index_file:

        oid_list = []
        # final OIDs
        oid_list.append('1.3.6.1.4.1.2620.1.1.27.1.3.' + str(i['Index_1']) + '.0')
        oid_list.append('1.3.6.1.4.1.2620.1.1.27.1.4.' + str(i['Index_1']) + '.0')
        oid_list.append('1.3.6.1.2.1.31.1.1.1.18.' + str(i['Index_2']))
        oid_list.append('1.3.6.1.2.1.2.2.1.8.' + str(i['Index_2']))
        
        # testing OIDs
        #oid_list.append('1.3.6.1.2.1.2.2.1.4.' + str(i['Index_2']))
        #oid_list.append('1.3.6.1.2.1.2.2.1.5.' + str(i['Index_2']))
        #oid_list.append('1.3.6.1.2.1.2.2.1.6.' + str(i['Index_2']))
        #oid_list.append('1.3.6.1.2.1.2.2.1.7.' + str(i['Index_2']))           
        interface_gets = []

        for o in oid_list:
            dic['OID'] = o

            try:
                b = snmpengine(dic)
            except Exception, err:
                logger.error('Initialising host failed with an exception, skipping host')
                logger.error('Error returned - %s', err)
                break

            logger.debug('Grabbing details for OID %s', dic['OID'])
            try:
                error, value = b.get_host()
            except Exception, err:
                logger.error('Get host failed with an exception, skipping host')
                logger.error('Error returned - %s', err)
                break

            if error:
                logger.error('Get host returned an error, skipping host')
                logger.error('Error returned - %s', error)
                break

            interface_gets.append(value)


        interface = {'HostName': dic['Hostname'],
                     'HostIP': dic['Host'],
                     'Index': i['Index_1'],
                     'IntName': i['IntName']}

        interface['IntIP'] = interface_gets[0]
        interface['IntSub'] = interface_gets[1]
        interface['Alias'] = interface_gets[2]
        

        if interface_gets[3] == '1':
            interface['Status'] = 'Up'
        elif interface_gets[3] == '2':
            interface['Status'] = 'Down'
        else:
            interface['Status'] = 'Other'

        logger.debug('Interface get results %s', interface_gets)
        all_interfaces.append(interface)

    return all_interfaces


def output_header(output_file):
    '''
    Print headers to file and screen
    '''
    logger = logging.getLogger(__name__)

    logger.info('%s, %s, %s, %s, %s, %s, %s, %s', 'HostName', 'HostIP',
                 'Index', 'Status', 'IntName', 'IntIP', 'IntSub', 'Alias')

    with open(output_file, 'w') as f:
        f.write('HostName,HostIP,Index,Status,IntName,IntIP,IntSub,Alias\n')


def output_results(interface_details, output_file):
    '''
    Print results to file and screen
    '''
    logger = logging.getLogger(__name__)

    with open(output_file, 'a') as f:
        for i in interface_details:
            f.write('%s, %s, %s, %s, %s, %s, %s, %s \n' % (i['HostName'], i['HostIP'], i['Index'],
                    i['Status'], i['IntName'], i['IntIP'], i['IntSub'], i['Alias']))
            logger.info('%s, %s, %s, %s, %s, %s, %s, %s', i['HostName'], i['HostIP'], i['Index'],
                    i['Status'], i['IntName'], i['IntIP'], i['IntSub'], i['Alias'])


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
        output_file, input_file, current_working_dir = cptop_tools.permissions(args)
    except Exception, err:
        logger.error(str(err))
        sys.exit(1)

    # create input file
    cptop_input.main(input_file)
    alive_hosts = process_input(input_file)

    # collect details of interfaces from live hosts only
    output_header(output_file)
    for dic in alive_hosts:
        final_index_file = index_hosts(dic)
        interface_details = get_int_details(dic, final_index_file)
        output_results(interface_details, output_file)



if __name__ == "__main__":
    main()