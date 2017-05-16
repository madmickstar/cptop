#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import re
import time
import logging
import datetime
from codecs import open


def process_working_dir():
    '''
    Checks for working dir in home directory and if writable
    If it is not there it checks for write access to home dir and creates working dir
    
    Returns working dir
    '''
    # prep working dir in users home DIR
    home_dir = os.path.expanduser('~')
    working_dir = os.path.join(home_dir, '.cptop')

    if os.path.isdir(working_dir):
        if not check_write_dir(working_dir):
            sys.stderr.write('ERROR: Failed write access to working DIR %s, exiting....' % working_dir)
            sys.exit(1)
    else:
        if not os.path.isdir(home_dir):
            sys.stderr.write('ERROR: Failed to find HOME DIR %s, exiting....' % home_dir)
            sys.exit(1)
        else:
            if not check_write_dir(home_dir):
                sys.stderr.write('ERROR: Failed write access to HOME DIR %s, exiting....' % home_dir)
                sys.exit(1)
            else:
                # create working dir in home dir
                try:
                    os.makedirs(working_dir)
                except:
                    sys.stderr.write('ERROR: Failed to create logging DIR %s, exiting....' % working_dir)
                    sys.exit(1)                

    return working_dir


def check_write_dir(test_dir):
    if not os.access(test_dir, os.W_OK):
        return False
    return True


def check_write_file(test_file):
    if not os.access(test_file, os.W_OK):
        return False
    return True


def check_exists_file(test_file):
    if not os.access(test_file, os.F_OK):
        return False
    return True
    
def check_read_file(test_file):
    if not os.access(test_file, os.R_OK):
        return False
    return True


def permissions(args):
    # check write permissions
    logger = logging.getLogger(__name__)

    input_dir = os.path.dirname(sys.argv[0])
    input_file = os.path.join(input_dir, args.file)
    current_working_dir = os.getcwd()
    
    # test input file
    if os.path.isfile(input_file):
        if not check_read_file(input_file):
            raise RuntimeError('Permissions check - Failed to read input file %s exiting....' % input_file)
        else:
            logger.debug('Input file exists and is readable %s', input_file)
       
    # test current dir
    if not check_write_dir(current_working_dir):
        raise RuntimeError('Permissions check - Failed write access in current working folder %s exiting....' % current_working_dir)
    else:
        logger.debug('Current working DIR is writable %s', current_working_dir)

    logger.debug('Successfully passed all read write access tests')

    return input_file, current_working_dir




