#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import re
from pysnmp.entity.rfc3413.oneliner import cmdgen


class snmpengine:

    def __init__(self, query_profile):

        self.query_profile = query_profile

        # setup and validate variables for common t oall versions of SNMP
        try:
            self._validate_input()
        except:
            raise

        self.q_host = query_profile['Host']
        self.q_version = query_profile['Version']

        # if values are set to None it sets them to default
        if query_profile['OID'] is None:
            self.q_oid = '1.3.6.1.2.1.1.5.0'
        else:
            self.q_oid = query_profile['OID']

        if query_profile['Timeout'] is None:
            self.q_timeout = 2
        else:
            self.q_timeout = query_profile['Timeout']

        if query_profile['Retry'] is None:
            self.q_repeat = 1
        else:
            self.q_repeat = query_profile['Retry']

        # setup variables for SNMPv1 and 2
        # v1 - mpModel=0, v2c - mpModel=1 (default)
        if self.q_version in ('1', '2'):
            self.q_community = query_profile['Community']
            if self.q_version is '1':
                self.mpModel=0
            else:
                self.mpModel=1

        # setup variables for SNMPv3
        elif self.q_version is '3':
            self.q_authkey = query_profile['AuthKey']
            self.q_privkey = query_profile['PrivKey']
            self.q_user = query_profile['User']
            self.authproto = query_profile['AuthProto']
            self.privproto = query_profile['PrivProto']

            if self.authproto is '0':
                self.q_auth_proto = cmdgen.usmNoAuthProtocol
            elif self.authproto is '1':
                self.q_auth_proto = cmdgen.usmHMACMD5AuthProtocol
            elif self.authproto is '2':
                self.q_auth_proto = cmdgen.usmHMACSHAAuthProtocol

            if self.privproto is '0':
                self.q_priv_proto = cmdgen.usmNoPrivProtocol
            elif self.privproto is '1':
                self.q_priv_proto = cmdgen.usmDESPrivProtocol
            elif self.privproto is '2':
                self.q_priv_proto = cmdgen.usm3DESEDEPrivProtocol
            elif self.privproto is '3':
                self.q_priv_proto = cmdgen.usmAesCfb128Protocol
            elif self.privproto is '4':
                self.q_priv_proto = cmdgen.usmAesCfb192Protocol
            elif self.privproto is '5':
                self.q_priv_proto = cmdgen.usmAesCfb256Protocol



    def _validate_input(self):

        # validate host
        if 'Host' not in self.query_profile:
            raise ValueError("Host missing from SNMP query")
        allowed = re.compile("(?!-)[A-Za-z0-9-_]{1,63}(?<!-)$", re.IGNORECASE)
        if not all(allowed.match(x) for x in self.query_profile['Host'].split(".")):
            raise ValueError("Host includes invalid characters - %s" % self.query_profile['Host'])
        if len(self.query_profile['Host']) > 255:
            raise ValueError("Host invalid length - %s" % self.query_profile['Host'])
        self._hostname_type = self._hostnameType()
        if self._hostname_type is None:
            raise ValueError("Format of host is unrecognised - %s" % self.query_profile['Host'])

        # validate version number for SNMPv1, 2 and 3
        if 'Version' not in self.query_profile:
            raise ValueError("Version missing from SNMP query")
        if self.query_profile['Version'] not in ('1', '2', '3'):
            #raise ValueError("Incorrect version value, expecting 1, 2, or 3")
            raise ValueError("Incorrect version supplied %s, expecting 1, 2, or 3" % self.query_profile['Version'])

        # validate common values if they were provided in query
        if 'OID' in self.query_profile:
            if self.query_profile['OID'] is not None:
                allowed = re.compile("[0-9]{1,63}", re.IGNORECASE)
                if not all(allowed.match(x) for x in self.query_profile['OID'].split(".")):
                    raise ValueError("Incorrect OID format supplied - %s" % self.query_profile['OID'])

        if 'Timeout' in self.query_profile:
            if self.query_profile['Timeout'] is not None:
                if self.query_profile['Timeout'] not in range(1,11):
                    raise ValueError("Incorrect timeout supplied %s, expecting 1 to 10" % self.query_profile['Timeout'])

        if 'Retry' in self.query_profile:
            if self.query_profile['Retry'] is not None:
                if self.query_profile['Retry'] not in range(1,11):
                    raise ValueError("Incorrect Retry value supplied %s, expecting 1 to 10" % self.query_profile['Retry'])

        if self.query_profile['Version'] in ('1','2'):
            if 'Community' not in self.query_profile:
                raise ValueError("Using SNMPv2 and missing Community from SNMP query")
        else:
            if 'AuthKey' not in self.query_profile:
                raise ValueError("SNMPv3 AuthKey missing from SNMP query")
            if len(self.query_profile['AuthKey']) < 8:
                raise ValueError("SNMPv3 Authkey needs to be >8 characters - %s" % self.query_profile['AuthKey'])

            if 'PrivKey' not in self.query_profile:
                raise ValueError("SNMPv3 PrivKey missing from SNMP query")
            if len(self.query_profile['PrivKey']) < 8:
                raise ValueError("SNMPv3 Privkey needs to be >8 characters - %s" % self.query_profile['PrivKey'])

            if 'User' not in self.query_profile:
                raise ValueError("SNMPv3 User missing from SNMP query")

            if 'AuthProto' not in self.query_profile:
                raise ValueError("Using SNMPv3 and missing AuthProto from SNMP query")
            if self.query_profile['AuthProto'] not in ('0', '1', '2'):
                raise ValueError("Incorrect AuthProto value supplied %s, expecting 0-2" % self.query_profile['AuthProto'])

            if 'PrivProto' not in self.query_profile:
                raise ValueError("Using SNMPv3 and missing PrivProto from SNMP query")
            if self.query_profile['PrivProto'] not in ('0', '1', '2', '3', '4', '5'):
                raise ValueError("Incorrect PrivProto value supplied %s, expecting 0-5" % self.query_profile['PrivProto'])


    def hostname_type(self):
        return self._hostname_type

    def _hostnameType(self):
        #try:
        #    socket.inet_aton(self.query_profile['Host'])
        #    return "IP"
        #except:
        #    pass

        allowed = re.compile("^(\d{1,3}\.){3}\d{1,3}$", re.IGNORECASE)
        valid = allowed.match(self.query_profile['Host'])
           
        if valid:
           allowed = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", re.IGNORECASE)   
           valid = allowed.match(self.query_profile['Host'])
           if valid:
               return "IP"
           else:
               return None
        else:
           pass 
        
        try:
            valid = re.search('^([A-Za-z0-9-_]){1,255}$', self.query_profile['Host'], re.M|re.I)
            valid.group(1)
            return "HOSTNAME"
        except:
            pass
        allowed = re.compile("(?!-)[A-Za-z0-9-_]{1,255}(?<!-)$", re.IGNORECASE)
        if all(allowed.match(x) for x in self.query_profile['Host'].split(".")):
            return "FQDN"
        return None

    def walk_host(self):
        self.error, self.value = self._walk_host()
        return self.error, self.value

    def _walk_host(self):
        cmdGen = cmdgen.CommandGenerator()
        if self.q_version is not '3':
            errorIndication, errorStatus, errorIndex, varBinds = cmdGen.nextCmd(
                cmdgen.CommunityData(self.q_community, mpModel=self.mpModel),
                cmdgen.UdpTransportTarget((self.q_host, 161),
                                          timeout=self.q_timeout,
                                          retries=self.q_repeat),
                                          self.q_oid)
        else:
            errorIndication, errorStatus, errorIndex, varBinds = cmdGen.nextCmd(
                             cmdgen.UsmUserData(self.q_user,
                                                self.q_authkey,
                                                self.q_privkey,
                                                authProtocol=self.q_auth_proto,
                                                privProtocol=self.q_priv_proto),
                             cmdgen.UdpTransportTarget((self.q_host, 161),
                                                       timeout=self.q_timeout,
                                                       retries=self.q_repeat),
                                                       self.q_oid)

        #print errorIndication, errorStatus, errorIndex, varBinds

        # Check for errors and print out results
        if errorIndication:
            self.r_error = True
            self.r_value = errorIndication
        else:
            if errorStatus:
                self.r_error = True
                self.r_value = errorStatus.prettyPrint()
            else:
                self.r_error = False
                self.r_value = []
                for varBindTableRow in varBinds:
                    for name, val in varBindTableRow:
                        index_dict = {'Index': name,
                                      'Result': val.prettyPrint()} 
                        self.r_value.append(index_dict)
                        #print name[-1], self.r_value         

        return self.r_error, self.r_value


        
    def get_host(self):
        self.get_error, self.get_value = self._get_host()
        return self.get_error, self.get_value

    def _get_host(self):
        cmdGen = cmdgen.CommandGenerator()
        if self.q_version is not '3':
            errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
                cmdgen.CommunityData(self.q_community, mpModel=self.mpModel),
                cmdgen.UdpTransportTarget((self.q_host, 161),
                                          timeout=self.q_timeout,
                                          retries=self.q_repeat),
                                          self.q_oid)
        else:
            errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
                             cmdgen.UsmUserData(self.q_user,
                                                self.q_authkey,
                                                self.q_privkey,
                                                authProtocol=self.q_auth_proto,
                                                privProtocol=self.q_priv_proto),
                             cmdgen.UdpTransportTarget((self.q_host, 161),
                                                       timeout=self.q_timeout,
                                                       retries=self.q_repeat),
                                                       self.q_oid)

        print errorIndication, errorStatus, errorIndex, varBinds

        # Check for errors and print out results
        if errorIndication:
            self.r_error = True
            self.r_value = errorIndication
        else:
            if errorStatus:
                self.r_error = True
                self.r_value = errorStatus.prettyPrint()
            else:
                for name, val in varBinds:
                    self.r_error = False
                    self.r_value = val.prettyPrint()

        return self.r_error, self.r_value
