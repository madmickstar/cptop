from distutils.core import setup
import py2exe, sys, os, glob

# automatically add py2exe to command
sys.argv.append('py2exe')

# fix py2exe ability to find applications modules
sys.path.insert(0, 'cptop')

py2exe_options = {
    'bundle_files': 1,
    'compressed': True,
    'optimize': 2,
    'packages': ['pysnmp'],
    'dll_excludes': ['w9xpopen.exe'], # exclude win95 98 dll files
    'includes': ['pysnmp.smi.mibs.*',
                 'pysnmp.smi.mibs.instances.*',
                 'pysnmp.entity.rfc3413.oneliner.*'], # additional modules
    #'excludes': ['pysmi.lexer', 'pysmi.lexer.smi', '_scproxy', 'asyncio', 'http.client', 'ipaddress', 'ordereddict', 'simplejson', 'trollius', 'twisted.internet', 'twisted.internet.defer', 'twisted.internet.protocol', 'twisted.python.failure']  # exluded modules 
    'excludes': ['pysmi.lexer', 'pysmi.lexer.smi', '_scproxy', 'asyncio', 'http.client', 'ipaddress', 'ordereddict', 'simplejson', 'trollius', 'twisted.internet', 'twisted.internet.defer', 'twisted.internet.protocol', 'twisted.python.failure']  # exluded modules 
}


setup(
  options = {
            'py2exe': py2exe_options,
            },
  #console = ['cptop.py'],
  console = ['cptop/cptop.py'],
  zipfile = None,
)