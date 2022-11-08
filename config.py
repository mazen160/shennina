#!/usr/bin/env python3
import json
import os
from pymetasploit3.msfrpc import MsfRpcClient

# Base config
PROJECT_PATH = os.path.dirname(os.path.abspath(__file__))
SCANS_PATH = PROJECT_PATH + "/.scans/"
REPORTS_PATH = PROJECT_PATH + "/reports/"

# Second brain configuration
SUPERVISOD_CSV_FILE = 'data/exploits.csv'
SECOND_BRAIN_NAME = 'second_brain'

if not os.path.exists(SCANS_PATH):
    os.mkdir(SCANS_PATH)
if not os.path.exists(REPORTS_PATH):
    os.mkdir(REPORTS_PATH)

EXPLOITS_TREE_PATH = PROJECT_PATH + "/data/" + "exploits_tree.json"

EXFILTRATION_SERVER = "172.17.0.1:8040"
MAX_TESTING_THREADS = 10
SCANNING_THROUGH_TEST = False
TTL_FOR_EXPLOIT_VALIDATION = 15.0

# TODO: remove these lines and use config.EXPLOITS_TREE instead
SERVICE_LIST = 'openssh@dav@login@rpc@php@joomla@http@rmiregistry@krb524@x11@java@bind@domain@tcpwrapped@drupal@postfix@apache@vsftpd@proftpd@telnet@irc@jetty@nginx@unix@tikiwiki@postgresql@ftp@ajp13@vnc@smtp@sambasmbd@upnp@ldap@mysql@phpbb@ubuntu@webmin@samba@oscommerce@ms-wbt-server@exec@rpcbind@moodle@mediawiki@python@phpmyadmin@shell@wordpress@ssh@sugarcrm@netbios-ssn@tomcat@linuxtelnetd'
OS_LIST = 'fortinet@windows@unix@solaris@osx@netware@linux@irix@hpux@freebsd@firefox@dialup@bsdi@apple_ios@android@aix@unknown'

# Cache Search Results
CACHED_SEARCH_RESULTS = {}

# Exploits Tree & Array
EXPLOITS_TREE = []
EXPLOITS_ARRAY = []





# Functions
def getClient():
    MSFRPC_CONFIG = open(PROJECT_PATH + "/config/" + "msfrpc-config.json")

    MSFRPC_CONFIG = json.loads(MSFRPC_CONFIG.read())
    client = None
    try:
        client = MsfRpcClient(MSFRPC_CONFIG["password"],
                              user=MSFRPC_CONFIG["user"],
                              host=MSFRPC_CONFIG["host"],
                              port=MSFRPC_CONFIG["port"],
                              ssl=MSFRPC_CONFIG["ssl"])
    except Exception:
        pass

    return client


def loadExploitsTree(detailed=True):
    exploits_tree = json.loads(open(EXPLOITS_TREE_PATH, "r").read())
    if detailed:
        return exploits_tree
    return [_['exploit'] for _ in exploits_tree]
