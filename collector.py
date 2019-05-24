#!/usr/bin/python
import getopt
import sys, os.path
import logging
import re
# T3
from t3_PyLib.Collector import Collector
from t3_PyLib.Topology import Topology
from t3_PyLib.Logger import LogGlobal

DEFAULT_LOGFILE  = "%s.log" % re.sub(r'.*/', '', re.sub(r'\.py$', '', sys.argv[0])) # filename without path and suffix
DEFAULT_LOGDIR   = "/var/log/collector"
DEFAULT_CACHEDIR = "/var/cache/collector"


#
# Logging

glog = LogGlobal()
logger = glog.getLogger()


#
# Local

def usage():
    usage = """
Usage: %s <option> <value> [<option> ...]
Options:
 Must
    -t|--topo     <file>    topology file
 May
    -c|--cachedir <dir>     collector cache directory
    -l|--logdir   <dir>     log directory
    -d|--debug              debug on
    -h|--help               show this helpful message
"""
    print usage % re.sub(r'.*/', '', sys.argv[0])

def goodbye(exit=0):
    usage()
    sys.exit(exit)


#
# Main

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hdc:vl:vt:v", ["help","debug","cachedir=","logdir=","topo="])
    except getopt.GetoptError:
        logger.critical("Unknown or missing arg(s) to %s" % sys.argv[0])
        goodbye(127)

    debug = False
    cachedir = None
    logdir = None

    for opt, val in opts:
        if opt in ("-h", "--help"):
            goodbye()

        if opt in ("-d", "--debug"):
            debug = True
            continue

        if opt in ("-c", "--cachedir"):
            cachedir = val
            continue

        if opt in ("-l", "--logdir"):
            logdir = val
            continue

        if opt in ("-t", "--topo"):
            topofile = val

    try:
        t = Topology(topofile)
    except NameError:
        logger.critical("No topofile defined, cannot continue")
        goodbye(127)

    if not logdir:   logdir   = DEFAULT_LOGDIR
    if not cachedir: cachedir = DEFAULT_CACHEDIR

    # set logfile
    logger = glog.rebuild("%s/%s" % (re.sub(r'/$', '', logdir), DEFAULT_LOGFILE))

    c = Collector(cachedir=cachedir, logdir=logdir, debug=debug)
    result = c.ingestTopology(t).run()

    sys.exit(0) if result == 1 else sys.exit(result)
