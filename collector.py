#!/usr/bin/python
import os, os.path
import sys, re
import getopt, pexpect
import pickle, json
import time, signal
from pprint import pprint
from datetime import datetime
# T3
import t3_PyLib.Logger
from t3_PyLib import Utils
from t3_PyLib.Topology import Topology
from t3_PyLib.Ssh import Ssh

CMTSCACHEDIR  = 'cmtscache'
CMTSCACHEIPPOOL = 10
CMTSLOGDIR = 'cmtslogs'
BASEDIR = os.path.dirname(sys.argv[0])

Log = t3_PyLib.Logger.Log('%s.log' % sys.argv[0])
Log.info('********** Starting Collection Run ***********')

def unshift(arr, val):
    if not type(val) is list:
        val = [val]

    val.extend(arr)
    return val

def run_child(cmts):
    pid = os.getpid()
    basedir = BASEDIR
    if not basedir: basedir = '.'

    # log your own shit.. :)
    Cmtslog = t3_PyLib.Logger.Log('%s/%s/%s.log' % (basedir, CMTSLOGDIR, cmts))
    Cmtslog.info("Fork() CMTS %s, PID %d" % (cmts, pid))

    cmtscachefile = "%s/%s/%s" % (basedir, CMTSCACHEDIR, cmts)
    cmtscachefilejson = "%s.json" % cmtscachefile
    cmtscachefilejsontmp = "%s.json.tmp" % cmtscachefile

    # We use both pickle + JSON
    # In Python we read-in with pickle but dump both pickle and JSON
    # Pickle is only used to track last IPs (up to 5) per each CM
    # Reason:
    # 1. make read in python quicker
    # 2. allow for reading of results by Go in JSON - see T3 webservice
    pickledict = {}
    finaldict = {} # this is our result

    # load existing cache from disk
    if os.path.isfile(cmtscachefile):
        Cmtslog.info("Reading previous collection from file: %s" % cmtscachefile)
        with open(cmtscachefile, "rb") as fh:
            pickledict = pickle.loads(fh.read())

    # each child gets their own creds
    # so in theory (when creds change) the next bach will succeed

    ssh = Ssh()
    if not ssh.loginCmts_NoHostCheck(cmts):
        Cmtslog.crit("Could not log in to CMTS %s" % cmts)
        sys.exit(1)

    ##
    ## 1. collect CM details

    # After long testing it seems that the best option is to simply collect what's currently on the CMTS.
    # Discard anything that has disappeared. This will lose some historical data for eg ppl who are on holidays,
    # but currently it seems to be the best option. (do I hear.. doh?)

    for line in ssh.cmdCmts('show cable modem', 120):
        # 1) 5/7/0-3/7/10      48     8x4   Operational 3.0    12M/1240     0  bcca.b5ff.69b5  fde5:c758:f711:2f:fc63:55cf:fa7d:9992
        # 2) 10/2/8-2/1/12     19     16x4  Operational 3.1    25M/5215     0  7823.aea8.376d  fde5:c758:f711:6512:7d0c:5025:efaf:494f
        # 3) 11/2/14-1/7/12    11     16x4  Online-d    3.1                 0  203d.66ae.f34d  fd29:b4b0:cf0c:c10a:9142:e3c:3170:3f62
        # 4) 10/2/8-2/1/12     19           Offline     3.1                 0  7823.aea8.37b9
        if not re.match('\d+/\d+/\d+\-\d+/\d+/\d+', line):
            continue

        # this will (should) yield single output
        reip6 = re.findall('[a-f0-9]+\:[a-f0-9\:]+', line)
        remac = re.findall('[a-f0-9]{4}\.[a-f0-9]{4}\.[a-f0-9]{4}', line)
        if not remac:
            Cmtslog.warn("Could not retrieve MAC from: %s" % line)
            continue

        # STATUS
        src = re.search('\d+/\d+/\d+\-\d+/\d+/\d+\s+[0-9]+\s+[0-9]+x[0-9]\s+([a-zA-Z\-]+)\s+[0-9]\.[0-9]', line)    # line 1, 2, 3  (Operational, Online-d)
        if not src:
            src = re.search('\d+/\d+/\d+\-\d+/\d+/\d+\s+[0-9]+\s+([a-zA-Z]+)\s+[0-9]\.[0-9]', line)                 # line 4        (Offline)

        try:
            status = src.group(1)
        except AttributeError:
            status = "unknown"

        # FNODE
        n = re.search('\d+/\d+/\d+\-\d+/\d+/\d+\s+([0-9]+)\s+', line)

        try:
            node = n.group(1)
        except AttributeError:
            node = "unknown" # should not happen

        # CHANNELS, PROFILE
        rechn = re.findall('[0-9]+x[0-9]+', line)
        reprf = re.findall('[0-9]+[K,M]/[0-9]+[K,M]?', line)

        mac = remac[0]
        ip6 = None
        chn = "unknown"
        prf = "unknown"

        if reip6: ip6 = reip6[0]
        if rechn: chn = rechn[0]
        if reprf: prf = reprf[0]

        if not mac in finaldict: # is this really necessary?
            finaldict[mac] = {}

        finaldict[mac]["status"] = status
        finaldict[mac]["node"] = node
        finaldict[mac]["chans"] = chn
        finaldict[mac]["speed"] = prf

        # get current IP (if any)
        ips = []
        if not mac in pickledict:
            pickledict[mac] = {}

        if "ip" in pickledict[mac]:
            ips.extend(pickledict[mac]["ip"])

        # action this only:
        # 1. when current IP available
        # 2. current IP differs from last recorded one

        if ip6:
            ip6 = ip6.rstrip() # strip \r\n

            if ips:
                if ip6 != ips[0]: # current vs last
                    # keep IP pool size
                    if len(ips) == CMTSCACHEIPPOOL:
                        ips = ips[:-1]

                    ips = unshift(ips, ip6)
            else:
                ips.append(ip6)

        # assign result
        finaldict[mac]["ip"] = ips
        pickledict[mac]["ip"] = ips


    ##
    ## 2. collect FW version

    for line in ssh.cmdCmts('show cable modem system-description', 120):
        #5/7/0-3/7/8       fde5:c758:f711:2f:1c74:53c2:21a1:7b40   7823.aeab.ca75 Scan-A <<HW_REV: 4; VENDOR: ARRIS Group, Inc.; BOOTR: 2700; SW_REV: nbnD31CM-FALCON-1.0.0.1-GA-10-NOSH; MODEL: CM8200B>>
        #5/7/0-3/7/6                                               909d.7d80.b6f9 Scan-A <<HW_REV: 4; VENDOR: ARRIS Group, Inc.; BOOTR: 2700; SW_REV: nbnCM8200.0200.174F.311438.NSH.NB.EU; MODEL: CM8200B>>
        #5/7/0-3/7/11      fde5:c758:f711:2f:f12f:122e:5a81:f1f    909d.7d80.b7dd Scan-A <<HW_REV: 4; VENDOR: ARRIS Group, Inc.; BOOTR: 2700; SW_REV: nbnCM8200.0200.174F.311438.NSH.NB.EU; MODEL: CM8200B>>
        #5/7/8-3/7/10      fde5:c758:f711:2f:ed0b:b54f:4fdd:86f4   90c7.92fa.3d41 ARRIS EuroDOCSIS 3.0 Touchstone WideBand Cable Modem <<HW_REV: 1; VENDOR: Arris Interactive, L.L.C.; BOOTR: 1.2.1.62; SW_REV: nbn9.1.103P7; MODEL: CM820B/AU>>
        #5/2/6-3/5/2                                               0007.1117.fea8 Viavi Solutions ONX DOCSIS 3.1 <<HW_REV: V1.0 US; VENDOR: Viavi Solutions; BOOTR: V1.0; SW_REV: V1.0; MODEL: onxdocsis31>>
        if not re.match('\d+/\d+/\d+\-\d+/\d+/\d+', line):
            continue

        # this will (should) yield single output
        refwmac = re.findall('[a-f0-9]{4}\.[a-f0-9]{4}\.[a-f0-9]{4}', line)
        refwver = re.findall('<<.*>>', line)

        if not refwmac:
            Cmtslog.warn("Could not retrieve FW MAC from: %s" % line)
            continue
        if not refwver:
            Cmtslog.warn("Could not retrieve FW ver from: %s" % line)
            continue

        m = refwmac[0]
        f = refwver[0]

        # this should always succeed
        try:
            finaldict[m]["fw"] = f
        except KeyError:
            Cmtslog.warn("Could not find MAC %s in finaldictionary[...]" % m)
            continue

    ssh.close()

    #pprint(pickledict)
    #pprint(finaldict)

    # dump result to files
    Cmtslog.info("Dumping collection result to file (pickle): %s" % cmtscachefile)
    with open(cmtscachefile, "wb") as fh:
        pickle.dump(pickledict, fh)

    # At times the T3 webservice cannot parse the JSON file (JSON invalid - missing end of file) which is due
    # to race condition here. Try to avoid it by dumping into a .tmp file and then renaming.
    Cmtslog.info("Dumping collection result to file (json): %s" % cmtscachefilejsontmp)
    with open(cmtscachefilejsontmp, "w") as fh:
        json.dump(finaldict, fh)

    Cmtslog.info("Renaming '%s' to '%s' to finalize collection" % (cmtscachefilejsontmp, cmtscachefilejson))
    os.rename(cmtscachefilejsontmp, cmtscachefilejson)

    Cmtslog.close()
    sys.exit(0)

def cmts_collection(cmtsbatch):
    for cmts in cmtsbatch:
        try:
            pid = os.fork()
        except OSError:
            Log.crit("Could not fork() %s" % cmts)
            continue

        # child
        if pid == 0:
            run_child(cmts)

        Log.info("Fork() CMTS %s, PID %d" % (cmts, pid))

    for _ in range(len(cmtsbatch)):
        finished = os.waitpid(0, 0)
        msg = "Reaped child PID %d, exit status %d" % finished
        Log.info(msg) if finished[1] == 0 else Log.warn(msg)

    return 1

def main(params):
    try:
        opts, args = getopt.getopt(params[1:], "hdt:v", ["help","debug","topo="])
    except getopt.GetoptError as e:
        print str(e)
        usage(params[0])
        sys.exit(127)

    topofile = None
    debug = False
    for opt, val in opts:
        if opt in ("-h", "--help"):
            usage(params[0])
            sys.exit(0)

        if opt in ("-d", "--debug"):
            debug = True
            continue

        if opt in ("-t", "--topo"):
            topofile = val

    if not topofile:
        Log.crit("No topology file supplied")
        usage(params[0])
        sys.exit(127)

    t = Topology(topofile, debug)

    allcmts = t.getCmts()
    #allcmts = ['SWCMT0000282', 'SWCMT0000283']

    # We expect ~300 CMTS in total.
    # Limit max number of CMTS batches to 10 per itiration.
    # Log if batch size goes over 30 CMTS as things may need to be re-thought.
    if len(allcmts) > 300:
        Log.warn("Hitting limit of 300+ CMTS - this may cause some problems and will need attention!")

    ITIRATION_LIMIT = 10

    cmts_batch_size = int(len(allcmts) / ITIRATION_LIMIT)
    cmts_batch_mod = len(allcmts) % ITIRATION_LIMIT

    if cmts_batch_mod > 0:
        cmts_batch_size = cmts_batch_size + 1

    batch = []
    for i in range(0, len(allcmts)):
        if (i % cmts_batch_size) == 0 and i != 0:
            Log.info(">>> Running CMTS batch with %d CMTS (%s)" % (len(batch), batch))
            cmts_collection(batch)
            batch = []

        batch.append(allcmts[i])

    if len(batch):
        Log.info(">>> Running last CMTS batch with %d CMTS (%s)" % (len(batch), batch))
        cmts_collection(batch)

    return 1

def usage(self):
    usage = """
Usage: {0} <option> <value> [<option> ...]
Options:
 Must
    -t|--topo <file>    topology file
 May
    -d|--debug          debug on
    -h|--help           show this helpful message
""".format(self)

    print usage

## TODO this needs fixing!!!
def ctrlc_handler(signum, frame):
    print "\nCaught CTRL+C, leaving at user's request.."
    time.sleep(.5)
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, ctrlc_handler)

    try:
        res = main(sys.argv)
        if res == 1:
            sys.exit(0)

        sys.exit(res)
    except Exception, e:
        print str(e)
        sys.exit(1)
