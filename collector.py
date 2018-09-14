#!/usr/bin/python
import os, sys, re
import pexpect
import pickle, json
import time, signal
from pprint import pprint
# T3
from t3_PyLib import utils

CMTS_BATCH_SIZE = 20

CMTSCACHEDIR  = 'cmtscache'
CMTSCACHEIPPOOL = 10
CMTSLOGDIR = 'cmtslogs'
BASEDIR = os.path.dirname(sys.argv[0])
LOG = open('%s.log' % sys.argv[0], 'a', 0)
LOG.write('*** RUN ***** %s *****************************************\n' % utils.now())

def log(logfh, msg, lvl='INFO'):
    logfh.write("%s [%s]  %s\n" % (utils.now(), lvl, msg))

def unshift(arr, val):
    r = [val]
    r.extend(arr)
    return r

def run_child(cmts, uname, passw):
    pid = os.getpid()
    basedir = BASEDIR
    if not basedir: basedir = '.'

    # log your own shit.. :)
    cmtslog = open('%s/%s/%s.log' % (basedir, CMTSLOGDIR, cmts), 'a', 0)
    log(cmtslog, "Fork() CMTS %s, PID %d" % (cmts, pid))

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
        log(cmtslog, "Reading previous collection from file: %s" % cmtscachefile)
        with open(cmtscachefile, "rb") as fh:
            pickledict = pickle.loads(fh.read())

    cmtsprompt = '%s#' % cmts
    passprompt = 'password:'

    now = int(utils.now('%s'))
    try:
        child = pexpect.spawn('ssh {0}@{1}'.format(uname, cmts), timeout=90)
        res = child.expect( [pexpect.TIMEOUT, 'Are you sure you want to continue connecting', passprompt] );

        if res == 0:
            raise Exception("Timeout connecting to CMTS")

        if res == 1: # new CMTS (SSH key)
            child.sendline('yes')
            res = child.expect( [pexpect.TIMEOUT, passprompt] )
            if res == 0:
                raise Exception("Timeout accepting new SSH key")

        child.sendline(passw)
        child.expect(cmtsprompt)

        child.sendline("show cable modem")
        child.expect(cmtsprompt)

        result = child.before
        #pprint(result)

        ##
        ## 1. collect CM details

        # After long testing it seems that the best option is to simply collect what's currently on the CMTS.
        # Discard anything that has disappeared. This will lose some historical data for eg ppl who are on holidays,
        # but currently it seems to be the best option. (do I hear.. doh?)

        for line in result.split('\r\n'):
            # 5/7/0-3/7/10      48     8x4   Operational 3.0    12M/1240     0  bcca.b5ff.69b5  fde5:c758:f711:2f:fc63:55cf:fa7d:9992
            # 10/2/8-2/1/12     19     16x4  Operational 3.1    25M/5215     0  7823.aea8.376d  fde5:c758:f711:6512:7d0c:5025:efaf:494f
            # 10/2/8-2/1/12     19           Offline     3.1                 0  7823.aea8.37b9
            if not re.match('\d+/\d+/\d+\-\d+/\d+/\d+', line):
                continue

            # this will (should) yield single output
            reip6 = re.findall('[a-f0-9]+\:[a-f0-9\:]+', line)
            remac = re.findall('[a-f0-9]{4}\.[a-f0-9]{4}\.[a-f0-9]{4}', line)
            if not remac:
                log(cmtslog, "Could not retrieve MAC from: %s" % line, 'WARNING')
                continue

            # STATUS
            src = re.search('\d+/\d+/\d+\-\d+/\d+/\d+\s+[0-9]+\s+[0-9]+x[0-9]\s+([a-zA-Z]+)\s+[0-9]\.[0-9]', line)  # line 1, 2 above
            if not src:
                src = re.search('\d+/\d+/\d+\-\d+/\d+/\d+\s+[0-9]+\s+([a-zA-Z]+)\s+[0-9]\.[0-9]', line)             # line 3 above

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
                    if ip6 != ips[-1]: # current vs last
                        # keep IP pool size
                        if len(ips) == CMTSCACHEIPPOOL:
                            ips = ips[:-1]

                        ips = unshift(ips, ip6)
                else:
                    ips.append(ip6)

            # assign result
            finaldict[mac]["ip"] = ips
            pickledict[mac]["ip"] = ips

        #pprint(finaldict)

        ##
        ## 2. collect FW version

        child.sendline("show cable modem system-description")
        child.expect(cmtsprompt)

        fwresult = child.before
        #pprint(fwresult)

        for line in fwresult.split('\r\n'):
            #10/2/8-2/1/12     fde5:c758:f711:6512:a991:eef9:bdd7:edf2 b093.5baa.a13d Scan-A <<HW_REV: 4; VENDOR: ARRIS Group, Inc.; BOOTR: 2700; SW_REV: nbnD31CM-FALCON-1.0.0.1-GA-10-NOSH; MODEL: CM8200B>>
            if not re.match('\d+/\d+/\d+\-\d+/\d+/\d+', line):
                continue

            # this will (should) yield single output
            refwmac = re.findall('[a-f0-9]{4}\.[a-f0-9]{4}\.[a-f0-9]{4}', line)
            refwver = re.findall('<<.*>>', line)

            if not refwmac:
                log(cmtslog, "Could not retrieve FW MAC from: %s" % line, 'WARNING')
                continue
            if not refwver:
                log(cmtslog, "Could not retrieve FW ver from: %s" % line, 'WARNING')
                continue

            m = refwmac[0]
            f = refwver[0]

            # this should always succeed
            try:
                finaldict[m]["fw"] = f
            except KeyError:
                continue

    except Exception, e:
        log(cmtslog, "CMTS %s failed processing with: %s" % (cmts, str(e)), 'CRITICAL')

    #pprint(pickledict)
    #pprint(finaldict)
    #sys.exit(0)

    # dump result to files
    log(cmtslog, "Dumping collection result to file (pickle): %s" % cmtscachefile)
    with open(cmtscachefile, "wb") as fh:
        pickle.dump(pickledict, fh)

    # At times the T3 webservice cannot parse the JSON file (JSON invalid - missing end of file) which is due
    # to race condition here. Try to avoid it by dumping into a .tmp file and then renaming.
    log(cmtslog, "Dumping collection result to file (json): %s" % cmtscachefilejsontmp)
    with open(cmtscachefilejsontmp, "w") as fh:
        json.dump(finaldict, fh)

    log(cmtslog, "Renaming '%s' to '%s' to finalize collection" % (cmtscachefilejsontmp, cmtscachefilejson))
    os.rename(cmtscachefilejsontmp, cmtscachefilejson)

    cmtslog.close()
    sys.exit(0)

def cmts_collection(allcmts):
    # Retrieve creds here to allow for creds change mid-flight.
    # (not to lose the full run)
    uname, passw = utils.get_creds()
    if not uname or not passw:
        log(LOG, "Failed retrieving uname/passw", 'CRITICAL')
        sys.exit(1)

    count = 0
    for cmts in allcmts:
        try:
            pid = os.fork()
        except OSError:
            log(LOG, "Could not fork() %s" % cmts, "CRITICAL")
            continue

        # child
        if pid == 0:
            run_child(cmts, uname, passw)

        log(LOG, "Fork() CMTS %s, PID %d" % (cmts, pid))
        count += 1

    for count in range(len(allcmts)):
        finished = os.waitpid(0, 0)
        log(LOG, "Reaped child PID %d, exit status %d" % finished)

    return 1

def main(params):
    allcmts = utils.get_cmts_list().keys()
    #allcmts = ['SWCMT0000221']
    #allcmts = ['SWCMT0000019']
    #allcmts = [ 'SWCMT0000164']
    #allcmts = [ 'SWCMT0000279' ]

    # we assume we have ~300 CMTS in total
    # split them by CMTS_BATCH_SIZE

    start = 0
    end = 0
    while True:
        end += CMTS_BATCH_SIZE
        start = end - CMTS_BATCH_SIZE 

        try:
            if allcmts[end]:
                cmts_collection(allcmts[start:end])
        except IndexError:
            cmts_collection(allcmts[start:])
            break

        # since we wait and collect our children in cmts_collection
        # this is 1 sec wait since the finish of last child in batch
        time.sleep(1)

    return 1

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
