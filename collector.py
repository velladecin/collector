#!/usr/bin/python
import os, sys, re
import pexpect
import pickle, json
import time
from pprint import pprint
# T3
from t3_PyLib import utils

CMTS_BATCH_SIZE = 20
CMTS_CM_AGEING = 8 * 24 * 60 * 60  # 8 days

CMTSCACHEDIR  = 'cmtscache'
CMTSCACHEMAXKEEP = 10
CMTSLOGDIR = 'cmtslogs'
BASEDIR = os.path.dirname(sys.argv[0])
LOG = open('%s.log' % sys.argv[0], 'a', 0)
LOG.write('*** RUN ***** %s *****************************************\n' % utils.now())

def log(logfh, msg, lvl='INFO'):
    logfh.write("%s [%s]  %s\n" % (utils.now(), lvl, msg))

def run_child(cmts):
    pid = os.getpid()
    basedir = BASEDIR
    if not basedir: basedir = '.'

    # log your own shit.. :)
    cmtslog = open('%s/%s/%s.log' % (basedir, CMTSLOGDIR, cmts), 'a', 0)
    log(cmtslog, "Fork() CMTS %s, PID %d" % (cmts, pid))

    uname, passw = utils.get_creds()
    if not uname or not passw:
        log(cmtslog, "Failed retrieving uname/passw", 'CRITICAL')
        sys.exit(1)

    cmtsdict = {}
    cmtscachefile = "%s/%s/%s" % (basedir, CMTSCACHEDIR, cmts)
    cmtscachefilejson = "%s.json" % cmtscachefile

    # We use both pickle + JSON
    # In Python we read-in with pickle but dump both pickle and JSON
    # Reason:
    # 1. make read in python quicker
    # 2. allow for reading of results by Go in JSON - see T3 webservice

    # load existing cache from disk
    if os.path.isfile(cmtscachefile):
        log(cmtslog, "Reading previous collection from file: %s" % cmtscachefile)
        with open(cmtscachefile, "rb") as fh:
            cmtsdict = pickle.loads(fh.read())

    # 'Offline' modems disappear from CMTS after 7 days of inactivity. We want smth similar
    # to happen here too. This is to avoid indefinite modem growth due to tech's hand held
    # devices that move around. (also possibly due to the unlikely modem migrations)
    # Delete any modems older than 8 days.

    # see 'lastseen' below
    now = int(utils.now('%s'))
    for mac in cmtsdict.keys():
        # added feature due to collections having gotten bloated,
        # so start fresh :)
        if not "lastseen" in cmtsdict[mac]:
            del cmtsdict[mac]
            continue

        if not isinstance(cmtsdict[mac]["lastseen"], int):
            cmtsdict[mac]["lastseen"] = int(cmtsdict[mac]["lastseen"])

        if (now - cmtsdict[mac]["lastseen"]) > CMTS_CM_AGEING:
            del cmtsdict[mac]
            
    cmtsprompt = '%s#' % cmts
    passprompt = 'password:'

    try:
        child = pexpect.spawn('ssh {0}@{1}'.format(uname, cmts), timeout=90)
        res = child.expect( [pexpect.TIMEOUT, 'Are you sure you want to continue connecting', passprompt] );

        if res == 0:
            raise Exception("Timeout connecting to CMTS")

        if res == 1: # new CMTS (SSH key)
            child.sendline('yes')
            res = child.expect( [pexpect.TIMEOUT, pass_prompt] )
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

        for line in result.split('\r\n'):
            # 5/7/0-3/7/10      48     8x4   Operational 3.0    12M/1240     0  bcca.b5ff.69b5  fde5:c758:f711:2f:fc63:55cf:fa7d:9992
            if not re.match('\d+/\d+/\d+\-\d+/\d+/\d+', line):
                continue

            # this will (should) yield single output
            reip6 = re.findall('[a-f0-9]+\:[a-f0-9\:]+', line)
            remac = re.findall('[a-f0-9]{4}\.[a-f0-9]{4}\.[a-f0-9]{4}', line)
            if not remac:
                log(cmtslog, "Could not retrieve MAC from: %s" % line, 'WARNING')
                continue

            # STATUS
            #10/2/8-2/1/12     19     16x4  Operational 3.1    25M/5215     0  7823.aea8.376d  fde5:c758:f711:6512:7d0c:5025:efaf:494f
            #10/2/8-2/1/12     19           Offline     3.1                 0  7823.aea8.37b9

            src = re.search('\d+/\d+/\d+\-\d+/\d+/\d+\s+[0-9]+\s+[0-9]+x[0-9]\s+([a-zA-Z]+)\s+[0-9]\.[0-9]', line)  # line 1 above
            if not src:
                src = re.search('\d+/\d+/\d+\-\d+/\d+/\d+\s+[0-9]+\s+([a-zA-Z]+)\s+[0-9]\.[0-9]', line)             # line 2 above

            status = "unknown"
            try:
                status = src.group(1)
            except AttributeError:
                pass

            # FNODE
            n = re.search('\d+/\d+/\d+\-\d+/\d+/\d+\s+([0-9]+)\s+', line)
            node = "unknown"
            try:
                node = n.group(1)
            except AttributeError:
                pass # should not happen

            # CHANNELS, PROFILE
            rechn = re.findall('[0-9]+x[0-9]+', line)
            reprf = re.findall('[0-9]+[K,M]/[0-9]+[K,M]?', line)

            mac = remac[0]
            ip6 = None
            chn = "unknown"
            prf = "unknown"

            if reip6:
                ip6 = reip6[0]
            if rechn:
                chn = rechn[0]
            if reprf:
                prf = reprf[0]

            # If modem not present in collection yet - then it's a new (or returning) modem.
            # We add 'lastseen' key to keep track as to when it was last seen on a CMTS

            if not mac in cmtsdict:
                cmtsdict[mac] = {}
                cmtsdict[mac]["ip"] = []

            cmtsdict[mac]["status"] = status
            cmtsdict[mac]["node"] = node
            cmtsdict[mac]["chans"] = chn
            cmtsdict[mac]["speed"] = prf
            cmtsdict[mac]["lastseen"] = now

            app = False
            if ip6:
                ips = cmtsdict[mac]["ip"]

                # add IP to cache when:
                # 1. no previous ips recorded yet (eg: first run)
                # 2. current ip does not match previous

                # TODO
                # keep times of from when till when IP was in use?

                if ips:
                    # previous vs current IP
                    if ips[-1] != ip6:
                        app = True
                        # remove index 0 if cache limit hit
                        if len(ips) >= CMTSCACHEMAXKEEP: # XXX should we chop to size here??
                            cmtsdict[mac]["ip"] = ips[1:]
                else:
                    app = True

            if app:
                cmtsdict[mac]["ip"].append(ip6)

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
                cmtsdict[m]["fw"] = f
            except KeyError:
                continue

    except Exception, e:
        log(cmtslog, "CMTS %s failed processing with: %s" % (cmts, str(e)), 'CRITICAL')

    #pprint(cmtsdict)
    #sys.exit(0)

    # dump result to file
    log(cmtslog, "Dumping collection result to file (pickle): %s" % cmtscachefile)
    with open(cmtscachefile, "wb") as fh:
        pickle.dump(cmtsdict, fh)

    log(cmtslog, "Dumping collection result to file (json): %s" % cmtscachefilejson)
    with open(cmtscachefilejson, "w") as fh:
        json.dump(cmtsdict, fh)

    cmtslog.close()
    sys.exit(0)

def cmts_collection(allcmts):
    count = 0
    for cmts in allcmts:
        try:
            pid = os.fork()
        except OSError:
            log(LOG, "Could not fork() %s" % cmts, "CRITICAL")
            continue

        # child
        if pid == 0:
            run_child(cmts)

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

if __name__ == "__main__":
    try:
        res = main(sys.argv)
        if res == 1:
            sys.exit(0)

        sys.exit(res)
    except Exception, e:
        print str(e)
        sys.exit(1)
