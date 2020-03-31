#!/usr/bin/python
import os, os.path
import errno
import logging
import re, sys
import pickle, json
from pprint import pprint
# T3
from t3_PyLib.Topology import Topology
from t3_PyLib.Cmts import *
from t3_PyLib.Ssh import *

logger = logging.getLogger(__name__)


class Collector:

    DEFAULT_IPPOOL_SIZE = 10

    def __init__(self, cachedir, logdir, cmts=None, debug=False):
        # incoming cmts can be a list or a string
        # self.cmts must be a list
        self.cachedir   = cachedir
        self.logdir     = logdir
        self.logcmtsdir = "%s/cmts" % self.logdir
        self.debug      = debug
        self.creds      = FileCreds()   # Should this be more "dynamic"?
                                        # As collector runs from cron this would pick up creds update on each run..
        if cmts:
            if   isinstance(cmts, str):  self.cmts = [cmts]
            elif isinstance(cmts, list): self.cmts =  cmts
            else:
                logger.critical("CMTS argument for Collector must be either string or list (got %s)" % type(cmts))
                sys.exit(127)

        # cache
        self.pickledict = {}

        for d in [ self.cachedir, self.logdir, self.logcmtsdir ]:
            try:
                os.makedirs(d)
                logger.info("Make dir: %s" % d)
            except OSError as e:
                if e.errno == errno.EEXIST and os.path.isdir(d):
                    logger.debug("Found dir: %s" % d)
                    pass
                else:
                    raise


    #
    # Public
    # only these (until Private) are to be called directly!
    # Well, protected are also acceptable.. sort of :)

    def ingestTopology(self, topo):
        assert isinstance(topo, Topology)

        try:
            if self.cmts:
                logger.warn("Overwriting existing CMTS' names - ingesting topology")
        except AttributeError:
            pass

        self.cmts = topo.getCmts()
        #self.cmts = [ 'SWCMT0000120' ]

        return self

    def run(self):
        logger.info("==>>> run()ning collection")

        # We expect max 300 CMTS in total. Limit number of CMTS batches to Itiration_Limit per run.
        # Log if batch size goes over 30 CMTS as things may need to be re-thought.

        try:
            cmtscount = len(self.cmts)
        except NameError:
            logger.critical("No CMTS specified for collection - nothing to do")
            sys.exit(127)

        if cmtscount > 300:
            logger.warn("Total # of CMTS is %d, which is %d more than expected" % (cmtscount, (cmtscount - 300)))
            logger.warn("This may require revision and rethink on CMTS batching.")

        ITIRATION_LIMIT = 10
        cmts_batch_size = int(cmtscount / ITIRATION_LIMIT)

        if (cmtscount % ITIRATION_LIMIT) > 0:
            cmts_batch_size = cmts_batch_size + 1

        batchcount = 1
        for i in range(0, cmtscount, cmts_batch_size):
            start = i
            end = start + cmts_batch_size

            logger.info("Running batch #%d with %d CMTS' (%s)" % (batchcount, len(self.cmts[start:end]), self.cmts[start:end]))
            self.__batchCollection(self.cmts[start:end])

            batchcount = batchcount + 1


    #
    # Protected

    def _cmtsinfo(self, msg): self.__cmtslog('INFO', msg)
    def _cmtswarn(self, msg): self.__cmtslog('WARN', msg)
    def _cmtscrit(self, msg): self.__cmtslog('CRIT', msg)
        

    #
    # Private

    def __batchCollection(self, batch):
        forked = 0
        for cmts in batch:
            try:
                pid = os.fork()
                forked = forked + 1
            except OSError:
                logger.critical("Could not fork() %s" % cmts)
                continue

            # child
            if pid == 0:
                self.__runChild(cmts)
            else:
                logger.info("Fork() CMTS %s, PID %d" % (cmts, pid))

        for _ in range(forked):
            finished = os.waitpid(0, 0)
            msg = "Reaped child PID %d, exit status %d" % finished
            logger.info(msg) if finished[1] == 0 else logger.warning(msg)

        return 1

    def __runChild(self, cmts):
        pid = os.getpid()

        # custom logger per CMTS
        # bit ugly..?
        from t3_PyLib.Logger import Log
        log = Log("%s/%s.log" % (self.logcmtsdir, cmts))
        self.cmtslog = log

        self._cmtsinfo("Running child: %s, pid %d" % (cmts, pid))

        cmtscachefile     = "%s/%s"             % (self.cachedir, cmts)
        cmtscachefilejson = "%s.json"           % cmtscachefile
        ipv6gwcachefile   = "%s/%s.ipv6gw.json" % (self.cachedir, cmts)
        fncachefile       = "%s/%s.fn.json"     % (self.cachedir, cmts)
        ofdmacachefile    = "%s/%s.ofdma.json"  % (self.cachedir, cmts)
        ofdmcachefile     = "%s/%s.ofdm.json"   % (self.cachedir, cmts)

        # We use both pickle & JSON - read-in cache with pickle and dump both pickle and JSON.
        # Cache is really only used for tracking IPs history per CM.
        # 1. make reading of disk cache quicker with Pickle
        # 2. read results by Go in JSON - see T3 webservice

        try:
            # load disk cache
            with open(cmtscachefile, "rb") as f:
                self.pickledict = pickle.loads(f.read())
        except IOError: 
            pass
        except ValueError:
            print("Could not load pickle file for %s" % cmts)
            self._cmtscrit("Could not load pickle file for %s" % cmts)

        swcmt = self.__initCmts(cmts)
        if not swcmt:
            #print ">>>>>>>>>> No login to CMTS: %s" % cmts
            self._cmtscrit("Could not login to CMTS: %s" % cmts)
            os._exit(0)

        # After long testing it seems that the best option is to simply collect what's currently on the CMTS.
        # Discard anything that has disappeared. This will lose some data for eg ppl who are on holidays (7 day caching on CMTS),
        # but currently it seems to be the best option. (do I hear.. doh?)

        # get ready 'common' stuff
        # will select from these when scm is running
        self.__ipv6routingelements(swcmt)
        self.__scfn(swcmt)
        # OFDM/A
        self.__ofdma(swcmt)
        self.__ofdm(swcmt)

        # scm is the base
        self.__scm(swcmt)
        # append FW version
        self.__sysdescr(swcmt)

        #pprint(self.scm)
        #pprint(self.pickledict)

        # close connection
        swcmt.disconnect()

        # dump result to files
        # 1. pickle
        # 2. JSON

        self._cmtsinfo("Dumping collection result to file (pickle): %s" % cmtscachefile)
        with open(cmtscachefile, "wb") as fh:
            pickle.dump(self.pickledict, fh)

        for combo in (["scm", cmtscachefilejson], ["ipv6gw", ipv6gwcachefile], ["fn", fncachefile], ["ofdm", ofdmcachefile], ["ofdma", ofdmacachefile]):
            type, filename = combo

            try:
                self.__dumpToJson(type, filename)
            except (ValueError, AttributeError) as e:
                # ValueError is raised by me
                # AttributeError could be raised by missing self.{scm,ipv6gw,fn,..}
                self._cmtscrit("JSON file dump failed with: %s" % str(e))

        os._exit(0)

    def __dumpToJson(self, type, filename):
        if type == "scm":       dict = self.scm
        elif type == "ipv6gw":  dict = self.ipv6gw
        elif type == "fn":      dict = self.fn
        elif type == "ofdma":   dict = self.ofdma
        elif type == "ofdm":    dict = self.ofdm
        else:                   raise ValueError("Unknown type name: '%s'" % type)

        # At times the t3.service cannot parse the JSON file (JSON invalid - missing end of file) which is due to race condition here.
        # Try to mitigate it as much as possible by dumping into a .tmp file and then renaming.

        filenametmp = "%s.tmp" % filename
        with open(filenametmp, "w") as fh:
            json.dump(dict, fh)

        self._cmtsinfo("Renaming '%s' to '%s' to finalize collection" % (filenametmp, filename))
        os.rename(filenametmp, filename)

    def __initCmts(self, cmts):
        try:
            swcmt = Cmts(cmts, 0, self.creds)
        except (CmtsBadName, CmtsLoginFail):
            swcmt = None

        return swcmt
            

    #
    # Actual collecting

    def __ofdm(self, swcmt):
        self.ofdm = {}

        for line in swcmt.executeCmd("show interface cable-downstream ds-type ofdm"):
            #OFDM Channels:
            #DS         Cable Chan Prim  Oper   Freq Low-High   PLC Band   LicBW    Num of  Subcarrier    Rolloff Cyclic  Intrlv
            #S/C/CH     Mac   ID   Cap   State   (MHz.KHz)        (MHz)    (MHz)     Prof   Spacing(KHz)  Period  Prefix  Depth(time)
            #5/0/32       41   33  False   IS  762.000-858.000     763      94        4          50         256    512     4
            #5/1/32       42   33  False   IS  762.000-858.000     763      94        4          50         256    512     4
            #12/7/32       8   33  False   IS  762.000-858.000     763      94        4          50         256    512     4

            if not re.match('\d+/\d+/\d+', line):
                continue

            dets = re.findall('\d+/\d+/\d+\s+(\d+)\s+\d+\s+[A-Za-z]+\s+[A-Z]+\s+([0-9\.\-]+)\s+', line)

            try:
                cablemac, freq = dets[0]
            except ValueError:
                self._cmtswarn("OFDM - could not retrive cable-mac and/or frequency from: %s" % line)
            else:
                swcmtname = swcmt.getName()

                try:
                    self.ofdm[swcmtname]
                except KeyError:
                    self.ofdm[swcmtname] = {}

                self.ofdm[swcmtname][cablemac] = freq

    def __ofdma(self, swcmt):
        self.ofdma = {}

        for line in swcmt.executeCmd("show interface cable-upstream us-type ofdma"):
            #OFDMA Channels:
            #US          Cable     Oper    Freq Low-High    LicBW   Minislots  Mod  Subcarrier   Rolloff Cyclic Sym/  Rx Power(dBmV)
            #S/CG/CH     Mac  Conn State    (MHz.KHz)      (100KHz) per frame  Prof Spacing(KHz) Period  Prefix Frame (6.4MHz Norm)
            #1/5/25        8    11    IS  14.600-25.800     112        28        1       50         96    192      16         0

            if not re.match('\d+/\d+/\d+', line):
                continue

            dets = re.findall('\d+/\d+/\d+\s+(\d+)\s+\d+\s+[A-Za-z]+\s+([0-9\.\-]+)\s+', line)

            try:
                cablemac, freq = dets[0]
            except ValueError:
                self._cmtswarn("OFDM-A - could not retrive cable-mac and/or frequency from: %s" % line)
            else:
                swcmtname = swcmt.getName()

                try:
                    self.ofdma[swcmtname]
                except KeyError:
                    self.ofdma[swcmtname] = {}

                self.ofdma[swcmtname][cablemac] = freq

    def __sysdescr(self, swcmt):
        self.sysdescr = {}

        for line in swcmt.executeCmd("show cable modem system-description", 180):
            #5/7/0-3/7/8       fde5:c758:f711:2f:1c74:53c2:21a1:7b40   7823.aeab.ca75 Scan-A <<HW_REV: 4; VENDOR: ARRIS Group, Inc.; BOOTR: 2700; SW_REV: nbnD31CM-FALCON-1.0.0.1-GA-10-NOSH; MODEL: CM8200B>>
            #5/7/0-3/7/6                                               909d.7d80.b6f9 Scan-A <<HW_REV: 4; VENDOR: ARRIS Group, Inc.; BOOTR: 2700; SW_REV: nbnCM8200.0200.174F.311438.NSH.NB.EU; MODEL: CM8200B>>
            #5/2/6-3/5/2                                               0007.1117.fea8 Viavi Solutions ONX DOCSIS 3.1 <<HW_REV: V1.0 US; VENDOR: Viavi Solutions; BOOTR: V1.0; SW_REV: V1.0; MODEL: onxdocsis31>>

            if not re.match('\d+/\d+/\d+\-\d+/\d+/\d+', line):
                continue

            # this will (should) yield single output
            refwmac = re.findall('[a-f0-9]{4}\.[a-f0-9]{4}\.[a-f0-9]{4}', line)
            refwver = re.findall('<<.*>>', line)

            if not refwmac:
                self._cmtswarn("Could not retrieve FW MAC from: %s" % line)
                continue

            if not refwver:
                self._cmtswarn("Could not retrieve FW ver from: %s" % line)
                continue

            m = refwmac[0]
            f = refwver[0]

            try:
                self.sysdescr[m] = unicode(f, errors="strict")
            except UnicodeDecodeError:
                self._cmtswarn("Could not decode FW '%s' (%s)" % (f, m))
                self.sysdescr[m] = "<<COULD_NOT_DECODE>>"

            # any MAC that produces sysdescr on the cmts
            # should already be in self.scm, but... :)
            try:
                self.scm[m]["fw"] = self.sysdescr[m]
            except KeyError:
                continue

    def __scm(self, swcmt):
        # this is the 'base' of the collection
        # pickle and final dictionaries are build here
        self.scm = {}

        for line in swcmt.executeCmd("show cable modem", 180):
            line = line.rstrip() # \r\n

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
                self._cmtswarn("Could not retrieve MAC from: %s" % line)
                continue

            # STATUS
            try:
                status = re.search('\d+/\d+/\d+\-\d+/\d+/\d+\s+[0-9]+\s+[0-9]+x[0-9]\s+([a-zA-Z\-]+)\s+[0-9]\.[0-9]', line).group(1)  # line 1, 2, 3 (above)
            except AttributeError:
                try:
                    status = re.search('\d+/\d+/\d+\-\d+/\d+/\d+\s+[0-9]+\s+([a-zA-Z]+)\s+[0-9]\.[0-9]', line).group(1)               # line 4 (above)
                except AttributeError:
                    status = "unknown"
                
            # FNODE
            try:
                node = re.search('\d+/\d+/\d+\-\d+/\d+/\d+\s+([0-9]+)\s+', line).group(1)
            except AttributeError:
                node = [ "unknown" ] # should not happen
            else:
                try:
                    nodestring = self.fn[node]
                except KeyError:
                    nodestring = "unknown"

                node = [ node, nodestring ]

            # CHANNELS, PROFILE
            rechn = re.findall('[0-9]+x[0-9]+', line)
            reprf = re.findall('[0-9]+[K,M]/[0-9]+[K,M]?', line)

            mac = remac[0]
            # For whatever reason "ip6" stays defined with previous mac's IP (python bug?? and possibly the other values too..)
            # and so we need to make sure to declare it for the logic further below.. :/
            ip6 = "unknown"
            chn = "unknown"
            prf = "unknown"


            if reip6: ip6 = reip6[0]
            if rechn: chn = rechn[0]
            if reprf: prf = reprf[0]

            if not mac in self.scm:
                self.scm[mac] = {}

            self.scm[mac]["status"] = status
            self.scm[mac]["node"] = node
            self.scm[mac]["chans"] = chn
            self.scm[mac]["speed"] = prf
            self.scm[mac]["ip"] = [ip6]

            # Merge IPs from disk/pickle cache + current IP, pickle dict exists from __runChild()

            # Logic:
            # self.scm[mac]["ip"] already exists, the only KeyError can be on non-existent self.pickledict[mac], or [mac]["ip"]
            # if that's the case then just move on as self.scm will cover pickle + JSON later

            try:
                cacheips = self.pickledict[mac]["ip"]
            except KeyError:
                cacheips = [] # eg: new modem

            if self.scm[mac]["ip"] and cacheips:
                # 1. compare old/new - do nothing if same
                if self.scm[mac]["ip"][0] != cacheips[0]:
                    # 2. check IP cache size
                    cacheips = cacheips[:self.DEFAULT_IPPOOL_SIZE-1]
                    # 3. update cache
                    cacheips = self.scm[mac]["ip"] + cacheips
            elif self.scm[mac]["ip"] and not cacheips:
                cacheips = self.scm[mac]["ip"]
            # any other "else" leaves cacheips unchanged

            # assign result
            # current
            self.scm[mac]["ip"] = cacheips
            # cache
            try:
                self.pickledict[mac]["ip"] = cacheips
            except KeyError:
                self.pickledict[mac] = {}
                self.pickledict[mac]["ip"] = cacheips

            # add routing element / ipv6 gateway
            try:
                self.scm[mac]["ipv6gw"] = self.ipv6gw[node[0]]
            except KeyError:
                self.scm[mac]["ipv6gw"] = "Missing"

        return 1

    def __ipv6routingelements(self, swcmt):
        self.ipv6gw = {}

        for line in swcmt.executeCmd("show running-config verbose | include ipv6 address", 20):
            line = line.rstrip()
            #configure interface cable-mac 11.0 ipv6 address fda8:d103:cf95:150a::1/64          <<== we want this one
            #configure interface loopback 0 ipv6 address fdc9:2578:20e0:b300:ffff::16/128
            #configure interface link-aggregate 1.1 ipv6 address fdc9:2578:20e1:b305::6/64

            ipv6 = re.findall(r"configure interface cable-mac (\d+)\.0 ipv6 address (.*)", line)
            if not ipv6: continue

            cmac = ipv6[0][0]
            gw = ipv6[0][1]

            # keep
            self.ipv6gw[cmac] = gw

    def __scfn(self, swcmt):
        self.fn = {}

        for line in swcmt.executeCmd("show cable fiber-node | include D1"):
            #CR73                15     1  D1       11/6/0-15 (data: 11/6/1-5,7,9,11,13,15)
            #CR41-1              17     1  D1       10/0/0-15 (data: 10/0/1-5,7,9,11,13,15)
            fncmac = re.findall(r"^([A-Z0-9-]+)\s+([0-9]+)\s+", line)

            if not fncmac:
                self._cmtswarn("Unknown line '%s' for SCFN, skipping.." % line)
                continue

            fn = fncmac[0][0]
            cmac = fncmac[0][1]

            # keep
            self.fn[cmac] = fn
            
    def __cmtslog(self, level, msg):
        try:
            if   level == "INFO":   self.cmtslog.info(msg)
            elif level == "WARN":   self.cmtslog.warn(msg)
            elif level == "CRIT":   self.cmtslog.crit(msg)
            else:
                self.cmtslog.warn("Unknown level %s for: %s" % (level, msg))
        except AttributeError:
            return
