#!/bin/bash

T3=/root/HFCNOC_T3
CRON_DIR=/usr/local/t3/collector
CREDS_DIR=$T3/SCRIPT_USER_CREDS__do_not_remove
KEYS_DIR=${CREDS_DIR}/.ssh
LOG_FILE="$0.log"
SAPM_CTL=emdpc0101001pr

log_header="-------- `date` --------"
echo $log_header >> $LOG_FILE

# bring topology
today=`date +"%Y%m%d"`
file=topology_${today}.txt

scp -q -i $KEYS_DIR/id_rsa root@${SAPM_CTL}:/root/HFCNOC_T3/DNS_CMTS_LIST/$file $CRON_DIR

if [ $? -ne 0 ]; then
    echo "Failed to bring in TOPOLOGY with error '$?'" >> $LOG_FILE
    exit 1
fi

echo "Successfully brought in TOPOLOGY from $SAPM_CTL" >> $LOG_FILE

if [ ! -f $CRON_DIR/$file ]; then
    echo "Succeeded bringing in TOPOLOGY, but file not found !THIS SHOULD NOT HAPPEN!" >> $LOG_FILE
    exit 1
fi

f_md5="`md5sum $CRON_DIR/$file`"

echo "TOPOLOGY file ($file) found" >> $LOG_FILE
echo "TOPOLOGY file: $f_md5" >> $LOG_FILE

# Everything should be good now.. phewww
chmod 644 $CRON_DIR/$file

# update topology.txt
echo "Moving $file over to topology.txt" >> $LOG_FILE
cp -a $CRON_DIR/$file $CRON_DIR/topology.txt

# clean up
old_topology=`find $CRON_DIR -name 'topology_*' -mtime +3`
echo "Removing old TOPOLOGY files: $old_topology" >> $LOG_FILE
rm -f $old_topology

# finish
echo "Done" >> $LOG_FILE
echo >> $LOG_FILE
