#! /bin/sh

LOGFILE="regcheck-result-`uname -n`.log"

sudo taskset -c 1 ./regcheck-checker | tee $LOGFILE
echo "Finished"
echo "Result saved in ${LOGFILE}"
