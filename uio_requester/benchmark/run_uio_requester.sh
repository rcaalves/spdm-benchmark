#!/bin/sh

# exit on error
set -e

COMMAND=uio_requester_bench1.3
INTERATIONS=100

for i in $(seq 1 $INTERATIONS)
do
	${COMMAND} > "${COMMAND}_i$i.log"
done
