#!/bin/sh

HOST=${HOST:=192.168.137.7}
IPERF3_TEST_LEN=${IPERF3_TEST_LEN:=5}
IPERF3_REPS=${IPERF3_REPS:=5}

DATE=`date +%Y%m%d%H%M`
echo "Date label:" $DATE
echo
echo "IPERF3_TEST_LEN" $IPERF3_TEST_LEN
echo "IPERF3_REPS" $IPERF3_REPS

echo disabling TCP Segmentation Offload and Scatter-Gather, not supported by modified e1000 network card
ethtool -K eth0 tx off sg off tso off
echo

####################
echo iperf3 tests ##
####################

echo "**********************************************************************************************"
echo  iperf3 server should be started at the host as follows: iperf3 -s -J -i 0 --udp-counters-64bit
echo "**********************************************************************************************"

ping -c 5 -A $HOST -q > /dev/null

if [ $? -ne 0 ]; then
    echo "Could not ping HOST IP" $HOST
    echo "You can set the IP by \$ HOST=<IP>" $0
    exit
fi

for i in `seq $IPERF3_REPS`; do
    echo iteration $i of $IPERF3_REPS

    echo TCP send test
    iperf3 \
        -c $HOST    `# starts a client connection to target ip 										`	\
        -i 0        `# disables periodic reports													`	\
        -J          `# JSON output																	`	\
        -t $IPERF3_TEST_LEN																				\
        --logfile iperf3_${DATE}_tcp_send.log

    echo TCP receive test
    iperf3 \
        -c $HOST    `# starts a client connection to target ip 										`	\
        -i 0        `# disables periodic reports													`	\
        -J          `# JSON output																	`	\
        -t $IPERF3_TEST_LEN																				\
        -R          `# reverse the direction of a test, so that the server sends data to the client	`	\
        --get-server-output `# rtt metric on this test have to be retrieved from the server         `   \
        --logfile iperf3_${DATE}_tcp_receive.log

    echo UDP send test
    iperf3 \
        -c $HOST    `# starts a client connection to target ip 										`	\
        -i 0        `# disables periodic reports													`	\
        -J          `# JSON output																	`	\
        -t $IPERF3_TEST_LEN																				\
        --udp       `# use UDP rather than TCP														`	\
        --logfile iperf3_${DATE}_udp_send.log                                                           \
        -b 0        `# removes BW limiter                                                           `   \
        --udp-counters-64bit `# uses 64 bit counters to avoid overflow                              `

    echo UDP receive test
    iperf3 \
        -c $HOST    `# starts a client connection to target ip 										`	\
        -i 0        `# disables periodic reports													`	\
        -J          `# JSON output																	`	\
        -t $IPERF3_TEST_LEN																				\
        --udp       `# use UDP rather than TCP														`	\
        -R          `# reverse the direction of a test, so that the server sends data to the client	`	\
        --logfile iperf3_${DATE}_udp_receive.log                                                        \
        -b 0        `# removes BW limiter                                                           `   \
        --udp-counters-64bit `# uses 64 bit counters to avoid overflow                              `
done

echo

#####################
echo netperf tests ##
#####################

NETPERF_CSV_COLS="RESULT_BRAND,SOCKET_TYPE,PROTOCOL,DIRECTION,ELAPSED_TIME,THROUGHPUT,THROUGHPUT_UNITS,THROUGHPUT_CONFID,\
LOCAL_CPU_UTIL,LOCAL_CPU_CONFID,REMOTE_CPU_UTIL,REMOTE_CPU_CONFID,\
TRANSACTION_RATE,RT_LATENCY,BURST_SIZE,LOCAL_SEND_THROUGHPUT,LOCAL_RECV_THROUGHPUT,\
REMOTE_SEND_THROUGHPUT,REMOTE_RECV_THROUGHPUT,\
MIN_LATENCY,MAX_LATENCY,P50_LATENCY,P90_LATENCY,P99_LATENCY,MEAN_LATENCY,STDDEV_LATENCY,\
UUID,COMMAND_LINE"

echo TCP upload
netperf \
    `# global options ` \
    -B "TCP upload" \
    -c -C       `# measure CPU usage at client and server` \
    -I 95,5     `# calculates 95% confidence intervals` \
    -j          `# keep additional timing statistics` \
    -H ${HOST} 	`# connects to netserver at <ip>` \
    -t omni     `# test type "omni"` \
    --          `# separator from global to test specific options` \
    -d send	    `# test direction ` \
    -T TCP		`# sets protocol type.` \
    -o ${NETPERF_CSV_COLS} `# sets output format to CSV, listing the output columns` \
    >> netperf_${DATE}.log

echo TCP download
netperf \
    `# global options ` \
    -B "TCP download" \
    -c -C       `# measure CPU usage at client and server` \
    -I 95,5     `# calculates 95% confidence intervals` \
    -j          `# keep additional timing statistics` \
    -H ${HOST} 	`# connects to netserver at <ip>` \
    -t omni     `# test type "omni"` \
    --          `# separator from global to test specific options` \
    -d receive  `# test direction ` \
    -T TCP		`# sets protocol type.` \
    -o ${NETPERF_CSV_COLS} `# sets output format to CSV, listing the output columns`\
    >> netperf_${DATE}.log

echo TCP send/receive
netperf \
    `# global options ` \
    -B "TCP send/receive" \
    -c -C       `# measure CPU usage at client and server` \
    -I 95,5     `# calculates 95% confidence intervals` \
    -j          `# keep additional timing statistics` \
    -H ${HOST} 	`# connects to netserver at <ip>` \
    -t omni     `# test type "omni"` \
    --          `# separator from global to test specific options` \
    -d rr	    `# test direction ` \
    -T TCP		`# sets protocol type.` \
    -o ${NETPERF_CSV_COLS} `# sets output format to CSV, listing the output columns`\
    >> netperf_${DATE}.log

echo UDP upload
netperf \
    `# global options ` \
    -B "UDP upload" \
    -c -C       `# measure CPU usage at client and server` \
    -I 95,5     `# calculates 95% confidence intervals` \
    -j          `# keep additional timing statistics` \
    -H ${HOST} 	`# connects to netserver at <ip>` \
    -t omni     `# test type "omni"` \
    --          `# separator from global to test specific options` \
    -d send	    `# test direction ` \
    -T UDP		`# sets protocol type.` \
    -R 1        `# enables send packets across networks` \
    -o ${NETPERF_CSV_COLS} `# sets output format to CSV, listing the output columns`\
    >> netperf_${DATE}.log

# echo UDP download
# This test only works if it is the first netperf command run after QEMU stats... Unknow reason
#   decided not to keep it, since it could be buggy
# netperf \
#     `# global options ` \
#     -B "UDP download" \
#     -c -C       `# measure CPU usage at client and server` \
#     -I 95,5     `# calculates 95% confidence intervals` \
#     -j          `# keep additional timing statistics` \
#     -H ${HOST} 	`# connects to netserver at <ip>` \
#     -t omni     `# test type "omni"` \
#     --          `# separator from global to test specific options` \
#     -d receive  `# test direction ` \
#     -T UDP		`# sets protocol type.` \
#     -R 1        `# enables send packets acress networks` \
#     -P 50001,50002 `# selects ports to use. 50001 and 50002 ports need to be forwarded on qemu command line options` \
#     -o ${NETPERF_CSV_COLS} `# sets output format to CSV, listing the output columns`\
#     >> netperf_${DATE}.log

# alternate form without using -t omni
# netperf \
#     `# global options ` \
#     -B "UDP download" \
#     -c -C           `# measure CPU usage at client and server` \
#     -I 95,5         `# calculates 95% confidence intervals` \
#     -j              `# keep additional timing statistics` \
#     -H ${HOST}      `# connects to netserver at <ip>` \
#     -t UDP_STREAM   `# test type "omni"` \
#     --              `# separator from global to test specific options` \
#     -o ${NETPERF_CSV_COLS} `# sets output format to CSV, listing the output columns`\
#     >> netperf_${DATE}.log

echo UDP send/receive
netperf \
    `# global options ` \
    -B "UDP send/receive" \
    -c -C       `# measure CPU usage at client and server` \
    -I 95,5     `# calculates 95% confidence intervals` \
    -j          `# keep additional timing statistics` \
    -H ${HOST} 	`# connects to netserver at <ip>` \
    -t omni     `# test type "omni"` \
    --          `# separator from global to test specific options` \
    -d rr	    `# test direction ` \
    -T UDP		`# sets protocol type.` \
    -o ${NETPERF_CSV_COLS} `# sets output format to CSV, listing the output columns`\
    >> netperf_${DATE}.log

# alternate form without using -t omni
# netperf \
#     `# global options ` \
#     -B "UDP send/receive" \
#     -c -C           `# measure CPU usage at client and server` \
#     -I 95,5         `# calculates 95% confidence intervals` \
#     -j              `# keep additional timing statistics` \
#     -H ${HOST}      `# connects to netserver at <ip>` \
#     -t UDP_RR       `# test type "omni"` \
#     --              `# separator from global to test specific options` \
#     -o ${NETPERF_CSV_COLS} `# sets output format to CSV, listing the output columns`\
#     >> netperf_${DATE}.log

echo
echo Done
echo