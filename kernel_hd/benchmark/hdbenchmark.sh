#!/bin/sh
DEVICE=/dev/vda
TARGET_DIR=/mnt/extra_hd
NRUNS=10
DATE=`date +%Y%m%d%H%M`

echo $DATE

#################
#### dd test ####
#################

# busybox's dd command is limited compared to the full dd found on most host systems
# for example, status=progress and oflag-direct are not available
# an alternative to measure might be just use the "time" command, but doing so decreases the accuracy

# could use dd to test read as well, but requires extra care and a sample file to read from (https://www.jamescoyle.net/how-to/599-benchmark-disk-io-with-dd-and-bonnie)

FILENAME=hdtest

# write test (2GB, small blocks)
echo "dd test #1"
for i in `seq $NRUNS`; do
	time dd if=/dev/zero of=${TARGET_DIR}/${FILENAME} conv=fsync bs=4k count=524288 >> hdbenchmark_${DATE}_dd1.out 2>&1
	rm ${TARGET_DIR}/${FILENAME}
done

# write test (2GB, big block, block size bounded by available memory)
echo "dd test #2"
for i in `seq $NRUNS`; do
	time dd if=/dev/zero of=${TARGET_DIR}/${FILENAME} conv=fsync bs=512MB count=4   >> hdbenchmark_${DATE}_dd2.out 2>&1
	rm ${TARGET_DIR}/${FILENAME}
done

# parameters:
#  if=<file> origin
#  of=<file> destination
#  conv=fsync physically write data before finishing
#  bs=<size> size of each block
#  count=<number> number of blocks to write

################
#### ioping ####
################

# default size is 4k
echo "ioping"
ioping -B -c $NRUNS ${TARGET_DIR} > hdbenchmark_${DATE}_ioping_read.out
ioping -B -c $NRUNS -W ${TARGET_DIR} > hdbenchmark_${DATE}_ioping_write.out

# parameters:
#  -B run in batch mode, does not show human readable output
#  -c <num> number of pings
#  -W write instead of read

# output format (from man page)
#       100 24165 4138 16950134 190 242 2348 214
#       (1) (2)   (3)  (4)      (5) (6) (7)  (8)
#
#       (1) number of requests
#       (2) serving time         (usec)
#       (3) requests per second  (iops)
#       (4) transfer speed       (bytes/sec)
#       (5) minimal request time (usec)
#       (6) average request time (usec)
#       (7) maximum request time (usec)
#       (8) request time standard deviation (usec)


################
#### hdparm ####
################

# hdparm issues some strange warnings when run in the VM: "HDIO_DRIVE_CMD: Inappropriate ioctl for device"
echo "hdparm"
for i in `seq $NRUNS`; do
	hdparm -t $DEVICE >> hdbenchmark_${DATE}_hdparm.out
done;

# parameters
# -t to perform a timing test
# --direct Use the kernel´s "O_DIRECT" flag when performing a -t timing test. (not available in buildroot version)
# -T to perform a timing test of cache reads (not relevant to us)

##################
#### bonnie++ ####
##################

# it is recommended to set size at least x2 the sytems RAM size. Current test VM contains 1GB RAM
echo "bonnie++"
bonnie++ -q -x $NRUNS -d ${TARGET_DIR} -s 2G -n 0 -f -b -D -u root > hdbenchmark_${DATE}_bonnie.out
rm ${TARGET_DIR}/Bonnie*.*

# parameters
#  -q quiet mode
#  -x <n> run n times
#  -d <directory>
#  -s <size>
#  -n <number> of files created, 0 to skip test
#  -f fast mode, skips per-char IO tests.
#  -b no write buffering.  fsync() after every write.
#  -D use direct IO (O_DIRECT) for the bulk IO tests
#  -u <user>

# output when not run in quiet mode:
#	Writing intelligently...done
#	Rewriting...done
#	Reading intelligently...done
#	start 'em...done...done...done...
# 	Create files in sequential order...done.
#	Stat files in sequential order...done.
#	Delete files in sequential order...done.
#	Create files in random order...done.
#	Stat files in random order...done.
#	Delete files in random order...done.

# we are interested mostly on the put_block and get_block columns from the output, which is given in KB/s
# only parameter to vary is -s


#############
#### fio ####
#############

# based on answer of this question: https://askubuntu.com/questions/87035/how-to-check-hard-disk-performance
FIO_TIME_LIMIT="--runtime=20m --time_based"
FIO_HEADER="terse_version5;fio_version;jobname;groupid;error;read_kb;read_bandwidth;read_iops;read_runtime_ms;read_slat_min;read_slat_max;read_slat_mean;read_slat_dev;read_clat_min;read_clat_max;read_clat_mean;read_clat_dev;read_clat_pct01;read_clat_pct02;read_clat_pct03;read_clat_pct04;read_clat_pct05;read_clat_pct06;read_clat_pct07;read_clat_pct08;read_clat_pct09;read_clat_pct10;read_clat_pct11;read_clat_pct12;read_clat_pct13;read_clat_pct14;read_clat_pct15;read_clat_pct16;read_clat_pct17;read_clat_pct18;read_clat_pct19;read_clat_pct20;read_tlat_min;read_lat_max;read_lat_mean;read_lat_dev;read_bw_min;read_bw_max;read_bw_agg_pct;read_bw_mean;read_bw_dev;read_bw_n;read_iops_min;read_iops_max;read_iops_mean;read_iops_stdev;read_iops_n;write_kb;write_bandwidth;write_iops;write_runtime_ms;write_slat_min;write_slat_max;write_slat_mean;write_slat_dev;write_clat_min;write_clat_max;write_clat_mean;write_clat_dev;write_clat_pct01;write_clat_pct02;write_clat_pct03;write_clat_pct04;write_clat_pct05;write_clat_pct06;write_clat_pct07;write_clat_pct08;write_clat_pct09;write_clat_pct10;write_clat_pct11;write_clat_pct12;write_clat_pct13;write_clat_pct14;write_clat_pct15;write_clat_pct16;write_clat_pct17;write_clat_pct18;write_clat_pct19;write_clat_pct20;write_tlat_min;write_lat_max;write_lat_mean;write_lat_dev;write_bw_min;write_bw_max;write_bw_agg_pct;write_bw_mean;write_bw_dev;write_bw_n;write_iops_min;write_iops_max;write_iops_mean;write_iops_stdev;write_iops_n;trim_kb;trim_bandwidth;trim_iops;trim_runtime_ms;trim_slat_min;trim_slat_max;trim_slat_mean;trim_slat_dev;trim_clat_min;trim_clat_max;trim_clat_mean;trim_clat_dev;trim_clat_pct01;trim_clat_pct02;trim_clat_pct03;trim_clat_pct04;trim_clat_pct05;trim_clat_pct06;trim_clat_pct07;trim_clat_pct08;trim_clat_pct09;trim_clat_pct10;trim_clat_pct11;trim_clat_pct12;trim_clat_pct13;trim_clat_pct14;trim_clat_pct15;trim_clat_pct16;trim_clat_pct17;trim_clat_pct18;trim_clat_pct19;trim_clat_pct20;trim_tlat_min;trim_lat_max;trim_lat_mean;trim_lat_dev;trim_bw_min;trim_bw_max;trim_bw_agg_pct;trim_bw_mean;trim_bw_dev;trim_bw_n;trim_iops_min;trim_iops_max;trim_iops_mean;trim_iops_stdev;trim_iops_n;cpu_user;cpu_sys;cpu_csw;cpu_mjf;cpu_minf;iodepth_1;iodepth_2;iodepth_4;iodepth_8;iodepth_16;iodepth_32;iodepth_64;lat_2us;lat_4us;lat_10us;lat_20us;lat_50us;lat_100us;lat_250us;lat_500us;lat_750us;lat_1000us;lat_2ms;lat_4ms;lat_10ms;lat_20ms;lat_50ms;lat_100ms;lat_250ms;lat_500ms;lat_750ms;lat_1000ms;lat_2000ms;lat_over_2000ms;disk_name;disk_read_iops;disk_write_iops;disk_read_merges;disk_write_merges;disk_read_ticks;write_ticks;disk_queue_time;disk_util"
# Sequential read speed with big blocks
echo "fio #1"
echo $FIO_HEADER > hdbenchmark_${DATE}_fio.out
fio --terse-version=5 --minimal --name readbig      --directory=${TARGET_DIR} --filename=fio-tempfile1.dat --rw=read     --size=2G --io_size=5g --blocksize=1024k --ioengine=psync --fsync=10000 --iodepth=32 --direct=1 --numjobs=1 --group_reporting --ramp_time=2 $FIO_TIME_LIMIT >> hdbenchmark_${DATE}_fio.out
rm ${TARGET_DIR}/fio-tempfile1.dat

# Sequential write speed with big blocks
echo "fio #2"
fio --terse-version=5 --minimal --name writebig     --directory=${TARGET_DIR} --filename=fio-tempfile2.dat --rw=write    --size=2G --io_size=5g --blocksize=1024k --ioengine=psync --fsync=10000 --iodepth=32 --direct=1 --numjobs=1 --group_reporting --ramp_time=2 $FIO_TIME_LIMIT >> hdbenchmark_${DATE}_fio.out
rm ${TARGET_DIR}/fio-tempfile2.dat

# Random 4K read QD1:
echo "fio #3"
fio --terse-version=5 --minimal --name readrng      --directory=${TARGET_DIR} --filename=fio-tempfile3.dat --rw=randread --size=2G --io_size=5g --blocksize=4k    --ioengine=psync --fsync=1     --iodepth=1  --direct=1 --numjobs=1 --group_reporting --ramp_time=2 $FIO_TIME_LIMIT >> hdbenchmark_${DATE}_fio.out
rm ${TARGET_DIR}/fio-tempfile3.dat

# Mixed random 4K read and write QD1 with sync
echo "fio #4"
fio --terse-version=5 --minimal --name readwriterng --directory=${TARGET_DIR} --filename=fio-tempfile4.dat --rw=randrw   --size=2G --io_size=5g --blocksize=4k    --ioengine=psync --fsync=1     --iodepth=1  --direct=1 --numjobs=1 --group_reporting --ramp_time=2 $FIO_TIME_LIMIT >> hdbenchmark_${DATE}_fio.out
rm ${TARGET_DIR}/fio-tempfile4.dat

# old
## Sequential read speed with big blocks
#fio --name TEST --eta-newline=5s --filename=fio-tempfile.dat --rw=read     --size=500m --io_size=10g --blocksize=1024k --ioengine=libaio --fsync=10000 --iodepth=32 --direct=1 --numjobs=1 --runtime=60 --group_reporting
#
## Sequential write speed with big blocks
#fio --name TEST --eta-newline=5s --filename=fio-tempfile.dat --rw=write    --size=500m --io_size=10g --blocksize=1024k --ioengine=libaio --fsync=10000 --iodepth=32 --direct=1 --numjobs=1 --runtime=60 --group_reporting
#
## Random 4K read QD1:
#fio --name TEST --eta-newline=5s --filename=fio-tempfile.dat --rw=randread --size=500m --io_size=10g --blocksize=4k     --ioengine=libaio --fsync=1    --iodepth=1  --direct=1 --numjobs=1 --runtime=60 --group_reporting
#
## Mixed random 4K read and write QD1 with sync
#fio --name TEST --eta-newline=5s --filename=fio-tempfile.dat --rw=randrw   --size=500m --io_size=10g --blocksize=4k     --ioengine=libaio --fsync=1    --iodepth=1  --direct=1 --numjobs=1 --runtime=60 --group_reporting

# parameters
#  --name <name> job name
#  --eta-newline=<time>
#  --filename=<filename>
#  --rw=[rand]<read|write|rw|trim> type of operation
#  --size=<size> size of the region the operations take place
#  --io_size=<size> actual amount of data that will be read/written
#  --blocksize=<size> the size of each individual operation
#  --ioengine=<string> selects engine. libaio is not available in the buildroot VM. Available in the VM: sync, psync, vsync, pvsync, pvsync2. There are many other options, didnt test them, but don't seem relevant
#  --fsync=<number> issues a fsync on writting files after <number> of writtes is issued
#  --iodepth=<number> Number of I/O units to keep in flight against the file. Note that increasing iodepth beyond 1 will not affect synchronous ioengines
#  --direct=<0|1> If value is true, use non-buffered I/O
#  --numjobs=<num> Create the specified number of clones of this job
#  --runtime=<num> Tell fio to terminate processing after the specified period of time (default unit seconds)
#  --group_reporting show grouped statistics instead of per job
#  --randseed=<int> set the random seed

###########
echo "done"
###########
