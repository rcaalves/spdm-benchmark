import sys
import numpy as np

def parse_dd_output(filename, record_size):
	try:
		f = open(filename)
	except:
		print("error on f = open(filename)", filename, file=sys.stderr)
		return (-1, -1)

	# assuming the file contains the output of multiple dd runs following the format:
	# [0-9]++0 records in
	# [0-9]++0 records out
	# real    [0-9]+m [0-9]+.[0-9]+s
	# user    [0-9]+m [0-9]+.[0-9]+s
	# sys     [0-9]+m [0-9]+.[0-9]+s

	linecounter = 0
	sizes=[]
	times=[]
	for line in f:
		# print line
		if linecounter == 1:
			spl = line.split()
			if spl[-1] != "out":
				print("warning: expected 'out'")
			sizes += (int(spl[0][:-2]),)
		if linecounter == 2:
			spl = line.split()
			if spl[0] != "real":
				print("warning: expected 'real'")
			minutes = int(spl[1][:-1])
			seconds = float(spl[2][:-1])
			times += (minutes*60+seconds,)

		linecounter = (linecounter+1)%5

	rates=[]
	for time,size in zip(times,sizes):
		# print record_size*size/time
		rates += (record_size*size/time,)
	f.close()

	average = np.mean(rates)
	stdev = np.std(rates, ddof=1)

	# print "average", average
	# print "stdev  ", stdev
	return (average, stdev)

def parse_ioping_output(filename):
	try:
		f = open(filename)
	except:
		print("error on f = open(filename)", filename, file=sys.stderr)
		return (-1, -1)

# 	output format (from man page):
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
	average = stdev = -1
	for line in f:
		spl = line.split()
		if (average != -1): print >> sys.stderr, "Warning: expected only one line in ioping log"
		average = float(spl[5])
		stdev = float(spl[7])
	f.close()
	return (average, stdev)

def parse_hdparm_output(filename):
	try:
		f = open(filename)
	except:
		print("error on f = open(filename)", filename, file=sys.stderr)
		return (-1, -1)

	rates = []
	for line in f:
		spl = line.split()
		if len(spl) == 12:
			rates += (float(spl[-2]),)
	f.close()
	average = np.mean(rates)
	stdev = np.std(rates, ddof=1)
	return (average, stdev)

def parse_bonnie_output(filename):
	try:
		f = open(filename)
	except:
		print("error on f = open(filename)", filename, file=sys.stderr)
		return (-1, -1, -1, -1)

	read_rates = []
	write_rates = []
	f.readline() # get rid of headers
	for line in f:
		spl = line.split(',')
		if len(spl) == 27:
			read_rates += (float(spl[10]),)
			write_rates += (float(spl[4]),)
	f.close()
	read_average = np.mean(read_rates)
	read_stdev = np.std(read_rates, ddof=1)
	write_average = np.mean(write_rates)
	write_stdev = np.std(write_rates, ddof=1)
	return (read_average, read_stdev, write_average, write_stdev)


def parse_fio_output(filename):
	try:
		f = open(filename)
	except:
		print("error on f = open(filename)", filename, file=sys.stderr)
		return (-1, -1, -1, -1)

	results_mean = []
	results_stdev = []
	f.readline() # get rid of headers
	for line in f:
		spl = line.split(';')
		if len(spl) == 189:
			jobname = spl[2]
			if "read" in jobname:
				if (float(spl[49]) != 0):
					results_mean += (float(spl[49]),)
					results_stdev += (float(spl[50]),)
				else:
					results_mean += (float(spl[7]),)
					results_stdev += (1,)
			if "write" in jobname:
				results_mean += (float(spl[96]),)
				results_stdev += (float(spl[97]),)
	f.close()
	return list(zip(results_mean, results_stdev))

if __name__ == "__main__":
	if len(sys.argv) >= 2:
		date = sys.argv[1]
		outfilename = "hdbenchmark_" + date + "_summary.csv"
		fout = open(outfilename, 'w')
		fout.write("label;average;stdev\n")

		(average, stdev) = parse_dd_output("hdbenchmark_"+date+"_dd1.out", 4*1024)
		fout.write("dd small blocks [B/s];" + repr(average) + ";" + repr(stdev) + "\n")

		(average, stdev) = parse_dd_output("hdbenchmark_"+date+"_dd2.out", 512*1024*1024)
		fout.write("dd big blocks [B/s];" + repr(average) + ";" + repr(stdev) + "\n")

		(average, stdev) = parse_ioping_output("hdbenchmark_"+date+"_ioping_read.out")
		fout.write("ioping read latency [us];" + repr(average) + ";" + repr(stdev) + "\n")

		(average, stdev) = parse_ioping_output("hdbenchmark_"+date+"_ioping_write.out")
		fout.write("ioping write latency [us];" + repr(average) + ";" + repr(stdev) + "\n")

		(average, stdev) = parse_hdparm_output("hdbenchmark_"+date+"_hdparm.out")
		fout.write("hdparm read speed [kB/s];" + repr(average) + ";" + repr(stdev) + "\n")

		result = parse_bonnie_output("hdbenchmark_"+date+"_bonnie.out")
		(average, stdev) = result[0:2]
		fout.write("bonnie read speed [kB/s];" + repr(average) + ";" + repr(stdev) + "\n")
		(average, stdev) = result[2:4]
		fout.write("bonnie write speed [kB/s];" + repr(average) + ";" + repr(stdev) + "\n")

		result = parse_fio_output("hdbenchmark_"+date+"_fio.out")
		(average, stdev) = result[0]
		fout.write("fio sequential read [iops];" + repr(average) + ";" + repr(stdev) + "\n")
		(average, stdev) = result[1]
		fout.write("fio sequential write [iops];" + repr(average) + ";" + repr(stdev) + "\n")
		(average, stdev) = result[2]
		fout.write("fio random read [iops];" + repr(average) + ";" + repr(stdev) + "\n")
		(average, stdev) = result[3]
		fout.write("fio random rw read [iops];" + repr(average) + ";" + repr(stdev) + "\n")
		(average, stdev) = result[4]
		fout.write("fio random rw write [iops];" + repr(average) + ";" + repr(stdev) + "\n")

		fout.close()
		print(outfilename, "written")
		exit(0)

	print("No arguments passed")
	print("Usage: ")
	print("\t python", sys.argv[0], "YYYYmmDDHHMM")
	exit(-1)


