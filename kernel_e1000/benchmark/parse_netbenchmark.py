import sys
import numpy as np
import json, csv
from collections import defaultdict

def parse_iperf3_str(jsonstr, partial_results):
	data = json.loads(jsonstr)

	v = data['intervals'][-1]['sum']['bits_per_second']
	partial_results[("throughput","bps")] += [v]

	try:
		v = data['end']['streams'][-1]['sender']['mean_rtt']
		if v == 0:
			v = data['server_output_json']['end']['streams'][-1]['sender']['mean_rtt']
		partial_results[("rtt","us")] += [v]
	except KeyError:
		pass

	try:
		v = data['end']['sum']['jitter_ms'] # UDP only
		partial_results[("jitter","ms")] += [v]
	except KeyError:
		pass
	
	try:
		v = data['end']['sum']['lost_percent'] # UDP only
		partial_results[("lost packets","%")] += [v]

	except KeyError:
		pass
	
	v = data['end']['cpu_utilization_percent']['host_total']
	partial_results[("guest CPU utilization","%")] += [v]
	
	v = data['end']['cpu_utilization_percent']['remote_total']
	partial_results[("host CPU utilization","%")] += [v]
	

def parse_iperf3_output(filename):

	with open(filename) as myfile:
		balance = 0
		jsonstr = ""
		partial_results = defaultdict(lambda: [])
		for line in myfile:
			jsonstr += line
			balance += line.count('{')
			balance -= line.count('}')

			if balance == 0:
				parse_iperf3_str(jsonstr, partial_results)
				jsonstr = ""

		results = []
		for i in partial_results:
			metric, unit = i
			# print(i, "\t\t", 	partial_results[i])
			avg = np.mean(partial_results[i])
			stdev = np.std(partial_results[i], ddof=1)
			if unit == "bps":
				avg /= 1000000
				stdev /= 1000000
				unit = "Mbps"
			results += [(metric, unit, avg, stdev)]
		return results

def parse_netperf_output(filename):
	with open(filename) as myfile:
		lines = csv.reader(myfile, delimiter=',', quotechar='"')
		results = []
		for line in lines:
			if len(line) == 1:
				# print("skipping extra line")
				continue

			(result_tag,socket_type,protocol,direction,time,throughput,throughput_unit,
			throughput_conf,local_CPU_util,local_CPU_confidence,remote_CPU_util,
			remote_CPU_conf,transaction_rate,round_trip_latency,burst_requests,
			local_send_throughput,local_recv_throughput,remote_send_throughput,
			remote_recv_throughput,minimum_latency,maximum_latency,
			latency_50th_percentile,latency_90th_percentile,latency_99th_percentile,
			mean_latency_microseconds,latency_stddev,testUUID,command) = line


			if(not time.replace('.','',1).isdigit()):
				# print("skipping header")
				continue

			if throughput_unit == "10^6bits/s":
				throughput_unit = "Mbps"

			# print("throughput", throughput)
			results+=[(protocol,direction,"throughput",throughput_unit,throughput,throughput_conf)]
			results+=[(protocol,direction,"guest CPU utilization","%",local_CPU_util,local_CPU_confidence)]
			results+=[(protocol,direction,"host CPU utilization","%",remote_CPU_util,remote_CPU_conf)]
			results+=[(protocol,direction,"latency","us",mean_latency_microseconds,latency_stddev)]
		return results

if __name__ == "__main__":
	#ToDo: check units for consistency

	if len(sys.argv) >= 2:
		if len(sys.argv) > 2: print("Ignoring command line arguments:", sys.argv[2:])

		date = sys.argv[1]
		outfilename = "netbenchmark_" + date + "_summary.csv"
		fout = open(outfilename, 'w')
		# output csv header
		fout.write("tool;protocol;direction;metric;unit;average;stdev\n")

		for proto in ("tcp", "udp"):
			for direction in ("receive", "send"):
				iperf3_file = "iperf3_" + date + "_" + proto + "_" + direction + ".log"
				print("Processing", iperf3_file)
				result = parse_iperf3_output(iperf3_file)
				for metric, unit, avg, stdev in result:
					fout.write(";".join(("iperf3", proto, direction, metric, unit, repr(avg), repr(stdev))) + "\n")

		netperf_file = "netperf_"+date+".log"
		print("Processing", netperf_file)
		result = parse_netperf_output(netperf_file)
		for protocol, direction, metric, unit, avg, stdev in result:
			fout.write( ";".join(("netperf", protocol, direction, metric, unit, avg, stdev)) + "\n" )

		fout.close()
		print(outfilename, "written")
		exit(0)

	print("No arguments passed")
	print("Usage: ")
	print("\t python", sys.argv[0], "YYYYmmDDHHMM")
	exit(-1)
