from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np
import sys


def get_ylabel(metric, unit):
	unitmap = {
				'Trans/s'	: "Transactions per second",
			}

	metricmap = {
				"host CPU utilization"	: "CPU utilization",
				"guest CPU utilization"	: "CPU utilization",
				"lost packets"			: "Loss rate",
				"latency"				: "Latency",
				"throughput"			: "Throughput",
				"jitter"				: "Jitter",
				"rtt"					: "Round trip time",
			}

	if unit in unitmap:
		return unitmap[unit]
	if metric in metricmap:
		metric = metricmap[metric]
	return metric + " ["+unit+"]"

def format_plot_lables(labels):
	mysep = " "
	if len(labels) > 2: mysep = "\n"
	return map(lambda x: mysep.join(x.split()[:]), labels)

# plt.rcParams['ps.useafm'] = True
# plt.rcParams['pdf.use14corefonts'] = True
# plt.rcParams['text.usetex'] = True
# plt.rcParams["font.family"] = "Arial"

files = []
labels = []

if len(sys.argv) == 1:
	print("No input files")
	print("Usage:")
	print("\t python " + sys.argv[0] + " file1 label1 file2 label2 ...")
	exit()

if len(sys.argv) % 2 == 0:
	print("Odd number of parameters")
	print("Usage:")
	print("\t python " + sys.argv[0] + " file1 label1 file2 label2 ...")
	exit()

i = 1
while i < len(sys.argv):
	files += (sys.argv[i],)
	labels += (sys.argv[i+1],)
	i+=2


values = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: (-1, -1, ""))))))
protocols = set()
directions = set()
metric_names = set()
file_labels = set()

for (filename, filelabel) in zip(files,labels):
	f_current = open(filename)

	f_current.readline() # skip header
	for line in f_current:
		line = line.strip()
		spl = line.split(";")
		(tool, protocol, direction, metric, unit, avg, desv) = spl

		avg = float(avg)
		desv = float(desv)
		protocol = protocol.upper()
		direction = direction.lower()

		protocols.add(protocol)
		directions.add(direction)
		metric_names.add(metric)
		file_labels.add(filelabel)

		values[tool][protocol][direction][metric][filelabel] = (avg, desv, unit)
	f_current.close()

print("Metrics:")
print('\t'+", ".join(metric_names))

savetype = 'png'
colors = ("red", "green", "cyan", "gray", "orange", "pink")
# colors = ("#d73027", "#fc8d59", "#fee090", "#e0f3f8", "#91bfdb", "#4575b4")
# colors = ("#f7f7f7", "#d9d9d9", "#bdbdbd", "#969696", "#636363", "#252525")
# colors = ("#f7f7f7", "#bdbdbd", "#d9d9d9", "#636363", "#969696", "#353535")
# colors = ("#ffffb2", "#fdae6b", "#c7e9c0", "#de2d26", "#9e9ac8", "#353535")
colors = ("#4B0082", "#66CDAA", "#B22222", "#DEB887", "#BDB76B", "#B0C4DE", "#fdae0b", "#472940")
# colors = ("#ffffb2", "#fdae6b", "#c7e9c0")
hatches = ('//', '', '\\\\', 'o', '-', '+', 'x', '*', 'O', '.', '/', '\\')
markers = ('o', 'v', '^', '<', '>', '8', 's', 'p', '*', 'h', 'H', 'D', 'd')
lss = ['solid', 'dashed', 'dashdot', 'dotted', '-', '--', '-.', ':', 'None', ' ', '']
plt.rcParams.update({'font.size': 12, 'legend.fontsize': 10})

metric_names = sorted(metric_names)
file_labels = sorted(file_labels)
protocols = sorted(protocols)
directions = sorted(directions)


for tool in values:
	print()
	print("processing", tool)
	for metric in metric_names:
		print("\t", metric)

		# if not should_plot(metric, metric_names):
		# 	print("\t\tskipping...")
		# 	continue

		# fig, ax = plt.subplots()

		for file_label in file_labels:
			plot_means  = defaultdict(lambda: [])
			plot_errors = defaultdict(lambda: [])
			plot_labels = defaultdict(lambda: [])
			for protocol in protocols:
				for direction in directions:
					value, error, unit = values[tool][protocol][direction][metric][file_label]
					#if metric == "rtt" and direction == "receive":
					#	continue
					if value != -1:
						print("\t", tool, protocol, direction, metric, file_label)
						plot_means[unit]  += [value]
						plot_errors[unit] += [error]
						plot_labels[unit] += [protocol + " " + direction]


			if not len(plot_labels):
				# print(plot_labels)
				print("\t\t skipping (no data) ...", file_label)
				continue

			# print(plot_means)

			units = sorted(plot_means.keys())
			print ("\t\t Detected units for", file_label, ":", units, "=>", list(map(get_ylabel, [metric]*len(units), units)))

			# create a figure for each different unit
			#	This is done basically to create two plots for netperf throughput (which can be Mbps or Trans/s)
			for unit in units:
				fig = plt.figure(units.index(unit))
				if not len(fig.get_axes()):
					ax = fig.add_subplot()
					plt.grid(visible=True, which='major', color='gray', linestyle='--', lw=0.5, axis='y')
				else:
					ax = fig.get_axes()[0]

				data = plot_means[unit]
				errors = plot_errors[unit]
				labels = plot_labels[unit]

				x = np.arange(len(data))  # the label locations

				width = 1.0 / (len(file_labels) + 1) # the width of the bars
				where =  (file_labels.index(file_label) - (len(file_labels)-1)/2) * width
				myrects = ax.bar(x + where, data, width, yerr=errors, label=file_label)

				if "jitter" in metric:
					ax.set_yscale('log')
					#ax.set_ylim([0.001, 1])
					
				if "netperf" in tool and "throughput" in metric and "Trans" in unit:
					ax.set_ylim([0, max(map(max,plot_means.values()))*1.2])

				# Add some text for labels, title and custom x-axis tick labels, etc.
				ax.set_ylabel(get_ylabel(metric, unit))
				# ax.set_title(title_from_metric(metric))
				ax.set_xticks(x)
				ax.set_xticklabels(format_plot_lables(plot_labels[unit]))
				ax.legend(loc='best')

				figname_prefix = 'r_'
				figname = figname_prefix + tool + "_" + metric[:5].strip()
				figname += ( unit[0] if len(units)>1 else "")

				plt.savefig(figname + '.' + savetype, format=savetype, dpi=300, bbox_inches='tight')
		# closes all open figures
		plt.close('all')

with open("plot_netbenchmark.cmd", 'w') as outfile:
	myargs = map(lambda x: x if ' ' not in x else "\""+x+"\"", [x for x in sys.argv])
	outfile.write(' '.join(myargs) + "\n")
