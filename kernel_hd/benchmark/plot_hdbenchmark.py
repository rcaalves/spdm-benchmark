from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np
import sys


def get_ylabel(metric):
	if metric.startswith("dd"):
		return "data rate [KB/s]"

	if metric.startswith("ioping"):
		return "latency [us]"

	if metric.startswith("bonn") or metric.startswith("hdp"):
		return "data rate [KB/s]"

	if metric.startswith("fio"):
		return "operations per second [iops]"

	if "boot" in metric:
		return "boot time [s]"

	return "???"

def title_from_metric(metric):
	if metric.startswith("dd"):
		return "dd command results"

	if metric.startswith("ioping"):
		return "ioping results"

	if metric.startswith("bonn"):
		return "bonnie++ benchmark"

	if metric.startswith("hdp"):
		return "hdparm results"

	if metric.startswith("fio"):
		return "fio benchmark"

	return "???"

def format_plot_lables(labels):
	mysep = " "
	if len(labels) > 2: mysep = "\n"
	return map(lambda x: mysep.join(x.split()[1:-1]) ,labels)


def should_plot(el, mylist):
	nextel = mylist[mylist.index(el)+1]
	if el[:3] == nextel[:3]:
		return False
	return True


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


# values = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: -1))))
values = defaultdict(lambda: defaultdict(lambda: (-1, -1)))
metric_names = set()

for (filename, seqname) in zip(files,labels):
	f_current = open(filename)

	f_current.readline() # skip header
	for line in f_current:
		line = line.strip()
		spl = line.split(";")
		(metric, avg, desv) = spl
		avg = float(avg)
		desv = float(desv)
		metric_names.add(metric)
		if "dd" in metric:
			avg /= 1024
			desv /= 1024
		values[metric][seqname] = (avg, desv)
	f_current.close()

print(metric_names)

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


plot_labels = []
metric_names = sorted(metric_names)

for metric in metric_names:
	print()
	print("processing", metric)

	if not len(plot_labels):
		plot_means = defaultdict(lambda: [])
		plot_errors = defaultdict(lambda: [])
		fig, ax = plt.subplots()
		plt.grid(b=True, which='major', color='gray', linestyle='--', lw=0.5, axis='y')

	plot_labels += (metric,)

	for seqname in sorted(values[metric].keys()):
		plot_means[seqname] += (values[metric][seqname][0],)
		plot_errors[seqname] += (values[metric][seqname][1],)

	if metric == metric_names[-1] or should_plot(metric, metric_names):

		print(plot_labels)
		print(plot_means)
		x = np.arange(len(plot_labels))  # the label locations
		# x = x*10
		width = 0.35  # the width of the bars
		where = - (len(plot_means.keys()) - 1) * width / 2
		for k,v in plot_means.items():
			print(k)
			print(v)
			myrects = ax.bar(x + where, v, width, yerr=plot_errors[k], label=k)
			where += width

		if "fio" in metric:
			ax.set_yscale('log')

		# Add some text for labels, title and custom x-axis tick labels, etc.
		ax.set_ylabel(get_ylabel(metric))
		# ax.set_title(title_from_metric(metric))
		ax.set_xticks(x)
		ax.set_xticklabels(format_plot_lables(plot_labels))
		ax.legend(loc='best')

		savetype = 'png'
		plt.savefig('r_' + metric[:3].strip() + '.' + savetype, format=savetype, dpi=300, bbox_inches='tight')

		plot_labels = []
