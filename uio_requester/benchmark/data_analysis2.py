import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.transforms

graph_name = sys.argv[1]
format_name = sys.argv[2]


def plot(graph_name: str, format_name: str) -> None:

    df = pd.read_csv(graph_name + ".csv", index_col=0)

    width = 0.35
    fig = plt.figure()
    ax1 = fig.add_subplot(111)
    plt.grid(True, which="both", linestyle='--')
    ax1.set_axisbelow(True)
    values = df.index
    ax1.bar(np.arange(len(values)) - width/2, df['Number of cycles'],
            width, yerr=df['NoC_IC'], color='red')
    print(df)
    # print(values[0])
    ax2 = ax1.twinx()
    ax2.bar(np.arange(len(values)) + width/2, df['Execution time'],
            width, yerr=df['ET_IC'], color='blue')

    ax1.set_ylabel("Number of cycles", color='red')

    ax2.set_ylabel("Execution time (ns)", color='blue')

    ax1.tick_params(axis='y', colors='red')

    ax2.spines['right'].set_color('blue')
    ax2.spines['left'].set_color('red')
    ax2.tick_params(axis='y', colors='blue')
    ax2.set_yscale("log")
    ax2.yaxis.set_tick_params(width=1, length=6, which='both')

    ax1.set_xticks(np.arange(len(values)))
    ax1.set_xticklabels(values, rotation=45, ha='right', fontsize=8)
    ax1.set_yscale("log")
    ax1.yaxis.set_tick_params(width=1, length=6, which='both')

    # props = dict(boxstyle='round', facecolor='white', alpha=1, edgecolor='none')
    # textstr = "logscale"
    # ax1.text(0.02, 1.07, textstr, transform=ax1.transAxes, fontsize=14,
    #          verticalalignment='top', bbox=props)


    plt.subplots_adjust(top=0.95,
                        bottom=0.335,
                        left=0.135,
                        right=0.900,
                        hspace=0.2,
                        wspace=0.2)

    # Create offset transform by 5 points in x direction
    dx = 5/72.
    dy = 0/72.
    offset = matplotlib.transforms.ScaledTranslation(dx,
                                                     dy,
                                                     fig.dpi_scale_trans)

    # apply offset transform to all x ticklabels.
    for label in ax1.xaxis.get_ticklabels(which='both'):
        label.set_transform(label.get_transform() + offset)

    fig.savefig(graph_name + '.' + format_name, format=format_name)


plot(graph_name, format_name)
