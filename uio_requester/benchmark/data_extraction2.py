import pandas as pd
import numpy as np
import sys
from scipy.stats import t
from typing import List

file_name = sys.argv[1]
extreme_a = int(sys.argv[2])
extreme_b = int(sys.argv[3])


files_list = []

number_of_files = extreme_b - extreme_a + 1

while extreme_a != extreme_b:
    files_list.append(str(extreme_a))
    extreme_a += 1
files_list.append(str(extreme_b))


def read_data(filename: str) -> pd.DataFrame:
    file_name = filename
    f = open(file_name, "r")
    index, cycles, ns, instructions = [], [], [], []
    while True:
        line = f.readline().split()
        if (not line):
            break
        index.append(line[0][:-1])
        cycles.append(line[1])
        ns.append(line[3])
        instructions.append(line[5])
    steps_dic = {
        "Number of cycles": cycles,
        "Execution time": ns,
        "Instructions": instructions
    }
    df = pd.DataFrame(steps_dic, index=index)
    f.close()
    return df


def mean_of_files(files_list: List[str], number_of_lines: int) -> pd.DataFrame:
    global number_of_files

    # Initializing vector to calculate the average
    noc_f = np.zeros(number_of_lines)
    et_f = np.zeros(number_of_lines)
    ins_f = np.zeros(number_of_lines)

    # Initializing std matrixes
    std_matrix_noc = [[0] for i in range(number_of_lines)]
    std_matrix_et = [[0] for i in range(number_of_lines)]
    std_matrix_ins = [[0] for i in range(number_of_lines)]

    # Iterate over files and separate data
    for i in files_list:
        df_i = read_data(file_name + "_i" + i + ".log")
        noc = np.array(df_i["Number of cycles"], dtype=np.float64)
        et = np.array(df_i["Execution time"], dtype=np.float64)
        ins = np.array(df_i["Instructions"], dtype=np.float64)
        for j in range(len(noc)):
            std_matrix_noc[j].append(noc[j])
            std_matrix_et[j].append(et[j])
            std_matrix_ins[j].append(ins[j])
        noc_f = noc_f + noc
        et_f = et_f + et
        ins_f = ins_f + ins

    # Calculating the averages
    noc_f = noc_f/number_of_files
    et_f = et_f/number_of_files
    ins_f = ins_f/number_of_files

    index = df_i.index

    # Pop initial 0 value
    for j in range(number_of_lines):
        std_matrix_noc[j].pop(0)
        std_matrix_et[j].pop(0)
        std_matrix_ins[j].pop(0)

    # Calculating sample stds
    std_vector_noc = np.array([np.std(i, ddof=1) for i in std_matrix_noc])
    std_vector_et = np.array([np.std(i, ddof=1) for i in std_matrix_et])
    std_vector_ins = np.array([np.std(i, ddof=1) for i in std_matrix_ins])

    # Calculations Confidence Intervals
    t_student = t.ppf(0.975, number_of_files - 1)

    ic_et = t_student*std_vector_et/np.sqrt(number_of_files)
    ic_noc = t_student*std_vector_noc/np.sqrt(number_of_files)
    ic_ins = t_student*std_vector_ins/np.sqrt(number_of_files)

    dic_final = {
        "Number of cycles": noc_f,
        "Execution time": et_f,
        "Instruction": ins_f,
        "NoC_std": std_vector_noc,
        "ET_std": std_vector_et,
        "Ins_std": std_vector_ins,
        "NoC_IC": ic_noc,
        "ET_IC": ic_et,
        "Ins_IC": ic_ins
    }

    df_final = pd.DataFrame(dic_final, index=index)
    return df_final


def save_data(df: pd.DataFrame):
    df.to_csv(file_name + ".csv")
    return np.nan


if __name__ == "__main__":
    number_of_lines = 0
    f = open(f'{file_name}_i{extreme_a}.log', "r")
    for line in f:
        if line !="\n":
            number_of_lines += 1
    f.close()
    df = mean_of_files(files_list, number_of_lines)
    save_data(df)
