**Order to run the programs**

1. run uio_requester_bench multiple times
2. data_extraction
3. data_analysis

Running uio_requester_bench multiple times can be automated as follows (to run 100 times):

```Shell Session
for i in `seq 1 100`; do uio_requester_bench > uio_requester_i${i}.log; done
```


To create a .csv file summarizing the .log files you have to run:

``` Shell Session
python3 data_extraction2.py <file_name> <extreme_a> <extreme_b>
```

The command above will take every .log file from extreme_a to extreme_b (including them) and create a .csv file named file_name.csv.
For example, if uio_requester_bench was executed as the previous example: `python3 data_extraction2.py uio_requester 1 100`

The next step would be analysing the data and generate a graph, that can be done by running:

``` Shell Session
python3 data_analysis2.py <file_name> <file_format>
```

This will take the file_name.csv file and create a graph out of it named file_name.file_format.
For example: `python3 data_analysis2.py uio_requester png`


