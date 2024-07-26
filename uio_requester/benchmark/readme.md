**Order to run the programs**

1. script
2. data_extraction
3. data_analysis

To generate the .log files, run withing the VM:
``` Shell Session
run_uio_requester.sh
```
Requester logs will be generated at the running directory, while responder logs are generate at the qemu running directory.


To create a .csv file with the .log files you have to run:

``` Shell Session
python3 data_extraction2.py <file_name> <extreme_a> <extreme_b>
```

The line of code above will take every .log file between extreme_a and extreme_b (including them) and create a .csv file named file_name.csv

The next step would be analysing the data and generate a graph, that can be done by running:

``` Shell Session
python3 data_analysis2.py <file_name> <file_format>
```

This will take the file_name.csv file and create a graph out of it named file_name.file_format


