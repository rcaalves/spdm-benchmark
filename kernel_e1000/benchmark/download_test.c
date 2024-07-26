#include<sys/time.h>
#include<stdio.h>
#include<stdlib.h>

int main(int argc,char** argv)
{
	if(argc<4)
	{
		printf("Usage: %s [target: port] [input file] [iterations] \n", argv[0]);
		return 0;
	}
	FILE* inputs = fopen(argv[2], "r");
	if(!inputs)
	{
		printf("Failed to open file %s\n", argv[2]);
		return 0;
	}
	struct timeval start, end;
	int iterations = atoi (argv[3]);
	char *line = NULL;
	size_t len;
	ssize_t read;
	while ((read = getline(&line, &len, inputs)) != -1)
	{
		char outfile[0x100];
		char cmd[0x1000];
		line[read-1]=0;
		sprintf(outfile, "%s.time", line);
		FILE* output = fopen(outfile, "w");
		printf("%s\n", outfile);
		int i;
		for(i = 0; i < iterations; ++i)
		{
			sprintf(cmd, "wget -q %s/%s", argv[1], line);
			gettimeofday (&start, NULL);
			system(cmd);
			gettimeofday(&end, NULL);
			sprintf (cmd, "rm -f %s", line);
			system(cmd);
			long secs, usecs;
			secs = end.tv_sec - start.tv_sec;
			usecs = (secs*1000000 + end.tv_usec - start.tv_usec);
			sprintf(cmd, "%ld\n", usecs);
			fputs(cmd ,output);
		}
		fclose(output);
	}
	fclose(inputs);
	free(line);
	return 0;
}