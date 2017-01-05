#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "sys_xmergesort.h"
#include <string.h>
#ifndef __NR_xmergesort
#error xmergesort system call not defined
#endif

/* start of main */
int main(int argc, char *argv[])
{
	long rc;
	unsigned int dataVar = 0;
	int opt;
	int dExists = 0;
	int check = 0;
	struct xmergesort_args args;

	if (argc < 5) {
		printf("\n One or more arguments missing....");
		rc = -1;
		goto end;
	} else if (argc == 5) {
		strcpy(args.inputFile1, argv[3]);
		strcpy(args.inputFile2, argv[4]);
		strcpy(args.outputFile, argv[2]);
		args.flag = 0;
		args.data = &dataVar;
		while ((opt = getopt(argc, argv, "uaitd")) != -1) {
			switch (opt) {
			case 'u':
				args.flag = args.flag | 0x01;
				break;
			case 'a':
				args.flag = args.flag | 0x02;
				break;
			case 'i':
				args.flag = args.flag | 0x04;
				break;
			case 't':
				args.flag = args.flag | 0x10;
				break;
			case 'd':
				args.flag = args.flag | 0x20;
				dExists = 1;
				break;
			default:
				check = 1;
			}
			if (check == 1)
				args.flag = 0;

		}
	} else {
		printf("\nToo many arguments passed...");
		rc = -1;
		goto end;
	}

	void *dummy = (void *) &args;

	rc = syscall(__NR_xmergesort, dummy);

	if (rc == 0) {
		if (dExists)
			printf("\nNumber of sorted records produced = %d", dataVar);
		printf("\nMerge Successful...syscall returned %ld", rc);
	} else {
		printf("\nsyscall returned %ld (errno=%d)", rc, errno);
	}

end:
	exit(rc);
} /* end of main */
