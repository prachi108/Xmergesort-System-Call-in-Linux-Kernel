/*  This structure is used to pass the arguments value from userland to the kernel method  */
struct xmergesort_args{
	
	char inputFile1[512];
	char inputFile2[512];
	char outputFile[512];
	unsigned int flag;
	unsigned int *data;
};

