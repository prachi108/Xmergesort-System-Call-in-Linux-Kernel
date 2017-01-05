#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "sys_xmergesort.h"
#include <linux/ctype.h>
#include <linux/string.h>
#define BUFF_SIZE 4096


asmlinkage extern long (*sysptr)(void *arg);

void stringCopy(char *dest, int destSize, char *source, int sourceSize)
{
	int i = 0;
	while (i < sourceSize) {
		dest[i] = source[i];
		i++;
	}
	destSize = sourceSize;
}


int extract(char *buff, int buffSize, int *offset, char *res, int *flag)
{
	/* this method will return resSize */
	int resSize = 0;
	int i;
	*flag = 0;
	for (i = *offset; i < buffSize; i++) {
		if (buff[i] == '\n' && resSize != 0) {
			*offset = i+1;
			return resSize;
		}
		if (buff[i] == '\n')
			continue;
		res[resSize] = buff[i];
		resSize++;
	}
	*flag = 1;
	*offset = i;
	return resSize;
}


int embed(char *temp, int tempSize, char *outBuff, int *offset, int *outBuffSize)
{
	/* return 1 on SUCCESS AND 0 on FAILURE */
	int i;
	int j = 0;
	if (tempSize > (BUFF_SIZE - *offset))
		return 0;
	for (i = *offset; j < tempSize; i++) {
		outBuff[i] = temp[j];
		(*offset)++;
		(*outBuffSize)++;
		j++;
	}
	outBuff[i] = '\n';
	(*offset)++;
	(*outBuffSize)++;
	return 1;
}


int compareCaseSensitive(char *w1, int l1, char *w2, int l2)
{
	/* -returns 1 if w1 is greater
	   -returns -1 if w2 is greater
	   -returns 0 if both are equal */
	int j;
	int i = l1 >= l2 ? l2 : l1;

	if (l1 == 0 && l2 != 0)
		return 1;

	if (l1 != 0 && l2 == 0)
		return -1;

	for (j = 0; j < i; j++) {
		if (w1[j] > w2[j])
			return 1;
		if (w1[j] < w2[j])
			return -1;
	}
	if (l1 == l2)
		return 0;
	else if (l1 > l2)
		return 1;
	else
		return -1;
}



int compareCaseInsensitive(char *w1, int l1, char *w2, int l2)
{
	/* -returns 1 if w1 is greater
	   -returns -1 if w2 is greater
	   -returns 0 if both are equal  */
	int j;
	int i = l1 >= l2 ? l2 : l1;

	if (l1 == 0 && l2 != 0)
		return 1;

	if (l1 != 0 && l2 == 0)
		return -1;

	for (j = 0; j < i; j++) {
		if (toupper(w1[j]) > toupper(w2[j]))
			return 1;
		if (toupper(w1[j]) < toupper(w2[j]))
			return -1;
	}
	if (l1 == l2)
		return 0;
	else if (l1 > l2)
		return 1;
	else
		return -1;
}




int file_open(const char *path, int flags, int rights, struct file **fileptr)
{
	struct file *filp = NULL;
	mm_segment_t oldfs;
	oldfs = get_fs();
	set_fs(get_ds());
	filp = filp_open(path, flags, rights);
	set_fs(oldfs);
	if (IS_ERR(filp)) {
		*fileptr = NULL;
		return PTR_ERR(filp);
	}
	*fileptr = filp;
	return 0;
}


void file_close(struct file **fileptr)
{
	if (*fileptr != NULL)
		filp_close(*fileptr, NULL);
	*fileptr = NULL;
}


int file_read(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size)
{
	mm_segment_t oldfs;
	int ret;

	oldfs = get_fs();
	set_fs(get_ds());

	ret = vfs_read(file, data, size, &offset);

	set_fs(oldfs);
	return ret;
}



int file_write(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size)
{
	mm_segment_t oldfs;
	int ret;

	oldfs = get_fs();
	set_fs(get_ds());

	ret = vfs_write(file, data, size, &offset);

	set_fs(oldfs);
	return ret;
}


void file_remove(struct file **fileptr)
{
	int ret_unlink;
	mm_segment_t oldfs;
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	ret_unlink = vfs_unlink((*fileptr)->f_path.dentry->d_parent->d_inode, (*fileptr)->f_path.dentry, NULL);
	set_fs(oldfs);
	if (ret_unlink)
		printk(KERN_ALERT "Could not unlink output file \n");
	file_close(fileptr);
}


asmlinkage long xmergesort(void *arg)
{
	struct xmergesort_args *args = (struct xmergesort_args *) arg;
	struct file *inpFile1Ptr = NULL;
	int inpFile1Offset = 0;
	struct file *inpFile2Ptr = NULL;
	int inpFile2Offset = 0;
	struct file *outFilePtr = NULL;
	int outFileOffset = 0;
	char *buff1 = NULL;
	int buff1Size = 0;
	int buff1Offset = 0;
	char *buff2 = NULL;
	int buff2Size = 0;
	int buff2Offset = 0;
	char *outBuff = NULL;
	int outBuffSize = 0;
	int outBuffOffset = 0;
	char *temp1 = NULL;
	int temp1Size = 0;
	int temp1Offset = 0;
	char *temp2 = NULL;
	int temp2Size = 0;
	int temp2Offset = 0;
	char *pastBuff = NULL;
	int pastBuffSize = 1;
	int flag = 0;
	int i, j;
	int error_no = 0;

	int uExists = (args->flag & 0x01) == 0x01?1:0;
	int aExists = (args->flag & 0x02) == 0x02?1:0;
	int iExists = (args->flag & 0x04) == 0x04?1:0;
	int tExists = (args->flag & 0x10) == 0x10?1:0;
	int dExists = (args->flag & 0x20) == 0x20?1:0;

	printk("\nfewiferifnierngke");
	/* flag validation */
	if (args->flag == 0) {
		error_no = -EINVAL;
		goto end;
	}
	if (uExists && aExists) {
		error_no = -EINVAL;
		goto end;
	}
	if (!uExists && !aExists) {
		error_no = -EINVAL;
		goto end;
	}
	if (dExists) {
		(*(args->data)) = 0;
	}

	/* dummy syscall: returns 0 for non null, -EINVAL for NULL */
	if (args == NULL) {
		error_no = -EINVAL;
		goto end;
	} else {
		/* checking the validity of input file paths and trying to open all files */
		i = access_ok(VERIFY_READ, args->inputFile1, strlen(args->inputFile1));
		if (i == 0) {
			error_no = -EACCES;
			goto end;
		}
		i = access_ok(VERIFY_READ, args->inputFile2, strlen(args->inputFile2));
		if (i == 0) {
			error_no = -EACCES;
			goto end;
		}
		i = file_open(args->inputFile1, O_RDONLY, 0, &inpFile1Ptr);
		if (i != 0) {
			error_no = i;
			goto end;
		}
		i = file_open(args->inputFile2, O_RDONLY, 0, &inpFile2Ptr);
		if (i != 0) {
			error_no = i;
			goto end1;
		}
		i = file_open(args->outputFile, O_WRONLY|O_CREAT|O_TRUNC, 0, &outFilePtr);
		if (i != 0) {
			error_no = i;
			goto end2;
		}

		/* allocating all 6 buffers */
		buff1 = (char *)kmalloc(sizeof(char) * BUFF_SIZE, GFP_KERNEL);
		if (buff1 == NULL) {
			error_no = -ENOMEM;
			goto end3;
		}
		buff2 = (char *)kmalloc(sizeof(char) * BUFF_SIZE, GFP_KERNEL);
		if (buff2 == NULL) {
			error_no = -ENOMEM;
			goto end4;
		}
		outBuff = (char *)kmalloc(sizeof(char) * BUFF_SIZE, GFP_KERNEL);
		if (outBuff == NULL) {
			error_no = -ENOMEM;
			goto end5;
		}
		temp1 = (char *)kmalloc(sizeof(char) * BUFF_SIZE, GFP_KERNEL);
		if (temp1 == NULL) {
			error_no = -ENOMEM;
			goto end6;
		}
		temp2 = (char *)kmalloc(sizeof(char) * BUFF_SIZE, GFP_KERNEL);
		if (temp2 == NULL) {
			error_no = -ENOMEM;
			goto end7;
		}
		pastBuff = (char *)kmalloc(sizeof(char) * BUFF_SIZE, GFP_KERNEL);
		if (pastBuff == NULL) {
			error_no = -ENOMEM;
			goto end8;
		}
		pastBuff[0] = -128;

		/* initializing buff1, buff2, temp1, temp2 */
		buff1Size = file_read(inpFile1Ptr, inpFile1Offset, buff1, BUFF_SIZE);
		buff1Offset = 0;
		inpFile1Offset += buff1Size;
		buff2Size = file_read(inpFile2Ptr, inpFile2Offset, buff2, BUFF_SIZE);
		buff2Offset = 0;
		inpFile2Offset += buff2Size;
		temp1Size = extract(buff1, buff1Size, &buff1Offset, temp1, &flag);
		temp2Size = extract(buff2, buff2Size, &buff2Offset, temp2, &flag);


		while (temp1Size != 0 || temp2Size != 0) {
			if (temp1Size != 0 || temp2Size != 0) {
				if (iExists)
					i = compareCaseInsensitive(temp1, temp1Size, temp2, temp2Size);
				else
					i = compareCaseSensitive(temp1, temp1Size, temp2, temp2Size);
				if (i > 0) {
					if (iExists)
						j = compareCaseInsensitive(pastBuff, pastBuffSize, temp2, temp2Size);
					else
						j = compareCaseSensitive(pastBuff, pastBuffSize, temp2, temp2Size);
					if (j == 1 && tExists == 1) {
						error_no = -EINVAL;
						goto partialOutput;
					} else if (j <= 0) {
						j = embed(temp2, temp2Size, outBuff, &outBuffOffset, &outBuffSize);
						if (j == 0) {
							file_write(outFilePtr, outFileOffset, outBuff, outBuffSize);
							outFileOffset += outBuffSize;
							outBuffOffset = 0;
							outBuffSize = 0;
							embed(temp2, temp2Size, outBuff, &outBuffOffset, &outBuffSize);
						}
						stringCopy(pastBuff, pastBuffSize, temp2, temp2Size);
						if (dExists)
							(*(args->data))++;
					}
					temp2Size = 0;
					temp2Offset = 0;
					temp2Size = extract(buff2, buff2Size, &buff2Offset, temp2, &flag);
					if (temp2Size == 0) {
						buff2Size = file_read(inpFile2Ptr, inpFile2Offset, buff2, BUFF_SIZE);
						buff2Offset = 0;
						inpFile2Offset = inpFile2Offset + buff2Size;
						temp2Size = extract(buff2, buff2Size, &buff2Offset, temp2, &flag);
					} else if (flag == 1) {
						inpFile2Offset = inpFile2Offset - temp2Size;
						buff2Size = file_read(inpFile2Ptr, inpFile2Offset, buff2, BUFF_SIZE);
						buff2Offset = 0;
						inpFile2Offset = inpFile2Offset + buff2Size;
						temp2Size = extract(buff2, buff2Size, &buff2Offset, temp2, &flag);
					}
				} else if (i == 0) {
					if (iExists)
						j = compareCaseInsensitive(pastBuff, pastBuffSize, temp2, temp2Size);
					else
						j = compareCaseSensitive(pastBuff, pastBuffSize, temp2, temp2Size);
					if (j == 1 && tExists == 1) {
						error_no = -EINVAL;
						goto partialOutput;
					} else if (j <= 0 && aExists) {
						j = embed(temp2, temp2Size, outBuff, &outBuffOffset, &outBuffSize);
						if (j == 0) {
							file_write(outFilePtr, outFileOffset, outBuff, outBuffSize);
							outFileOffset += outBuffSize;
							outBuffOffset = 0;
							outBuffSize = 0;
							embed(temp2, temp2Size, outBuff, &outBuffOffset, &outBuffSize);
						}
						stringCopy(pastBuff, pastBuffSize, temp2, temp2Size);
						if (dExists)
							(*(args->data))++;
					}
					temp2Size = 0;
					temp2Offset = 0;
					temp2Size = extract(buff2, buff2Size, &buff2Offset, temp2, &flag);
					if (temp2Size == 0) {
						buff2Size = file_read(inpFile2Ptr, inpFile2Offset, buff2, BUFF_SIZE);
						buff2Offset = 0;
						inpFile2Offset = inpFile2Offset + buff2Size;
						temp2Size = extract(buff2, buff2Size, &buff2Offset, temp2, &flag);
					} else if (flag == 1) {
						inpFile2Offset = inpFile2Offset - temp2Size;
						buff2Size = file_read(inpFile2Ptr, inpFile2Offset, buff2, BUFF_SIZE);
						buff2Offset = 0;
						inpFile2Offset = inpFile2Offset + buff2Size;
						temp2Size = extract(buff2, buff2Size, &buff2Offset, temp2, &flag);
					}
				} else {
					if (iExists)
						j = compareCaseInsensitive(pastBuff, pastBuffSize, temp1, temp1Size);
					else
						j = compareCaseSensitive(pastBuff, pastBuffSize, temp1, temp1Size);
					if (j == 1 && tExists == 1) {
						error_no = -EINVAL;
						goto partialOutput;
					} else if (j <= 0) {
						j = embed(temp1, temp1Size, outBuff, &outBuffOffset, &outBuffSize);
						if (j == 0) {
							file_write(outFilePtr, outFileOffset, outBuff, outBuffSize);
							outFileOffset += outBuffSize;
							outBuffOffset = 0;
							outBuffSize = 0;
							embed(temp1, temp1Size, outBuff, &outBuffOffset, &outBuffSize);
						}
						stringCopy(pastBuff, pastBuffSize, temp1, temp1Size);
						if (dExists)
							(*(args->data))++;
					}
					temp1Size = 0;
					temp1Offset = 0;
					temp1Size = extract(buff1, buff1Size, &buff1Offset, temp1, &flag);
					if (temp1Size == 0) {
						buff1Size = file_read(inpFile1Ptr, inpFile1Offset, buff1, BUFF_SIZE);
						buff1Offset = 0;
						inpFile1Offset = inpFile1Offset + buff1Size;
						temp1Size = extract(buff1, buff1Size, &buff1Offset, temp1, &flag);
					} else if (flag == 1) {
						inpFile1Offset = inpFile1Offset - temp1Size;
						buff1Size = file_read(inpFile1Ptr, inpFile1Offset, buff1, BUFF_SIZE);
						buff1Offset = 0;
						inpFile1Offset = inpFile1Offset + buff1Size;
						temp1Size = extract(buff1, buff1Size, &buff1Offset, temp1, &flag);
					}
				}
			}
		}
		file_write(outFilePtr, outFileOffset, outBuff, outBuffSize);
		outFileOffset += outBuffSize;
		outBuffOffset = 0;
		outBuffSize = 0;
		kfree(pastBuff);
		kfree(temp1);
		kfree(temp2);
		kfree(outBuff);
		kfree(buff2);
		kfree(buff1);
		error_no = 0;
		file_close(&outFilePtr);
		goto end2;
	}

partialOutput:
	kfree(pastBuff);
end8:
	kfree(temp2);
end7:
	kfree(temp1);
end6:
	kfree(outBuff);
end5:
	kfree(buff2);
end4:
	kfree(buff1);
end3:
	file_remove(&outFilePtr);
end2:
	file_close(&inpFile2Ptr);
end1:
	file_close(&inpFile1Ptr);
end:
	return error_no;

}



static int __init init_sys_xmergesort(void)
{
	printk("installed new sys_xmergesort module\n");
	if (sysptr == NULL)
		sysptr = xmergesort;
	return 0;
}

static void  __exit exit_sys_xmergesort(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xmergesort module\n");
}



module_init(init_sys_xmergesort);
module_exit(exit_sys_xmergesort);
MODULE_LICENSE("GPL");
