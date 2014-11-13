#include <stdio.h>
#include <stdlib.h>
#include "utils.h"

FILE *open_file(char *name, int *size)
{
	FILE *fp;
	fp = fopen(name, "rb");
	if(fp==NULL){
		perror("open_file");
		return NULL;
	}
	fseek(fp, 0, SEEK_END);
	*size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	return fp;
}

u8 *load_file(char *name, int *size)
{
	FILE *fp;
	u8 *buf;
	fp = open_file(name, size);
	if(fp==NULL)
		return NULL;
	buf = malloc(*size);
	fread(buf, *size, 1, fp);
	fclose(fp);
	return buf;
}

int save_file(char *name, void *buf, int size)
{
	FILE *fp;
	fp = fopen(name, "wb");
	if(fp==NULL){
		printf("Open file %s failed!\n", name);
		return -1;
	}
	fwrite(buf, size, 1, fp);
	fclose(fp);
	return 0;
}

void hex_dump(char *str, void *buf, int size)
{
	int i;
	u8 *ubuf = buf;

	if(str)
		printf("%s:", str);

	for(i=0; i<size; i++){
		if((i%16)==0){
			printf("\n%4x:", i);
		}
		printf(" %02x", ubuf[i]);
	}
	printf("\n\n");
}

