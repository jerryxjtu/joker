#ifndef __UTILS_H__
#define __UTILS_H__

typedef signed int   		s32;
typedef signed short 		s16;
typedef signed char  		s8;
typedef unsigned int   		u32;
typedef unsigned short 	u16;
typedef unsigned char  	u8;

//export functions
FILE *open_file(char *name, int *size);
u8 *load_file(char *name, int *size);
int save_file(char *name, void *buf, int size);
void hex_dump(char *str, void *buf, int size);

#endif /* __UTILS_H__ */
