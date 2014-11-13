#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "loader.h"
#include "utils.h"

#include "syscalltbl.c"

/* 
* hardcode the kernel signatures.
* dirty hack.
*/
#define ARMExcVector 		"\x0E\x00\x00\xEA" "\x18\xF0\x9F\xE5" "\x18\xF0\x9F\xE5"
#define SIG1 					"\x00\x00\x00\x00"  "\x00\x00\x00\x00"  "\x01\x00\x00\x00"  "\x00\x00\x00\x00"  "\x01\x00\x00\x00"
#define SIG1_SUF 			"\x00\x00\x00\x00" "\x00\x00\x00\x00" "\x00\x00\x00\x00" "\x04\x00\x00\x00" 
#define SIG1_2423_ONWARDS "\x00\x00\x00\x00"  "\x00\x00\x00\x00"  "\x01\x00\x00\x00"  "\x00\x00\x00\x00"
#define SIG2_2423_ONWARDS "\x00\x00\x00\x00"  "\x00\x00\x00\x00"  "\x00\x00\x00\x00"  "\x01\x00\x04\x00"

void *sysent = NULL;
void *mach = NULL;
int ios7 = 0;

void dumpMachTraps(char *mach)
{
	int i;
	printf("\ndump mach_trap_table\n");
	if (mach)
		printf("Kern invalid should be %08x. Ignoring those\n", *((int *) &mach[4]));
	for (i = 0; i < 128; i++){
		int thumb = 0;
		int addr = * ((int *) (mach + 4 + 8*i));
		if (addr == *((int *) (mach + 4))) continue;
		if ((addr % 4) == 1) {addr--; thumb++;}
		if ((addr % 4) == -3) {addr--; thumb++;}
		if (addr % 4) {thumb = '?';}
		printf("%3d %-40s %x %s\n", i, mach_syscall_name_table[i], addr, (thumb? "T": "-"));
	}
}

void dumpPosixSyscall(void)
{
	int i;
	printf("\ndump posix_syscall_table\n");
	printf ("Suppressing enosys (0x%08x)\n", *(int *)(sysent + 20 + 24*4));
	for (i = 0;  i< (ios7 ? SYS_MAXSYSCALL_7 : SYS_MAXSYSCALL); i++){
		int suppress = 0;
		int thumb = 0;
		int jump = (ios7? 20 : 24);
		int addr = * ((int *) (sysent + 20 + jump*i));
		if (addr == *((int *)(sysent + 20 + jump * 8)))
			suppress =1;
		if ((addr % 4) == 1) { addr--; thumb++; }
		if ((addr % 4) == -3) { addr--; thumb++; }
		if (!suppress)
			printf ("%3d %-40s %x %s\n", i,syscall_names[i], addr, (thumb? "T": "-"));
	}
}

int main(int argc, char *argv[])
{
	u8 *buf;
	int filesize, i;
	uint32_t	magic;
	
	struct mach_header *phdr;
	struct load_command *ploadcmd;
	struct source_version_command *svc;

	if(argc < 2){
		printf("useage: %s [mach-o file]\n", argv[0]);
		return -1;		
	}
	buf = load_file(argv[1], &filesize);
	magic = *(u32 *)(buf);

	if((magic == FAT_MAGIC) || (magic == FAT_CIGAM)){
		printf("Erro: fat image is not support.\n");
		free(buf);
		return -1;		
	}
	phdr = (struct mach_header *)buf;
	if((MH_MAGIC !=phdr->magic) || (CPU_TYPE_ARM != phdr->cputype)){
		printf("Erro: not vaild arm mach-o file.\n");
		free(buf);
		return -1;		
	}
	printf("start to process file[%s]\n", argv[1]);
	ploadcmd = (struct load_command *)(buf+sizeof(struct mach_header));
	for(i=0; i<phdr->ncmds; i++, ploadcmd =(struct load_command *)((u8 *)ploadcmd+ploadcmd->cmdsize)){
		if(LC_SOURCE_VERSION == ploadcmd->cmd){
			svc = (struct source_version_command *)ploadcmd;
			printf("%-25s%ld.%d.%d.%d.%d\n", "Source Version:", (long) ((svc->version) >> 40),
				(int) (svc->version >> 30) & 0x000003FF,
				(int) (svc->version >> 20) & 0x000003FF,
				(int) (svc->version >> 10) & 0x000003FF,
				(int) (svc->version) & 0x000003FF);
			if (svc && (svc->version >> 40) >= 2423){
				printf("This is iOS 7.x, or later\n");
				ios7 = 1;
			}
			break;
		}
	}
	
	for(i = 0; i < filesize-50; i++){
		if (memcmp(buf+i, ARMExcVector, 12) == 0){
			printf("ARM Exception Vector is at file offset @[0x%x], addr [0x%x]\n", i, 0x80041000+i);
		}
		if (memcmp(buf+i, SIG1, 20) == 0){
			if (memcmp(buf+i+24, SIG1_SUF, 16) == 0){
				printf ("Sysent offset in file (for patching purposes) @[0x%08x], addr [0x%08x]\n",i-8, 0x80041000+(i -8));  
				sysent = buf + i - 24;
			}
		}
		if ((memcmp(buf+i, SIG1_2423_ONWARDS, 16) == 0) &&
			(memcmp(buf+i, SIG2_2423_ONWARDS, 16) ==0) &&
			(memcmp(buf+i, SIG1_2423_ONWARDS, 16) ==0)){
				printf ("Sysent offset in file (for patching purposes) @[0x%08x], addr [0x%08x]\n",i-8,0x80041000+(i -8));  
				sysent = buf + i - 24 ; 
		}
		if (! mach && (memcmp(buf+i, buf+i+40, 40) == 0) && (memcmp(buf+i, buf+i+32, 32) == 0) && 
			(memcmp(buf+i, buf+i+24, 24 ) == 0) && (memcmp(buf+i, buf+i+16, 16) == 0) &&
			(memcmp(buf+i, buf+i+24, 24) == 0) && (memcmp(buf+i, buf+i+8, 8) == 0) &&
			(  (!*((int *)(buf+i))) &&  *((int *)(buf+i+4)))){
				printf("mach_trap_table offset in file/memory (for patching purposes) @[0x%08x], addr [0x%08x]\n", i, 0x80041000+i);
				mach = buf+i;
				dumpMachTraps(mach);
		}
	}
	if(sysent){
		dumpPosixSyscall();
	}
	free(buf);
	return 0;
}

