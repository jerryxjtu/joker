
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
//#include <segment.hpp>
#include <diskio.hpp>
#include <kernwin.hpp>
#include <name.hpp>

#include "loader.h"
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

static const char comment[] = "Find out syscalls from xnu kernel (arm only)";
void *sysent = NULL;
unsigned char *mach = NULL;
int ios7 = 0;

static void dumpMachTraps(unsigned char *mach)
{
	int i;
	msg("\ndump mach_trap_table\n");
	if (mach){
		msg("Kern invalid should be %08x. Ignoring those\n", *((int *) &mach[4]));
		set_name((ea_t)(*((int *) &mach[4])), "kern_invalid", SN_NOWARN);
	}
	for (i = 0; i < 128; i++){
		int thumb = 0;
		int addr = * ((int *) (mach + 4 + 8*i));
		if (addr == *((int *) (mach + 4))) continue;
		if ((addr % 4) == 1) {addr--; thumb++;}
		if ((addr % 4) == -3) {addr--; thumb++;}
		if (addr % 4) {thumb = '?';}
		msg("%3d %-40s %x %s\n", i, mach_syscall_name_table[i], addr, (thumb? "T": "-"));
		set_name((ea_t)addr, mach_syscall_name_table[i], SN_NOWARN);
	}
}

static void dumpPosixSyscall(void)
{
	int i;
	msg("\ndump posix_syscall_table\n");
	msg("Suppressing enosys (0x%08x)\n", *(int *)((char *)sysent + 20 + 24*4));
	for (i = 0;  i< (ios7 ? SYS_MAXSYSCALL_7 : SYS_MAXSYSCALL); i++){
		int suppress = 0;
		int thumb = 0;
		int jump = (ios7? 20 : 24);
		int addr = * ((int *) ((char *)sysent + 20 + jump*i));
		if (addr == *((int *)((char *)sysent + 20 + jump * 8)))
			suppress =1;
		if ((addr % 4) == 1) { addr--; thumb++; }
		if ((addr % 4) == -3) { addr--; thumb++; }
		if (!suppress){
			msg("%3d %-40s %x %s\n", i, syscall_names[i], addr, (thumb? "T": "-"));
			set_name((ea_t)addr, syscall_names[i], SN_NOWARN);
		}
	}
}

int idaapi joker_init(void)
{
	if(ph.id != PLFM_ARM)
		return PLUGIN_SKIP;
	if(inf.filetype != f_MACHO)
		return PLUGIN_SKIP;
	return PLUGIN_OK;
}

void idaapi joker_run(int)
{
	struct mach_header *phdr;
	struct load_command *ploadcmd;
	struct source_version_command *svc;
	unsigned char *buf;
	int i, filesize;
	char *kernelfile;
	linput_t *li;
	
	msg("Joker start to run...\n");
#if 0
	segment_t *s;
	unsigned char *hdr;
	s = get_segm_by_name("HEADER");
	msg("Find header at [%08x] ~ [%08x]\n", s->startEA, s->endEA);
	hdr = (unsigned char *)qalloc(s->endEA - s->startEA);
	get_many_bytes(s->startEA, hdr, s->endEA - s->startEA);

	phdr = (struct mach_header *)hdr;
	ploadcmd = (struct load_command *)(hdr+sizeof(struct mach_header));
	for(i=0; i<phdr->ncmds; i++, ploadcmd =(struct load_command *)((unsigned char *)ploadcmd+ploadcmd->cmdsize)){
		if(LC_SOURCE_VERSION == ploadcmd->cmd){
			svc = (struct source_version_command *)ploadcmd;
			msg("%-25s%ld.%d.%d.%d.%d\n", "Source Version:", (long) ((svc->version) >> 40),
				(int) (svc->version >> 30) & 0x000003FF,
				(int) (svc->version >> 20) & 0x000003FF,
				(int) (svc->version >> 10) & 0x000003FF,
				(int) (svc->version) & 0x000003FF);
			if (svc && (svc->version >> 40) >= 2423){
				msg("This is iOS 7.x, or later\n");
				ios7 = 1;
			}
			break;
		}
	}	
	free(hdr);
#endif
	kernelfile = askfile_c(0, NULL, "Select orgi kernel mach-o file");
	if ( kernelfile == NULL){
		msg("Quit as NO file selected\n");
		return;
	}
	li = open_linput(kernelfile, false);
	if ( li == NULL ){
		msg("Open kernel file failed\n");
		return;
	}
	filesize = qlsize(li);
	buf = (unsigned char *)qalloc(filesize);
	qlread(li, buf, filesize);
	close_linput(li);

	phdr = (struct mach_header *)buf;
	ploadcmd = (struct load_command *)(buf+sizeof(struct mach_header));
	for(i=0; i<phdr->ncmds; i++, ploadcmd =(struct load_command *)((unsigned char *)ploadcmd+ploadcmd->cmdsize)){
		if(LC_SOURCE_VERSION == ploadcmd->cmd){
			svc = (struct source_version_command *)ploadcmd;
			msg("%-25s%ld.%d.%d.%d.%d\n", "Source Version:", (long) ((svc->version) >> 40),
				(int) (svc->version >> 30) & 0x000003FF,
				(int) (svc->version >> 20) & 0x000003FF,
				(int) (svc->version >> 10) & 0x000003FF,
				(int) (svc->version) & 0x000003FF);
			if (svc && (svc->version >> 40) >= 2423){
				msg("This is iOS 7.x, or later\n");
				ios7 = 1;
			}
			break;
		}
	}
	for(i = 0; i < filesize-50; i++){
		if (memcmp(buf+i, ARMExcVector, 12) == 0){
			msg("ARM Exception Vector is at file offset @[0x%x], addr [0x%x]\n", i, 0x80041000+i);
			set_name((ea_t)(0x80041000+i), "_Exception_Vector", SN_NOWARN);
		}
		if (memcmp(buf+i, SIG1, 20) == 0){
			if (memcmp(buf+i+24, SIG1_SUF, 16) == 0){
				msg("Sysent offset in file (for patching purposes) @[0x%08x], addr [0x%08x]\n",i-8, 0x80041000+(i -8));  
				sysent = buf + i - 24;
			}
		}
		if ((memcmp(buf+i, SIG1_2423_ONWARDS, 16) == 0) &&
			(memcmp(buf+i, SIG2_2423_ONWARDS, 16) ==0) &&
			(memcmp(buf+i, SIG1_2423_ONWARDS, 16) ==0)){
				msg("Sysent offset in file (for patching purposes) @[0x%08x], addr [0x%08x]\n",i-8,0x80041000+(i -8));  
				sysent = buf + i - 24 ; 
		}
		if (! mach && (memcmp(buf+i, buf+i+40, 40) == 0) && (memcmp(buf+i, buf+i+32, 32) == 0) && 
			(memcmp(buf+i, buf+i+24, 24 ) == 0) && (memcmp(buf+i, buf+i+16, 16) == 0) &&
			(memcmp(buf+i, buf+i+24, 24) == 0) && (memcmp(buf+i, buf+i+8, 8) == 0) &&
			(  (!*((int *)(buf+i))) &&  *((int *)(buf+i+4)))){
				msg("mach_trap_table offset in file/memory (for patching purposes) @[0x%08x], addr [0x%08x]\n", i, 0x80041000+i);
				mach = buf+i;
				dumpMachTraps(mach);
		}
	}
	if(sysent){
		dumpPosixSyscall();
	}	
	qfree(buf);
	return;
}

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_UNL,		// plugin flags
	joker_init,		// initialize
	NULL,			// terminate. this pointer may be NULL.
	joker_run,		// invoke plugin
	comment,		// long comment about the plugin
	NULL,			// multiline help about the plugin
	"Joker (to export xnu syscall)",	// the preferred short name of the plugin
	NULL			// the preferred hotkey to run the plugin
};

