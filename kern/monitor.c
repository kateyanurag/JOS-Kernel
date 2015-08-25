// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/trap.h>
#include <kern/challenge.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "mon_backtrace", "Calls mon_backtrace function", mon_backtrace},
	{ "backtrace", "To backtrace functions and print debug information", mon_backtrace},
	{ "showmappings", "To display all physical page mappings that apply to a particular range of physical address", showmappings},
	{ "setperms" , "parameters --perm, --va. Sets permissions for the mapping at va", setperms},
	{ "clearperms", "parameters --perm, --va. Sets permissions for the mapping at va" , clearperms},
	{ "changeperms" , "parameters --perm, --va. Sets permissions for the mapping at va" , changeperms},
	{ "dump" , "parameters --perm, --va. Sets permissions for the mapping at va" , dump}
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}


char *
truncate_func_name(const char *str){
	int i=0;
	int count = 0;
	char *name = "";
	cprintf("\n IN TRUNCATE: %s", str);
	while(str[i] != ':'){
		i++;
		count ++;
	}
	strncpy(name, str, count);
	return name;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{


		int *ebp = (int *)read_ebp();
		struct Eipdebuginfo info;
		char file_name[15];
		int i=0;
        	cprintf("\n Stack backtrace:\n");
        	while(ebp != 0){
			debuginfo_eip(*(ebp+1), &info);
			i = 0;
			if (strcmp(info.eip_fn_name, "<unknown>")) {
				while(info.eip_fn_name[i] != ':'){
					file_name[i] = info.eip_fn_name[i];	
					i++;
				}	
			}
			file_name[i] = '\0';
                	cprintf("ebp %08x  eip %08x args %08x %08x %08x %08x %08x \n",ebp, *(ebp+1), *(ebp+2), *(ebp+3), *(ebp+4), *(ebp+5), *(ebp+6));
                	cprintf("\t%s:%d: %s+%d\n", info.eip_file, info.eip_line, file_name, *(ebp + 1) - info.eip_fn_addr);
		ebp =(int *)(*ebp);
       	      	}     	
	return 0;
}

int showmappings(int argc, char** argv, struct Trapframe* tf) {

		if (argc != 0) {
			int start =(int) strtol(argv[1], NULL, 16);
			int end = (int) strtol(argv[2], NULL, 16);
			//cprintf("\n Address  start: %d %x      end : %d  %x", start, start, end, end);
			int *s = (int *)start;
			int *e = (int *)end;
			show_mappings(s, e);
		}
			

	return 0;
}
void check_perm(char *perm, int *u, int *t, int *w) {
	if (!strcmp(perm, "pte_t")) {	
		*t = 1;
		return;
	}
	if (!strcmp(perm, "pte_u")){
		*u = 1;
		return;
	}
	if (!strcmp(perm, "pte_w"))
		*w = 1;
}
int setperms(int argc, char** argv, struct Trapframe* tf) {
	if (argc <= 1 && argc > 4){
		cprintf("\n Correct usage of the command : setpemrms hex-virt-addr perm");
		cprintf("\n perm : pte_t pte_u pte_w");
		goto ret;
	}
	int *va = (int *)argv[1];
	int u=0, p=0, w=0;
	int i;
	for(i = 2; i <= argc; i++)
		check_perm(argv[i], &u, &p, &w);
	set_perms((pte_t *)va, u, p, w);
ret:
	return 0;
}
int clearperms(int argc, char** argv, struct Trapframe* tf) {
	if (argc > 2){
		cprintf ("\n Incorrect usage of command. No arguments expected");
		goto ret;
	}
	int *va = (int *)argv[1];
	clear_perms((pte_t *)va);
ret:
	return 0;
}
int changeperms(int argc, char** argv, struct Trapframe* tf) {
	return 0;
}
int dump(int argc, char** argv, struct Trapframe* tf) {
		if (argc != 0) {
			int start =(int) strtol(argv[1], NULL, 16);
			int end = (int) strtol(argv[2], NULL, 16);
			//cprintf("\n Address  start: %d %x      end : %d  %x", start, start, end, end);
			int *s = (int *)start;
			int *e = (int *)end;
			dump_mem(s, e);
			return 0;
		}
	return -1;	
}

/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

	if (tf != NULL)
		print_trapframe(tf);


	cprintf("Type 'help' for a list of commands.\n");

	//cprintf(" Type 'help' for a  list of commands.\n") ;
	//cprintf(" Octal 9 is : %o\n", 9);
	//cprintf("%yellow This text is %red yellow\n");
	//cprintf("%red This text %yellow is red\n");
	//cprintf("%violet This text is violet\n");

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}

