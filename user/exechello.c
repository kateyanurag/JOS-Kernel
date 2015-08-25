#include <inc/lib.h>

void
umain(int argc, char **argv)
{
	#ifdef ENABLE_EXEC
		int r;
		cprintf("Heyyy .... i am parent environment %08x\n", thisenv->env_id);
		if ((r = execl("hello", "hello", 0)) < 0)
			panic("exec(hello) failed: %e", r);
	#else
		//cprintf("\n Exec call not enable !");
	#endif
}
