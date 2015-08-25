// hello, world
#include <inc/lib.h>
#include <inc/string.h>
#include <inc/lib.h>

static int prev_rand = 13;
int get_random_priority(){
	int new_rand = (6 * prev_rand + 7) % 5;
	prev_rand = new_rand;
	return new_rand+1;	
}
void 
umain(int argc, char **argv){
/*	int i, j;
	int envid = 0; 
    for (i = 1; i <= 5; ++i) {
	int priority = get_random_priority();
	cprintf("\n=====> FORKING A CHILD with PRIORITY : %d ", priority);

	#ifdef ENABLE_PRIORITY_SCHEDULING
	envid = priority_fork(priority);
	#endif
	
        if (envid == 0) {
            cprintf("Environment %08x is currently executing and has Priority: %d\n", thisenv->env_id, thisenv->env_priority);
            for (j = 1; j <= 5; ++j) {
                cprintf("Environmet %08x will now yield the CPU and has Priority: %d\n", thisenv->env_id, thisenv->env_priority);
                sys_yield();
            }
            //break;
        }
    }
*/}
