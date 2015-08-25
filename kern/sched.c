#include <inc/assert.h>
#include <inc/x86.h>
#include <kern/spinlock.h>
#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/monitor.h>


//#define ENABLE_PRIORITY_SCHEDULING

void sched_halt(void);
// Choose a user environment to run and run it.
void print_priorities(){
	int i = 0;
	for(i = 0; i < NENV; i++){
		if(envs[i].env_id == 0x00001001)
			cprintf("\n @@@@@@@@@@@@@@@@ENV PRI for 1001: %d State : %d", envs[i].env_priority, envs[i].env_status);
		if(envs[i].env_id == 0x00001002)
			cprintf("\n @@@@@@@@@@@@@@@@ENV PRI for 1002: %d State: %d", envs[i].env_priority, envs[i].env_status);
		if(envs[i].env_id == 0x00001003)
			cprintf("\n @@@@@@@@@@@@@@@@ENV PRI for 1003: %d State: %d", envs[i].env_priority, envs[i].env_status);
		if(envs[i].env_id == 0x00001004)
			cprintf("\n @@@@@@@@@@@@@@@@ENV PRI for 1004: %d State: %d", envs[i].env_priority, envs[i].env_status);
		if(envs[i].env_id == 0x00001005)
			cprintf("\n @@@@@@@@@@@@@@@@ENV PRI for 1005: %d State: %d", envs[i].env_priority, envs[i].env_status);
	}
}
void
sched_yield(void)
{
	struct Env *idle;

	// Implement simple round-robin scheduling.
	//
	// Search through 'envs' for an ENV_RUNNABLE environment in
	// circular fashion starting just after the env this CPU was
	// last running.  Switch to the first such environment found.
	//
	// If no envs are runnable, but the environment previously
	// running on this CPU is still ENV_RUNNING, it's okay to
	// choose that environment.
	//
	// Never choose an environment that's currently running on
	// another CPU (env_status == ENV_RUNNING). If there are
	// no runnable environments, simply drop through to the code
	// below to halt the cpu.

	// LAB 4: Your code here.

	#ifdef ENABLE_PRIORITY_SCHEDULING
	//	print_priorities();
		    struct Env *e, *runenv = NULL;
		    int i, cur=0;
		    if (curenv) cur=ENVX(curenv->env_id);
		    else cur = 0;
			runenv = curenv;
		    for (i = 0; i < NENV; ++i) {
		        int j = (cur+i) % NENV;
		        if (envs[j].env_status == ENV_RUNNABLE) {
		            if (runenv==NULL || envs[j].env_priority < runenv->env_priority){ 
				//cprintf("\n %d*********** envs[j].env_priority: %d\n",i ,envs[j].env_priority);                
				runenv = envs+j; 
			    }
		        }
		    }
		    if (curenv && (curenv->env_status == ENV_RUNNING) && ((runenv==NULL) || (curenv->env_priority < runenv->env_priority))) {
		        env_run(curenv);
		    }
		    if (runenv) {
		        env_run(runenv);
		    }
		    sched_halt();
	#else
		// cprintf("NOT ENABLE_PRIORITY_SCHEDULING!!!");
		int cur_envid = 0;
		if (curenv != NULL)
			cur_envid = ENVX(curenv->env_id);
		int i = 0;
		int new_envid;
		while (i < NENV) {
			new_envid = (cur_envid + i) % NENV;
			if (envs[new_envid].env_status == ENV_RUNNABLE)	
				env_run(envs + new_envid);
			i++;
		}
		if (curenv != NULL && curenv->env_status == ENV_RUNNING)
			env_run(curenv);
		sched_halt();

	#endif

}

// Halt this CPU when there is nothing to do. Wait until the
// timer interrupt wakes it up. This function never returns.
//
void
sched_halt(void)
{
	int i;

	// For debugging and testing purposes, if there are no runnable
	// environments in the system, then drop into the kernel monitor.
	for (i = 0; i < NENV; i++) {
		if ((envs[i].env_status == ENV_RUNNABLE ||
		     envs[i].env_status == ENV_RUNNING ||
		     envs[i].env_status == ENV_DYING))
			break;
	}
	if (i == NENV) {
		cprintf("No runnable environments in the system!\n");
		while (1)
			monitor(NULL);
	}

	// Mark that no environment is running on this CPU
	curenv = NULL;
	lcr3(PADDR(kern_pgdir));

	// Mark that this CPU is in the HALT state, so that when
	// timer interupts come in, we know we should re-acquire the
	// big kernel lock
	xchg(&thiscpu->cpu_status, CPU_HALTED);

	// Release the big kernel lock as if we were "leaving" the kernel
	unlock_kernel();

	// Reset stack pointer, enable interrupts and then halt.
	asm volatile (
		"movl $0, %%ebp\n"
		"movl %0, %%esp\n"
		"pushl $0\n"
		"pushl $0\n"
		"sti\n"
		"1:\n"
		"hlt\n"
		"jmp 1b\n"
	: : "a" (thiscpu->cpu_ts.ts_esp0));
}

