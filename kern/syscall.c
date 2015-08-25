/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/syscall.h>
#include <kern/console.h>
#include <kern/sched.h>
#include <kern/time.h>
#include <inc/elf.h>
#include <kern/e1000.h>

//#define ETEMP 0xe0000000

// Print a string to the system console.
// The string is exactly 'len' characters long.
// Destroys the environment on memory errors.
static void
sys_cputs(const char *s, size_t len)
{
	// Check that the user has permission to read memory [s, s+len).
	// Destroy the environment if not.

		// LAB 3: Your code here.
	user_mem_assert(curenv, s, len, PTE_U);

	// Print the string supplied by the user.
	cprintf("%.*s",len,s);
}

// Read a character from the system console without blocking.
// Returns the character, or 0 if there is no input waiting.
static int
sys_cgetc(void)
{
	return cons_getc();
}

// Returns the current environment's envid.
static envid_t
sys_getenvid(void)
{
	return curenv->env_id;
}

// Destroy a given environment (possibly the currently running environment).
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_destroy(envid_t envid)
{
	int r;
	struct Env *e;

	if ((r = envid2env(envid, &e, 1)) < 0)
		return r;
	if (e == curenv)
		cprintf("[%08x] exiting gracefully\n", curenv->env_id);
	else
		cprintf("[%08x] destroying %08x\n", curenv->env_id, e->env_id);
	env_destroy(e);
	return 0;
}

// Deschedule current environment and pick a different one to run.
static void
sys_yield(void)
{
	sched_yield();
}

// Allocate a new environment.
// Returns envid of new environment, or < 0 on error.  Errors are:
//	-E_NO_FREE_ENV if no free environment is available.
//	-E_NO_MEM on memory exhaustion.
static envid_t
sys_exofork(void)
{
	// Create the new environment with env_alloc(), from kern/env.c.
	// It should be left as env_alloc created it, except that
	// status is set to ENV_NOT_RUNNABLE, and the register set is copied
	// from the current environment -- but tweaked so sys_exofork
	// will appear to return 0.

	// LAB 4: Your code here.
	//panic("sys_exofork not implemented");
        struct Env *new_env;
	int ret_val = env_alloc(&new_env, ENVX(curenv->env_id));
	if (ret_val < 0){
		return ret_val;
	}
	new_env->env_status = ENV_NOT_RUNNABLE;
	new_env->env_tf = curenv->env_tf;	
	// return value (in eax) = 0
	new_env->env_tf.tf_regs.reg_eax = 0;
	new_env->env_parent_id = curenv->env_id;
	return new_env->env_id;
}

// Set envid's env_status to status, which must be ENV_RUNNABLE
// or ENV_NOT_RUNNABLE.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if status is not a valid status for an environment.
static int
sys_env_set_status(envid_t envid, int status)
{
	// Hint: Use the 'envid2env' function from kern/env.c to translate an
	// envid to a struct Env.
	// You should set envid2env's third argument to 1, which will
	// check whether the current environment has permission to set
	// envid's status.

	// LAB 4: Your code here.
	//panic("sys_env_set_status not implemented");
	struct Env *new_env;
	if (status == ENV_RUNNABLE || status == ENV_NOT_RUNNABLE){
		if (envid2env(envid, &new_env, 1) < 0)
			return -E_BAD_ENV;
		else		
			new_env->env_status = status;
		return 0;		
	} 
	return -E_INVAL;
}

// Set envid's trap frame to 'tf'.
// tf is modified to make sure that user environments always run at code
// protection level 3 (CPL 3) with interrupts enabled.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_set_trapframe(envid_t envid, struct Trapframe *tf)
{
	// LAB 5: Your code here.
	// Remember to check whether the user has supplied us with a good
	// address!
	//panic("sys_env_set_trapframe not implemented");
	
	struct Env *new_env;
	if(envid2env(envid, &new_env, 1) < 0)
		return -E_BAD_ENV;
//	user_mem_assert(env_instance, tf, sizeof(struct Trapframe), PTE_U);
//	new_env->env_tf.tf_cs=GD_UT|3;
	new_env->env_tf.tf_eflags=new_env->env_tf.tf_eflags | FL_IF;
	new_env->env_tf = *tf;
	return 0;
}

// Set the page fault upcall for 'envid' by modifying the corresponding struct
// Env's 'env_pgfault_upcall' field.  When 'envid' causes a page fault, the
// kernel will push a fault record onto the exception stack, then branch to
// 'func'.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_set_pgfault_upcall(envid_t envid, void *func)
{
	// LAB 4: Your code here.
	//panic("sys_env_set_pgfault_upcall not implemented");
    
    	struct Env *new_env;
    	if (envid2env(envid, &new_env, 1) < 0) {
        	return -E_BAD_ENV;
    	}
    	new_env->env_pgfault_upcall = func;
    	return 0;

}

// Allocate a page of memory and map it at 'va' with permission
// 'perm' in the address space of 'envid'.
// The page's contents are set to 0.
// If a page is already mapped at 'va', that page is unmapped as a
// side effect.
//
// perm -- PTE_U | PTE_P must be set, PTE_AVAIL | PTE_W may or may not be set,
//         but no other bits may be set.  See PTE_SYSCALL in inc/mmu.h.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
//	-E_INVAL if perm is inappropriate (see above).
//	-E_NO_MEM if there's no memory to allocate the new page,
//		or to allocate any necessary page tables.
static int
sys_page_alloc(envid_t envid, void *va, int perm)
{
	// Hint: This function is a wrapper around page_alloc() and
	//   page_insert() from kern/pmap.c.
	//   Most of the new code you write should be to check the
	//   parameters for correctness.
	//   If page_insert() fails, remember to free the page you
	//   allocated!

	// LAB 4: Your code here.
	//panic("sys_page_alloc not implemented");
	
	
    	struct Env *new_env;
    	struct PageInfo *new_page;

    	if ((int)va >= UTOP || ((int)va % PGSIZE) != 0) {
        	return -E_INVAL;
    	}

    	if (!(perm & PTE_U) || (!(perm & PTE_P)) || (perm & ~PTE_SYSCALL)) {
       		 return -E_INVAL;
    	}
    	if (envid2env(envid, &new_env, 1) < 0) {
        	return -E_BAD_ENV;
    	}

   	 new_page = page_alloc(ALLOC_ZERO);
    	if (new_page == NULL) {
       		 return -E_NO_MEM;
    	}
	
    	int ret_val = page_insert(new_env->env_pgdir, new_page, va, perm);
	if (ret_val == -E_NO_MEM){
        	page_free(new_page);
        	return ret_val;
	}
    	return 0;
    }

// Map the page of memory at 'srcva' in srcenvid's address space
// at 'dstva' in dstenvid's address space with permission 'perm'.
// Perm has the same restrictions as in sys_page_alloc, except
// that it also must not grant write access to a read-only
// page.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if srcenvid and/or dstenvid doesn't currently exist,
//		or the caller doesn't have permission to change one of them.
//	-E_INVAL if srcva >= UTOP or srcva is not page-aligned,
//		or dstva >= UTOP or dstva is not page-aligned.
//	-E_INVAL is srcva is not mapped in srcenvid's address space.
//	-E_INVAL if perm is inappropriate (see sys_page_alloc).
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in srcenvid's
//		address space.
//	-E_NO_MEM if there's no memory to allocate any necessary page tables.
static int
sys_page_map(envid_t srcenvid, void *srcva,
	     envid_t dstenvid, void *dstva, int perm)
{
	// Hint: This function is a wrapper around page_lookup() and
	//   page_insert() from kern/pmap.c.
	//   Again, most of the new code you write should be to check the
	//   parameters for correctness.
	//   Use the third argument to page_lookup() to
	//   check the current permissions on the page.

	// LAB 4: Your code here.
	//panic("sys_page_map not implemented");
    	
    	struct Env *srcenv, *dstenv;
	if ((int)srcva >= UTOP || ((int)srcva % PGSIZE) != 0) {
		panic("\n HERE1");
        	return -E_INVAL;
    	}
	
    	if ((int)dstva >= UTOP || ((int)dstva % PGSIZE) != 0) {
		panic("\n HERE2");
        	return -E_INVAL;
    	}
    	if (!(perm & PTE_U) || (!(perm & PTE_P)) || (perm & ~PTE_SYSCALL)) {
		panic("\n HERE3");
       		 return -E_INVAL;
    	}
    	if (envid2env(srcenvid, &srcenv, 1) < 0 || envid2env(dstenvid, &dstenv, 1) < 0) {
		panic("\n HERE4");
    		return -E_BAD_ENV;
    	}

    	pte_t *pgtb_entry;
    	struct PageInfo *page = page_lookup(srcenv->env_pgdir, srcva, &pgtb_entry);
    	if (page == NULL) {
		panic("\n HERE5");
        	return -E_INVAL;
    	}

    	if ((perm & PTE_W) && !(*pgtb_entry & PTE_W)) {
		panic("\n HERE6");
        	return -E_INVAL;
    	}

    	if (page_insert(dstenv->env_pgdir, page, dstva, perm)) {
		panic("\n HERE7");
        	return -E_NO_MEM;
    	}
    	return 0;
}

// Unmap the page of memory at 'va' in the address space of 'envid'.
// If no page is mapped, the function silently succeeds.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
static int
sys_page_unmap(envid_t envid, void *va)
{
	// Hint: This function is a wrapper around page_remove().

	// LAB 4: Your code here.
    	if ((int)va >= UTOP || ((int)va % PGSIZE) != 0) {
        	return -E_INVAL;
    	}

	    // find environment.
    	struct Env *new_env;
    	if (envid2env(envid, &new_env, 1) < 0) {
        	return -E_BAD_ENV;
    	}
    	page_remove(new_env->env_pgdir, va);
    	return 0;
}

// Try to send 'value' to the target env 'envid'.
// If srcva < UTOP, then also send page currently mapped at 'srcva',
// so that receiver gets a duplicate mapping of the same page.
//
// The send fails with a return value of -E_IPC_NOT_RECV if the
// target is not blocked, waiting for an IPC.
//
// The send also can fail for the other reasons listed below.
//
// Otherwise, the send succeeds, and the target's ipc fields are
// updated as follows:
//    env_ipc_recving is set to 0 to block future sends;
//    env_ipc_from is set to the sending envid;
//    env_ipc_value is set to the 'value' parameter;
//    env_ipc_perm is set to 'perm' if a page was transferred, 0 otherwise.
// The target environment is marked runnable again, returning 0
// from the paused sys_ipc_recv system call.  (Hint: does the
// sys_ipc_recv function ever actually return?)
//
// If the sender wants to send a page but the receiver isn't asking for one,
// then no page mapping is transferred, but no error occurs.
// The ipc only happens when no errors occur.
//
// Returns 0 on success, < 0 on error.
// Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist.
//		(No need to check permissions.)
//	-E_IPC_NOT_RECV if envid is not currently blocked in sys_ipc_recv,
//		or another environment managed to send first.
//	-E_INVAL if srcva < UTOP but srcva is not page-aligned.
//	-E_INVAL if srcva < UTOP and perm is inappropriate
//		(see sys_page_alloc).
//	-E_INVAL if srcva < UTOP but srcva is not mapped in the caller's
//		address space.
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in the
//		current environment's address space.
//	-E_NO_MEM if there's not enough memory to map srcva in envid's
//		address space.


int is_valid_ipc_perm(int perms){
	if (!(perms & PTE_U) ||!(perms & PTE_P) ||(perms & ~PTE_SYSCALL))
		return -1;
	return 1; 
}

static int
sys_ipc_try_send(envid_t envid, uint32_t value, void *srcva, unsigned perm)
{
/*	// LAB 4: Your code here.
	panic("sys_ipc_try_send not implemented");
*/
    	struct Env *dest_env;
    	struct PageInfo *page_to_send;
    	pte_t *pgtb_entry;
    	if (envid2env(envid, &dest_env, 0) < 0)
       		return -E_BAD_ENV;
       	if (dest_env->env_ipc_recving == false)
        		return -E_IPC_NOT_RECV;
        	if((int)srcva < UTOP){
        		if((int)srcva % PGSIZE != 0)
        			return -E_INVAL;
        		if(is_valid_ipc_perm(perm) < 0)
        			return -E_INVAL;
        		page_to_send = page_lookup(curenv->env_pgdir, srcva, &pgtb_entry);
        		if(page_to_send == NULL)
        			return -E_INVAL;
        		if ((perm & PTE_W) && (*pgtb_entry & PTE_W) == 0)        		
           			return -E_INVAL;
           		if ((uintptr_t)dest_env->env_ipc_dstva < UTOP && page_insert(dest_env->env_pgdir, page_to_send, dest_env->env_ipc_dstva, perm) < 0)
            		return -E_NO_MEM;
            	dest_env->env_ipc_perm = perm;
          	}else {
          		dest_env->env_ipc_perm = 0;
        	}
        	dest_env->env_ipc_from = curenv->env_id;
        	dest_env->env_ipc_recving = 0;
    	dest_env->env_status = ENV_RUNNABLE;
    	dest_env->env_ipc_value = value;
    	
        	return 0;

}

// Block until a value is ready.  Record that you want to receive
// using the env_ipc_recving and env_ipc_dstva fields of struct Env,
// mark yourself not runnable, and then give up the CPU.
//
// If 'dstva' is < UTOP, then you are willing to receive a page of data.
// 'dstva' is the virtual address at which the sent page should be mapped.
//
// This function only returns on error, but the system call will eventually
// return 0 on success.
// Return < 0 on error.  Errors are:
//	-E_INVAL if dstva < UTOP but dstva is not page-aligned.
static int
sys_ipc_recv(void *dstva)
{

/*	// LAB 4: Your code here.
	panic("sys_ipc_recv not implemented");
	return 0;
*/
	if((int)dstva < UTOP){
		if(((int)dstva % PGSIZE != 0))
			return -E_INVAL;
	}
	curenv->env_status = ENV_NOT_RUNNABLE;
	curenv->env_ipc_dstva = dstva;
	curenv->env_ipc_recving = 1;
	curenv->env_tf.tf_regs.reg_eax = 0;
    	sys_yield(); 
    	return 0;
}

static int
sys_transmit_packet(char *packet, int size){
	if(packet == NULL || sizeof(packet) == 0){
		cprintf("\n Data for the packet is Null or is Empty");
		return -E_INVAL;
	}
	int retval = transmit_packets(packet, size);
	if (retval < 0){
		cprintf("\n Packet Transmit function failed");
		return -2;
	}
	return 0;
}

static int
sys_recieve_packet(char *packet, int *size){
	if(packet == NULL || sizeof(packet) == 0){
		cprintf("\n Data for the packet is Null or is Empty");
		return -E_INVAL;
	}
	int retval = recieve_packets(packet, size);
	if (retval < 0){
		cprintf("\n Packet Recieve function failed");
		return -2;
	}
	return retval;
}

// Return the current time.
static int
sys_time_msec(void)
{
	// LAB 6: Your code here.
	//panic("sys_time_msec not implemented");
	int ticks = time_msec();
	return ticks;
}

static int
sys_get_mac_address(void *mac_address){
	get_mac_address(mac_address);
	return 0;
}


static int
sys_env_assign_priority(int priority_number)
{
	/*
    if (priority_number > ENV_PRIORITY_TIME_CRITICAL || priority_number < ENV_PRIORITY_LOWEST)
        return -E_INVAL_PRIORITY;
    
    struct Env *new_env;
    if(envid2env(envid, &new_env, 1) < 0)
        return -E_BAD_ENV;
    
    new_env->env_priority=priority_number;       */           
	curenv->env_priority = priority_number;
    return 0;
}

static int
sys_exec(uint32_t eip, uint32_t esp, void * _ph, uint32_t phnum)
{
	#ifdef ENABLE_EXEC

	/*NOTE : I have taken help from Internet to design the logic for this system call. It is not originally written by me! */

	int perm = 0;
	struct Proghdr *ph = (struct Proghdr *)_ph;
	int count = 0;
	uint32_t mem_loc = 0xe0000000; // Memory location where pages of new program are stored. 
	uint32_t va, limit;
	struct PageInfo *page; 
	while(count < phnum){
		if(ph->p_type == ELF_PROG_LOAD){
	        	perm = PTE_P | PTE_U;
		        if (ph->p_flags & ELF_PROG_FLAG_WRITE)
		            perm |= PTE_W;
	        	limit = ROUNDUP(ph->p_va + ph->p_memsz, PGSIZE);
			va = ROUNDDOWN(ph->p_va, PGSIZE);
			while(va != limit){
            			if ((page = page_lookup(curenv->env_pgdir, (void *)mem_loc, NULL)) == NULL) 
			                return -E_NO_MEM;
		               	if (page_insert(curenv->env_pgdir, page, (void *)va, perm) < 0)
			                return -E_NO_MEM;
	            		page_remove(curenv->env_pgdir, (void *)mem_loc);
				va = va + PGSIZE;
				mem_loc = mem_loc + PGSIZE;
			}
		
		}
		count++;
		ph++;
	}
	if ((page = page_lookup(curenv->env_pgdir, (void *)mem_loc, NULL)) == NULL) 
		return -E_NO_MEM;
	if (page_insert(curenv->env_pgdir, page, (void *)(USTACKTOP - PGSIZE), PTE_P|PTE_U|PTE_W) < 0) 
	        return -E_NO_MEM;
	page_remove(curenv->env_pgdir, (void *)mem_loc);    
	curenv->env_tf.tf_eip = eip;
	curenv->env_tf.tf_esp = esp;
	env_run(curenv);


	#else
	   	printf("\n EXEC NOT ENABLED !!!");

	#endif
	return 0;
}

// Dispatches to the correct kernel function, passing the arguments.
int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
	// Call the function corresponding to the 'syscallno' parameter.
	// Return any appropriate return value.
	// LAB 3: Your code here.
	
    switch (syscallno) {
    case SYS_cputs: 
            	sys_cputs((const char*)a1,(size_t) a2);
            	return 0;
    case SYS_cgetc:
            	return (int)sys_cgetc();
    case SYS_getenvid:
           		return (int)sys_getenvid();
    case SYS_env_destroy:
            	sys_env_destroy((envid_t) a1);
            	return 0;   
    case SYS_yield:
            	sys_yield();
          		 return 0;
    case SYS_exofork:
            	return sys_exofork();   
    case SYS_page_alloc:
            	return sys_page_alloc(a1, (void*)a2, a3);      
    case SYS_page_map:
            	return sys_page_map(a1, (void*)a2, a3, (void*)a4, a5);       
    case SYS_page_unmap:
            	return sys_page_unmap(a1, (void*)a2);           
    case SYS_env_set_trapframe:     
		return sys_env_set_trapframe(a1, (struct Trapframe *)a2);
    case SYS_env_set_status:
            	return sys_env_set_status(a1, a2);        
    case SYS_env_set_pgfault_upcall:
            	return sys_env_set_pgfault_upcall(a1, (void*)a2);
    case SYS_ipc_try_send:
		return sys_ipc_try_send(a1, a2, (void *)a3, a4);
    case SYS_ipc_recv:
		return sys_ipc_recv((void *)a1);
    case SYS_env_assign_priority:
                return sys_env_assign_priority(a1);
    #ifdef EXEC_ENABLE
    case SYS_exec:
		return sys_exec((uint32_t)a1, (uint32_t)a2, (void *)a3, (uint32_t)a4);
    #endif
    case SYS_time_msec:
		return sys_time_msec();
    case SYS_transmit_packet:
		return sys_transmit_packet((char *)a1, a2);
    case SYS_recieve_packet:
		return sys_recieve_packet((char *)a1, (int *)a2);
    case SYS_get_mac_address:
		return sys_get_mac_address((void *)a1);
    default:
       		 return -E_INVAL;
    }
}

