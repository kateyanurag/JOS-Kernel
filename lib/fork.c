// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800
//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	if((err & FEC_WR) == 0) // is the pagefault caused by write ?
		panic("In lib/fork.c:pgfault - Kernel Panic. This page fault not caused by write ");
	int  pg_num = PGNUM(addr);
	uintptr_t pgtb_entry = uvpt[pg_num];
	if ((pgtb_entry & PTE_COW) == 0)
		panic("In lib/fork.c:pgfault - Kernel Panic. This page doesn't have PTE_COW permissions ");

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.

	//sys_page_alloc(curenv->env_id, addr, PTE_P | PTE_W);
	//sys_page_map(curenv->env_id, addr, curenv->env_id, PFTEMP, )
	
	// LAB 4: Your code here.
	if (sys_page_alloc(0, PFTEMP, PTE_W | PTE_U | PTE_P))
		panic("In lib/fork.c:pgfault - Kernel Panic. No Pages to Allocate");
	addr = (void *)ROUNDDOWN(addr, PGSIZE);
	memmove(PFTEMP, addr, PGSIZE);
	if (sys_page_map(0, PFTEMP, 0, addr, PTE_U | PTE_P | PTE_W))
		panic("In lib/fork.c:pgfault - Kernel Panic. Error during Mapping");
		

	//panic("pgfault not implemented");

}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;

	// LAB 4: Your code here.
	//panic("duppage not implemented");
	void *va = (void*) (pn*PGSIZE);
	pte_t pgtb_entry = uvpt[pn];
	int retval = 0;
    	if (pgtb_entry & PTE_SHARE) {
        	retval = sys_page_map(0, va, envid, va, uvpt[pn]&PTE_SYSCALL);
		if(retval < 0)
			panic("In lib/fork.c:duppage - Kernel Panic. Mappings cannot be copied for PTE_SHARE bit");
    	} else if ((pgtb_entry & PTE_W) || (pgtb_entry & PTE_COW)) {
        	if (sys_page_map(0, va, envid, va, PTE_COW|PTE_U|PTE_P) < 0){
            		panic("In lib/fork.c:duppage - Kernel Panic. Cannot Map page to child's address space");
		}
        	if (sys_page_map(0, va, 0, va, PTE_COW|PTE_U|PTE_P) < 0){
			panic("In lib/fork.c:duppage - Kernel Panic. Cannot Map page to child's address space");
		}
    	} else {
		if(sys_page_map(0, va, envid, va, PTE_U|PTE_P) < 0)
			panic("In lib/fork.c:duppage - Kernel Panic. Cannot Map page Remaining pages to child's address space");
	}
    	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//

int
get_page_num(int pgdir_index, int pgtb_index) {	
	pgdir_index = pgdir_index * 1024;
	return (pgdir_index | pgtb_index);
} 
void
allocate_exception_stack_to_child(int env_id){
	int perms = PTE_W | PTE_U | PTE_P;
            if (sys_page_alloc(env_id, (void *)(UXSTACKTOP - PGSIZE), perms))
		panic("In lib/fork.c:fork - Kernel Panic. Cannot allocate new page for chils's user exception stack");
}

	
#ifdef ENABLE_PRIORITY_SCHEDULING
int
priority_fork(int priority){
	// LAB 4: Your code here.
	//panic("fork not implemented");
	// 1) Set Pagefault handler
    	set_pgfault_handler(pgfault);
	
	// 2) Call sys_exofork to create child
    	int id = sys_exofork();
	if (id == 0){ // Child process
		int cur_envid = sys_getenvid();	
		int envs_array_index = ENVX(cur_envid); // Environment index of the envid is shared by multiple environments.
		thisenv = &envs[envs_array_index];
		if(sys_env_assign_priority(priority) < 0)
				cprintf("\n  Not Able to set Priority to this env!!");
		return 0;
	}
	else if (id < 0)
		panic("In lib/fork.c:fork - Kernel Panic. Sys_exofork System call failed. It returned -1");

	// 3) For each writable or copy-on-write page in parents address space below UTOP, call duppage		
	int pgdir_index = 0, pgtb_index = 0;
	while (pgdir_index != PDX(UTOP)){
		if ((uvpd[pgdir_index] & PTE_P) != 0) {
			pgtb_index = 0;
			while (pgtb_index != NPTENTRIES) {
				int pgnum = get_page_num(pgdir_index, pgtb_index);
				if (pgnum == PGNUM(UXSTACKTOP - PGSIZE))
					allocate_exception_stack_to_child(id);		
				else if (uvpt[pgnum] & PTE_P)
					duppage(id, pgnum);	
				pgtb_index = pgtb_index + 1 ;
			}
		}
		pgdir_index = pgdir_index + 1;
	} 

    // 4) Parent sets User Pagefault entrypoint for the child
    	if (sys_env_set_pgfault_upcall(id, thisenv->env_pgfault_upcall))
		panic("In lib/fork.c:fork - Kernel Panic. Cannot set Pagefault entry for child env");

    // 5) Change child's status to ENV_RUNNABLE.
    	if (sys_env_set_status(id, ENV_RUNNABLE))
		panic("In lib/fork.c:fork - Kernel Panic. Cannot change child's status to runnable");
    // 6) Assign Priority to child ENV
//	if(sys_env_assign_priority(id, priority) < 0)
//		cprintf("\n !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Not Able to set Priority to this env !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");;
   	
   	return id;	

}

#endif



int
fork(void)
{
	// LAB 4: Your code here.
	//panic("fork not implemented");
	// 1) Set Pagefault handler
	
    	set_pgfault_handler(pgfault);
    	
	
	// 2) Call sys_exofork to create child

    	int id = sys_exofork();
	if (id == 0){ // Child process
		int cur_envid = sys_getenvid();	
		int envs_array_index = ENVX(cur_envid); // Environment index of the envid is shared by multiple environments.
		thisenv = &envs[envs_array_index];
		return 0;
	}
	else if (id < 0)
		panic("In lib/fork.c:fork - Kernel Panic. Sys_exofork System call failed. It returned -1");
	
	// 3) For each writable or copy-on-write page in parents address space below UTOP, call duppage		
	int pgdir_index = 0, pgtb_index = 0;
	while (pgdir_index != PDX(UTOP)){
		if ((uvpd[pgdir_index] & PTE_P) != 0) {
			pgtb_index = 0;
			while (pgtb_index != NPTENTRIES) {
				int pgnum = get_page_num(pgdir_index, pgtb_index);
				if (pgnum == PGNUM(UXSTACKTOP - PGSIZE))
					allocate_exception_stack_to_child(id);		
				else if (uvpt[pgnum] & PTE_P)
					duppage(id, pgnum);	
				pgtb_index = pgtb_index + 1 ;
			}
		}
		pgdir_index = pgdir_index + 1;
	} 
	
    // 4) Parent sets User Pagefault entrypoint for the child
    	if (sys_env_set_pgfault_upcall(id, thisenv->env_pgfault_upcall))
		panic("In lib/fork.c:fork - Kernel Panic. Cannot set Pagefault entry for child env");

    // 5) Change child's status to ENV_RUNNABLE.
    	if (sys_env_set_status(id, ENV_RUNNABLE))
		panic("In lib/fork.c:fork - Kernel Panic. Cannot change child's status to runnable");

   	return id;	
}
// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
