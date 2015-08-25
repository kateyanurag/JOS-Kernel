	#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>
#include <kern/sched.h>
#include <kern/kclock.h>
#include <kern/picirq.h>
#include <kern/cpu.h>
#include <kern/spinlock.h>
#include <kern/time.h>

static struct Taskstate ts;

/* For debugging, so print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case.
 */
static struct Trapframe *last_tf;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
struct Gatedesc idt[256] = { { 0 } };
struct Pseudodesc idt_pd = {
	sizeof(idt) - 1, (uint32_t) idt
};


static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
		"Divide error",
		"Debug",
		"Non-Maskable Interrupt",
		"Breakpoint",
		"Overflow",
		"BOUND Range Exceeded",
		"Invalid Opcode",
		"Device Not Available",
		"Double Fault",
		"Coprocessor Segment Overrun",
		"Invalid TSS",
		"Segment Not Present",
		"Stack Fault",
		"General Protection",
		"Page Fault",
		"(unknown trap)",
		"x87 FPU Floating-Point Error",
		"Alignment Check",
		"Machine-Check",
		"SIMD Floating-Point Exception"
	};

	if (trapno < sizeof(excnames)/sizeof(excnames[0]))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	if (trapno >= IRQ_OFFSET && trapno < IRQ_OFFSET + 16)
		return "Hardware Interrupt";
	return "(unknown trap)";
}


 void DivideError();
 void Debug();
void NonMaskableInt();
void BrkPoint();
 void Overflow();
 void RangeExceeded();
 void InvalidOpcode();
 void DeviceUnavail();
 void DoubleFault();
 void InvalidTSS();
 void SegNotPresent();
 void StackFault();
 void GenProtection();
 void PageFault();
 void FloatingPtErr();
void AlignCheck();
 void MachineCheck();
 void SIMDFloatErr();
void SysCallTrapHandler();
 void PageFault();

  void irq0();void irq1();void irq2();void irq3();void irq4();void irq5();void irq6();void irq7();void irq8();
 void irq9();void irq10();void irq11();void irq12();void irq13();void irq14();void irq15();

void (*interrupts[20])();
extern int interruptss[];
void init_interrupts();
void 
trap_init(void)
{
	extern struct Segdesc gdt[];
	init_interrupts();
	// LAB 3: Your code here.
	/*SETGATE(idt[T_DIVIDE], 0, GD_KT, DivideError, 3);
	SETGATE(idt[1], 0, GD_KT, Debug, 3);
	SETGATE(idt[2], 0, GD_KT, NonMaskableInt, 3);
	SETGATE(idt[3], 0, GD_KT, BrkPoint, 3);
	SETGATE(idt[4], 0, GD_KT, Overflow, 3);
	SETGATE(idt[5], 0, GD_KT, RangeExceeded, 3);
	SETGATE(idt[6], 0, GD_KT, InvalidOpcode, 3);
	SETGATE(idt[7], 0, GD_KT, DeviceUnavail, 3);
	SETGATE(idt[8], 0, GD_KT, DoubleFault, 3);
	SETGATE(idt[10], 0, GD_KT, InvalidTSS, 3);
	SETGATE(idt[11], 0, GD_KT, SegNotPresent, 3);
	SETGATE(idt[12], 0, GD_KT, StackFault, 3);
	SETGATE(idt[13], 0, GD_KT, GenProtection, 3);
	SETGATE(idt[14], 0, GD_KT, PageFault, 0);
	SETGATE(idt[16], 0, GD_KT, FloatingPtErr, 3);
	SETGATE(idt[17], 0, GD_KT, AlignCheck, 3);
	SETGATE(idt[18], 0, GD_KT, MachineCheck, 3);
	SETGATE(idt[19], 0, GD_KT, SIMDFloatErr, 3);
	SETGATE(idt[48], 0, GD_KT, SysCallTrapHandler, 3);
	*/
	int i = 0;
	for( i = 0 ; i< 20; i++) {
		if( i != 9 || i != 15 )
			SETGATE(idt[i], 0, GD_KT, interrupts[i], 3);
		if( i == 14 )
			SETGATE(idt[i], 0, GD_KT, interrupts[i], 0);
	}	
	cprintf("\n");
	SETGATE(idt[14], 0, GD_KT, PageFault, 0);
	SETGATE(idt[48], 0, GD_KT, SysCallTrapHandler, 3); 

	SETGATE(idt[IRQ_OFFSET+0], 0, GD_KT, irq0, 3);
	SETGATE(idt[IRQ_OFFSET+1], 0, GD_KT, irq1, 0);
	SETGATE(idt[IRQ_OFFSET+2], 0, GD_KT, irq2, 0);
	SETGATE(idt[IRQ_OFFSET+3], 0, GD_KT, irq3, 0);
	SETGATE(idt[IRQ_OFFSET+4], 0, GD_KT, irq4, 0);
	SETGATE(idt[IRQ_OFFSET+5], 0, GD_KT, irq5, 0);
	SETGATE(idt[IRQ_OFFSET+6], 0, GD_KT, irq6, 0);
	SETGATE(idt[IRQ_OFFSET+7], 0, GD_KT, irq7, 0);
	SETGATE(idt[IRQ_OFFSET+8], 0, GD_KT, irq8, 0);
	SETGATE(idt[IRQ_OFFSET+9], 0, GD_KT, irq9, 0);
	SETGATE(idt[IRQ_OFFSET+10], 0, GD_KT, irq10, 0);
	SETGATE(idt[IRQ_OFFSET+11], 0, GD_KT, irq11, 0);
	SETGATE(idt[IRQ_OFFSET+12], 0, GD_KT, irq12, 0);
	SETGATE(idt[IRQ_OFFSET+13], 0, GD_KT, irq13, 0);
	SETGATE(idt[IRQ_OFFSET+14], 0, GD_KT, irq14, 0);
	SETGATE(idt[IRQ_OFFSET+15], 0, GD_KT, irq15, 0);

	// Per-CPU setup 
	trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
void
trap_init_percpu(void)
{
	// The example code here sets up the Task State Segment (TSS) and
	// the TSS descriptor for CPU 0. But it is incorrect if we are
	// running on other CPUs because each CPU has its own kernel stack.
	// Fix the code so that it works for all CPUs.
	//
	// Hints:
	//   - The macro "thiscpu" always refers to the current CPU's
	//     struct CpuInfo;
	//   - The ID of the current CPU is given by cpunum() or
	//     thiscpu->cpu_id;
	//   - Use "thiscpu->cpu_ts" as the TSS for the current CPU,
	//     rather than the global "ts" variable;
	//   - Use gdt[(GD_TSS0 >> 3) + i] for CPU i's TSS descriptor;
	//   - You mapped the per-CPU kernel stacks in mem_init_mp()
	//
	// ltr sets a 'busy' flag in the TSS selector, so if you
	// accidentally load the same TSS on more than one CPU, you'll
	// get a triple fault.  If you set up an individual CPU's TSS
	// wrong, you may not get a fault until you try to return from
	// user space on that CPU.
	//
	// LAB 4: Your code here:

	uint8_t curr_cpuid = thiscpu->cpu_id;
	struct Taskstate *curr_ts = &thiscpu->cpu_ts;
	curr_ts->ts_esp0 = KSTACKTOP - (KSTKSIZE + KSTKGAP) * curr_cpuid;
	curr_ts->ts_ss0 = GD_KD;
	gdt[(GD_TSS0 >> 3) + curr_cpuid] = SEG16(STS_T32A, (uint32_t)curr_ts, sizeof(struct Taskstate), 0);	
	gdt[(GD_TSS0 >> 3) + curr_cpuid].sd_s = 0;	
	ltr(GD_TSS0 + curr_cpuid * sizeof(struct Segdesc));
	lidt(&idt_pd);

}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p from CPU %d\n", tf, cpunum());
	print_regs(&tf->tf_regs);
	cprintf("  es 0x----%04x\n", tf->tf_es);
	cprintf("  ds 0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	// If this trap was a page fault that just happened
	// (so %cr2 is meaningful), print the faulting linear address.
	if (tf == last_tf && tf->tf_trapno == T_PGFLT)
		cprintf(" cr2 0x%08x\n", rcr2());
	cprintf("  err  0x%08x", tf->tf_err);
	// For page faults, print decoded fault error code:
	// U/K=fault occurred in user/kernel mode
	// W/R=a write/read caused the fault
	// PR=a protection violation caused the fault (NP=page not present).
	if (tf->tf_trapno == T_PGFLT)
		cprintf(" [%s, %s, %s]\n",
			tf->tf_err & 4 ? "user" : "kernel",
			tf->tf_err & 2 ? "write" : "read",
			tf->tf_err & 1 ? "protection" : "not-present");
	else
		cprintf("\n");
	//cprintf(" eip 0x%08x\n", tf->tf_eip);
	cprintf("  eip  0x%08x\n", tf->tf_eip);
	cprintf("  cs 0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	if ((tf->tf_cs & 3) != 0) {
		cprintf(" esp 0x%08x\n", tf->tf_esp);
		cprintf("  ss   0x----%04x\n", tf->tf_ss);
	}
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  edi  0x%08x\n", regs->reg_edi);
	cprintf("  esi  0x%08x\n", regs->reg_esi);
	cprintf("  ebp  0x%08x\n", regs->reg_ebp);
	cprintf("  oesp 0x%08x\n", regs->reg_oesp);
	cprintf("  ebx  0x%08x\n", regs->reg_ebx);
	cprintf("  edx  0x%08x\n", regs->reg_edx);
	cprintf("  ecx  0x%08x\n", regs->reg_ecx);
	cprintf("  eax  0x%08x\n", regs->reg_eax);
}

static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	// LAB 3: Your code here.
	if (tf->tf_trapno == T_PGFLT)
		page_fault_handler(tf);
	if (tf->tf_trapno == T_BRKPT)
		monitor(tf);	
	if (tf->tf_trapno == T_SYSCALL) {
		uint32_t ret_val = syscall(tf->tf_regs.reg_eax, tf->tf_regs.reg_edx, tf->tf_regs.reg_ecx, tf->tf_regs.reg_ebx, tf->tf_regs.reg_edi, tf->tf_regs.reg_esi);
		tf->tf_regs.reg_eax = ret_val;
		return;
	}
	

	// Handle spurious interrupts
	// The hardware sometimes raises these because of noise on the
	// IRQ line or other reasons. We don't care.
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_SPURIOUS) {
		cprintf("Spurious interrupt on irq 7\n");
		print_trapframe(tf);
		return;
	}


	// Add time tick increment to clock interrupts.
	// Be careful! In multiprocessors, clock interrupts are
	// triggered on every CPU.
	// LAB 6: Your code here.
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_TIMER) {
		time_tick();
		lapic_eoi();
		sched_yield();
        		return;
    	}

	// Handle clock interrupts. Don't forget to acknowledge the
	// interrupt using lapic_eoi() before calling the scheduler!
	// LAB 4: Your code here.
	if (tf->tf_trapno == (IRQ_OFFSET + IRQ_TIMER)) {
		lapic_eoi();
		sched_yield();
		return;
	}

	// Handle keyboard and serial interrupts.
	// LAB 5: Your code here.

	if(tf->tf_trapno == IRQ_OFFSET + IRQ_KBD){
		kbd_intr();
		return;
	}
	if(tf->tf_trapno == IRQ_OFFSET + IRQ_SERIAL){
		serial_intr();
		return;
	}
	// Unexpected trap: The user process or the kernel has a bug.
	print_trapframe(tf);
	if (tf->tf_cs == GD_KT){
		cprintf("\n XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
		panic("unhandled trap in kernel");
	}
	else {
		env_destroy(curenv);
		return;
	}
}

void
trap(struct Trapframe *tf)
{
		// The environment may have set DF and some versions
	// of GCC rely on DF being clear
	asm volatile("cld" ::: "cc");
	// Halt the CPU if some other CPU has called panic()
	extern char *panicstr;
	if (panicstr)
		asm volatile("hlt");

	// Re-acqurie the big kernel lock if we were halted in
	// sched_yield()
	if (xchg(&thiscpu->cpu_status, CPU_STARTED) == CPU_HALTED)
		lock_kernel();
	// Check that interrupts are disabled. If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
	assert(!(read_eflags() & FL_IF));
	//cprintf("Incoming TRAP frame at %p\n", tf);
	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		lock_kernel();
		assert(curenv);
		// Garbage collect if current enviroment is a zombie
		if (curenv->env_status == ENV_DYING) {
			env_free(curenv);
			curenv = NULL;
			sched_yield();
		}
		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}
	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	last_tf = tf;
	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);
	// If we made it to this point, then no other environment was
	// scheduled, so we should return to the current environment
	// if doing so makes sense.
	if (curenv && curenv->env_status == ENV_RUNNING)
		env_run(curenv);
	else
		sched_yield();
}


void
page_fault_handler(struct Trapframe *tf)
{
	uint32_t fault_va;
	// Read processor's CR2 register to find the faulting address
	fault_va = rcr2();


// Handle kernel-mode page faults.

	// LAB 3: Your code here.
	if((tf->tf_cs  & 3) == 0){
	 // if kernel text
		panic ("\n !!! --- In page_fault_handler : Kerne Level Page fault  --- !!!");
	} 
	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.

	// Call the environment's page fault upcall, if one exists.  Set up a
	// page fault stack frame on the user exception stack (below
	// UXSTACKTOP), then branch to curenv->env_pgfault_upcall.
	//
	// The page fault upcall might cause another page fault, in which case
	// we branch to the page fault upcall recursively, pushing another
	// page fault stack frame on top of the user exception stack.
	//
	// The trap handler needs one word of scratch space at the top of the
	// trap-time stack in order to return.  In the non-recursive case, we
	// don't have to worry about this because the top of the regular user
	// stack is free.  In the recursive case, this means we have to leave
	// an extra word between the current top of the exception stack and
	// the new stack frame because the exception stack _is_ the trap-time
	// stack.
	//
	// If there's no page fault upcall, the environment didn't allocate a
	// page for its exception stack or can't write to it, or the exception
	// stack overflows, then destroy the environment that caused the fault.
	// Note that the grade script assumes you will first check for the page
	// fault upcall and print the "user fault va" message below if there is
	// none.  The remaining three checks can be combined into a single test.
	//
	// Hints:
	//   user_mem_assert() and env_run() are useful here.
	//   To change what the user environment runs, modify 'curenv->env_tf'
	//   (the 'tf' variable points at 'curenv->env_tf').
	
	// 1) Set up a page fault stack frame oon user exception stack, then branch to curenv->env_pgfault_upcall
	// 2) If page_fault_upcall causes another page fault, in which case we branch to the page fault upcall recursively pushing another page fault stack frame
	//	on top of user exception stack
	// 3)  
	
	/*
	*	THIS IS PAGE FAULT CAUSED IN USER MODE.
	*
	*/
		
	if(curenv->env_pgfault_upcall != NULL){
		uint32_t trapframe_top = UXSTACKTOP;

		if(tf->tf_esp <= UXSTACKTOP - 1 && tf->tf_esp >= UXSTACKTOP - PGSIZE)
                      	 	trapframe_top=tf->tf_esp-(int)4;
                	else
                        		trapframe_top=UXSTACKTOP;
		trapframe_top = trapframe_top - sizeof(struct UTrapframe);
		
	        	struct UTrapframe *user_tf = (struct UTrapframe*) trapframe_top;
	       	 user_mem_assert(curenv, user_tf, sizeof (struct UTrapframe), PTE_W);

	        	user_tf->utf_fault_va = fault_va;
	       	user_tf->utf_err = tf->tf_err;
	       	user_tf->utf_regs = tf->tf_regs;
	       	user_tf->utf_eip = tf->tf_eip;
	       	user_tf->utf_eflags = tf->tf_eflags;
	      	user_tf->utf_esp = tf->tf_esp;
	       	tf->tf_eip = (int)curenv->env_pgfault_upcall;
        	      	tf->tf_esp = trapframe_top;
       		env_run(curenv);
       	}

	// LAB 4: Your code here.
	// Destroy the environment that caused the fault.

	cprintf("[%08x] user fault va %08x ip %08x\n",
	curenv->env_id, fault_va, tf->tf_eip);
	print_trapframe(tf);
	env_destroy(curenv);
}
















































void init_interrupts(){

	interrupts[0] = DivideError; 	 	interrupts[10] = InvalidTSS; interrupts[11] = SegNotPresent;
	interrupts[1] = Debug;  			interrupts[12] = StackFault;
	interrupts[2] = NonMaskableInt; 	interrupts[13] = GenProtection;
	interrupts[3] = BrkPoint;  		interrupts[14] = PageFault;
	interrupts[4] = Overflow;  		
	interrupts[5] = RangeExceeded;  	interrupts[16] = FloatingPtErr;
	interrupts[6] = InvalidOpcode; 		interrupts[17] = AlignCheck;
	interrupts[7] = DeviceUnavail;		interrupts[18] = MachineCheck;
	interrupts[8] = DoubleFault;  		interrupts[19] = SIMDFloatErr;
	
	interrupts[48] = SysCallTrapHandler;
	// 9 15.
}
