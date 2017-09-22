/*
 *  linux/arch/x86_64/entry.S
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 2000, 2001, 2002  Andi Kleen SuSE Labs
 *  Copyright (C) 2000  Pavel Machek <pavel@suse.cz>
 *  Jun Nakajima <jun.nakajima@intel.com>
 *  Asit Mallick <asit.k.mallick@intel.com>
 *      Modified for Xen
 *
 * entry.S contains the system-call and fault low-level handling routines.
 *
 * Some of this is documented in Documentation/x86/entry_64.txt
 *
 * A note on terminology:
 * - iret frame:	Architecture defined interrupt frame from SS to RIP
 *			at the top of the kernel process stack.
 *
 * Some macro usage:
 * - ENTRY/END:		Define functions in the symbol table.
 * - TRACE_IRQ_*:	Trace hardirq state for lock debugging.
 * - idtentry:		Define exception entry points.
 */
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/cache.h>
#include <asm/errno.h>
#include "calling.h"
#include <asm/asm-offsets.h>
#include <asm/msr.h>
#include <asm/unistd.h>
#include <asm/thread_info.h>
#include <asm/hw_irq.h>
#include <asm/page_types.h>
#include <asm/irqflags.h>
#include <asm/processor-flags.h>
#include <asm/percpu.h>
#include <asm/asm.h>
#include <asm/smap.h>
#include <asm/pgtable_types.h>
#include <asm/export.h>
#include <asm/frame.h>
#include <linux/err.h>
#include <xen/interface/xen.h>
#include <xen/interface/features.h>

.code64
.section .entry.text, "ax"

.macro TRACE_IRQS_IRETQ
#ifdef CONFIG_TRACE_IRQFLAGS
	bt	$9, EFLAGS(%rsp)		/* interrupts off? */
	jnc	1f
	TRACE_IRQS_ON
1:
#endif
.endm

/*
 * When dynamic function tracer is enabled it will add a breakpoint
 * to all locations that it is about to modify, sync CPUs, update
 * all the code, sync CPUs, then remove the breakpoints. In this time
 * if lockdep is enabled, it might jump back into the debug handler
 * outside the updating of the IST protection. (TRACE_IRQS_ON/OFF).
 *
 * We need to change the IDT table before calling TRACE_IRQS_ON/OFF to
 * make sure the stack pointer does not get reset back to the top
 * of the debug stack, and instead just reuses the current stack.
 */
#if defined(CONFIG_DYNAMIC_FTRACE) && defined(CONFIG_TRACE_IRQFLAGS)

.macro TRACE_IRQS_OFF_DEBUG
	call	debug_stack_set_zero
	TRACE_IRQS_OFF
	call	debug_stack_reset
.endm

.macro TRACE_IRQS_ON_DEBUG
	call	debug_stack_set_zero
	TRACE_IRQS_ON
	call	debug_stack_reset
.endm

.macro TRACE_IRQS_IRETQ_DEBUG
	bt	$9, EFLAGS(%rsp)		/* interrupts off? */
	jnc	1f
	TRACE_IRQS_ON_DEBUG
1:
.endm

#else
# define TRACE_IRQS_OFF_DEBUG			TRACE_IRQS_OFF
# define TRACE_IRQS_ON_DEBUG			TRACE_IRQS_ON
# define TRACE_IRQS_IRETQ_DEBUG			TRACE_IRQS_IRETQ
#endif

NMI_MASK = 0x80000000

	/*
	 * Must be consistent with the definition in arch-x86/xen-x86_64.h:
	 *     struct iret_context {
	 *        u64 rax, r11, rcx, flags, rip, cs, rflags, rsp, ss;
	 *     };
	 * with rax, r11, and rcx being taken care of in the hypercall stub.
	 */
	.macro HYPERVISOR_IRET flag
	.if \flag == 0	# return from syscall always uses the hypercall
	testb	$3, 1*8(%rsp)
	jnz	2f
	testl	$NMI_MASK, 2*8(%rsp)
	jnz	2f

	cmpb	$0, xen_features+XENFEAT_supervisor_mode_kernel(%rip)
	jne	1f

	/* Direct iret to kernel space. Correct CS and SS. */
	orl	$3, 1*8(%rsp)
	orl	$3, 4*8(%rsp)
1:	iretq
	.endif

2:	/* Slow iret via hypervisor. */
	andl 	$~NMI_MASK, 2*8(%rsp)
	pushq	$\flag & VGCF_in_syscall
	jmp	hypercall_page + (__HYPERVISOR_iret * 32)
	.endm

/*
 * 64-bit SYSCALL instruction entry. Up to 6 arguments in registers.
 *
 * This is the only entry point used for 64-bit system calls.  The
 * hardware interface is reasonably well designed and the register to
 * argument mapping Linux uses fits well with the registers that are
 * available when SYSCALL is used.
 *
 * SYSCALL instructions can be found inlined in libc implementations as
 * well as some other programs and libraries.  There are also a handful
 * of SYSCALL instructions in the vDSO used, for example, as a
 * clock_gettimeofday fallback.
 *
 * 64-bit SYSCALL saves rip to rcx, clears rflags.RF, then saves rflags to r11,
 * then loads new ss, cs, and rip from previously programmed MSRs.
 * rflags gets masked by a value from another MSR (so CLD and CLAC
 * are not needed). SYSCALL does not save anything on the stack
 * and does not change rsp.
 *
 * Registers on entry:
 * rax  system call number
 * rcx  return address
 * r11  saved rflags (note: r11 is callee-clobbered register in C ABI)
 * rdi  arg0
 * rsi  arg1
 * rdx  arg2
 * r10  arg3 (needs to be moved to rcx to conform to C ABI)
 * r8   arg4
 * r9   arg5
 * (note: r12-r15, rbp, rbx are callee-preserved in C ABI)
 *
 * Only called from user space.
 *
 * When user can change pt_regs->foo always force IRET. That is because
 * it deals with uncanonical addresses better. SYSRET has trouble
 * with them due to bugs in both AMD and Intel CPUs.
 */

ENTRY(entry_SYSCALL_64)
	UNWIND_HINT_EMPTY
	/*
	 * Interrupts are enabled on entry.
	 */
	/* Construct struct pt_regs on stack */
	movl	$__USER_DS, 6*8(%rsp)		/* pt_regs->ss */
	movl	$__USER_CS, 3*8(%rsp)		/* pt_regs->cs */
	movq	%rax, 8(%rsp)			/* pt_regs->orig_ax */
	movq	%rdi, 0(%rsp)			/* pt_regs->di */
	pushq	%rsi				/* pt_regs->si */
	pushq	%rdx				/* pt_regs->dx */
	pushq	%rcx				/* pt_regs->cx */
	pushq	$-ENOSYS			/* pt_regs->ax */
	pushq	%r8				/* pt_regs->r8 */
	pushq	%r9				/* pt_regs->r9 */
	pushq	%r10				/* pt_regs->r10 */
	pushq	%r11				/* pt_regs->r11 */
	sub	$(6*8), %rsp			/* pt_regs->bp, bx, r12-15 not saved */
	UNWIND_HINT_REGS extra=0

	/*
	 * If we need to do entry work or if we guess we'll need to do
	 * exit work, go straight to the slow path.
	 */
	movq	PER_CPU_VAR(current_task), %r11
	testl	$_TIF_WORK_SYSCALL_ENTRY|_TIF_ALLWORK_MASK, TASK_TI_flags(%r11)
	jnz	entry_SYSCALL64_slow_path

entry_SYSCALL_64_fastpath:
	/*
	 * Easy case: issue the syscall.  If the syscall
	 * needs pt_regs, we'll call a stub that disables interrupts again
	 * and jumps to the slow path.
	 */
#if __SYSCALL_MASK == ~0
	cmpq	$__NR_syscall_max, %rax
#else
	andl	$__SYSCALL_MASK, %eax
	cmpl	$__NR_syscall_max, %eax
#endif
	ja	1f				/* return -ENOSYS (already in pt_regs->ax) */
	movq	%r10, %rcx

	/*
	 * This call instruction is handled specially in stub_ptregs_64.
	 * It might end up jumping to the slow path.  If it jumps, RAX
	 * and all argument registers are clobbered.
	 */
	call	*sys_call_table(, %rax, 8)
.Lentry_SYSCALL_64_after_fastpath_call:

	movq	%rax, RAX(%rsp)
1:

	/*
	 * If we get here, then we know that pt_regs is clean for SYSRET64.
	 * If we see that no exit work is required (which we are required
	 * to check with IRQs off), then we can go straight to SYSRET64.
	 */
	DISABLE_INTERRUPTS(CLBR_ANY)
	TRACE_IRQS_OFF
	movq	PER_CPU_VAR(current_task), %r11
	testl	$_TIF_ALLWORK_MASK, TASK_TI_flags(%r11)
	jnz	1f

	LOCKDEP_SYS_EXIT
	TRACE_IRQS_ON		/* user mode is traced as IRQs on */
	RESTORE_C_REGS_EXCEPT_RCX_R11
	REMOVE_PT_GPREGS_FROM_STACK 8
	UNWIND_HINT_EMPTY
	xor	%ecx, %ecx
	xor	%r11, %r11
	HYPERVISOR_IRET VGCF_IN_SYSCALL

1:
	/*
	 * The fast path looked good when we started, but something changed
	 * along the way and we need to switch to the slow path.  Calling
	 * raise(3) will trigger this, for example.  IRQs are off.
	 */
	TRACE_IRQS_ON
	ENABLE_INTERRUPTS(CLBR_ANY)
	SAVE_EXTRA_REGS
	movq	%rsp, %rdi
	call	syscall_return_slowpath	/* returns with IRQs disabled */
	jmp	return_from_SYSCALL_64

entry_SYSCALL64_slow_path:
	/* IRQs are on. */
	SAVE_EXTRA_REGS
	movq	%rsp, %rdi
	call	do_syscall_64		/* returns with IRQs disabled */

return_from_SYSCALL_64:
	jmp	restore_regs_and_iret
END(entry_SYSCALL_64)

ENTRY(stub_ptregs_64)
	/*
	 * Syscalls marked as needing ptregs land here.
	 * If we are on the fast path, we need to save the extra regs,
	 * which we achieve by trying again on the slow path.  If we are on
	 * the slow path, the extra regs are already saved.
	 *
	 * RAX stores a pointer to the C function implementing the syscall.
	 * IRQs are on.
	 */
	cmpq	$.Lentry_SYSCALL_64_after_fastpath_call, (%rsp)
	jne	1f

	/*
	 * Called from fast path -- pop return address and jump to slow path
	 */
	popq	%rax
	UNWIND_HINT_REGS extra=0
	jmp	entry_SYSCALL64_slow_path

1:
	jmp	*%rax				/* Called from C */
END(stub_ptregs_64)

.macro ptregs_stub func
ENTRY(ptregs_\func)
	UNWIND_HINT_FUNC
	leaq	\func(%rip), %rax
	jmp	stub_ptregs_64
END(ptregs_\func)
.endm

/* Instantiate ptregs_stub for each ptregs-using syscall */
#define __SYSCALL_64_QUAL_(sym)
#define __SYSCALL_64_QUAL_ptregs(sym) ptregs_stub sym
#define __SYSCALL_64(nr, sym, qual) __SYSCALL_64_QUAL_##qual(sym)
#include <asm/syscalls_64.h>

/*
 * %rdi: prev task
 * %rsi: next task
 */
ENTRY(__switch_to_asm)
	UNWIND_HINT_FUNC
	/*
	 * Save callee-saved registers
	 * This must match the order in inactive_task_frame
	 */
	pushq	%rbp
	pushq	%rbx
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15

	/* switch stack */
	movq	%rsp, TASK_threadsp(%rdi)
	movq	TASK_threadsp(%rsi), %rsp

#ifdef CONFIG_CC_STACKPROTECTOR
	movq	TASK_stack_canary(%rsi), %rbx
	movq	%rbx, PER_CPU_VAR(irq_stack_union)+stack_canary_offset
#endif

	/* restore callee-saved registers */
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbx
	popq	%rbp

	jmp	__switch_to
END(__switch_to_asm)

/*
 * A newly forked process directly context switches into this address.
 *
 * rax: prev task we switched from
 * rbx: kernel thread func (NULL for user thread)
 * r12: kernel thread arg
 */
ENTRY(ret_from_fork)
	UNWIND_HINT_EMPTY
	movq	%rax, %rdi
	call	schedule_tail			/* rdi: 'prev' task parameter */

	testq	%rbx, %rbx			/* from kernel_thread? */
	jnz	1f				/* kernel threads are uncommon */

2:
	UNWIND_HINT_REGS
	movq	%rsp, %rdi
	call	syscall_return_slowpath	/* returns with IRQs disabled */
	jmp	restore_regs_and_iret

1:
	/* kernel thread */
	movq	%r12, %rdi
	call	*%rbx
	/*
	 * A kernel thread is allowed to return here after successfully
	 * calling do_execve().  Exit to userspace to complete the execve()
	 * syscall.
	 * Need to set the proper %ss (not NULL) for ring 3 iretq
	 */
	movl	$__KERNEL_DS, SS(%rsp)
	movq	$0, RAX(%rsp)
	jmp	2b
END(ret_from_fork)

.macro DEBUG_ENTRY_ASSERT_IRQS_OFF
#ifdef CONFIG_DEBUG_ENTRY
	pushfq
	testl $X86_EFLAGS_IF, (%rsp)
	jz .Lokay_\@
	ud2
.Lokay_\@:
	addq $8, %rsp
#endif
.endm

/*
 * Enters the IRQ stack if we're not already using it.  NMI-safe.  Clobbers
 * flags and puts old RSP into old_rsp, and leaves all other GPRs alone.
 * Requires kernel GSBASE.
 *
 * The invariant is that, if irq_count != -1, then the IRQ stack is in use.
 */
.macro ENTER_IRQ_STACK regs=1 old_rsp
	DEBUG_ENTRY_ASSERT_IRQS_OFF
	movq	%rsp, \old_rsp

	.if \regs
	UNWIND_HINT_REGS base=\old_rsp
	.endif

	incl	PER_CPU_VAR(irq_count)
	jnz	.Lirq_stack_push_old_rsp_\@

	/*
	 * Right now, if we just incremented irq_count to zero, we've
	 * claimed the IRQ stack but we haven't switched to it yet.
	 *
	 * If anything is added that can interrupt us here without using IST,
	 * it must be *extremely* careful to limit its stack usage.  This
	 * could include kprobes and a hypothetical future IST-less #DB
	 * handler.
	 *
	 * The OOPS unwinder relies on the word at the top of the IRQ
	 * stack linking back to the previous RSP for the entire time we're
	 * on the IRQ stack.  For this to work reliably, we need to write
	 * it before we actually move ourselves to the IRQ stack.
	 */

	movq	\old_rsp, PER_CPU_VAR(irq_stack_union + IRQ_STACK_SIZE - 8)
	movq	PER_CPU_VAR(irq_stack_ptr), %rsp

#ifdef CONFIG_DEBUG_ENTRY
	/*
	 * If the first movq above becomes wrong due to IRQ stack layout
	 * changes, the only way we'll notice is if we try to unwind right
	 * here.  Assert that we set up the stack right to catch this type
	 * of bug quickly.
	 */
	cmpq	-8(%rsp), \old_rsp
	je	.Lirq_stack_okay\@
	ud2
	.Lirq_stack_okay\@:
#endif

.Lirq_stack_push_old_rsp_\@:
	pushq	\old_rsp

	.if \regs
	UNWIND_HINT_REGS indirect=1
	.endif
.endm

/*
 * Undoes ENTER_IRQ_STACK.
 */
.macro LEAVE_IRQ_STACK regs=1
	DEBUG_ENTRY_ASSERT_IRQS_OFF
	/* We need to be off the IRQ stack before decrementing irq_count. */
	popq	%rsp

	.if \regs
	UNWIND_HINT_REGS
	.endif

	/*
	 * As in ENTER_IRQ_STACK, irq_count == 0, we are still claiming
	 * the irq stack but we're not on it.
	 */

	decl	PER_CPU_VAR(irq_count)
.endm

/*
 * Interrupt exit.
 */
	/* Interrupt came from user space */
GLOBAL(retint_user)
	mov	%rsp,%rdi
	call	prepare_exit_to_usermode
	jmp	restore_regs_and_iret
END(retint_user)

/* Returning to kernel space */
retint_kernel:
#ifdef CONFIG_PREEMPT
	/* Interrupts are off */
	/* Check if we need preemption */
	bt	$9, EFLAGS(%rsp)		/* were interrupts off? */
	jnc	1f
0:	cmpl	$0, PER_CPU_VAR(__preempt_count)
	jnz	1f
	call	preempt_schedule_irq
	jmp	0b
1:
#endif

/*
 * At this label, code paths which return to kernel and to user,
 * which come from interrupts/exception and from syscalls, merge.
 */
GLOBAL(restore_regs_and_iret)
	RESTORE_EXTRA_REGS
	movl	EFLAGS(%rsp), %eax
	shr	$9, %eax			/* EAX[0] == IRET_EFLAGS.IF */
	GET_VCPU_INFO
	andb	evtchn_upcall_mask(%rsi), %al
	andb	$1, %al				/* EAX[0] == IRET_EFLAGS.IF & event_mask */
	jnz	restore_all_enable_events	/*        != 0 => enable event delivery */
restore_c_regs_and_iret:
	/*
	 * The iretq could re-enable interrupts:
	 */
	TRACE_IRQS_IRETQ
	RESTORE_C_REGS
	REMOVE_PT_GPREGS_FROM_STACK 8
	HYPERVISOR_IRET 0
END(retint_kernel)

/*
 * Exception entry points.
 */
#define CPU_TSS_IST(x) PER_CPU_VAR(cpu_tss) + (TSS_ist + ((x) - 1) * 8)

.macro idtentry sym do_sym has_error_code:req paranoid=0 shift_ist=-1
ENTRY(\sym)
	UNWIND_HINT_IRET_REGS offset=8

	/* Sanity check */
	.if \shift_ist != -1 && \paranoid == 0
	.error "using shift_ist requires paranoid=1"
	.endif

	ASM_CLAC
	movq	0(%rsp), %rcx
	movq	8(%rsp), %r11

	.if \has_error_code
	ALLOC_PT_GPREGS_ON_STACK -2*8
	.else
	movq	$-1, 8(%rsp)			/* ORIG_RAX: no syscall to restart */
	ALLOC_PT_GPREGS_ON_STACK -1*8
	.endif

	.if \paranoid
	.if \paranoid == 1
	testb	$3, CS(%rsp)			/* If coming from userspace, switch stacks */
	jnz	1f
	.endif
	call	paranoid_entry
	.else
	call	error_entry
	.endif
	UNWIND_HINT_REGS
	/* returned flag: ebx=0: need swapgs on exit, ebx=1: don't need it */

	.if \paranoid
	.if \shift_ist != -1
	TRACE_IRQS_OFF_DEBUG			/* reload IDT in case of recursion */
	.else
	TRACE_IRQS_OFF
	.endif
	.endif

	movq	%rsp, %rdi			/* pt_regs pointer */

	.if \has_error_code
	movq	ORIG_RAX(%rsp), %rsi		/* get error code */
	movq	$-1, ORIG_RAX(%rsp)		/* no syscall to restart */
	.else
	xorl	%esi, %esi			/* no error code */
	.endif

	.if \shift_ist != -1
	subq	$EXCEPTION_STKSZ, CPU_TSS_IST(\shift_ist)
	.endif

	call	\do_sym

	.if \shift_ist != -1
	addq	$EXCEPTION_STKSZ, CPU_TSS_IST(\shift_ist)
	.endif

	/* these procedures expect "no swapgs" flag in ebx */
	.if \paranoid
	jmp	paranoid_exit
	.else
	jmp	error_exit
	.endif

	.if \paranoid == 1
	/*
	 * Paranoid entry from userspace.  Switch stacks and treat it
	 * as a normal entry.  This means that paranoid handlers
	 * run in real process context if user_mode(regs).
	 */
1:
	call	error_entry


	movq	%rsp, %rdi			/* pt_regs pointer */
	call	sync_regs
	movq	%rax, %rsp			/* switch stack */

	movq	%rsp, %rdi			/* pt_regs pointer */

	.if \has_error_code
	movq	ORIG_RAX(%rsp), %rsi		/* get error code */
	movq	$-1, ORIG_RAX(%rsp)		/* no syscall to restart */
	.else
	xorl	%esi, %esi			/* no error code */
	.endif

	call	\do_sym

	jmp	error_exit			/* %ebx: no swapgs flag */
	.endif
END(\sym)
.endm

#ifdef CONFIG_TRACING
.macro trace_idtentry sym do_sym has_error_code:req
idtentry trace_\sym trace_\do_sym has_error_code=\has_error_code
idtentry \sym \do_sym has_error_code=\has_error_code
.endm
#else
.macro trace_idtentry sym do_sym has_error_code:req
idtentry \sym \do_sym has_error_code=\has_error_code
.endm
#endif

/*
 * Copied from arch/xen/i386/kernel/entry.S
 */               
# A note on the "critical region" in our callback handler.
# We want to avoid stacking callback handlers due to events occurring
# during handling of the last event. To do this, we keep events disabled
# until we've done all processing. HOWEVER, we must enable events before
# popping the stack frame (can't be done atomically) and so it would still
# be possible to get enough handler activations to overflow the stack.
# Although unlikely, bugs of that kind are hard to track down, so we'd
# like to avoid the possibility.
# So, on entry to the handler we detect whether we interrupted an
# existing activation in its critical region -- if so, we pop the current
# activation and restart the handler using the previous one.
ENTRY(do_hypervisor_callback)   # do_hypervisor_callback(struct *pt_regs)
# Since we don't modify %rdi, evtchn_do_upall(struct *pt_regs) will
# see the correct pointer to the pt_regs
	UNWIND_HINT_FUNC
	movq	%rdi, %rsp		# we don't return, adjust the stack frame
	UNWIND_HINT_REGS
11:
	ENTER_IRQ_STACK old_rsp=%r10
	call	evtchn_do_upcall
	LEAVE_IRQ_STACK

#ifndef CONFIG_PREEMPT
	test	%al, %al
	jz	error_exit
	cmpl	$0, PER_CPU_VAR(__preempt_count)
	jnz	error_exit
	bt	$9, EFLAGS(%rsp)
	jnc	error_exit
	movb	$0, PER_CPU_VAR(privcmd_hcall)
	call	preempt_schedule_irq
	movb	$1, PER_CPU_VAR(privcmd_hcall)
#endif

	jmp	error_exit
END(do_hypervisor_callback)

        ALIGN
restore_all_enable_events:  
	TRACE_IRQS_ON
	__ENABLE_INTERRUPTS

.Lscrit: /**** START OF CRITICAL REGION ****/
	__TEST_PENDING
	jz	restore_c_regs_and_iret

	__DISABLE_INTERRUPTS
.Lecrit: /**** END OF CRITICAL REGION ****/
	SAVE_EXTRA_REGS
	ENCODE_FRAME_POINTER
        movq	%rsp, %rdi		# set the argument again
	jmp	11b
# At this point, unlike on x86-32, we don't do the fixup to simplify the 
# code and the stack frame is more complex on x86-64.
# When the kernel is interrupted in the critical section, the kernel 
# will do IRET in that case, and everything will be restored at that point, 
# i.e. it just resumes from the next instruction interrupted with the same context. 

# Hypervisor uses this for application faults while it executes.
# We get here for two reasons:
#  1. Fault while reloading DS, ES, FS or GS
#  2. Fault while executing IRET
# Category 1 we do not need to fix up as Xen has already reloaded all segment
# registers that could be reloaded and zeroed the others.
# Category 2 we fix up by killing the current process. We cannot use the
# normal Linux return path in this case because if we use the IRET hypercall
# to pop the stack frame we end up in an infinite loop of failsafe callbacks.
# We distinguish between categories by comparing each saved segment register
# with its current contents: any discrepancy means we in category 1.
ENTRY(failsafe_callback)
	ASM_CLAC
	movw	%ds, %cx
	cmpw	%cx, 0x10(%rsp)
	jne	1f
	movw	%es, %cx
	cmpw	%cx, 0x18(%rsp)
	jne	1f
	movw	%fs, %cx
	cmpw	%cx, 0x20(%rsp)
	jne	1f
	movw	%gs, %cx
	cmpw	%cx, 0x28(%rsp)
	jne	1f
	/* All segments match their saved values => Category 2 (Bad IRET). */
	movq	0(%rsp), %rcx
	movq	8(%rsp), %r11
	addq	$0x30, %rsp
	movq	$11, %rdi		/* SIGSEGV */
	jmp	do_exit
1:	/* Segment mismatch => Category 1 (Bad segment). Retry the IRET. */
	movq	0(%rsp), %rcx
	movq	8(%rsp), %r11
	addq	$0x30, %rsp
	pushq	$-1
	ALLOC_PT_GPREGS_ON_STACK
	SAVE_C_REGS
	SAVE_EXTRA_REGS
	ENCODE_FRAME_POINTER
	jmp	error_exit

idtentry divide_error			do_divide_error			has_error_code=0
idtentry overflow			do_overflow			has_error_code=0
idtentry bounds				do_bounds			has_error_code=0
idtentry invalid_op			do_invalid_op			has_error_code=0
idtentry device_not_available		do_device_not_available		has_error_code=0
idtentry hypervisor_callback		do_hypervisor_callback		has_error_code=0
idtentry coprocessor_segment_overrun	do_coprocessor_segment_overrun	has_error_code=0
idtentry invalid_TSS			do_invalid_TSS			has_error_code=1
idtentry segment_not_present		do_segment_not_present		has_error_code=1
idtentry coprocessor_error		do_coprocessor_error		has_error_code=0
idtentry alignment_check		do_alignment_check		has_error_code=1
idtentry simd_coprocessor_error		do_simd_coprocessor_error	has_error_code=0

/* Call softirq on interrupt stack. Interrupts are off. */
ENTRY(do_softirq_own_stack)
	pushq	%rbp
	mov	%rsp, %rbp
	ENTER_IRQ_STACK regs=0 old_rsp=%r11
	call	__do_softirq
	LEAVE_IRQ_STACK regs=0
	leaveq
	ret
ENDPROC(do_softirq_own_stack)

idtentry debug			do_debug		has_error_code=0
idtentry nmi			do_nmi_callback		has_error_code=0
idtentry int3			do_int3			has_error_code=0
idtentry stack_segment		do_stack_segment	has_error_code=1

idtentry general_protection	do_general_protection	has_error_code=1
trace_idtentry page_fault	do_page_fault		has_error_code=1

#ifdef CONFIG_KVM_GUEST
idtentry async_page_fault	do_async_page_fault	has_error_code=1
#endif

#ifdef CONFIG_X86_MCE
idtentry machine_check					has_error_code=0	do_sym=*machine_check_vector(%rip)
#endif

#ifndef CONFIG_XEN
/*
 * Save all registers in pt_regs, and switch gs if needed.
 * Use slow, but surefire "are we in kernel?" check.
 * Return: ebx=0: need swapgs on exit, ebx=1: otherwise
 */
ENTRY(paranoid_entry)
	UNWIND_HINT_FUNC
	cld
	SAVE_C_REGS 8
	SAVE_EXTRA_REGS 8
	ENCODE_FRAME_POINTER 8
	movl	$1, %ebx
	movl	$MSR_GS_BASE, %ecx
	rdmsr
	testl	%edx, %edx
	js	1f				/* negative -> in kernel */
	SWAPGS
	xorl	%ebx, %ebx
1:	ret
END(paranoid_entry)

/*
 * "Paranoid" exit path from exception stack.  This is invoked
 * only on return from non-NMI IST interrupts that came
 * from kernel space.
 *
 * We may be returning to very strange contexts (e.g. very early
 * in syscall entry), so checking for preemption here would
 * be complicated.  Fortunately, we there's no good reason
 * to try to handle preemption here.
 *
 * On entry, ebx is "no swapgs" flag (1: don't need swapgs, 0: need it)
 */
ENTRY(paranoid_exit)
	UNWIND_HINT_REGS
	DISABLE_INTERRUPTS(CLBR_ANY)
	TRACE_IRQS_OFF_DEBUG
	testl	%ebx, %ebx			/* swapgs needed? */
	jnz	paranoid_exit_no_swapgs
	TRACE_IRQS_IRETQ
	SWAPGS_UNSAFE_STACK
	jmp	paranoid_exit_restore
paranoid_exit_no_swapgs:
	TRACE_IRQS_IRETQ_DEBUG
paranoid_exit_restore:
	RESTORE_EXTRA_REGS
	RESTORE_C_REGS
	REMOVE_PT_GPREGS_FROM_STACK 8
	INTERRUPT_RETURN
END(paranoid_exit)
#endif

/*
 * Save all registers in pt_regs, and switch gs if needed.
 * Return: EBX=0: came from user mode; EBX=1: otherwise
 */
ENTRY(error_entry)
	UNWIND_HINT_FUNC
	cld
	SAVE_C_REGS 8
	SAVE_EXTRA_REGS 8
	ENCODE_FRAME_POINTER 8
#ifndef CONFIG_XEN
	xorl	%ebx, %ebx
	testb	$3, CS+8(%rsp)
	jz	.Lerror_kernelspace

	/*
	 * We entered from user mode or we're pretending to have entered
	 * from user mode due to an IRET fault.
	 */
	SWAPGS

.Lerror_entry_from_usermode_after_swapgs:
	/*
	 * We need to tell lockdep that IRQs are off.  We can't do this until
	 * we fix gsbase, and we should do it before enter_from_user_mode
	 * (which can take locks).
	 */
	TRACE_IRQS_OFF
	CALL_enter_from_user_mode
	ret

.Lerror_entry_done:
#endif
	TRACE_IRQS_OFF
	ret

#ifndef CONFIG_XEN
	/*
	 * There are two places in the kernel that can potentially fault with
	 * usergs. Handle them here.  B stepping K8s sometimes report a
	 * truncated RIP for IRET exceptions returning to compat mode. Check
	 * for these here too.
	 */
.Lerror_kernelspace:
	incl	%ebx
	leaq	native_irq_return_iret(%rip), %rcx
	cmpq	%rcx, RIP+8(%rsp)
	je	.Lerror_bad_iret
	movl	%ecx, %eax			/* zero extend */
	cmpq	%rax, RIP+8(%rsp)
	je	.Lbstep_iret
	cmpq	$.Lgs_change, RIP+8(%rsp)
	jne	.Lerror_entry_done

	/*
	 * hack: .Lgs_change can fail with user gsbase.  If this happens, fix up
	 * gsbase and proceed.  We'll fix up the exception and land in
	 * .Lgs_change's error handler with kernel gsbase.
	 */
	SWAPGS
	jmp .Lerror_entry_done

.Lbstep_iret:
	/* Fix truncated RIP */
	movq	%rcx, RIP+8(%rsp)
	/* fall through */

.Lerror_bad_iret:
	/*
	 * We came from an IRET to user mode, so we have user gsbase.
	 * Switch to kernel gsbase:
	 */
	SWAPGS

	/*
	 * Pretend that the exception came from user mode: set up pt_regs
	 * as if we faulted immediately after IRET and clear EBX so that
	 * error_exit knows that we will be returning to user mode.
	 */
	mov	%rsp, %rdi
	call	fixup_bad_iret
	mov	%rax, %rsp
	decl	%ebx
	jmp	.Lerror_entry_from_usermode_after_swapgs
#endif
END(error_entry)


ENTRY(error_exit)
	UNWIND_HINT_REGS
	DISABLE_INTERRUPTS(CLBR_ANY)
	TRACE_IRQS_OFF
	testb	$3, CS(%rsp)
	jz	retint_kernel
	jmp	retint_user
END(error_exit)

#define extern #
#include <asm-generic/percpu.h>

.pushsection PER_CPU_BASE_SECTION, "aw", @progbits
in_NMI:	.byte	0
.popsection

do_nmi_callback:
	addq	$8, %rsp
	orb	$1, PER_CPU_VAR(in_NMI)
	js	1f
0:
	movb	$0x80, PER_CPU_VAR(in_NMI)
	call	do_nmi
	movl	$0x80, %eax
	cmpxchgb %ah, PER_CPU_VAR(in_NMI)
	jne 	0b
	orl	$NMI_MASK, EFLAGS(%rsp)
1:
	DISABLE_INTERRUPTS(CLBR_ANY)
	TRACE_IRQS_OFF
	jmp	restore_regs_and_iret
END(do_nmi_callback)

#ifndef CONFIG_IA32_EMULATION
ENTRY(ignore_sysret)
	popq	%rcx
	popq	%r11
	UNWIND_HINT_EMPTY
	mov	$-ENOSYS, %eax
	HYPERVISOR_IRET VGCF_i387_valid
END(ignore_sysret)
#endif

ENTRY(rewind_stack_do_exit)
	UNWIND_HINT_FUNC
	/* Prevent any naive code from trying to unwind to our caller. */
	xorl	%ebp, %ebp

	movq	PER_CPU_VAR(cpu_current_top_of_stack), %rax
	leaq	-PTREGS_SIZE(%rax), %rsp
	UNWIND_HINT_FUNC sp_offset=PTREGS_SIZE

	call	do_exit
END(rewind_stack_do_exit)
