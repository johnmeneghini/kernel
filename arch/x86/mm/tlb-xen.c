#include <linux/init.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/cpumask.h>

#include <asm/tlbflush.h>
#include <asm/mmu_context.h>
#include <asm/cache.h>
#include <linux/debugfs.h>

void switch_mm(struct mm_struct *prev, struct mm_struct *next,
	       struct task_struct *tsk)
{
	unsigned long flags;

	local_irq_save(flags);
	switch_mm_irqs_off(prev, next, tsk);
	local_irq_restore(flags);
}

void switch_mm_irqs_off(struct mm_struct *prev, struct mm_struct *next,
			struct task_struct *tsk)
{
	unsigned cpu = smp_processor_id();
#ifndef CONFIG_XEN /* XEN: no lazy tlb */
	struct mm_struct *real_prev = this_cpu_read(cpu_tlbstate.loaded_mm);
#else
	struct mmuext_op _op[2 + (sizeof(long) > 4)], *op = _op;
#endif
#ifdef CONFIG_X86_64_XEN
	pgd_t *upgd;
#endif

	/*
	 * NB: The scheduler will call us with prev == next when
	 * switching from lazy TLB mode to normal mode if active_mm
	 * isn't changing.  When this happens, there is no guarantee
	 * that CR3 (and hence cpu_tlbstate.loaded_mm) matches next.
	 *
	 * NB: leave_mm() calls us with prev == NULL and tsk == NULL.
	 */

	BUG_ON(!xen_feature(XENFEAT_writable_page_tables) &&
	       !PagePinned(virt_to_page(next->pgd)));

#ifndef CONFIG_XEN /* XEN: no lazy tlb */
	this_cpu_write(cpu_tlbstate.state, TLBSTATE_OK);
#endif

	if (prev == next) {
		/*
		 * There's nothing to do: we always keep the per-mm control
		 * regs in sync with cpu_tlbstate.loaded_mm.  Just
		 * sanity-check mm_cpumask.
		 */
		if (WARN_ON_ONCE(!cpumask_test_cpu(cpu, mm_cpumask(next))))
			cpumask_set_cpu(cpu, mm_cpumask(next));
		return;
	}

	if (IS_ENABLED(CONFIG_VMAP_STACK)) {
		/*
		 * If our current stack is in vmalloc space and isn't
		 * mapped in the new pgd, we'll double-fault.  Forcibly
		 * map it.
		 */
		unsigned int stack_pgd_index = pgd_index(current_stack_pointer());

		pgd_t *pgd = next->pgd + stack_pgd_index;

		if (unlikely(pgd_none(*pgd)))
			set_pgd(pgd, init_mm.pgd[stack_pgd_index]);
	}

#ifndef CONFIG_XEN /* XEN: no lazy tlb */
	this_cpu_write(cpu_tlbstate.loaded_mm, next);
#endif

	WARN_ON_ONCE(cpumask_test_cpu(cpu, mm_cpumask(next)));
	cpumask_set_cpu(cpu, mm_cpumask(next));

	/*
	 * Re-load page tables: load_cr3(next->pgd).
	 *
	 * This logic has an ordering constraint:
	 *
	 *  CPU 0: Write to a PTE for 'next'
	 *  CPU 0: load bit 1 in mm_cpumask.  if nonzero, send IPI.
	 *  CPU 1: set bit 1 in next's mm_cpumask
	 *  CPU 1: load from the PTE that CPU 0 writes (implicit)
	 *
	 * We need to prevent an outcome in which CPU 1 observes
	 * the new PTE value and CPU 0 observes bit 1 clear in
	 * mm_cpumask.  (If that occurs, then the IPI will never
	 * be sent, and CPU 0's TLB will contain a stale entry.)
	 *
	 * The bad outcome can occur if either CPU's load is
	 * reordered before that CPU's store, so both CPUs must
	 * execute full barriers to prevent this from happening.
	 *
	 * Thus, switch_mm needs a full barrier between the
	 * store to mm_cpumask and any operation that could load
	 * from next->pgd.  TLB fills are special and can happen
	 * due to instruction fetches or for no reason at all,
	 * and neither LOCK nor MFENCE orders them.
	 * Fortunately, load_cr3() is serializing and gives the
	 * ordering guarantee we need.
	 */
	op->cmd = MMUEXT_NEW_BASEPTR;
	op->arg1.mfn = virt_to_mfn(next->pgd);
	op++;

#ifdef CONFIG_X86_64_XEN
	/* xen_new_user_pt(next->pgd) */
	op->cmd = MMUEXT_NEW_USER_BASEPTR;
	upgd = __user_pgd(next->pgd);
	op->arg1.mfn = likely(upgd) ? virt_to_mfn(upgd) : 0;
	op++;
#endif

	trace_tlb_flush(TLB_FLUSH_ON_TASK_SWITCH, TLB_FLUSH_ALL);

	/* Load per-mm CR4 and LDTR state */
	load_mm_cr4(next);
	op += switch_ldt(prev, next, op);

	BUG_ON(HYPERVISOR_mmuext_op(_op, op - _op, NULL, DOMID_SELF));

	/* Stop TLB flushes for the previous mm */
	WARN_ON_ONCE(!cpumask_test_cpu(cpu, mm_cpumask(prev)) &&
		     prev != &init_mm);
	cpumask_clear_cpu(cpu, mm_cpumask(prev));
}

void flush_tlb_others(const struct cpumask *cpumask,
		      const struct flush_tlb_info *info)
{
	count_vm_tlb_event(NR_TLB_REMOTE_FLUSH);
	if (info->end == TLB_FLUSH_ALL) {
		xen_tlb_flush_mask(cpumask);
		trace_tlb_flush(TLB_REMOTE_SHOOTDOWN, TLB_FLUSH_ALL);
	} else {
		/* flush range by one by one 'invlpg' */
		unsigned long addr;

		for (addr = info->start; addr < info->end; addr += PAGE_SIZE)
			xen_invlpg_mask(cpumask, addr);
		trace_tlb_flush(TLB_REMOTE_SHOOTDOWN,
				PFN_DOWN(info->end - info->start));
	}
}

/*
 * See Documentation/x86/tlb.txt for details.  We choose 33
 * because it is large enough to cover the vast majority (at
 * least 95%) of allocations, and is small enough that we are
 * confident it will not cause too much overhead.  Each single
 * flush is about 100 ns, so this caps the maximum overhead at
 * _about_ 3,000 ns.
 *
 * This is in units of pages.
 */
static unsigned long tlb_single_page_flush_ceiling __read_mostly = 33;

void flush_tlb_mm_range(struct mm_struct *mm, unsigned long start,
				unsigned long end, unsigned long vmflag)
{
	int cpu;
	const cpumask_t *mask = mm_cpumask(mm);
	cpumask_var_t temp;
	struct flush_tlb_info info = {
		.mm = mm,
	};

	cpu = get_cpu();

	/* Synchronize with switch_mm. */
	smp_mb();

	/* Should we flush just the requested range? */
	if ((end != TLB_FLUSH_ALL) &&
	    !(vmflag & VM_HUGETLB) &&
	    ((end - start) >> PAGE_SHIFT) <= tlb_single_page_flush_ceiling) {
		info.start = start;
		info.end = end;
	} else {
		info.start = 0UL;
		info.end = TLB_FLUSH_ALL;
	}

	if (current->active_mm != mm || !current->mm) {
		if (cpumask_any_but(mask, cpu) >= nr_cpu_ids) {
			put_cpu();
			return;
		}
		if (alloc_cpumask_var(&temp, GFP_ATOMIC)) {
			cpumask_andnot(temp, mask, cpumask_of(cpu));
			mask = temp;
		}
	}

	flush_tlb_others(mask, &info);
	put_cpu();

	if (mask != mm_cpumask(mm))
		free_cpumask_var(temp);
}

void flush_tlb_kernel_range(unsigned long start, unsigned long end)
{

	/* Balance as user space task's flush, a bit conservative */
	if (end == TLB_FLUSH_ALL ||
	    (end - start) > tlb_single_page_flush_ceiling << PAGE_SHIFT) {
		xen_tlb_flush_all();
	} else {
		unsigned long addr;

		/* flush range by one by one 'invlpg' */
		for (addr = start; addr < end; addr += PAGE_SIZE)
			xen_invlpg_all(addr);
	}
}

void arch_tlbbatch_flush(struct arch_tlbflush_unmap_batch *batch)
{
	struct flush_tlb_info info = {
		.mm = NULL,
		.start = 0UL,
		.end = TLB_FLUSH_ALL,
	};

	flush_tlb_others(&batch->cpumask, &info);
	cpumask_clear(&batch->cpumask);
}

static ssize_t tlbflush_read_file(struct file *file, char __user *user_buf,
			     size_t count, loff_t *ppos)
{
	char buf[32];
	unsigned int len;

	len = sprintf(buf, "%ld\n", tlb_single_page_flush_ceiling);
	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t tlbflush_write_file(struct file *file,
		 const char __user *user_buf, size_t count, loff_t *ppos)
{
	char buf[32];
	ssize_t len;
	int ceiling;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtoint(buf, 0, &ceiling))
		return -EINVAL;

	if (ceiling < 0)
		return -EINVAL;

	tlb_single_page_flush_ceiling = ceiling;
	return count;
}

static const struct file_operations fops_tlbflush = {
	.read = tlbflush_read_file,
	.write = tlbflush_write_file,
	.llseek = default_llseek,
};

static int __init create_tlb_single_page_flush_ceiling(void)
{
	debugfs_create_file("tlb_single_page_flush_ceiling", S_IRUSR | S_IWUSR,
			    arch_debugfs_dir, NULL, &fops_tlbflush);
	return 0;
}
late_initcall(create_tlb_single_page_flush_ceiling);
