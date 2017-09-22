/*
 *  linux/arch/i386/kernel/head32.c -- prepare to run common code
 *
 *  Copyright (C) 2000 Andrea Arcangeli <andrea@suse.de> SuSE
 *  Copyright (C) 2007 Eric Biederman <ebiederm@xmission.com>
 */

#include <linux/init.h>
#include <linux/start_kernel.h>
#include <linux/mm.h>
#include <linux/memblock.h>

#include <asm/setup.h>
#include <asm/sections.h>
#include <asm/e820/api.h>
#include <asm/apic.h>
#include <asm/io_apic.h>
#include <asm/tlbflush.h>

static void __init i386_default_early_setup(void)
{
	/* Initialize 32bit specific setup functions */
	x86_init.resources.reserve_resources = i386_reserve_resources;
#ifndef CONFIG_XEN
	x86_init.mpparse.setup_ioapic_ids = setup_ioapic_ids_from_mpc;
#endif
}

asmlinkage __visible void __init i386_start_kernel(void)
{
#ifdef CONFIG_XEN
	struct xen_platform_parameters pp;

	WARN_ON(HYPERVISOR_vm_assist(VMASST_CMD_enable,
				     VMASST_TYPE_4gb_segments));

	init_mm.pgd = swapper_pg_dir = (pgd_t *)xen_start_info->pt_base;

	if (HYPERVISOR_xen_version(XENVER_platform_parameters, &pp) == 0) {
		hypervisor_virt_start = pp.virt_start;
		reserve_top_address(0UL - pp.virt_start);
	}

	BUG_ON(pte_index(hypervisor_virt_start));

	set_cpu_cap(&new_cpu_data, X86_FEATURE_FPU);
#endif

	cr4_init_shadow();
#ifndef CONFIG_XEN
	sanitize_boot_params(&boot_params);
#endif

	x86_early_init_platform_quirks();

#ifndef CONFIG_XEN
	/* Call the subarch specific early setup function */
	switch (boot_params.hdr.hardware_subarch) {
	case X86_SUBARCH_INTEL_MID:
		x86_intel_mid_early_setup();
		break;
	case X86_SUBARCH_CE4100:
		x86_ce4100_early_setup();
		break;
	default:
		i386_default_early_setup();
		break;
	}
#else
#ifdef CONFIG_BLK_DEV_INITRD
	BUG_ON(xen_start_info->flags & SIF_MOD_START_PFN);
	if (xen_start_info->mod_start)
		xen_initrd_start = __pa(xen_start_info->mod_start);
#endif
	{
		int max_cmdline;

		if ((max_cmdline = MAX_GUEST_CMDLINE) > COMMAND_LINE_SIZE)
			max_cmdline = COMMAND_LINE_SIZE;
		memcpy(boot_command_line, xen_start_info->cmd_line, max_cmdline);
		boot_command_line[max_cmdline-1] = '\0';
	}

	i386_default_early_setup();
	xen_start_kernel();
#endif

	start_kernel();
}

#ifndef CONFIG_XEN
/*
 * Initialize page tables.  This creates a PDE and a set of page
 * tables, which are located immediately beyond __brk_base.  The variable
 * _brk_end is set up to point to the first "safe" location.
 * Mappings are created both at virtual address 0 (identity mapping)
 * and PAGE_OFFSET for up to _end.
 *
 * In PAE mode initial_page_table is statically defined to contain
 * enough entries to cover the VMSPLIT option (that is the top 1, 2 or 3
 * entries). The identity mapping is handled by pointing two PGD entries
 * to the first kernel PMD. Note the upper half of each PMD or PTE are
 * always zero at this stage.
 */
void __init mk_early_pgtbl_32(void)
{
#ifdef __pa
#undef __pa
#endif
#define __pa(x)  ((unsigned long)(x) - PAGE_OFFSET)
	pte_t pte, *ptep;
	int i;
	unsigned long *ptr;
	/* Enough space to fit pagetables for the low memory linear map */
	const unsigned long limit = __pa(_end) +
		(PAGE_TABLE_SIZE(LOWMEM_PAGES) << PAGE_SHIFT);
#ifdef CONFIG_X86_PAE
	pmd_t pl2, *pl2p = (pmd_t *)__pa(initial_pg_pmd);
#define SET_PL2(pl2, val)    { (pl2).pmd = (val); }
#else
	pgd_t pl2, *pl2p = (pgd_t *)__pa(initial_page_table);
#define SET_PL2(pl2, val)   { (pl2).pgd = (val); }
#endif

	ptep = (pte_t *)__pa(__brk_base);
	pte.pte = PTE_IDENT_ATTR;

	while ((pte.pte & PTE_PFN_MASK) < limit) {

		SET_PL2(pl2, (unsigned long)ptep | PDE_IDENT_ATTR);
		*pl2p = pl2;
#ifndef CONFIG_X86_PAE
		/* Kernel PDE entry */
		*(pl2p +  ((PAGE_OFFSET >> PGDIR_SHIFT))) = pl2;
#endif
		for (i = 0; i < PTRS_PER_PTE; i++) {
			*ptep = pte;
			pte.pte += PAGE_SIZE;
			ptep++;
		}

		pl2p++;
	}

	ptr = (unsigned long *)__pa(&max_pfn_mapped);
	/* Can't use pte_pfn() since it's a call with CONFIG_PARAVIRT */
	*ptr = (pte.pte & PTE_PFN_MASK) >> PAGE_SHIFT;

	ptr = (unsigned long *)__pa(&_brk_end);
	*ptr = (unsigned long)ptep + PAGE_OFFSET;
}
#endif
