#ifndef _ASM_X86_PGTABLE_64_H
#define _ASM_X86_PGTABLE_64_H

#include <linux/const.h>
#include <asm/pgtable_64_types.h>

#ifndef __ASSEMBLY__

/*
 * This file contains the functions and defines necessary to modify and use
 * the x86-64 page table tree.
 */
#include <asm/processor.h>
#include <linux/bitops.h>
#include <linux/threads.h>
#include <linux/sched.h>

#ifdef CONFIG_XEN
extern pud_t level3_user_pgt[512];

extern void xen_init_pt(void);
extern void xen_switch_pt(void);
#endif

extern p4d_t level4_kernel_pgt[512];
extern p4d_t level4_ident_pgt[512];
extern pud_t level3_kernel_pgt[512];
extern pud_t level3_ident_pgt[512];
extern pmd_t level2_kernel_pgt[512];
extern pmd_t level2_fixmap_pgt[512];
extern pmd_t level2_ident_pgt[512];
extern pte_t level1_fixmap_pgt[512];
extern pgd_t init_top_pgt[];

#define swapper_pg_dir init_top_pgt

extern void paging_init(void);

#define pte_ERROR(e)							\
	pr_err("%s:%d: bad pte %p(%016lx pfn %010lx).\n",		\
	       __FILE__, __LINE__, &(e), __pte_val(e), pte_pfn(e))
#define pmd_ERROR(e)							\
	pr_err("%s:%d: bad pmd %p(%016lx pfn %010lx).\n",		\
	       __FILE__, __LINE__, &(e), __pmd_val(e), pmd_pfn(e))
#define pud_ERROR(e)							\
	pr_err("%s:%d: bad pud %p(%016lx pfn %010Lx).\n",		\
	       __FILE__, __LINE__, &(e), __pud_val(e),			\
	       (pud_val(e) & __PHYSICAL_MASK) >> PAGE_SHIFT)

#if CONFIG_PGTABLE_LEVELS >= 5
#define p4d_ERROR(e)					\
 	pr_err("%s:%d: bad p4d %p(%016lx pfn %010Lx).\n",		\
	       __FILE__, __LINE__, &(e), __p4d_val(e),			\
	       (p4d_val(e) & __PHYSICAL_MASK) >> PAGE_SHIFT)
#endif

#define pgd_ERROR(e)							\
	pr_err("%s:%d: bad pgd %p(%016lx pfn %010Lx).\n",		\
	       __FILE__, __LINE__, &(e), __pgd_val(e),			\
	       (pgd_val(e) & __PHYSICAL_MASK) >> PAGE_SHIFT)

struct mm_struct;

void set_pte_vaddr_p4d(p4d_t *p4d_page, unsigned long vaddr, pte_t new_pte);
void set_pte_vaddr_pud(pud_t *pud_page, unsigned long vaddr, pte_t new_pte);

#define __xen_pte_clear(ptep) xen_set_pte(ptep, __pte(0))

static inline void xen_set_pte(pte_t *ptep, pte_t pte)
{
	*ptep = pte;
}

static inline void xen_set_pmd(pmd_t *pmdp, pmd_t pmd)
{
	xen_l2_entry_update(pmdp, pmd);
}

#define xen_pmd_clear(pmd)			\
({						\
	pmd_t *__pmdp = (pmd);			\
	PagePinned(virt_to_page(__pmdp))	\
	? set_pmd(__pmdp, xen_make_pmd(0))	\
	: (void)(*__pmdp = xen_make_pmd(0));	\
})

#ifdef CONFIG_SMP
static inline pte_t xen_ptep_get_and_clear(pte_t *xp, pte_t ret)
{
	return __pte_ma(xchg(&xp->pte, 0));
}
#else
#define xen_ptep_get_and_clear(xp, pte) xen_local_ptep_get_and_clear(xp, pte)
#endif

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
#ifdef CONFIG_SMP
static inline pmd_t xen_pmdp_get_and_clear(pmd_t *xp)
{
	return xen_make_pmd(xchg(&xp->pmd, 0));
}
#else
#define xen_pmdp_get_and_clear(xp) xen_local_pmdp_get_and_clear(xp)
#endif
#endif

static inline void xen_set_pud(pud_t *pudp, pud_t pud)
{
	xen_l3_entry_update(pudp, pud);
}

#define xen_pud_clear(pud)			\
({						\
	pud_t *__pudp = (pud);			\
	PagePinned(virt_to_page(__pudp))	\
	? set_pud(__pudp, xen_make_pud(0))	\
	: (void)(*__pudp = xen_make_pud(0));	\
})

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static inline pud_t xen_pudp_get_and_clear(pud_t *xp)
{
#ifdef CONFIG_SMP
	return xen_make_pud(xchg(&xp->pud, 0));
#else
	/* xen_local_pudp_get_and_clear,
	 * but duplicated because of cyclic dependency
	 */
	pud_t ret = *xp;

	xen_pud_clear(xp);
	return ret;
#endif
}
#endif

#ifndef CONFIG_X86_5LEVEL
#define __user_p4d(p4d) container_of(__user_pgd(&(p4d)->pgd), p4d_t, pgd)
#endif

static inline void xen_set_p4d(p4d_t *p4dp, p4d_t p4d)
{
	xen_l4_entry_update(p4dp, p4d);
}

#ifdef CONFIG_X86_5LEVEL
#define xen_p4d_clear(p4d)				\
({							\
	p4d_t *p4dp_ = (p4d);				\
	PagePinned(virt_to_page(p4dp_))			\
	? xen_l4_entry_update(p4dp_, xen_make_p4d(0))	\
	: (void)(*p4dp_ = xen_make_p4d(0));		\
})
#else
#define xen_p4d_clear(p4d)				\
({							\
	p4d_t *p4dp_ = (p4d);				\
	p4d_t p4de_ = (p4d_t){ .pgd = xen_make_pgd(0) }; \
	PagePinned(virt_to_page(p4dp_))			\
	? xen_l4_entry_update(p4dp_, p4de_)		\
	: (void)(*__user_p4d(p4dp_) = *p4dp_ = p4de_);	\
})
#endif

#define __user_pgd(pgd) \
	(((unsigned long)(pgd) & PAGE_MASK) != (unsigned long)init_top_pgt \
	 ? (typeof(pgd))(page_private(virt_to_page(pgd)) \
			 + ((unsigned long)(pgd) & ~PAGE_MASK)) \
	 : (typeof(pgd))NULL)

static inline void xen_set_pgd(pgd_t *pgdp, pgd_t pgd)
{
	xen_l5_entry_update(pgdp, pgd);
}

#define xen_pgd_clear(pgd)					\
({								\
	pgd_t *pgdp_ = (pgd);					\
	PagePinned(virt_to_page(pgdp_))				\
	? xen_l5_entry_update(pgdp_, xen_make_pgd(0))		\
	: (void)(*__user_pgd(pgdp_) = *pgdp_ = xen_make_pgd(0)); \
})

#define __pte_mfn(_pte) (((_pte).pte & PTE_PFN_MASK) >> PAGE_SHIFT)

extern unsigned long early_arbitrary_virt_to_mfn(void *va);

extern void sync_global_pgds(unsigned long start, unsigned long end);

/*
 * Conversion functions: convert a page and protection to a page entry,
 * and a page entry and page directory to the page they refer to.
 */

/*
 * Level 4 access.
 */
static inline int pgd_large(pgd_t pgd) { return 0; }
#define mk_kernel_pgd(address) __pgd((address) | _KERNPG_TABLE)

/* PUD - Level3 access */

/* PMD  - Level 2 access */

/* PTE - Level 1 access. */

/* x86-64 always has all page tables mapped. */
#define pte_offset_map(dir, address) pte_offset_kernel((dir), (address))
#define pte_unmap(pte) ((void)(pte))/* NOP */

/*
 * Encode and de-code a swap entry
 *
 * |     ...            | 11| 10|  9|8|7|6|5| 4| 3|2|1|0| <- bit number
 * |     ...            |SW3|SW2|SW1|G|L|D|A|CD|WT|U|W|P| <- bit names
 * | OFFSET (14->63) | TYPE (9-13)  |0|X|X|X| X| X|X|X|0| <- swp entry
 *
 * G (8) is aliased and used as a PROT_NONE indicator for
 * !present ptes.  We need to start storing swap entries above
 * there.  We also need to avoid using A and D because of an
 * erratum where they can be incorrectly set by hardware on
 * non-present PTEs.
 */
#define SWP_TYPE_FIRST_BIT (_PAGE_BIT_PROTNONE + 1)
#define SWP_TYPE_BITS 5
/* Place the offset above the type: */
#define SWP_OFFSET_FIRST_BIT (SWP_TYPE_FIRST_BIT + SWP_TYPE_BITS)

#define MAX_SWAPFILES_CHECK() BUILD_BUG_ON(MAX_SWAPFILES_SHIFT > SWP_TYPE_BITS)

#define __swp_type(x)			(((x).val >> (SWP_TYPE_FIRST_BIT)) \
					 & ((1U << SWP_TYPE_BITS) - 1))
#define __swp_offset(x)			((x).val >> SWP_OFFSET_FIRST_BIT)
#define __swp_entry(type, offset)	((swp_entry_t) { \
					 ((type) << (SWP_TYPE_FIRST_BIT)) \
					 | ((offset) << SWP_OFFSET_FIRST_BIT) })
#define __pte_to_swp_entry(pte)		((swp_entry_t) { __pte_val(pte) })
#define __swp_entry_to_pte(x)		((pte_t) { .pte = (x).val })

extern int kern_addr_valid(unsigned long addr);

#define HAVE_ARCH_UNMAPPED_AREA
#define HAVE_ARCH_UNMAPPED_AREA_TOPDOWN

#define pgtable_cache_init()   do { } while (0)
#define check_pgt_cache()      do { } while (0)

#define PAGE_AGP    PAGE_KERNEL_NOCACHE
#define HAVE_PAGE_AGP 1

/* fs/proc/kcore.c */
#define	kc_vaddr_to_offset(v) ((v) & __VIRTUAL_MASK)
#define	kc_offset_to_vaddr(o) ((o) | ~__VIRTUAL_MASK)

#define __HAVE_ARCH_PTE_SAME

#define vmemmap ((struct page *)VMEMMAP_START)

extern void init_extra_mapping_uc(unsigned long phys, unsigned long size);
extern void init_extra_mapping_wb(unsigned long phys, unsigned long size);

#define gup_fast_permitted gup_fast_permitted
static inline bool gup_fast_permitted(unsigned long start, int nr_pages,
		int write)
{
	unsigned long len, end;

	len = (unsigned long)nr_pages << PAGE_SHIFT;
	end = start + len;
	if (end < start)
		return false;
	if (end >> __VIRTUAL_MASK_SHIFT)
		return false;
	return true;
}

#endif /* !__ASSEMBLY__ */
#endif /* _ASM_X86_PGTABLE_64_H */
