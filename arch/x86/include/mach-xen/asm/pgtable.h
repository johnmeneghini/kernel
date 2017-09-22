#ifndef _ASM_X86_PGTABLE_H
#define _ASM_X86_PGTABLE_H

#include <asm/page.h>
#include <asm/pgtable_types.h>

/*
 * Macro to mark a page protection value as UC-
 */
#define pgprot_noncached(prot)						\
	((boot_cpu_data.x86 > 3)					\
	 ? (__pgprot(pgprot_val(prot) |					\
		     cachemode2protval(_PAGE_CACHE_MODE_UC_MINUS)))	\
	 : (prot))

#ifndef __ASSEMBLY__
#include <asm/x86_init.h>

void ptdump_walk_pgd_level(struct seq_file *m, pgd_t *pgd);
void ptdump_walk_pgd_level_checkwx(void);

#ifdef CONFIG_DEBUG_WX
#define debug_checkwx() ptdump_walk_pgd_level_checkwx()
#else
#define debug_checkwx() do { } while (0)
#endif

/*
 * ZERO_PAGE is a global shared page that is always zero: used
 * for zero-mapped memory areas etc..
 */
extern unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)]
	__visible;
#define ZERO_PAGE(vaddr) (virt_to_page(empty_zero_page))

extern spinlock_t pgd_lock;
extern struct list_head pgd_list;

extern struct mm_struct *pgd_page_get_mm(struct page *page);

#define set_pte(ptep, pte)		xen_set_pte(ptep, pte)
#define set_pte_at(mm, addr, ptep, pte)	xen_set_pte_at(mm, addr, ptep, pte)
#define set_pmd_at(mm, addr, pmdp, pmd)	xen_set_pmd_at(mm, addr, pmdp, pmd)
#define set_pud_at(mm, addr, pudp, pud)	xen_set_pud_at(mm, addr, pudp, pud)

#define set_pmd(pmdp, pmd)		xen_set_pmd(pmdp, pmd)

#ifndef __PAGETABLE_P4D_FOLDED
#define set_pgd(pgdp, pgd)		xen_set_pgd(pgdp, pgd)
#define pgd_clear(pgd)			xen_pgd_clear(pgd)
#endif

#ifndef set_p4d
# define set_p4d(p4dp, p4d)		xen_set_p4d(p4dp, p4d)
#endif

#ifndef __PAGETABLE_PUD_FOLDED
#define p4d_clear(p4d)			xen_p4d_clear(p4d)
#endif

#ifndef set_pud
# define set_pud(pudp, pud)		xen_set_pud(pudp, pud)
#endif

#ifndef __PAGETABLE_PUD_FOLDED
#define pud_clear(pud)			xen_pud_clear(pud)
#endif

#define pte_clear(mm, addr, ptep)	xen_pte_clear(mm, addr, ptep)
#define pmd_clear(pmd)			xen_pmd_clear(pmd)

#define pte_update(mm, addr, ptep)              do { } while (0)

#define pgd_val(x)	xen_pgd_val(x)
#define __pgd(x)	xen_make_pgd(x)

#ifndef __PAGETABLE_P4D_FOLDED
#define p4d_val(x)	xen_p4d_val(x)
#define __p4d(x)	xen_make_p4d(x)
#endif

#ifndef __PAGETABLE_PUD_FOLDED
#define pud_val(x)	xen_pud_val(x)
#define __pud(x)	xen_make_pud(x)
#endif

#ifndef __PAGETABLE_PMD_FOLDED
#define pmd_val(x)	xen_pmd_val(x)
#define __pmd(x)	xen_make_pmd(x)
#endif

#define pte_val(x)	xen_pte_val(x)
#define __pte(x)	xen_make_pte(x)

#define arch_end_context_switch(prev)	do {} while(0)

/*
 * The following only work if pte_present() is true.
 * Undefined behaviour if not..
 */
static inline int pte_dirty(pte_t pte)
{
	return pte_flags(pte) & _PAGE_DIRTY;
}


static inline u32 read_pkru(void)
{
	if (boot_cpu_has(X86_FEATURE_OSPKE))
		return __read_pkru();
	return 0;
}

static inline void write_pkru(u32 pkru)
{
	if (boot_cpu_has(X86_FEATURE_OSPKE))
		__write_pkru(pkru);
}

static inline int pte_young(pte_t pte)
{
	return pte_flags(pte) & _PAGE_ACCESSED;
}

static inline int pmd_dirty(pmd_t pmd)
{
	return pmd_flags(pmd) & _PAGE_DIRTY;
}

static inline int pmd_young(pmd_t pmd)
{
	return pmd_flags(pmd) & _PAGE_ACCESSED;
}

static inline int pud_dirty(pud_t pud)
{
	return pud_flags(pud) & _PAGE_DIRTY;
}

static inline int pud_young(pud_t pud)
{
	return pud_flags(pud) & _PAGE_ACCESSED;
}

static inline int pte_write(pte_t pte)
{
	return pte_flags(pte) & _PAGE_RW;
}

static inline int pte_huge(pte_t pte)
{
	return pte_flags(pte) & _PAGE_PSE;
}

static inline int pte_global(pte_t pte)
{
	return 0;
}

static inline int pte_exec(pte_t pte)
{
	return !(pte_flags(pte) & _PAGE_NX);
}

static inline int pte_special(pte_t pte)
{
	return pte_flags(pte) & _PAGE_SPECIAL;
}

#define pte_mfn(_pte) ((_pte).pte_low & _PAGE_PRESENT ? \
	__pte_mfn(_pte) : pfn_to_mfn(__pte_mfn(_pte)))
#define pte_pfn(_pte) ((_pte).pte_low & _PAGE_IOMAP ? max_mapnr : \
		       (_pte).pte_low & _PAGE_PRESENT ?		  \
		       mfn_to_local_pfn(__pte_mfn(_pte)) :	  \
		       __pte_mfn(_pte))

#define pte_page(pte)	pfn_to_page(pte_pfn(pte))

static inline unsigned long pmd_pfn(pmd_t pmd)
{
	return (pmd_val(pmd) & pmd_pfn_mask(pmd)) >> PAGE_SHIFT;
}

static inline unsigned long pud_pfn(pud_t pud)
{
	return (pud_val(pud) & pud_pfn_mask(pud)) >> PAGE_SHIFT;
}

static inline unsigned long p4d_pfn(p4d_t p4d)
{
	return (p4d_val(p4d) & p4d_pfn_mask(p4d)) >> PAGE_SHIFT;
}

static inline int p4d_large(p4d_t p4d)
{
	/* No 512 GiB pages yet */
	return 0;
}

static inline int pmd_large(pmd_t pte)
{
	return pmd_flags(pte) & _PAGE_PSE;
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static inline int pmd_trans_huge(pmd_t pmd)
{
	return (pmd_val(pmd) & (_PAGE_PSE|_PAGE_DEVMAP)) == _PAGE_PSE;
}

#ifdef CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD
static inline int pud_trans_huge(pud_t pud)
{
	return (pud_val(pud) & (_PAGE_PSE|_PAGE_DEVMAP)) == _PAGE_PSE;
}
#endif

#define has_transparent_hugepage has_transparent_hugepage
static inline int has_transparent_hugepage(void)
{
	return boot_cpu_has(X86_FEATURE_PSE);
}

#ifdef __HAVE_ARCH_PTE_DEVMAP
static inline int pmd_devmap(pmd_t pmd)
{
	return !!(pmd_val(pmd) & _PAGE_DEVMAP);
}

#ifdef CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD
static inline int pud_devmap(pud_t pud)
{
	return !!(pud_val(pud) & _PAGE_DEVMAP);
}
#else
static inline int pud_devmap(pud_t pud)
{
	return 0;
}
#endif

static inline int pgd_devmap(pgd_t pgd)
{
	return 0;
}
#endif
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

static inline pte_t pte_set_flags(pte_t pte, pteval_t set)
{
	pteval_t v = __pte_val(pte);

	return __pte_ma(v | set);
}

static inline pte_t pte_clear_flags(pte_t pte, pteval_t clear)
{
	pteval_t v = __pte_val(pte);

	return __pte_ma(v & ~clear);
}

static inline pte_t pte_mkclean(pte_t pte)
{
	return pte_clear_flags(pte, _PAGE_DIRTY);
}

static inline pte_t pte_mkold(pte_t pte)
{
	return pte_clear_flags(pte, _PAGE_ACCESSED);
}

static inline pte_t pte_wrprotect(pte_t pte)
{
	return pte_clear_flags(pte, _PAGE_RW);
}

static inline pte_t pte_mkexec(pte_t pte)
{
	return pte_clear_flags(pte, _PAGE_NX);
}

static inline pte_t pte_mkdirty(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_DIRTY | _PAGE_SOFT_DIRTY);
}

static inline pte_t pte_mkyoung(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_ACCESSED);
}

static inline pte_t pte_mkwrite(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_RW);
}

static inline pte_t pte_mkhuge(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_PSE);
}

static inline pte_t pte_clrhuge(pte_t pte)
{
	return pte_clear_flags(pte, _PAGE_PSE);
}

static inline pte_t pte_mkglobal(pte_t pte)
{
	return pte;
}

static inline pte_t pte_clrglobal(pte_t pte)
{
	return pte;
}

static inline pte_t pte_mkspecial(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_SPECIAL);
}

static inline pte_t pte_mkdevmap(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_SPECIAL|_PAGE_DEVMAP);
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static inline pmd_t pmd_set_flags(pmd_t pmd, pmdval_t set)
{
	pmdval_t v = native_pmd_val(pmd);

	return __pmd(v | set);
}

static inline pmd_t pmd_clear_flags(pmd_t pmd, pmdval_t clear)
{
	pmdval_t v = native_pmd_val(pmd);

	return __pmd(v & ~clear);
}

static inline pmd_t pmd_mkold(pmd_t pmd)
{
	return pmd_clear_flags(pmd, _PAGE_ACCESSED);
}

static inline pmd_t pmd_mkclean(pmd_t pmd)
{
	return pmd_clear_flags(pmd, _PAGE_DIRTY);
}

static inline pmd_t pmd_wrprotect(pmd_t pmd)
{
	return pmd_clear_flags(pmd, _PAGE_RW);
}

static inline pmd_t pmd_mkdirty(pmd_t pmd)
{
	return pmd_set_flags(pmd, _PAGE_DIRTY | _PAGE_SOFT_DIRTY);
}

static inline pmd_t pmd_mkdevmap(pmd_t pmd)
{
	return pmd_set_flags(pmd, _PAGE_DEVMAP);
}

static inline pmd_t pmd_mkhuge(pmd_t pmd)
{
	return pmd_set_flags(pmd, _PAGE_PSE);
}

static inline pmd_t pmd_mkyoung(pmd_t pmd)
{
	return pmd_set_flags(pmd, _PAGE_ACCESSED);
}

static inline pmd_t pmd_mkwrite(pmd_t pmd)
{
	return pmd_set_flags(pmd, _PAGE_RW);
}

static inline pmd_t pmd_mknotpresent(pmd_t pmd)
{
	return pmd_clear_flags(pmd, _PAGE_PRESENT | _PAGE_PROTNONE);
}
#endif

static inline pud_t pud_set_flags(pud_t pud, pudval_t set)
{
	pudval_t v = xen_pud_val(pud);

	return __pud(v | set);
}

static inline pud_t pud_clear_flags(pud_t pud, pudval_t clear)
{
	pudval_t v = xen_pud_val(pud);

	return __pud(v & ~clear);
}

static inline pud_t pud_mkold(pud_t pud)
{
	return pud_clear_flags(pud, _PAGE_ACCESSED);
}

static inline pud_t pud_mkclean(pud_t pud)
{
	return pud_clear_flags(pud, _PAGE_DIRTY);
}

static inline pud_t pud_wrprotect(pud_t pud)
{
	return pud_clear_flags(pud, _PAGE_RW);
}

static inline pud_t pud_mkdirty(pud_t pud)
{
	return pud_set_flags(pud, _PAGE_DIRTY | _PAGE_SOFT_DIRTY);
}

static inline pud_t pud_mkdevmap(pud_t pud)
{
	return pud_set_flags(pud, _PAGE_DEVMAP);
}

static inline pud_t pud_mkhuge(pud_t pud)
{
	return pud_set_flags(pud, _PAGE_PSE);
}

static inline pud_t pud_mkyoung(pud_t pud)
{
	return pud_set_flags(pud, _PAGE_ACCESSED);
}

static inline pud_t pud_mkwrite(pud_t pud)
{
	return pud_set_flags(pud, _PAGE_RW);
}

static inline pud_t pud_mknotpresent(pud_t pud)
{
	return pud_clear_flags(pud, _PAGE_PRESENT | _PAGE_PROTNONE);
}

#ifdef CONFIG_HAVE_ARCH_SOFT_DIRTY
static inline int pte_soft_dirty(pte_t pte)
{
	return pte_flags(pte) & _PAGE_SOFT_DIRTY;
}

static inline int pmd_soft_dirty(pmd_t pmd)
{
	return pmd_flags(pmd) & _PAGE_SOFT_DIRTY;
}

static inline int pud_soft_dirty(pud_t pud)
{
	return pud_flags(pud) & _PAGE_SOFT_DIRTY;
}

static inline pte_t pte_mksoft_dirty(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_SOFT_DIRTY);
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static inline pmd_t pmd_mksoft_dirty(pmd_t pmd)
{
	return pmd_set_flags(pmd, _PAGE_SOFT_DIRTY);
}

static inline pud_t pud_mksoft_dirty(pud_t pud)
{
	return pud_set_flags(pud, _PAGE_SOFT_DIRTY);
}
#endif

static inline pte_t pte_clear_soft_dirty(pte_t pte)
{
	return pte_clear_flags(pte, _PAGE_SOFT_DIRTY);
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static inline pmd_t pmd_clear_soft_dirty(pmd_t pmd)
{
	return pmd_clear_flags(pmd, _PAGE_SOFT_DIRTY);
}

static inline pud_t pud_clear_soft_dirty(pud_t pud)
{
	return pud_clear_flags(pud, _PAGE_SOFT_DIRTY);
}
#endif

#endif /* CONFIG_HAVE_ARCH_SOFT_DIRTY */

/*
 * Mask out unsupported bits in a present pgprot.  Non-present pgprots
 * can use those bits for other purposes, so leave them be.
 */
static inline pgprotval_t massage_pgprot(pgprot_t pgprot)
{
	pgprotval_t protval = pgprot_val(pgprot);

	if (protval & _PAGE_PRESENT)
		protval &= __supported_pte_mask;

	return protval;
}

static inline pte_t pfn_pte(unsigned long page_nr, pgprot_t pgprot)
{
	return __pte(((phys_addr_t)page_nr << PAGE_SHIFT) |
		     massage_pgprot(pgprot));
}

static inline pte_t pfn_pte_ma(phys_addr_t page_nr, pgprot_t pgprot)
{
	return __pte_ma((page_nr << PAGE_SHIFT) | massage_pgprot(pgprot));
}

static inline pmd_t pfn_pmd(unsigned long page_nr, pgprot_t pgprot)
{
	return __pmd(((phys_addr_t)page_nr << PAGE_SHIFT) |
		     massage_pgprot(pgprot));
}

static inline pud_t pfn_pud(unsigned long page_nr, pgprot_t pgprot)
{
	return __pud(((phys_addr_t)page_nr << PAGE_SHIFT) |
		     massage_pgprot(pgprot));
}

static inline pte_t pte_modify(pte_t pte, pgprot_t newprot)
{
	pteval_t val = pte_val(pte) & _PAGE_CHG_MASK;

	val |= massage_pgprot(newprot) & ~_PAGE_CHG_MASK;

	return __pte(val);
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static inline pmd_t pmd_modify(pmd_t pmd, pgprot_t newprot)
{
	pmdval_t val = pmd_val(pmd);

	val &= _HPAGE_CHG_MASK;
	val |= massage_pgprot(newprot) & ~_HPAGE_CHG_MASK;

	return __pmd(val);
}
#endif

/* mprotect needs to preserve PAT bits when updating vm_page_prot */
#define pgprot_modify pgprot_modify
static inline pgprot_t pgprot_modify(pgprot_t oldprot, pgprot_t newprot)
{
	pgprotval_t preservebits = pgprot_val(oldprot) & _PAGE_CHG_MASK;
	pgprotval_t addbits = pgprot_val(newprot);
	return __pgprot(preservebits | addbits);
}

#define pte_pgprot(x) __pgprot(pte_flags(x))
#define pmd_pgprot(x) __pgprot(pmd_flags(x))
#define pud_pgprot(x) __pgprot(pud_flags(x))
#define p4d_pgprot(x) __pgprot(p4d_flags(x))

#define canon_pgprot(p) __pgprot(massage_pgprot(p))

static inline int is_new_memtype_allowed(u64 paddr, unsigned long size,
					 enum page_cache_mode pcm,
					 enum page_cache_mode new_pcm)
{
	/*
	 * PAT type is always WB for untracked ranges, so no need to check.
	 */
	if (x86_platform.is_untracked_pat_range(paddr, paddr + size))
		return 1;

	/*
	 * Certain new memtypes are not allowed with certain
	 * requested memtype:
	 * - request is uncached, return cannot be write-back
	 * - request is write-combine, return cannot be write-back
	 * - request is write-through, return cannot be write-back
	 * - request is write-through, return cannot be write-combine
	 */
	if ((pcm == _PAGE_CACHE_MODE_UC_MINUS &&
	     new_pcm == _PAGE_CACHE_MODE_WB) ||
	    (pcm == _PAGE_CACHE_MODE_WC &&
	     new_pcm == _PAGE_CACHE_MODE_WB) ||
	    (pcm == _PAGE_CACHE_MODE_WT &&
	     new_pcm == _PAGE_CACHE_MODE_WB) ||
	    (pcm == _PAGE_CACHE_MODE_WT &&
	     new_pcm == _PAGE_CACHE_MODE_WC)) {
		return 0;
	}

	return 1;
}

pmd_t *populate_extra_pmd(unsigned long vaddr);
pte_t *populate_extra_pte(unsigned long vaddr);
#endif	/* __ASSEMBLY__ */

#ifdef CONFIG_X86_32
# include <asm/pgtable_32.h>
#else
# include <asm/pgtable_64.h>
#endif

#ifndef __ASSEMBLY__
#include <linux/mm_types.h>
#include <linux/mmdebug.h>
#include <linux/log2.h>
#include <asm/fixmap.h>

static inline int pte_none(pte_t pte)
{
	return !(pte.pte & ~(_PAGE_KNL_ERRATUM_MASK));
}

#define __HAVE_ARCH_PTE_SAME
static inline int pte_same(pte_t a, pte_t b)
{
	return a.pte == b.pte;
}

static inline int pte_present(pte_t a)
{
	return pte_flags(a) & (_PAGE_PRESENT | _PAGE_PROTNONE);
}

#ifdef __HAVE_ARCH_PTE_DEVMAP
static inline int pte_devmap(pte_t a)
{
	return (pte_flags(a) & _PAGE_DEVMAP) == _PAGE_DEVMAP;
}
#endif

#define pte_accessible pte_accessible
static inline bool pte_accessible(struct mm_struct *mm, pte_t a)
{
	if (pte_flags(a) & _PAGE_PRESENT)
		return true;

	if ((pte_flags(a) & _PAGE_PROTNONE) &&
			mm_tlb_flush_pending(mm))
		return true;

	return false;
}

static inline int pte_hidden(pte_t pte)
{
	return pte_flags(pte) & _PAGE_HIDDEN;
}

static inline int pmd_present(pmd_t pmd)
{
#if CONFIG_XEN_COMPAT <= 0x030002
/* pmd_present doesn't just test the _PAGE_PRESENT bit since wr.p.t.
   can temporarily clear it. */
	return __pmd_val(pmd) != 0;
#else
	/*
	 * Checking for _PAGE_PSE is needed too because
	 * split_huge_page will temporarily clear the present bit (but
	 * the _PAGE_PSE flag will remain set at all times while the
	 * _PAGE_PRESENT bit is clear).
	 */
	return pmd_flags(pmd) & (_PAGE_PRESENT | _PAGE_PROTNONE | _PAGE_PSE);
#endif
}

#ifdef CONFIG_NUMA_BALANCING
/*
 * These work without NUMA balancing but the kernel does not care. See the
 * comment in include/asm-generic/pgtable.h
 */
static inline int pte_protnone(pte_t pte)
{
	return (pte_flags(pte) & (_PAGE_PROTNONE | _PAGE_PRESENT))
		== _PAGE_PROTNONE;
}

static inline int pmd_protnone(pmd_t pmd)
{
	return (pmd_flags(pmd) & (_PAGE_PROTNONE | _PAGE_PRESENT))
		== _PAGE_PROTNONE;
}
#endif /* CONFIG_NUMA_BALANCING */

static inline int pmd_none(pmd_t pmd)
{
	/* Only check low word on 32-bit platforms, since it might be
	   out of sync with upper half. */
	unsigned long val = __pmd_val(pmd);
	return (val & ~_PAGE_KNL_ERRATUM_MASK) == 0;
}

static inline unsigned long pmd_page_vaddr(pmd_t pmd)
{
	return (unsigned long)__va(pmd_val(pmd) & pmd_pfn_mask(pmd));
}

/*
 * Currently stuck as a macro due to indirect forward reference to
 * linux/mmzone.h's __section_mem_map_addr() definition:
 */
#define pmd_page(pmd)		\
	pfn_to_page((pmd_val(pmd) & pmd_pfn_mask(pmd)) >> PAGE_SHIFT)

/*
 * the pmd page can be thought of an array like this: pmd_t[PTRS_PER_PMD]
 *
 * this macro returns the index of the entry in the pmd page which would
 * control the given virtual address
 */
static inline unsigned long pmd_index(unsigned long address)
{
	return (address >> PMD_SHIFT) & (PTRS_PER_PMD - 1);
}

/*
 * Conversion functions: convert a page and protection to a page entry,
 * and a page entry and page directory to the page they refer to.
 *
 * (Currently stuck as a macro because of indirect forward reference
 * to linux/mm.h:page_to_nid())
 */
#define mk_pte(page, pgprot)   pfn_pte(page_to_pfn(page), (pgprot))

/*
 * the pte page can be thought of an array like this: pte_t[PTRS_PER_PTE]
 *
 * this function returns the index of the entry in the pte page which would
 * control the given virtual address
 */
static inline unsigned long pte_index(unsigned long address)
{
	return (address >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
}

static inline pte_t *pte_offset_kernel(pmd_t *pmd, unsigned long address)
{
	return (pte_t *)pmd_page_vaddr(*pmd) + pte_index(address);
}

static inline int pmd_bad(pmd_t pmd)
{
#if CONFIG_XEN_COMPAT <= 0x030002
	return (pmd_flags(pmd) & ~_PAGE_USER & ~_PAGE_PRESENT)
	       != (_KERNPG_TABLE & ~_PAGE_PRESENT);
#else
	return (pmd_flags(pmd) & ~_PAGE_USER) != _KERNPG_TABLE;
#endif
}

static inline unsigned long pages_to_mb(unsigned long npg)
{
	return npg >> (20 - PAGE_SHIFT);
}

#define io_remap_pfn_range(vma, vaddr, pfn, size, prot)	\
	direct_remap_pfn_range(vma, vaddr, pfn, size, prot, DOMID_IO)

#if CONFIG_PGTABLE_LEVELS > 2
static inline int pud_none(pud_t pud)
{
	return (__pud_val(pud) & ~(_PAGE_KNL_ERRATUM_MASK)) == 0;
}

static inline int pud_present(pud_t pud)
{
	return pud_flags(pud) & _PAGE_PRESENT;
}

static inline unsigned long pud_page_vaddr(pud_t pud)
{
	return (unsigned long)__va(pud_val(pud) & pud_pfn_mask(pud));
}

/*
 * Currently stuck as a macro due to indirect forward reference to
 * linux/mmzone.h's __section_mem_map_addr() definition:
 */
#define pud_page(pud)		\
	pfn_to_page((pud_val(pud) & pud_pfn_mask(pud)) >> PAGE_SHIFT)

/* Find an entry in the second-level page table.. */
static inline pmd_t *pmd_offset(pud_t *pud, unsigned long address)
{
	return (pmd_t *)pud_page_vaddr(*pud) + pmd_index(address);
}

static inline int pud_large(pud_t pud)
{
	return (__pud_val(pud) & (_PAGE_PSE | _PAGE_PRESENT)) ==
		(_PAGE_PSE | _PAGE_PRESENT);
}

static inline int pud_bad(pud_t pud)
{
	return (pud_flags(pud) & ~(_KERNPG_TABLE | _PAGE_USER)) != 0;
}
#else
static inline int pud_large(pud_t pud)
{
	return 0;
}
#endif	/* CONFIG_PGTABLE_LEVELS > 2 */

static inline unsigned long pud_index(unsigned long address)
{
	return (address >> PUD_SHIFT) & (PTRS_PER_PUD - 1);
}

#if CONFIG_PGTABLE_LEVELS > 3
static inline int p4d_none(p4d_t p4d)
{
	return (__p4d_val(p4d) & ~(_PAGE_KNL_ERRATUM_MASK)) == 0;
}

static inline int p4d_present(p4d_t p4d)
{
	return p4d_flags(p4d) & _PAGE_PRESENT;
}

static inline unsigned long p4d_page_vaddr(p4d_t p4d)
{
	return (unsigned long)__va(p4d_val(p4d) & p4d_pfn_mask(p4d));
}

/*
 * Currently stuck as a macro due to indirect forward reference to
 * linux/mmzone.h's __section_mem_map_addr() definition:
 */
#define p4d_page(p4d)		\
	pfn_to_page((p4d_val(p4d) & p4d_pfn_mask(p4d)) >> PAGE_SHIFT)

/* Find an entry in the third-level page table.. */
static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
{
	return (pud_t *)p4d_page_vaddr(*p4d) + pud_index(address);
}

static inline int p4d_bad(p4d_t p4d)
{
	return (p4d_flags(p4d) & ~(_KERNPG_TABLE | _PAGE_USER)) != 0;
}
#endif  /* CONFIG_PGTABLE_LEVELS > 3 */

static inline unsigned long p4d_index(unsigned long address)
{
	return (address >> P4D_SHIFT) & (PTRS_PER_P4D - 1);
}

#if CONFIG_PGTABLE_LEVELS > 4
static inline int pgd_present(pgd_t pgd)
{
	return pgd_flags(pgd) & _PAGE_PRESENT;
}

static inline unsigned long pgd_page_vaddr(pgd_t pgd)
{
	return (unsigned long)__va((unsigned long)pgd_val(pgd) & PTE_PFN_MASK);
}

/*
 * Currently stuck as a macro due to indirect forward reference to
 * linux/mmzone.h's __section_mem_map_addr() definition:
 */
#define pgd_page(pgd)		pfn_to_page(pgd_val(pgd) >> PAGE_SHIFT)

/* to find an entry in a page-table-directory. */
static inline p4d_t *p4d_offset(pgd_t *pgd, unsigned long address)
{
	return (p4d_t *)pgd_page_vaddr(*pgd) + p4d_index(address);
}

static inline int pgd_bad(pgd_t pgd)
{
	return (pgd_flags(pgd) & ~_PAGE_USER) != _KERNPG_TABLE;
}

static inline int pgd_none(pgd_t pgd)
{
	/*
	 * There is no need to do a workaround for the KNL stray
	 * A/D bit erratum here.  PGDs only point to page tables
	 * except on 32-bit non-PAE which is not supported on
	 * KNL.
	 */
	return !__pgd_val(pgd);
}
#endif	/* CONFIG_PGTABLE_LEVELS > 4 */

#endif	/* __ASSEMBLY__ */

/*
 * the pgd page can be thought of an array like this: pgd_t[PTRS_PER_PGD]
 *
 * this macro returns the index of the entry in the pgd page which would
 * control the given virtual address
 */
#define pgd_index(address) (((address) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))

/*
 * pgd_offset() returns a (pgd_t *)
 * pgd_index() is used get the offset into the pgd page's array of pgd_t's;
 */
#define pgd_offset(mm, address) ((mm)->pgd + pgd_index((address)))
/*
 * a shortcut which implies the use of the kernel's pgd, instead
 * of a process's
 */
#define pgd_offset_k(address) pgd_offset(&init_mm, (address))


#define KERNEL_PGD_BOUNDARY	pgd_index(PAGE_OFFSET)
#define KERNEL_PGD_PTRS		(PTRS_PER_PGD - KERNEL_PGD_BOUNDARY)

#ifndef __ASSEMBLY__
#include <linux/mmzone.h>
#include <linux/page-flags.h>

#define direct_gbpages 0
void init_mem_mapping(void);
void early_alloc_pgt_buf(void);
extern void memblock_find_dma_reserve(void);

#if defined(CONFIG_X86_64) && !defined(CONFIG_XEN)
/* Realmode trampoline initialization. */
extern pgd_t trampoline_pgd_entry;
static inline void __meminit init_trampoline_default(void)
{
	/* Default trampoline pgd value */
	trampoline_pgd_entry = init_top_pgt[pgd_index(__PAGE_OFFSET)];
}
# ifdef CONFIG_RANDOMIZE_MEMORY
void __meminit init_trampoline(void);
# else
#  define init_trampoline init_trampoline_default
# endif
#else
static inline void init_trampoline(void) { }
#endif

/* local pte updates need not use xchg for locking */
static inline pte_t xen_local_ptep_get_and_clear(pte_t *ptep, pte_t res)
{
	xen_set_pte(ptep, __pte(0));
	return res;
}

static inline pmd_t xen_local_pmdp_get_and_clear(pmd_t *pmdp)
{
	pmd_t res = *pmdp;

	xen_set_pmd(pmdp, __pmd(0));
	return res;
}

static inline pud_t xen_local_pudp_get_and_clear(pud_t *pudp)
{
	pud_t res = *pudp;

	xen_pud_clear(pudp);
	return res;
}

static inline void xen_set_pte_at(struct mm_struct *mm, unsigned long addr,
				  pte_t *ptep , pte_t pte)
{
/*
 * I don't think modules are permitted to use this function, but the i915
 * DRM driver does nevertheless (and init_mm does not get exported).
 */
#ifndef MODULE
	if ((mm != current->mm && mm != &init_mm) ||
	    HYPERVISOR_update_va_mapping(addr, pte, 0))
#endif
		xen_set_pte(ptep, pte);
}

static inline void xen_set_pmd_at(struct mm_struct *mm, unsigned long addr,
				  pmd_t *pmdp , pmd_t pmd)
{
	xen_set_pmd(pmdp, pmd);
}

static inline void xen_set_pud_at(struct mm_struct *mm, unsigned long addr,
				   pud_t *pudp, pud_t pud)
{
	xen_set_pud(pudp, pud);
}

static inline void xen_pte_clear(struct mm_struct *mm, unsigned long addr,
				 pte_t *ptep)
{
	if ((mm != current->mm && mm != &init_mm)
	    || HYPERVISOR_update_va_mapping(addr, __pte(0), 0))
		__xen_pte_clear(ptep);
}

#ifndef CONFIG_PARAVIRT
/*
 * Rules for using pte_update - it must be called after any PTE update which
 * has not been done using the set_pte / clear_pte interfaces.  It is used by
 * shadow mode hypervisors to resynchronize the shadow page tables.  Kernel PTE
 * updates should either be sets, clears, or set_pte_atomic for P->P
 * transitions, which means this hook should only be called for user PTEs.
 * This hook implies a P->P protection or access change has taken place, which
 * requires a subsequent TLB flush.
 */
#define pte_update(mm, addr, ptep)		do { } while (0)
#endif

/*
 * We only update the dirty/accessed state if we set
 * the dirty bit by hand in the kernel, since the hardware
 * will do the accessed bit for us, and we don't want to
 * race with other CPU's that might be updating the dirty
 * bit at the same time.
 */
struct vm_area_struct;

#define  __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
extern int ptep_set_access_flags(struct vm_area_struct *vma,
				 unsigned long address, pte_t *ptep,
				 pte_t entry, int dirty);

#define __HAVE_ARCH_PTEP_TEST_AND_CLEAR_YOUNG
extern int ptep_test_and_clear_young(struct vm_area_struct *vma,
				     unsigned long addr, pte_t *ptep);

#define __HAVE_ARCH_PTEP_CLEAR_YOUNG_FLUSH
extern int ptep_clear_flush_young(struct vm_area_struct *vma,
				  unsigned long address, pte_t *ptep);

#define __HAVE_ARCH_PTEP_CLEAR_FLUSH
#define ptep_clear_flush(vma, addr, ptep)			\
({								\
	pte_t *__ptep = (ptep);					\
	pte_t __res = *__ptep;					\
	if (!pte_none(__res) &&					\
	    ((vma)->vm_mm != current->mm ||			\
	     HYPERVISOR_update_va_mapping(addr,	__pte(0),	\
			uvm_multi(mm_cpumask((vma)->vm_mm)) |	\
				UVMF_INVLPG))) {		\
		__xen_pte_clear(__ptep);			\
		xen_invlpg_mask(mm_cpumask((vma)->vm_mm), addr);\
	}							\
	__res;							\
})

#define __HAVE_ARCH_PTEP_GET_AND_CLEAR
static inline pte_t ptep_get_and_clear(struct mm_struct *mm, unsigned long addr,
				       pte_t *ptep)
{
	pte_t pte = *ptep;
	if (!pte_none(pte)
	    && (mm != &init_mm
	        || HYPERVISOR_update_va_mapping(addr, __pte(0), 0))) {
		pte = xen_ptep_get_and_clear(ptep, pte);
		pte_update(mm, addr, ptep);
	}
	return pte;
}

#define __HAVE_ARCH_PTEP_GET_AND_CLEAR_FULL
#define ptep_get_and_clear_full(mm, addr, ptep, full)		\
	((full) ? ({						\
		pte_t *__ptep = (ptep);				\
		pte_t __res = *__ptep;				\
		if (!PagePinned(virt_to_page((mm)->pgd)))	\
			__xen_pte_clear(__ptep);		\
		else if (!pte_none(__res))			\
			xen_l1_entry_update(__ptep, __pte(0));	\
		__res;						\
	 }) :							\
	 ptep_get_and_clear(mm, addr, ptep))

pte_t xen_ptep_get_and_clear_full(struct vm_area_struct *, unsigned long, pte_t *, int);

#define __HAVE_ARCH_PTEP_SET_WRPROTECT
static inline void ptep_set_wrprotect(struct mm_struct *mm,
				      unsigned long addr, pte_t *ptep)
{
	pte_t pte = *ptep;
	if (pte_write(pte))
		set_pte_at(mm, addr, ptep, pte_wrprotect(pte));
}

#define flush_tlb_fix_spurious_fault(vma, address) do { } while (0)

#define mk_pmd(page, pgprot)   pfn_pmd(page_to_pfn(page), (pgprot))

#define  __HAVE_ARCH_PMDP_SET_ACCESS_FLAGS
extern int pmdp_set_access_flags(struct vm_area_struct *vma,
				 unsigned long address, pmd_t *pmdp,
				 pmd_t entry, int dirty);
extern int pudp_set_access_flags(struct vm_area_struct *vma,
				 unsigned long address, pud_t *pudp,
				 pud_t entry, int dirty);

#define __HAVE_ARCH_PMDP_TEST_AND_CLEAR_YOUNG
extern int pmdp_test_and_clear_young(struct vm_area_struct *vma,
				     unsigned long addr, pmd_t *pmdp);
extern int pudp_test_and_clear_young(struct vm_area_struct *vma,
				     unsigned long addr, pud_t *pudp);

#define __HAVE_ARCH_PMDP_CLEAR_YOUNG_FLUSH
extern int pmdp_clear_flush_young(struct vm_area_struct *vma,
				  unsigned long address, pmd_t *pmdp);


#define __HAVE_ARCH_PMD_WRITE
static inline int pmd_write(pmd_t pmd)
{
	return pmd_flags(pmd) & _PAGE_RW;
}

#define __HAVE_ARCH_PMDP_HUGE_GET_AND_CLEAR
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static inline pmd_t pmdp_huge_get_and_clear(struct mm_struct *mm, unsigned long addr,
				       pmd_t *pmdp)
{
	return xen_pmdp_get_and_clear(pmdp);
}
#endif

#define __HAVE_ARCH_PUDP_HUGE_GET_AND_CLEAR
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static inline pud_t pudp_huge_get_and_clear(struct mm_struct *mm,
					unsigned long addr, pud_t *pudp)
{
	return xen_pudp_get_and_clear(pudp);
}
#endif

#define __HAVE_ARCH_PMDP_SET_WRPROTECT
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static inline void pmdp_set_wrprotect(struct mm_struct *mm,
				      unsigned long addr, pmd_t *pmdp)
{
	clear_bit(_PAGE_BIT_RW, (unsigned long *)pmdp);
}
#endif

/*
 * clone_pgd_range(pgd_t *dst, pgd_t *src, int count);
 *
 *  dst - pointer to pgd range anwhere on a pgd page
 *  src - ""
 *  count - the number of pgds to copy.
 *
 * dst and src can be on the same page, but the range must not overlap,
 * and must not cross a page boundary.
 */
static inline void clone_pgd_range(pgd_t *dst, pgd_t *src, int count)
{
       memcpy(dst, src, count * sizeof(pgd_t));
}

#define PTE_SHIFT ilog2(PTRS_PER_PTE)
static inline int page_level_shift(enum pg_level level)
{
	return (PAGE_SHIFT - PTE_SHIFT) + level * PTE_SHIFT;
}
static inline unsigned long page_level_size(enum pg_level level)
{
	return 1UL << page_level_shift(level);
}
static inline unsigned long page_level_mask(enum pg_level level)
{
	return ~(page_level_size(level) - 1);
}

/*
 * The x86 doesn't have any external MMU info: the kernel page
 * tables contain all the necessary information.
 */
static inline void update_mmu_cache(struct vm_area_struct *vma,
		unsigned long addr, pte_t *ptep)
{
}
static inline void update_mmu_cache_pmd(struct vm_area_struct *vma,
		unsigned long addr, pmd_t *pmd)
{
}
static inline void update_mmu_cache_pud(struct vm_area_struct *vma,
		unsigned long addr, pud_t *pud)
{
}

#define arbitrary_virt_to_mfn(va)					\
({									\
	unsigned int __lvl;						\
	pte_t *__ptep = lookup_address((unsigned long)(va), &__lvl);	\
	BUG_ON(!__ptep || __lvl != PG_LEVEL_4K || !pte_present(*__ptep));\
	pte_mfn(*__ptep);						\
})

#define arbitrary_virt_to_machine(va)					\
	(((maddr_t)arbitrary_virt_to_mfn(va) << PAGE_SHIFT)		\
	 | ((unsigned long)(va) & (PAGE_SIZE - 1)))

#ifdef CONFIG_HIGHPTE
#include <asm/io.h>
struct page *kmap_atomic_to_page(void *);
#define ptep_to_machine(ptep)						\
({									\
	pte_t *__ptep = (ptep);						\
	page_to_phys(kmap_atomic_to_page(__ptep))			\
		| ((unsigned long)__ptep & (PAGE_SIZE - 1));		\
})
#else
#define ptep_to_machine(ptep)	virt_to_machine(ptep)
#endif

#define __HAVE_ARCH_PTEP_MODIFY_PROT_TRANSACTION
static inline pte_t ptep_modify_prot_start(struct mm_struct *mm, unsigned long addr,
					   pte_t *ptep)
{
#if CONFIG_XEN_COMPAT < 0x030300
	if (unlikely(!xen_feature(XENFEAT_mmu_pt_update_preserve_ad)))
		return ptep_get_and_clear(mm, addr, ptep);
#endif
	return *ptep;
}

static inline void ptep_modify_prot_commit(struct mm_struct *mm, unsigned long addr,
					   pte_t *ptep, pte_t pte)
{
	mmu_update_t u;

#if CONFIG_XEN_COMPAT < 0x030300
	if (unlikely(!xen_feature(XENFEAT_mmu_pt_update_preserve_ad))) {
		set_pte_at(mm, addr, ptep, pte);
		return;
	}
#endif
	u.ptr = ptep_to_machine(ptep) | MMU_PT_UPDATE_PRESERVE_AD;
	u.val = __pte_val(pte);
	if (HYPERVISOR_mmu_update(&u, 1, NULL, DOMID_SELF))
		BUG();
}

#ifdef CONFIG_HAVE_ARCH_SOFT_DIRTY
static inline pte_t pte_swp_mksoft_dirty(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_SWP_SOFT_DIRTY);
}

static inline int pte_swp_soft_dirty(pte_t pte)
{
	return pte_flags(pte) & _PAGE_SWP_SOFT_DIRTY;
}

static inline pte_t pte_swp_clear_soft_dirty(pte_t pte)
{
	return pte_clear_flags(pte, _PAGE_SWP_SOFT_DIRTY);
}
#endif

#define PKRU_AD_BIT 0x1
#define PKRU_WD_BIT 0x2
#define PKRU_BITS_PER_PKEY 2

static inline bool __pkru_allows_read(u32 pkru, u16 pkey)
{
	int pkru_pkey_bits = pkey * PKRU_BITS_PER_PKEY;
	return !(pkru & (PKRU_AD_BIT << pkru_pkey_bits));
}

static inline bool __pkru_allows_write(u32 pkru, u16 pkey)
{
	int pkru_pkey_bits = pkey * PKRU_BITS_PER_PKEY;
	/*
	 * Access-disable disables writes too so we need to check
	 * both bits here.
	 */
	return !(pkru & ((PKRU_AD_BIT|PKRU_WD_BIT) << pkru_pkey_bits));
}

static inline u16 pte_flags_pkey(unsigned long pte_flags)
{
#ifdef CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS
	/* ifdef to avoid doing 59-bit shift on 32-bit values */
	return (pte_flags & _PAGE_PKEY_MASK) >> _PAGE_BIT_PKEY_BIT0;
#else
	return 0;
#endif
}

static inline bool __pkru_allows_pkey(u16 pkey, bool write)
{
	u32 pkru = read_pkru();

	if (!__pkru_allows_read(pkru, pkey))
		return false;
	if (write && !__pkru_allows_write(pkru, pkey))
		return false;

	return true;
}

/*
 * 'pteval' can come from a PTE, PMD or PUD.  We only check
 * _PAGE_PRESENT, _PAGE_USER, and _PAGE_RW in here which are the
 * same value on all 3 types.
 */
static inline bool __pte_access_permitted(unsigned long pteval, bool write)
{
	unsigned long need_pte_bits = _PAGE_PRESENT|_PAGE_USER;

	if (write)
		need_pte_bits |= _PAGE_RW;

	if ((pteval & need_pte_bits) != need_pte_bits)
		return 0;

	return __pkru_allows_pkey(pte_flags_pkey(pteval), write);
}

#define pte_access_permitted pte_access_permitted
static inline bool pte_access_permitted(pte_t pte, bool write)
{
	return __pte_access_permitted(pte_val(pte), write);
}

#define pmd_access_permitted pmd_access_permitted
static inline bool pmd_access_permitted(pmd_t pmd, bool write)
{
	return __pte_access_permitted(pmd_val(pmd), write);
}

#define pud_access_permitted pud_access_permitted
static inline bool pud_access_permitted(pud_t pud, bool write)
{
	return __pte_access_permitted(pud_val(pud), write);
}

#include <asm-generic/pgtable.h>

struct vm_area_struct;

int direct_remap_pfn_range(struct vm_area_struct *,
                           unsigned long address,
                           unsigned long mfn,
                           unsigned long size,
                           pgprot_t,
                           domid_t);
int direct_remap_pfns_range(struct vm_area_struct *,
			    unsigned long address,
			    const unsigned long *mfns,
			    unsigned long size,
			    pgprot_t,
			    domid_t,
			    void (*)(unsigned int idx, int rc, void *),
			    void *ctxt);
int direct_kernel_remap_pfn_range(unsigned long address,
				  unsigned long mfn,
				  unsigned long size,
				  pgprot_t,
				  domid_t);
int create_lookup_pte_addr(struct mm_struct *,
                           unsigned long address,
                           uint64_t *ptep);

#endif	/* __ASSEMBLY__ */

#endif /* _ASM_X86_PGTABLE_H */
