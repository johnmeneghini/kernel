#ifndef _ASM_X86_SPECIAL_INSNS_H
#define _ASM_X86_SPECIAL_INSNS_H


#ifdef __KERNEL__

#include <asm/barrier.h>
#include <asm/hypervisor.h>
#include <asm/maddr.h>
#include <asm/nops.h>

DECLARE_PER_CPU(unsigned long, xen_x86_cr0);
DECLARE_PER_CPU(unsigned long, xen_x86_cr0_upd);

static inline unsigned long xen_read_cr0_upd(void)
{
	unsigned long upd = raw_cpu_read_l(xen_x86_cr0_upd);
	rmb();
	return upd;
}

static inline void xen_clear_cr0_upd(void)
{
	wmb();
	raw_cpu_write_l(xen_x86_cr0_upd, 0);
}

/*
 * Volatile isn't enough to prevent the compiler from reordering the
 * read/write functions for the control registers and messing everything up.
 * A memory clobber would solve the problem, but would prevent reordering of
 * all loads stores around it, which can hurt performance. Solution is to
 * use a variable and mimic reads and writes to it to enforce serialization
 */
extern unsigned long __force_order;

static inline unsigned long native_read_cr0(void)
{
	unsigned long val;
	asm volatile("mov %%cr0,%0\n\t" : "=r" (val), "=m" (__force_order));
	return val;
}

static inline unsigned long xen_read_cr0(void)
{
	return likely(!xen_read_cr0_upd()) ?
	       raw_cpu_read_l(xen_x86_cr0) : native_read_cr0();
}

static inline void native_write_cr0(unsigned long val)
{
	asm volatile("mov %0,%%cr0": : "r" (val), "m" (__force_order));
}

static inline void xen_write_cr0(unsigned long val)
{
	unsigned long upd = val ^ raw_cpu_read_l(xen_x86_cr0);

	if (unlikely(percpu_cmpxchg_op(xen_x86_cr0_upd, 0, upd))) {
		native_write_cr0(val);
		return;
	}

	if (!upd)
		return;

	native_write_cr0(val);
	raw_cpu_write_l(xen_x86_cr0, val);
	xen_clear_cr0_upd();
}

#define xen_read_cr2() vcpu_info_read(arch.cr2)
#define xen_write_cr2(val) vcpu_info_write(arch.cr2, val)

static inline unsigned long __xen_read_cr3(void)
{
	unsigned long val;
	asm volatile("mov %%cr3,%0\n\t" : "=r" (val), "=m" (__force_order));
#ifdef CONFIG_X86_32
	return mfn_to_pfn(xen_cr3_to_pfn(val)) << PAGE_SHIFT;
#else
	return machine_to_phys(val);
#endif
}

static inline void xen_write_cr3(unsigned long val)
{
#ifdef CONFIG_X86_32
	val = xen_pfn_to_cr3(pfn_to_mfn(val >> PAGE_SHIFT));
#else
	val = phys_to_machine(val);
#endif
	asm volatile("mov %0,%%cr3": : "r" (val), "m" (__force_order));
}

static inline unsigned long xen_read_cr4(void)
{
	unsigned long val;
	asm volatile("mov %%cr4,%0\n\t" : "=r" (val), "=m" (__force_order));
	return val;
}


static inline void xen_write_cr4(unsigned long val)
{
	asm volatile("mov %0,%%cr4": : "r" (val), "m" (__force_order));
}

#ifdef CONFIG_X86_64
static inline unsigned long xen_read_cr8(void)
{
	return 0;
}

static inline void xen_write_cr8(unsigned long val)
{
	BUG_ON(val);
}
#endif

#ifdef CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS
static inline u32 __read_pkru(void)
{
	u32 ecx = 0;
	u32 edx, pkru;

	/*
	 * "rdpkru" instruction.  Places PKRU contents in to EAX,
	 * clears EDX and requires that ecx=0.
	 */
	asm volatile(".byte 0x0f,0x01,0xee\n\t"
		     : "=a" (pkru), "=d" (edx)
		     : "c" (ecx));
	return pkru;
}

static inline void __write_pkru(u32 pkru)
{
	u32 ecx = 0, edx = 0;

	/*
	 * "wrpkru" instruction.  Loads contents in EAX to PKRU,
	 * requires that ecx = edx = 0.
	 */
	asm volatile(".byte 0x0f,0x01,0xef\n\t"
		     : : "a" (pkru), "c"(ecx), "d"(edx));
}
#else
static inline u32 __read_pkru(void)
{
	return 0;
}

static inline void __write_pkru(u32 pkru)
{
}
#endif

static inline void native_wbinvd(void)
{
	asm volatile("wbinvd": : :"memory");
}

extern void xen_load_gs_index(unsigned);

static inline unsigned long read_cr0(void)
{
	return xen_read_cr0();
}

static inline void write_cr0(unsigned long x)
{
	xen_write_cr0(x);
}

static inline unsigned long read_cr2(void)
{
	return xen_read_cr2();
}

static inline void write_cr2(unsigned long x)
{
	xen_write_cr2(x);
}

/*
 * Careful!  CR3 contains more than just an address.  You probably want
 * read_cr3_pa() instead.
 */
static inline unsigned long __read_cr3(void)
{
	return __xen_read_cr3();
}

static inline void write_cr3(unsigned long x)
{
	xen_write_cr3(x);
}

static inline unsigned long __read_cr4(void)
{
	return xen_read_cr4();
}

static inline void __write_cr4(unsigned long x)
{
	xen_write_cr4(x);
}

static inline void wbinvd(void)
{
	native_wbinvd();
}

#ifdef CONFIG_X86_64

static inline unsigned long read_cr8(void)
{
	return xen_read_cr8();
}

static inline void write_cr8(unsigned long x)
{
	xen_write_cr8(x);
}

static inline void load_gs_index(unsigned selector)
{
	xen_load_gs_index(selector);
}

#endif

static inline void clflush(volatile void *__p)
{
	asm volatile("clflush %0" : "+m" (*(volatile char __force *)__p));
}

static inline void clflushopt(volatile void *__p)
{
	alternative_io(".byte " __stringify(NOP_DS_PREFIX) "; clflush %P0",
		       ".byte 0x66; clflush %P0",
		       X86_FEATURE_CLFLUSHOPT,
		       "+m" (*(volatile char __force *)__p));
}

static inline void clwb(volatile void *__p)
{
	volatile struct { char x[64]; } *p = __p;

	asm volatile(ALTERNATIVE_2(
		".byte " __stringify(NOP_DS_PREFIX) "; clflush (%[pax])",
		".byte 0x66; clflush (%[pax])", /* clflushopt (%%rax) */
		X86_FEATURE_CLFLUSHOPT,
		".byte 0x66, 0x0f, 0xae, 0x30",  /* clwb (%%rax) */
		X86_FEATURE_CLWB)
		: [p] "+m" (*p)
		: [pax] "a" (p));
}

#define nop() asm volatile ("nop")


#endif /* __KERNEL__ */

#endif /* _ASM_X86_SPECIAL_INSNS_H */
