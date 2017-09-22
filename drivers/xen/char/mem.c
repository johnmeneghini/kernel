/*
 *  Originally from linux/drivers/char/mem.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Added devfs support.
 *    Jan-11-1998, C. Scott Ananian <cananian@alumni.princeton.edu>
 *  Shared /dev/zero mmapping support, Feb 2000, Kanoj Sarcar <kanoj@sgi.com>
 */

#include <linux/mm.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <asm/io.h>
#include <asm/hypervisor.h>

static inline unsigned long size_inside_page(unsigned long start,
					     unsigned long size)
{
	unsigned long sz;

	sz = PAGE_SIZE - (start & (PAGE_SIZE - 1));

	return min(sz, size);
}

static inline int uncached_access(struct file *file)
{
	if (file->f_flags & O_DSYNC)
		return 1;
	/* Xen sets correct MTRR type on non-RAM for us. */
	return 0;
}

static inline int page_is_allowed(unsigned long pfn)
{
#ifdef CONFIG_STRICT_DEVMEM
	return devmem_is_allowed(pfn);
#else
	return 1;
#endif
}
static inline int range_is_allowed(unsigned long pfn, unsigned long size)
{
#ifdef CONFIG_STRICT_DEVMEM
	u64 from = ((u64)pfn) << PAGE_SHIFT;
	u64 to = from + size;
	u64 cursor = from;

	while (cursor < to) {
		if (!devmem_is_allowed(pfn))
			return 0;
		cursor += PAGE_SIZE;
		pfn++;
	}
#endif
	return 1;
}

/*
 * This funcion reads the *physical* memory. The f_pos points directly to the
 * memory location.
 */
static ssize_t read_mem(struct file *file, char __user *buf,
			size_t count, loff_t *ppos)
{
	phys_addr_t p = *ppos;
	ssize_t read = 0, sz;
	void __iomem *v;

	if (p != *ppos)
		return 0;

	while (count > 0) {
		unsigned long remaining;
		int allowed;

		sz = size_inside_page(p, count);

		allowed = page_is_allowed(p >> PAGE_SHIFT);
		if (!allowed)
			return -EPERM;

		if (allowed == 2) {
			/* Show zeros for restricted memory. */
			remaining = clear_user(buf, sz);
		} else {
			v = ioremap(p, sz);
			/*
			 * Some programs (e.g., dmidecode) groove off into
			 * weird RAM areas where no tables can possibly exist
			 * (because Xen will have stomped on them!). These
			 * programs get rather upset if we let them know that
			 * Xen failed their access, so we fake out a read of
			 * all zeroes.
			 */
			if (IS_ERR_OR_NULL(v)) {
				if (clear_user(buf, count))
					return -EFAULT;
				read += count;
				break;
			}

			remaining = copy_to_user(buf, v, sz);
			iounmap(v);
		}

		if (remaining)
			return -EFAULT;

		buf += sz;
		p += sz;
		count -= sz;
		read += sz;
	}

	*ppos += read;
	return read;
}

static ssize_t write_mem(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	phys_addr_t p = *ppos;
	ssize_t written = 0, sz, ignored;
	void __iomem *v;

	if (p != *ppos)
		return -EFBIG;

	while (count > 0) {
		int allowed;

		sz = size_inside_page(p, count);

		allowed = page_is_allowed(p >> PAGE_SHIFT);
		if (!allowed)
			return -EPERM;

		/* Skip actual writing when a page is marked as restricted. */
		if (allowed == 1) {
			v = ioremap(p, sz);
			if (v == NULL)
				break;
			if (IS_ERR(v)) {
				if (written == 0)
					return PTR_ERR(v);
				break;
			}

			ignored = copy_from_user(v, buf, sz);
			iounmap(v);
			if (ignored) {
				written += sz - ignored;
				if (written)
					break;
				return -EFAULT;
			}
		}
		buf += sz;
		p += sz;
		count -= sz;
		written += sz;
	}

	*ppos += written;
	return written;
}

#ifndef ARCH_HAS_DEV_MEM_MMAP_MEM
static const struct vm_operations_struct mmap_mem_ops = {
#ifdef CONFIG_HAVE_IOREMAP_PROT
	.access = generic_access_phys
#endif
};

static int xen_mmap_mem(struct file *file, struct vm_area_struct *vma)
{
	size_t size = vma->vm_end - vma->vm_start;
	phys_addr_t offset = (phys_addr_t)vma->vm_pgoff << PAGE_SHIFT;

	/* It's illegal to wrap around the end of the physical address space. */
	if (offset + (phys_addr_t)size - 1 < offset)
		return -EINVAL;

	if (uncached_access(file))
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	if (!range_is_allowed(vma->vm_pgoff, size))
		return -EPERM;

	if (!phys_mem_access_prot_allowed(file, vma->vm_pgoff, size,
					  &vma->vm_page_prot))
		return -EINVAL;

	vma->vm_ops = &mmap_mem_ops;

	/* We want to return the real error code, not EAGAIN. */
	return direct_remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
				      size, vma->vm_page_prot, DOMID_IO);
}
#endif

/*
 * The memory devices use the full 32/64 bits of the offset, and so we cannot
 * check against negative addresses: they are ok. The return value is weird,
 * though, in that case (0).
 *
 * also note that seeking relative to the "end of file" isn't supported:
 * it has no meaning, so it returns -EINVAL.
 */
static loff_t memory_lseek(struct file *file, loff_t offset, int orig)
{
	loff_t ret;

	inode_lock(file_inode(file));
	switch (orig) {
	case SEEK_CUR:
		offset += file->f_pos;
	case SEEK_SET:
		/* to avoid userland mistaking f_pos=-9 as -EBADF=-9 */
		if ((unsigned long long)offset >= -MAX_ERRNO) {
			ret = -EOVERFLOW;
			break;
		}
		file->f_pos = offset;
		ret = file->f_pos;
		force_successful_syscall_return();
		break;
	default:
		ret = -EINVAL;
	}
	inode_unlock(file_inode(file));
	return ret;
}

static int open_mem(struct inode * inode, struct file * filp)
{
	return capable(CAP_SYS_RAWIO) ? 0 : -EPERM;
}

const struct file_operations mem_fops = {
	.llseek		= memory_lseek,
	.read		= read_mem,
	.write		= write_mem,
	.mmap		= xen_mmap_mem,
	.open		= open_mem,
};
