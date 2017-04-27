#ifndef __ASM_CACHEFLUSH_H
#define __ASM_CACHEFLUSH_H

/* Keep includes the same across arches.  */
#include <linux/mm.h>

/*
 * The cache doesn't need to be flushed when TLB entries change when
 * the cache is mapped to physical memory, not virtual memory
 */
#define flush_cache_all()			do { } while (0)
#define flush_cache_mm(mm)			do { } while (0)
#define flush_cache_dup_mm(mm)			do { } while (0)
#define flush_cache_range(vma, start, end)	do { } while (0)
#define flush_cache_page(vma, vmaddr, pfn)	do { } while (0)
#define ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE 0
#define flush_dcache_page(page)			do { } while (0)
#define flush_dcache_mmap_lock(mapping)		do { } while (0)
#define flush_dcache_mmap_unlock(mapping)	do { } while (0)
#define flush_icache_range(start, end)		do { } while (0)
#define flush_icache_page(vma,pg)		do { } while (0)
#define flush_icache_user_range(vma,pg,adr,len)	do { } while (0)
#define flush_cache_vmap(start, end)		do { } while (0)
#define flush_cache_vunmap(start, end)		do { } while (0)

#ifdef CONFIG_SC_GUEST
#include <asm/sc.h>

#define sc_copy_to_user_page(vma, page, vaddr, dst, src, len) \
({				\
	sc_guest_data_move(src, dst, len);		\
})

#define sc_copy_from_user_page(vma, page, vaddr, dst, src, len) \
({				\
	sc_guest_data_move(src, dst, len);		\
})

#endif

#define orig_copy_to_user_page(vma, page, vaddr, dst, src, len) \
	do { \
		memcpy(dst, src, len); \
		flush_icache_user_range(vma, page, vaddr, len); \
	} while (0)
#define orig_copy_from_user_page(vma, page, vaddr, dst, src, len) \
	memcpy(dst, src, len)

#ifdef CONFIG_SC_GUEST
#define copy_to_user_page(vma, page, vaddr, dst, src, len) \
({		\
		if (sc_guest_is_in_sc())	\
			sc_copy_to_user_page(vma, page, vaddr, dst, src, len); \
		else		\
			orig_copy_to_user_page(vma, page, vaddr, dst, src, len); \
})
#define copy_from_user_page(vma, page, vaddr, dst, src, len) \
({	\
	if (sc_guest_is_in_sc())	\
		sc_copy_from_user_page(vma, page, vaddr, dst, src, len); \
	else		\
		orig_copy_from_user_page(vma, page, vaddr, dst, src, len);	\
})
#else
#define copy_to_user_page(vma, page, vaddr, dst, src, len)	\
	orig_copy_to_user_page(vma, page, vaddr, dst, src, len)
#define copy_from_user_page(vma, page, vaddr, dst, src, len) \
	orig_copy_from_user_page(vma, page, vaddr, dst, src, len)
#endif

#endif /* __ASM_CACHEFLUSH_H */
