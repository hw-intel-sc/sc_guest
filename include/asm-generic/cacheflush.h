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

#define copy_to_user_page(vma, page, vaddr, dst, src, len) \
({				\
	struct data_ex_cfg cfg;					\
	cfg.mov_src = __pa((uint64_t)src);		\
	cfg.mov_dst = uvirt_to_phys((const void*)dst, 1); \
	cfg.mov_size = len;				\
	cfg.op = SC_DATA_EXCHG_MOV;		\
	sc_guest_exchange_data(&cfg);		\
})

#define copy_from_user_page(vma, page, vaddr, dst, src, len) \
({				\
	struct data_ex_cfg cfg;					\
	cfg.mov_src = uvirt_to_phys((const void*)src, 0);		\
	cfg.mov_dst = __pa((uint64_t)dst); \
	cfg.mov_size = len;				\
	cfg.op = SC_DATA_EXCHG_MOV;		\
	sc_guest_exchange_data(&cfg);		\
})

#else

#define copy_to_user_page(vma, page, vaddr, dst, src, len) \
	do { \
		memcpy(dst, src, len); \
		flush_icache_user_range(vma, page, vaddr, len); \
	} while (0)
#define copy_from_user_page(vma, page, vaddr, dst, src, len) \
	memcpy(dst, src, len)

#endif

#endif /* __ASM_CACHEFLUSH_H */
