/*
 * sc_guest.c
 *
 * Secure container with EPT isolation
 *
 * Copyright (C) 2017 Huawei Technologies Co., Ltd.
 * Copyright (C) 2017 Intel Corporation
 *
 * Authors:
 *   Chunyan Liu <liuchunyan9@huawei.com>
 *   Jason CJ Chen <jason.cj.chen@intel.com>
 *   Liu, Jingqi <jingqi.liu@intel.com>
 *   Ye, Weize <weize.ye@intel.com>
 *   Gu, jixing <jixing.gu@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include <linux/init.h>
#include <linux/percpu-defs.h>
#include <linux/sched.h>
#include <linux/kvm_para.h>
#include <linux/ptrace.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <asm/vdso.h>
#include <asm/pgtable.h>
#include <asm/current.h>
#include <asm/thread_info.h>
#include <asm/vvar.h>
#include <asm/sections.h>
#include <asm/processor.h>
#include <asm/sc.h>

static bool enable_sc = true;

static int __init sc_guest_disable(char *str)
{
	enable_sc = false;
	return 1;
}
__setup("disable_sc", sc_guest_disable);

static int sc_send_vmcall(int id, int ops, void *param1, void *param2)
{
	unsigned long rax = id;
	unsigned long rbx = ops;
	unsigned long rcx = (unsigned long)param1;
	unsigned long rdx = (unsigned long)param2;
	int ret = 0;

	smp_mb();
	asm volatile ("vmcall"
			: "=a" (rax),  "=b" (rbx), "=c" (rcx), "=d" (rdx)
			: "0"  (rax),  "1"  (rbx), "2"  (rcx), "3"  (rdx));
	ret = (int)rax;
	smp_mb();

	return ret;
}

bool sc_guest_is_in_sc(void)
{
	return current->ept_viewid > 0;
}
EXPORT_SYMBOL_GPL(sc_guest_is_in_sc);

static bool enableSC = 0;
static uint8_t enable_cluster = 0;
static uint32_t cluster_id = 0;
void sc_guest_check_exec_env(const char __user *str)
{
	char *sc_str = "enableSC", *cluster_str = "enableCluster";

	if (!enable_sc)
		return;

	if (strncmp(str, sc_str, 8) == 0) {
		enableSC = true;
		return;
	}

	if (strncmp(str, cluster_str, 13) == 0) {
		enable_cluster = true;
		cluster_id = 0;
		if (strlen(str) > 14) { // "enableCluster=pid#"
			unsigned long pid = simple_strtoul(str+14, NULL, 10);
			struct task_struct *tsk = find_task_by_pid_ns((pid_t)pid, &init_pid_ns);
			if (tsk && (tsk->ept_viewid > 0)) {
				cluster_id = tsk->ept_viewid;
				printk(KERN_INFO "SC_GUEST: should trigger cluster into [pid %lu:viewid %u]\n",
						pid, tsk->ept_viewid);
			}
		}

	}
}
EXPORT_SYMBOL_GPL(sc_guest_check_exec_env);

/**
 * uvirt_to_phys   - get physical address from user space virtual address
 * @addr:       user space virtual address, it is maybe mapped as kernel space memory
 *
 * This will trigger a page fault to add memory map for the user space
 * virtual address to make sure its physical address already exist.
 *
 **/
phys_addr_t uvirt_to_phys(const volatile void *addr, int write)
{
	phys_addr_t phy;
	struct page *page;

	/**
	 ** (addr == 0) from  do_strncpy_from_user in lib/strncpy_from_user.c
	 ** and prctl_set_seccomp in kernel/secomp.c, it's from user space
	 ** if in this case, it is not a bug.
	 **/
	/*
	   if ((unsigned long)addr == 0) {
			printk(KERN_DEBUG "###: %s -- addr = 0x%lx  write=%d --\n",
					__func__,(unsigned long)addr,write);
	   }
	 */

	if ((uint64_t)addr < TASK_SIZE_MAX) {
		get_user_pages_fast((unsigned long)addr, 1, write, &page);
		phy = page_to_phys(page);
		return phy + ((unsigned long)addr & (PAGE_SIZE -1));
	} else if (!is_vmalloc_or_module_addr((const void*)addr)) {
		return __pa((uint64_t)addr);
	} else {
		return page_to_phys(vmalloc_to_page((const void *)addr)) + offset_in_page((unsigned long)addr);
	}
}
EXPORT_SYMBOL_GPL(uvirt_to_phys);

int sc_guest_exchange_data(struct data_ex_cfg *cfg)
{
	return sc_send_vmcall(KVM_HC_SC, HC_DATA_EXCHANGE,(void*)__pa(cfg), (void*)sizeof(struct data_ex_cfg));
}
EXPORT_SYMBOL_GPL(sc_guest_exchange_data);

int sc_guest_data_move(const unsigned long src, const unsigned long dst, uint64_t size)
{
	struct data_ex_cfg cfg;
	int ret;

	cfg.op = SC_DATA_EXCHG_MOV;
	cfg.mov_src = uvirt_to_phys(src, 0);
	cfg.mov_dst = uvirt_to_phys(dst, 1);
	cfg.mov_size = size;

	ret = sc_guest_exchange_data(&cfg);
	if (ret == -EFAULT) {
		printk(KERN_ERR "### sc_guest_exchange_data failed (%s:%d). ---\n",__func__,__LINE__);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(sc_guest_data_move);

int sc_guest_data_xchg(int *oldval, u32 __user *uaddr, int *oparg)
{
	struct data_ex_cfg cfg;
	int ret;

	cfg.op = SC_DATA_EXCHG_XCHG;
	cfg.oldval = uvirt_to_phys(oldval, 1);
	cfg.ptr2 = uvirt_to_phys(uaddr, 1);
	cfg.ptr1 = uvirt_to_phys(oparg, 1);

	ret = sc_guest_exchange_data(&cfg);
	if (ret == -EFAULT) {
		printk(KERN_ERR "### sc_guest_exchange_data failed (%s:%d). ---\n",__func__,__LINE__);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(sc_guest_data_xchg);

int sc_guest_data_add(int *oldval, u32 __user *uaddr, int *oparg)
{
	struct data_ex_cfg cfg;
	int ret;

	cfg.op = SC_DATA_EXCHG_ADD;
	cfg.oldval = uvirt_to_phys(oldval, 1);
	cfg.ptr2 = uvirt_to_phys(uaddr, 1);
	cfg.ptr1 = uvirt_to_phys(oparg, 0);

	ret = sc_guest_exchange_data(&cfg);
	if (ret == -EFAULT) {
		printk(KERN_ERR "### sc_guest_exchange_data failed (%s:%d). ---\n",__func__,__LINE__);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(sc_guest_data_add);

int sc_guest_data_or(int *oldval, u32 __user *uaddr, int *oparg)
{
	struct data_ex_cfg cfg;
	int ret;

	cfg.op = SC_DATA_EXCHG_OR;
	cfg.oldval = uvirt_to_phys(oldval, 1);
	cfg.ptr2 = uvirt_to_phys(uaddr, 1);
	cfg.ptr1 = uvirt_to_phys(oparg, 0);

	ret = sc_guest_exchange_data(&cfg);
	if (ret == -EFAULT) {
		printk(KERN_ERR "### sc_guest_exchange_data failed (%s:%d). ---\n",__func__,__LINE__);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(sc_guest_data_or);

int sc_guest_data_and(int *oldval, u32 __user *uaddr, int *oparg)
{
	struct data_ex_cfg cfg;
	int ret;

	cfg.op = SC_DATA_EXCHG_AND;
	cfg.oldval = uvirt_to_phys(oldval, 1);
	cfg.ptr2 = uvirt_to_phys(uaddr, 1);
	cfg.ptr1 = uvirt_to_phys(oparg, 0);

	ret = sc_guest_exchange_data(&cfg);
	if (ret == -EFAULT) {
		printk(KERN_ERR "### sc_guest_exchange_data failed (%s:%d). ---\n",__func__,__LINE__);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(sc_guest_data_and);

int sc_guest_data_xor(int *oldval, u32 __user *uaddr, int *oparg)
{
	struct data_ex_cfg cfg;
	int ret;

	cfg.op = SC_DATA_EXCHG_XOR;
	cfg.oldval = uvirt_to_phys(oldval, 1);
	cfg.ptr2 = uvirt_to_phys(uaddr, 1);
	cfg.ptr1 = uvirt_to_phys(oparg, 0);
	ret = sc_guest_exchange_data(&cfg);
	if (ret == -EFAULT) {
		printk(KERN_ERR "### sc_guest_exchange_data failed (%s:%d). ---\n",__func__,__LINE__);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(sc_guest_data_xor);

int sc_guest_data_cmpxchg(uint64_t *old, void *ptr, uint64_t new, int size)
{
	struct data_ex_cfg cfg;
	int ret;

	cfg.op = SC_DATA_EXCHG_CMPXCHG;
	cfg.cmpxchg_ptr1 = uvirt_to_phys(old, 1);
	cfg.cmpxchg_ptr2 = uvirt_to_phys(ptr, 1);
	cfg.cmpxchg_new = new;
	cfg.cmpxchg_size = size;

	ret = sc_guest_exchange_data(&cfg);
	if (ret == -EFAULT) {
		printk(KERN_ERR "### sc_guest_exchange_data failed (%s:%d). ---\n",__func__,__LINE__);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(sc_guest_data_cmpxchg);

int sc_guest_data_set(unsigned long uaddr, uint8_t val, unsigned long size)
{
	int ret;
	struct data_ex_cfg cfg;

	cfg.set_ptr = uvirt_to_phys(uaddr, 1);
	cfg.set_val = val;
	cfg.set_size = size;
	cfg.op = SC_DATA_EXCHG_SET;
	ret = sc_guest_exchange_data(&cfg);
	if (ret == -EFAULT) {
		printk(KERN_ERR "### sc_guest_exchange_data failed (%s:%d). ---\n",__func__,__LINE__);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(sc_guest_data_set);

void sc_clear_user_page(void *page, unsigned long vaddr,
		struct page *pg)
{
	int ret;
	struct data_ex_cfg cfg;

	ret = sc_guest_data_set(page, 0, PAGE_SIZE);
	if (ret == -EFAULT) {
		printk(KERN_ERR "### sc_guest_exchange_data failed (%s:%d). ---\n",__func__,__LINE__);
	}
}
EXPORT_SYMBOL_GPL(sc_clear_user_page);

void sc_copy_user_page(void *to, void *from, unsigned long vaddr,
		struct page *topage)
{
	int ret;
	struct data_ex_cfg cfg;

	cfg.mov_src = uvirt_to_phys((const void *)from, 0);
	cfg.mov_dst = uvirt_to_phys((const void *)to, 1);
	cfg.mov_size = PAGE_SIZE;
	cfg.op = SC_DATA_EXCHG_MOV;
	ret = sc_guest_exchange_data(&cfg);
	if (ret == -EFAULT) {
		printk(KERN_ERR "### sc_guest_exchange_data failed (%s:%d). ---\n",__func__,__LINE__);
	}
}
EXPORT_SYMBOL_GPL(sc_copy_user_page);

unsigned long sc_guest_copy_user_generic(void *to, const void *from, unsigned len)
{
	int ret = 0;
	unsigned long src, dst, size, left1, left2;

	src = (unsigned long) from;
	dst = (unsigned long) to;
	while (len) {
		left1 = PAGE_SIZE - (src & (PAGE_SIZE - 1));
		size = (len > left1) ? left1 : len;
		left2 = PAGE_SIZE - (dst & (PAGE_SIZE - 1));
		if( likely(left2 >= size)) {
			ret = sc_guest_data_move(src, dst, size);
			if (ret == -EFAULT) {
				printk(KERN_ERR "sc_guest_data_move failed (%s:%d) -\n",__func__,__LINE__);
			}
		} else {
			ret = sc_guest_data_move(src, dst, left2);
			if (ret == -EFAULT) {
				printk(KERN_ERR "sc_guest_data_move failed (%s:%d) -\n",__func__,__LINE__);
			}

			ret = sc_guest_data_move(src + left2, dst + left2, size - left2);
			if (ret == -EFAULT) {
				printk(KERN_ERR "sc_guest_data_move failed (%s:%d) -\n",__func__,__LINE__);
			}
		}
		len = len - size;
		src += size;
		dst += size;
	}

	return ret ? len : 0;
}
EXPORT_SYMBOL_GPL(sc_guest_copy_user_generic);

int sc_guest_free_pages(struct page *page, int numpages)
{
	struct free_page_cfg cfg;
	int ret = 0;

	cfg.start_gfn = page_to_pfn(page) ;
	cfg.numpages = numpages;
	ret = sc_send_vmcall(KVM_HC_SC, HC_SET_FREED_PAGE,(void*)__pa(&cfg),
			(void*)sizeof(struct free_page_cfg));

	return ret;
}
EXPORT_SYMBOL_GPL(sc_guest_free_pages);

int sc_guest_share_page(struct page *page)
{
	uint64_t gfn = 0;
	int ret = 0;

	gfn = page_to_pfn(page) ;
	ret = sc_send_vmcall(KVM_HC_SC, HC_SET_SHARED_PAGE,(void*)__pa(&gfn),
			(void*)sizeof(uint64_t));

	return ret;
}
EXPORT_SYMBOL_GPL(sc_guest_share_page);

int sc_guest_create_view(void)
{
	struct view_cfg cfg;
	struct pt_regs *regs = current_pt_regs();
	struct page *page;
	int ret;

	if (!enable_sc || !enableSC)
		return -ENOSYS;

	ret = get_user_pages_fast(regs->ip, 1, 0, &page);
	if (ret < 0) {
		printk(KERN_ERR "SC_GUEST: cannot setup first page for create view. ret = %d\n", ret);
		return ret;
	}

	cfg.first_pfn = page_to_pfn(page);
	cfg.enable_cluster = enable_cluster;
	cfg.cluster_id = cluster_id;

	enableSC = false;
	enable_cluster = 0;
	cluster_id = 0;

	printk(KERN_INFO "SC_GUEST: create view with first pfn 0x%lx, from ip 0x%lx\n",
			(unsigned long)cfg.first_pfn, regs->ip);

	return sc_send_vmcall(KVM_HC_SC, HC_CREATE_VIEW, (void *)__pa(&cfg), (void *)sizeof(struct view_cfg));
}
EXPORT_SYMBOL_GPL(sc_guest_create_view);

static int _sc_guest_init(struct sc_cfg *cfg)
{
	return sc_send_vmcall(KVM_HC_SC, HC_INIT_SC, (void *)__pa(cfg), (void *)sizeof(struct sc_cfg));
}

#if defined(CONFIG_X86_64)
extern unsigned int vdso64_enabled;
#endif
static int __init sc_guest_init(void)
{
	int i;
	struct sc_cfg cfg;
	const struct vdso_image *image;
	uint64_t bitmap_bytes;

	if (!enable_sc)
		return 0;

	memset(&cfg, 0, sizeof(struct sc_cfg));
	if (sizeof(long) == 4)
		cfg.is_x32 = 1;
	cfg.total_npages = max_pfn;
	cfg.kernel_text_start = __pa_symbol(_text);
	cfg.kernel_text_end = __pa_symbol(_etext);
#if defined(CONFIG_X86_64)
	if (vdso64_enabled) {
		image = &vdso_image_64;
		cfg.vdso_start = __pa(image->data);
		cfg.vdso_end = __pa(image->data + image->size);
		cfg.vvar_start = __pa_symbol(&__vvar_page);
		cfg.vvar_end = __pa_symbol(&__vvar_page + PAGE_SIZE);
	}
#endif
	cfg.zero_start = __pa_symbol(empty_zero_page);
	cfg.zero_end = __pa_symbol(empty_zero_page + PAGE_SIZE);
	cfg.user_vrange_max = TASK_SIZE_MAX;
	cfg.kernel_vrange_start = __START_KERNEL_map;
	cfg.kernel_vrange_end = MODULES_VADDR;
	cfg.module_vrange_start = MODULES_VADDR;
	cfg.module_vrange_end = MODULES_END;
	cfg.task_cfg.smp_cpu = num_active_cpus();
	for_each_present_cpu(i) {
		cfg.task_cfg.percpu_task[i] = (uint64_t)__pa(&per_cpu(current_task, i));
	}
	cfg.task_cfg.task_size = sizeof(struct task_struct);
	cfg.task_cfg.task2pid_off = offsetof(struct task_struct, pid);
	cfg.task_cfg.task2viewid_off = offsetof(struct task_struct, ept_viewid);
	cfg.task_cfg.task2comm_off = offsetof(struct task_struct, comm);
	cfg.task_cfg.task2thread_off = offsetof(struct task_struct, thread);
	cfg.pv_cfg.phys_base = phys_base;
	cfg.pv_cfg.start_kernel_map = __START_KERNEL_map;
	cfg.pv_cfg.page_offset = PAGE_OFFSET;
	cfg.erase_freed_page = 0;

	printk(KERN_INFO "SC_GUEST: init sc with below parameters:\n"
			"is_x32: %u\n"
			"total_npages: %lu\n"
			"kernel_text_start: 0x%lx\n"
			"kernel_text_end: 0x%lx\n"
			"vdso_start: 0x%lx\n"
			"vdso_end: 0x%lx\n"
			"vvar_start: 0x%lx\n"
			"vvar_end: 0x%lx\n"
			"zero_start: 0x%lx\n"
			"zero_end: 0x%lx\n"
			"user_vrange_max: 0x%lx\n"
			"kernel_vrange_start: 0x%lx\n"
			"kernel_vrange_end: 0x%lx\n"
			"module_vrange_start: 0x%lx\n"
			"module_vrange_end: 0x%lx\n"
			"task:\n"
			"\t smp_cpu: %u\n"
			"\t percpu_task[0]: 0x%lx\n"
			"\t task_size: %u\n"
			"\t task2pid_off: %u\n"
			"\t task2viewid_off: %u\n"
			"\t task2viewid_comm: %u\n"
			"pv:\n"
			"\t phys_base: 0x%lx\n"
			"\t start_kernel_map: 0x%lx\n"
			"\t page_offset: 0x%lx\n"
			"erase_freed_page: %u\n",
			cfg.is_x32,
			(unsigned long)cfg.total_npages,
			(unsigned long)cfg.kernel_text_start,
			(unsigned long)cfg.kernel_text_end,
			(unsigned long)cfg.vdso_start,
			(unsigned long)cfg.vdso_end,
			(unsigned long)cfg.vvar_start,
			(unsigned long)cfg.vvar_end,
			(unsigned long)cfg.zero_start,
			(unsigned long)cfg.zero_end,
			(unsigned long)cfg.user_vrange_max,
			(unsigned long)cfg.kernel_vrange_start,
			(unsigned long)cfg.kernel_vrange_end,
			(unsigned long)cfg.module_vrange_start,
			(unsigned long)cfg.module_vrange_end,
			cfg.task_cfg.smp_cpu,
			(unsigned long)cfg.task_cfg.percpu_task[0],
			cfg.task_cfg.task_size,
			cfg.task_cfg.task2pid_off,
			cfg.task_cfg.task2viewid_off,
			cfg.task_cfg.task2comm_off,
			(unsigned long)cfg.pv_cfg.phys_base,
			(unsigned long)cfg.pv_cfg.start_kernel_map,
			(unsigned long)cfg.pv_cfg.page_offset,
			cfg.erase_freed_page);

	_sc_guest_init(&cfg);

	return 0;
}
postcore_initcall(sc_guest_init);
