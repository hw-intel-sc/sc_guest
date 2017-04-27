/*
 * sc.h
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

#ifndef _LINUX_SC_H
#define _LINUX_SC_H

#include <linux/binfmts.h>
#ifdef CONFIG_SC_HOST
#include <linux/kvm_host.h>
#endif

#define MAX_CPU	32

/* SC hypercall IDs */
#define HC_INIT_SC 1
#define HC_CREATE_VIEW 2
#define HC_SET_SHARED_PAGE 3
#define HC_SET_FREED_PAGE 4
#define HC_DATA_EXCHANGE 5

enum data_exchg_type {
	SC_DATA_EXCHG_MOV  = 1,
	SC_DATA_EXCHG_SET,
	SC_DATA_EXCHG_XCHG,
	SC_DATA_EXCHG_ADD,
	SC_DATA_EXCHG_OR,
	SC_DATA_EXCHG_AND,
	SC_DATA_EXCHG_XOR,
	SC_DATA_EXCHG_CMPXCHG,
	SC_DATA_EXCHG_MAX,
};

struct sc_cfg {
	/*
	 * VM HW config:
	 * - is 32bit?
	 * - total phys memory page numbers
	 */
	uint8_t is_x32;
	uint64_t total_npages;
	/*
	 * VM OS config:
	 * - kernel text range (gpa)
	 * - vdso/vvar/zero page range (gpa)
	 * - free page status bitmap (gpa)
	 * - user virtual addr max (gva)
	 * - kernel virtual addr range (gva)
	 * - module virtual addr range (gva)
	 * - current task config
	 * - physical to virtual mapping config (kernel space)
	 */
	uint64_t kernel_text_start;
	uint64_t kernel_text_end;
	uint64_t vdso_start;
	uint64_t vdso_end;
	uint64_t vvar_start;
	uint64_t vvar_end;
	uint64_t zero_start;
	uint64_t zero_end;
	uint64_t user_vrange_max;
	uint64_t kernel_vrange_start;
	uint64_t kernel_vrange_end;
	uint64_t module_vrange_start;
	uint64_t module_vrange_end;
	struct task_cfg {
		uint32_t smp_cpu;
		uint64_t percpu_task[MAX_CPU];
		uint32_t task_size;
		uint32_t task2pid_off;
		uint32_t task2viewid_off;
		uint32_t task2comm_off;
		uint32_t task2thread_off;
	} task_cfg;
	struct pv_cfg {
		uint64_t phys_base;
		uint64_t start_kernel_map;
		uint64_t page_offset;
	} pv_cfg;
	/*
	 * Misc config:
	 * - erase freed page
	 */
	uint8_t erase_freed_page;
#ifdef CONFIG_SC_HOST
	/*
	 * HOST auxiliary parameters
	 */
	uint8_t is_sc_inited;
	struct guest_curr_task {
		uint64_t ptr[MAX_CPU];
		uint32_t offset[MAX_CPU];
	} guest_curr;
	unsigned long *shared_pages_bitmap;
	pfn_t w_emulate_pfn;
	pfn_t rx_emulate_pfn;
	spinlock_t sc_lock;
#endif
};

struct view_cfg {
	uint64_t first_pfn;
	uint8_t enable_cluster;
	uint32_t cluster_id;
};

struct data_ex_cfg {
	enum data_exchg_type op;
	union {
		struct {
			uint64_t mov_src;
			uint64_t mov_dst;
			uint64_t mov_size;
		};
		struct {
			uint64_t set_ptr;
			uint8_t set_val;
			uint64_t set_size;
		};
		struct {
			uint32_t ptr1;
			uint32_t ptr2;
			uint32_t oldval;
		};
		struct {
			uint64_t cmpxchg_ptr1;
			uint64_t cmpxchg_ptr2;
			uint64_t cmpxchg_new;
			uint32_t cmpxchg_size;
		};
	};
};

struct free_page_cfg {
	uint64_t start_gfn;
	uint32_t numpages;
};

#ifdef CONFIG_SC_HOST

/* Define debug level */
#define SC_HOST_ERR    1
#define SC_HOST_NOTICE 2
#define SC_HOST_INFO   3
#define SC_HOST_DBG    4

/*
 * EXCEPTION emulate type.
 *  - EXP_NO_EMUL - 0:	rip in user, just inject exception to kill process
 *  - EXP_R_EMUL  - 2:	rip in kernel, access gla for R, return fake page with "nop"
 *  - EXP_W_EMUL  - 3:	rip in kernel, access gla for W, return fake page for write
 *	- EXP_X_EMUL  - 4:	rip in kernel, access gla for X, return fake page with "nop"
 *	emulating priority: R < W < X
 * TODO: now it's fake code, just set all EMULATE to NO
 */
#define EXP_NO_EMUL		0
#define EXP_R_EMUL		2
#define EXP_W_EMUL		3
#define EXP_X_EMUL		4

extern int sc_host_debug;
#define SC_HOST_PRINT(level, fmt, arg...) \
	if (level <= sc_host_debug) { \
		printk(KERN_INFO "SC_HOST: " fmt, ##arg); \
	}

#ifdef CONFIG_PROC_FS
int sc_host_proc_init(void);
void sc_host_proc_exit(void);
#endif

#define SC_MAX_VIEW KVM_MAX_HPA
#define SC_VIEW_0 DEF_HPA
#define SC_VIEW_IS_INVALID(view)	((view) >= SC_MAX_VIEW)
#define SC_VIEW_IS_VIEW0(view)		((view) == SC_VIEW_0)
#define SC_VIEW_IS_SC(view)			(((view) != SC_VIEW_0) && ((view) < SC_MAX_VIEW))

#define SC_SPTE_PERM_MASK			0x7
#define for_each_active_view		for_each_active_hpa

int sc_host_handle_sc(struct kvm_vcpu *vcpu, unsigned long ops,
						unsigned long a1, unsigned long a2);
int sc_host_chk_edit_perm(struct kvm_vcpu *vcpu, gpa_t gpa,
						pfn_t pfn, u32 error_code, bool prefault);
int sc_host_emulate(struct kvm_vcpu *vcpu, gpa_t gpa, int type);
#else
#define SC_HOST_PRINT(level, fmt, arg...) do { } while (0)
#define sc_host_handle_sc NULL
#endif

#ifdef CONFIG_SC_GUEST
bool is_sc(struct task_struct *task);
void sc_guest_check_exec_env(const char __user *str);
phys_addr_t uvirt_to_phys(const volatile void *addr, int write);
int sc_guest_exchange_data(struct data_ex_cfg *cfg);
int sc_guest_create_view(void);
int sc_guest_free_page(struct page *page, int numpages);
int sc_guest_share_page(struct page *page);
#endif

#endif
