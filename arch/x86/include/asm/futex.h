#ifndef _ASM_X86_FUTEX_H
#define _ASM_X86_FUTEX_H

#ifdef __KERNEL__

#include <linux/futex.h>
#include <linux/uaccess.h>

#include <asm/asm.h>
#include <asm/errno.h>
#include <asm/processor.h>
#include <asm/smap.h>

#define __futex_atomic_op1(insn, ret, oldval, uaddr, oparg)	\
	asm volatile("\t" ASM_STAC "\n"				\
		     "1:\t" insn "\n"				\
		     "2:\t" ASM_CLAC "\n"			\
		     "\t.section .fixup,\"ax\"\n"		\
		     "3:\tmov\t%3, %1\n"			\
		     "\tjmp\t2b\n"				\
		     "\t.previous\n"				\
		     _ASM_EXTABLE(1b, 3b)			\
		     : "=r" (oldval), "=r" (ret), "+m" (*uaddr)	\
		     : "i" (-EFAULT), "0" (oparg), "1" (0))

#define __futex_atomic_op2(insn, ret, oldval, uaddr, oparg)	\
	asm volatile("\t" ASM_STAC "\n"				\
		     "1:\tmovl	%2, %0\n"			\
		     "\tmovl\t%0, %3\n"				\
		     "\t" insn "\n"				\
		     "2:\t" LOCK_PREFIX "cmpxchgl %3, %2\n"	\
		     "\tjnz\t1b\n"				\
		     "3:\t" ASM_CLAC "\n"			\
		     "\t.section .fixup,\"ax\"\n"		\
		     "4:\tmov\t%5, %1\n"			\
		     "\tjmp\t3b\n"				\
		     "\t.previous\n"				\
		     _ASM_EXTABLE(1b, 4b)			\
		     _ASM_EXTABLE(2b, 4b)			\
		     : "=&a" (oldval), "=&r" (ret),		\
		       "+m" (*uaddr), "=&r" (tem)		\
		     : "r" (oparg), "i" (-EFAULT), "1" (0))

#ifdef CONFIG_SC_GUEST
#include <asm/sc.h>
#endif
static inline int futex_atomic_op_inuser(int encoded_op, u32 __user *uaddr)
{
	int op = (encoded_op >> 28) & 7;
	int cmp = (encoded_op >> 24) & 15;
	int oparg = (encoded_op << 8) >> 20;
	int cmparg = (encoded_op << 20) >> 20;
	int oldval = 0, ret, tem;
#ifdef CONFIG_SC_GUEST
	struct data_ex_cfg cfg;
	uint32_t kpa, upa;
#endif

	if (encoded_op & (FUTEX_OP_OPARG_SHIFT << 28))
		oparg = 1 << oparg;

	if (!access_ok(VERIFY_WRITE, uaddr, sizeof(u32)))
		return -EFAULT;

	pagefault_disable();

#ifdef CONFIG_SC_GUEST
	if (sc_guest_is_in_sc()) {
		ret = 0;
		upa = uvirt_to_phys((const void *)uaddr, 1);
		kpa = __pa(&oparg);
		cfg.ptr1 = kpa;
		cfg.ptr2 = upa;
		cfg.oldval = __pa(&oldval);
		switch (op) {
			case FUTEX_OP_SET:
				cfg.op = SC_DATA_EXCHG_XCHG;
				break;
			case FUTEX_OP_ADD:
				cfg.op = SC_DATA_EXCHG_ADD;
				break;
			case FUTEX_OP_OR:
				cfg.op = SC_DATA_EXCHG_OR;
				break;
			case FUTEX_OP_ANDN:
				tem = ~oparg;
				kpa = __pa(&(tem));
				cfg.ptr1 = kpa;
				cfg.op = SC_DATA_EXCHG_AND;
				break;
			case FUTEX_OP_XOR:
				cfg.op = SC_DATA_EXCHG_XOR;
				break;
			default:
				ret = -ENOSYS;
		}
		if (!ret) {
			ret = sc_guest_exchange_data(&cfg);
			if (ret == -EFAULT) {
				printk(KERN_ERR "### sc_guest_exchange_data failed (%s:%d). op=%d---\n",__func__,__LINE__,op);
			}
		}
	} else {
		switch (op) {
		case FUTEX_OP_SET:
			__futex_atomic_op1("xchgl %0, %2", ret, oldval, uaddr, oparg);
			break;
		case FUTEX_OP_ADD:
			__futex_atomic_op1(LOCK_PREFIX "xaddl %0, %2", ret, oldval,
					   uaddr, oparg);
			break;
		case FUTEX_OP_OR:
			__futex_atomic_op2("orl %4, %3", ret, oldval, uaddr, oparg);
			break;
		case FUTEX_OP_ANDN:
			__futex_atomic_op2("andl %4, %3", ret, oldval, uaddr, ~oparg);
			break;
		case FUTEX_OP_XOR:
			__futex_atomic_op2("xorl %4, %3", ret, oldval, uaddr, oparg);
			break;
		default:
			ret = -ENOSYS;
		}
	}

#else
	switch (op) {
	case FUTEX_OP_SET:
		__futex_atomic_op1("xchgl %0, %2", ret, oldval, uaddr, oparg);
		break;
	case FUTEX_OP_ADD:
		__futex_atomic_op1(LOCK_PREFIX "xaddl %0, %2", ret, oldval,
				   uaddr, oparg);
		break;
	case FUTEX_OP_OR:
		__futex_atomic_op2("orl %4, %3", ret, oldval, uaddr, oparg);
		break;
	case FUTEX_OP_ANDN:
		__futex_atomic_op2("andl %4, %3", ret, oldval, uaddr, ~oparg);
		break;
	case FUTEX_OP_XOR:
		__futex_atomic_op2("xorl %4, %3", ret, oldval, uaddr, oparg);
		break;
	default:
		ret = -ENOSYS;
	}
#endif

	pagefault_enable();

	if (!ret) {
		switch (cmp) {
		case FUTEX_OP_CMP_EQ:
			ret = (oldval == cmparg);
			break;
		case FUTEX_OP_CMP_NE:
			ret = (oldval != cmparg);
			break;
		case FUTEX_OP_CMP_LT:
			ret = (oldval < cmparg);
			break;
		case FUTEX_OP_CMP_GE:
			ret = (oldval >= cmparg);
			break;
		case FUTEX_OP_CMP_LE:
			ret = (oldval <= cmparg);
			break;
		case FUTEX_OP_CMP_GT:
			ret = (oldval > cmparg);
			break;
		default:
			ret = -ENOSYS;
		}
	}
	return ret;
}

static inline int futex_atomic_cmpxchg_inatomic(u32 *uval, u32 __user *uaddr,
						u32 oldval, u32 newval)
{
	return user_atomic_cmpxchg_inatomic(uval, uaddr, oldval, newval);
}

#endif
#endif /* _ASM_X86_FUTEX_H */
