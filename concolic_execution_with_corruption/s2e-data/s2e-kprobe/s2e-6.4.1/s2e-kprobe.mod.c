#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif


static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x5a7a45f8, "__sanitizer_cov_trace_pc" },
	{ 0x7555b37d, "pcpu_hot" },
	{ 0xc60d0620, "__num_online_cpus" },
	{ 0x3c142fbd, "__sanitizer_cov_trace_const_cmp4" },
	{ 0x9316e318, "register_kretprobe" },
	{ 0xfcca5424, "register_kprobe" },
	{ 0x6a5cb5ee, "__get_free_pages" },
	{ 0xfb578fc5, "memset" },
	{ 0x63026490, "unregister_kprobe" },
	{ 0xbdbc439e, "unregister_kretprobe" },
	{ 0x88160f43, "__stack_chk_fail" },
	{ 0x148653, "vsnprintf" },
	{ 0xc639136b, "__sanitizer_cov_trace_const_cmp8" },
	{ 0x5ad7ad3a, "__sanitizer_cov_trace_cmp8" },
	{ 0x706c5a65, "preempt_count_sub" },
	{ 0x126eac8d, "__sanitizer_cov_trace_const_cmp2" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0xb34ee6f6, "kernel_read" },
	{ 0x37a0cba, "kfree" },
	{ 0xf229424a, "preempt_count_add" },
	{ 0xf6798d86, "open_exec" },
	{ 0x546a4dbe, "would_dump" },
	{ 0xae2d285e, "kmalloc_caches" },
	{ 0xea4e9610, "kmalloc_trace" },
	{ 0x5b3ebd4f, "kern_path" },
	{ 0x48d88a2c, "__SCT__preempt_schedule" },
	{ 0xffa90bf8, "d_path" },
	{ 0x754d539c, "strlen" },
	{ 0x9166fada, "strncpy" },
	{ 0x8d522714, "__rcu_read_lock" },
	{ 0x892da873, "debug_lockdep_rcu_enabled" },
	{ 0xce6db656, "rcu_is_watching" },
	{ 0xae0bd7af, "lockdep_rcu_suspicious" },
	{ 0x415269cf, "mas_find" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x2469810f, "__rcu_read_unlock" },
	{ 0xa2f050e8, "rcu_lock_map" },
	{ 0x709c929, "lock_acquire" },
	{ 0x9af0a615, "lock_release" },
	{ 0xd4682669, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "74691F04EA455644EF750B8");
