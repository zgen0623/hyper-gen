/*
 *  linux/init/main.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  GK 2/5/95  -  Changed to support mounting root fs via NFS
 *  Added initrd & change_root: Werner Almesberger & Hans Lermen, Feb '96
 *  Moan early if gcc is old, avoiding bogus kernels - Paul Gortmaker, May '96
 *  Simplified starting of init:  Michael A. Griffith <grif@acm.org>
 */

#define DEBUG		/* Enable initcall_debug */

#include <linux/types.h>
#include <linux/extable.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/binfmts.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/stackprotector.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/bootmem.h>
#include <linux/acpi.h>
#include <linux/console.h>
#include <linux/nmi.h>
#include <linux/percpu.h>
#include <linux/kmod.h>
#include <linux/vmalloc.h>
#include <linux/kernel_stat.h>
#include <linux/start_kernel.h>
#include <linux/security.h>
#include <linux/smp.h>
#include <linux/profile.h>
#include <linux/rcupdate.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/writeback.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/cgroup.h>
#include <linux/efi.h>
#include <linux/tick.h>
#include <linux/sched/isolation.h>
#include <linux/interrupt.h>
#include <linux/taskstats_kern.h>
#include <linux/delayacct.h>
#include <linux/unistd.h>
#include <linux/rmap.h>
#include <linux/mempolicy.h>
#include <linux/key.h>
#include <linux/buffer_head.h>
#include <linux/page_ext.h>
#include <linux/debug_locks.h>
#include <linux/debugobjects.h>
#include <linux/lockdep.h>
#include <linux/kmemleak.h>
#include <linux/pid_namespace.h>
#include <linux/device.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/sched/init.h>
#include <linux/signal.h>
#include <linux/idr.h>
#include <linux/kgdb.h>
#include <linux/ftrace.h>
#include <linux/async.h>
#include <linux/sfi.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/perf_event.h>
#include <linux/ptrace.h>
#include <linux/pti.h>
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/sched_clock.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/context_tracking.h>
#include <linux/random.h>
#include <linux/list.h>
#include <linux/integrity.h>
#include <linux/proc_ns.h>
#include <linux/io.h>
#include <linux/cache.h>
#include <linux/rodata_test.h>

#include <asm/io.h>
#include <asm/bugs.h>
#include <asm/setup.h>
#include <asm/sections.h>
#include <asm/cacheflush.h>

static int kernel_init(void *);

extern void init_IRQ(void);
extern void radix_tree_init(void);

/*
 * Debug helper: via this flag we know that we are in 'early bootup code'
 * where only the boot processor is running with IRQ disabled.  This means
 * two things - IRQ must not be enabled before the flag is cleared and some
 * operations which are not allowed with IRQ disabled are allowed while the
 * flag is set.
 */
bool early_boot_irqs_disabled __read_mostly;

enum system_states system_state __read_mostly;
EXPORT_SYMBOL(system_state);

/*
 * Boot command-line arguments
 */
#define MAX_INIT_ARGS CONFIG_INIT_ENV_ARG_LIMIT
#define MAX_INIT_ENVS CONFIG_INIT_ENV_ARG_LIMIT

extern void time_init(void);
/* Default late time init is NULL. archs can override this later. */
void (*__initdata late_time_init)(void);

/* Untouched command line saved by arch-specific code. */
char __initdata boot_command_line[COMMAND_LINE_SIZE];
/* Untouched saved command line (eg. for /proc) */
char *saved_command_line;
/* Command line for parameter parsing */
static char *static_command_line;
/* Command line for per-initcall parameter parsing */
static char *initcall_command_line;

static char *execute_command;
static char *ramdisk_execute_command;

/*
 * Used to generate warnings if static_key manipulation functions are used
 * before jump_label_init is called.
 */
bool static_key_initialized __read_mostly;
EXPORT_SYMBOL_GPL(static_key_initialized);

/*
 * If set, this is an indication to the drivers that reset the underlying
 * device before going ahead with the initialization otherwise driver might
 * rely on the BIOS and skip the reset operation.
 *
 * This is useful if kernel is booting in an unreliable environment.
 * For ex. kdump situation where previous kernel has crashed, BIOS has been
 * skipped and devices will be in unknown state.
 */
unsigned int reset_devices;
EXPORT_SYMBOL(reset_devices);

static int __init set_reset_devices(char *str)
{
	reset_devices = 1;
	return 1;
}

__setup("reset_devices", set_reset_devices);

static const char *argv_init[MAX_INIT_ARGS+2] = { "init", NULL, };
const char *envp_init[MAX_INIT_ENVS+2] = { "HOME=/", "TERM=linux", NULL, };
static const char *panic_later, *panic_param;

extern const struct obs_kernel_param __setup_start[], __setup_end[];

static bool __init obsolete_checksetup(char *line)
{
	const struct obs_kernel_param *p;
	bool had_early_param = false;

	p = __setup_start;
	do {
		int n = strlen(p->str);
		if (parameqn(line, p->str, n)) {
			if (p->early) {
				/* Already done in parse_early_param?
				 * (Needs exact match on param part).
				 * Keep iterating, as we can have early
				 * params and __setups of same names 8( */
				if (line[n] == '\0' || line[n] == '=')
					had_early_param = true;
			} else if (!p->setup_func) {
				pr_warn("Parameter %s is obsolete, ignored\n",
					p->str);
				return true;
			} else if (p->setup_func(line + n))
				return true;
		}
		p++;
	} while (p < __setup_end);

	return had_early_param;
}

/*
 * This should be approx 2 Bo*oMips to start (note initial shift), and will
 * still work even if initially too large, it will just take slightly longer
 */
unsigned long loops_per_jiffy = (1<<12);
EXPORT_SYMBOL(loops_per_jiffy);

static int __init debug_kernel(char *str)
{
	console_loglevel = CONSOLE_LOGLEVEL_DEBUG;
	return 0;
}

static int __init quiet_kernel(char *str)
{
	console_loglevel = CONSOLE_LOGLEVEL_QUIET;
	return 0;
}

early_param("debug", debug_kernel);
early_param("quiet", quiet_kernel);

static int __init loglevel(char *str)
{
	int newlevel;

	/*
	 * Only update loglevel value when a correct setting was passed,
	 * to prevent blind crashes (when loglevel being set to 0) that
	 * are quite hard to debug
	 */
	if (get_option(&str, &newlevel)) {
		console_loglevel = newlevel;
		return 0;
	}

	return -EINVAL;
}

early_param("loglevel", loglevel);

/* Change NUL term back to "=", to make "param" the whole string. */
static int __init repair_env_string(char *param, char *val,
				    const char *unused, void *arg)
{
	if (val) {
		/* param=val or param="val"? */
		if (val == param+strlen(param)+1)
			val[-1] = '=';
		else if (val == param+strlen(param)+2) {
			val[-2] = '=';
			memmove(val-1, val, strlen(val)+1);
			val--;
		} else
			BUG();
	}
	return 0;
}

/* Anything after -- gets handed straight to init. */
static int __init set_init_arg(char *param, char *val,
			       const char *unused, void *arg)
{
	unsigned int i;

	if (panic_later)
		return 0;

	repair_env_string(param, val, unused, NULL);

	for (i = 0; argv_init[i]; i++) {
		if (i == MAX_INIT_ARGS) {
			panic_later = "init";
			panic_param = param;
			return 0;
		}
	}
	argv_init[i] = param;
	return 0;
}

/*
 * Unknown boot options get handed to init, unless they look like
 * unused parameters (modprobe will find them in /proc/cmdline).
 */
static int __init unknown_bootoption(char *param, char *val,
				     const char *unused, void *arg)
{
	repair_env_string(param, val, unused, NULL);

	/* Handle obsolete-style parameters */
	if (obsolete_checksetup(param))
		return 0;

	/* Unused module parameter. */
	if (strchr(param, '.') && (!val || strchr(param, '.') < val))
		return 0;

	if (panic_later)
		return 0;

	if (val) {
		/* Environment option */
		unsigned int i;
		for (i = 0; envp_init[i]; i++) {
			if (i == MAX_INIT_ENVS) {
				panic_later = "env";
				panic_param = param;
			}
			if (!strncmp(param, envp_init[i], val - param))
				break;
		}
		envp_init[i] = param;
	} else {
		/* Command line option */
		unsigned int i;
		for (i = 0; argv_init[i]; i++) {
			if (i == MAX_INIT_ARGS) {
				panic_later = "init";
				panic_param = param;
			}
		}
		argv_init[i] = param;
	}
	return 0;
}

static int __init init_setup(char *str)
{
	unsigned int i;

	execute_command = str;
	/*
	 * In case LILO is going to boot us with default command line,
	 * it prepends "auto" before the whole cmdline which makes
	 * the shell think it should execute a script with such name.
	 * So we ignore all arguments entered _before_ init=... [MJ]
	 */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("init=", init_setup);

static int __init rdinit_setup(char *str)
{
	unsigned int i;

	ramdisk_execute_command = str;
	/* See "auto" comment in init_setup */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("rdinit=", rdinit_setup);

#ifndef CONFIG_SMP
static const unsigned int setup_max_cpus = NR_CPUS;
static inline void setup_nr_cpu_ids(void) { }
static inline void smp_prepare_cpus(unsigned int maxcpus) { }
#endif

/*
 * We need to store the untouched command line for future reference.
 * We also need to store the touched command line since the parameter
 * parsing is performed in place, and we should allow a component to
 * store reference of name/value for future reference.
 */
static void __init setup_command_line(char *command_line)
{
	saved_command_line =
		memblock_virt_alloc(strlen(boot_command_line) + 1, 0);
	initcall_command_line =
		memblock_virt_alloc(strlen(boot_command_line) + 1, 0);
	static_command_line = memblock_virt_alloc(strlen(command_line) + 1, 0);
	strcpy(saved_command_line, boot_command_line);
	strcpy(static_command_line, command_line);
}

/*
 * We need to finalize in a non-__init function or else race conditions
 * between the root thread and the init thread may cause start_kernel to
 * be reaped by free_initmem before the root thread has proceeded to
 * cpu_idle.
 *
 * gcc-3.4 accidentally inlines this function, so use noinline.
 */

static __initdata DECLARE_COMPLETION(kthreadd_done);

static noinline void __ref rest_init(void)
{
	struct task_struct *tsk;
	int pid;

	rcu_scheduler_starting();
	/*
	 * We need to spawn init first so that it obtains pid 1, however
	 * the init task will end up wanting to create kthreads, which, if
	 * we schedule it before we create kthreadd, will OOPS.
	 */
	pid = kernel_thread(kernel_init, NULL, CLONE_FS);
	/*
	 * Pin init on the boot CPU. Task migration is not properly working
	 * until sched_init_smp() has been run. It will set the allowed
	 * CPUs for init to the non isolated CPUs.
	 */
	rcu_read_lock();
	tsk = find_task_by_pid_ns(pid, &init_pid_ns);
	set_cpus_allowed_ptr(tsk, cpumask_of(smp_processor_id()));
	rcu_read_unlock();

	numa_default_policy();
	pid = kernel_thread(kthreadd, NULL, CLONE_FS | CLONE_FILES);
	rcu_read_lock();
	kthreadd_task = find_task_by_pid_ns(pid, &init_pid_ns);
	rcu_read_unlock();

	/*
	 * Enable might_sleep() and smp_processor_id() checks.
	 * They cannot be enabled earlier because with CONFIG_PRREMPT=y
	 * kernel_thread() would trigger might_sleep() splats. With
	 * CONFIG_PREEMPT_VOLUNTARY=y the init task might have scheduled
	 * already, but it's stuck on the kthreadd_done completion.
	 */
	system_state = SYSTEM_SCHEDULING;

	complete(&kthreadd_done);

	/*
	 * The boot idle thread must execute schedule()
	 * at least once to get things moving:
	 */
	schedule_preempt_disabled();
	/* Call into cpu_idle with preempt disabled */
	cpu_startup_entry(CPUHP_ONLINE);
}

/* Check for early params. */
static int __init do_early_param(char *param, char *val,
				 const char *unused, void *arg)
{
	const struct obs_kernel_param *p;

	for (p = __setup_start; p < __setup_end; p++) {
		if ((p->early && parameq(param, p->str)) ||
		    (strcmp(param, "console") == 0 &&
		     strcmp(p->str, "earlycon") == 0)
		) {
			if (p->setup_func(val) != 0)
				pr_warn("Malformed early option '%s'\n", param);
		}
	}
	/* We accept everything at this stage. */
	return 0;
}

void __init parse_early_options(char *cmdline)
{
	parse_args("early options", cmdline, NULL, 0, 0, 0, NULL,
		   do_early_param);
}

/* Arch code calls this early on, or if not, just before other parsing. */
void __init parse_early_param(void)
{
	static int done __initdata;
	static char tmp_cmdline[COMMAND_LINE_SIZE] __initdata;

	if (done)
		return;

	/* All fall through to do_early_param. */
	strlcpy(tmp_cmdline, boot_command_line, COMMAND_LINE_SIZE);
	parse_early_options(tmp_cmdline);
	done = 1;
}

void __init __weak arch_post_acpi_subsys_init(void) { }

void __init __weak smp_setup_processor_id(void)
{
}

# if THREAD_SIZE >= PAGE_SIZE
void __init __weak thread_stack_cache_init(void)
{
}
#endif

void __init __weak mem_encrypt_init(void) { }

/*
 * Set up kernel memory allocators
 */
static void __init mm_init(void)
{
	/*
	 * page_ext requires contiguous pages,
	 * bigger than MAX_ORDER unless SPARSEMEM.
	 */
	page_ext_init_flatmem();
	mem_init();
	kmem_cache_init();
	pgtable_init();
	vmalloc_init();
	ioremap_huge_init();
	/* Should be run before the first non-init thread is created */
	init_espfix_bsp();
	/* Should be run after espfix64 is set up. */
	pti_init();
}

asmlinkage __visible void __init start_kernel(void)
{
	char *command_line;
	char *after_dashes;

	set_task_stack_end_magic(&init_task);
	smp_setup_processor_id();
	debug_objects_early_init();

	cgroup_init_early();

	local_irq_disable();
	early_boot_irqs_disabled = true;

	/*
	 * Interrupts are still disabled. Do necessary setups, then
	 * enable them.
	 */
	boot_cpu_init();
	page_address_init();
	pr_notice("%s", linux_banner);
	setup_arch(&command_line);
	/*
	 * Set up the the initial canary and entropy after arch
	 * and after adding latent and command line entropy.
	 */
	add_latent_entropy();
	add_device_randomness(command_line, strlen(command_line));
	boot_init_stack_canary();
	mm_init_cpumask(&init_mm);
	setup_command_line(command_line);
	setup_nr_cpu_ids();
	setup_per_cpu_areas();
	smp_prepare_boot_cpu();	/* arch-specific boot-cpu hooks */
	boot_cpu_hotplug_init();

	build_all_zonelists(NULL);
	page_alloc_init();

	pr_notice("Kernel command line: %s\n", boot_command_line);
	/* parameters may set static keys */
	jump_label_init();
	parse_early_param();
	after_dashes = parse_args("Booting kernel",
				  static_command_line, __start___param,
				  __stop___param - __start___param,
				  -1, -1, NULL, &unknown_bootoption);
	if (!IS_ERR_OR_NULL(after_dashes))
		parse_args("Setting init args", after_dashes, NULL, 0, -1, -1,
			   NULL, set_init_arg);

	/*
	 * These use large bootmem allocations and must precede
	 * kmem_cache_init()
	 */
	setup_log_buf(0);
	vfs_caches_init_early();
	sort_main_extable();
	trap_init();
	mm_init();

	ftrace_init();

	/* trace_printk can be enabled here */
	early_trace_init();

	/*
	 * Set up the scheduler prior starting any interrupts (such as the
	 * timer interrupt). Full topology setup happens at smp_init()
	 * time - but meanwhile we still have a functioning scheduler.
	 */
	sched_init();
	/*
	 * Disable preemption - early bootup scheduling is extremely
	 * fragile until we cpu_idle() for the first time.
	 */
	preempt_disable();
	if (WARN(!irqs_disabled(),
		 "Interrupts were enabled *very* early, fixing it\n"))
		local_irq_disable();
	radix_tree_init();

	/*
	 * Set up housekeeping before setting up workqueues to allow the unbound
	 * workqueue to take non-housekeeping into account.
	 */
	housekeeping_init();

	/*
	 * Allow workqueue creation and work item queueing/cancelling
	 * early.  Work item execution depends on kthreads and starts after
	 * workqueue_init().
	 */
	workqueue_init_early();

	rcu_init();

	/* Trace events are available after this */
	trace_init();

	context_tracking_init();
	/* init some links before init_ISA_irqs() */
	early_irq_init();
	init_IRQ();
	tick_init();
	rcu_init_nohz();
	init_timers();
	hrtimers_init();
	softirq_init();
	timekeeping_init();
	time_init();
	sched_clock_postinit();
	printk_safe_init();
	perf_event_init();
	profile_init();
	call_function_init();
	WARN(!irqs_disabled(), "Interrupts were enabled early\n");
	early_boot_irqs_disabled = false;
	local_irq_enable();

	kmem_cache_init_late();

	/*
	 * HACK ALERT! This is early. We're enabling the console before
	 * we've done PCI setups etc, and console_init() must be aware of
	 * this. But we do want output early, in case something goes wrong.
	 */
	console_init();
	if (panic_later)
		panic("Too many boot %s vars at `%s'", panic_later,
		      panic_param);

	lockdep_info();

	/*
	 * Need to run this when irqs are enabled, because it wants
	 * to self-test [hard/soft]-irqs on/off lock inversion bugs
	 * too:
	 */
	locking_selftest();

	/*
	 * This needs to be called before any devices perform DMA
	 * operations that might use the SWIOTLB bounce buffers. It will
	 * mark the bounce buffers as decrypted so that their usage will
	 * not cause "plain-text" data to be decrypted when accessed.
	 */
	mem_encrypt_init();

#ifdef CONFIG_BLK_DEV_INITRD
	if (initrd_start && !initrd_below_start_ok &&
	    page_to_pfn(virt_to_page((void *)initrd_start)) < min_low_pfn) {
		pr_crit("initrd overwritten (0x%08lx < 0x%08lx) - disabling it.\n",
		    page_to_pfn(virt_to_page((void *)initrd_start)),
		    min_low_pfn);
		initrd_start = 0;
	}
#endif
	kmemleak_init();
	debug_objects_mem_init();
	setup_per_cpu_pageset();
	numa_policy_init();
	acpi_early_init();
	if (late_time_init)
		late_time_init();
	calibrate_delay();
	pid_idr_init();
	anon_vma_init();
#ifdef CONFIG_X86
	if (efi_enabled(EFI_RUNTIME_SERVICES))
		efi_enter_virtual_mode();
#endif
	thread_stack_cache_init();
	cred_init();
	fork_init();
	proc_caches_init();
	buffer_init();
	key_init();
	security_init();
	dbg_late_init();
	vfs_caches_init();
	pagecache_init();
	signals_init();
	proc_root_init();
	nsfs_init();
	cpuset_init();
	cgroup_init();
	taskstats_init_early();
	delayacct_init();

	check_bugs();

	acpi_subsystem_init();
	arch_post_acpi_subsys_init();
	sfi_init_late();

	if (efi_enabled(EFI_RUNTIME_SERVICES)) {
		efi_free_boot_services();
	}

	/* Do the rest non-__init'ed, we're now alive */
	rest_init();

	prevent_tail_call_optimization();
}

/* Call all constructor functions linked into the kernel. */
static void __init do_ctors(void)
{
#ifdef CONFIG_CONSTRUCTORS
	ctor_fn_t *fn = (ctor_fn_t *) __ctors_start;

	for (; fn < (ctor_fn_t *) __ctors_end; fn++)
		(*fn)();
#endif
}

bool initcall_debug;
core_param(initcall_debug, initcall_debug, bool, 0644);

#ifdef CONFIG_KALLSYMS
struct blacklist_entry {
	struct list_head next;
	char *buf;
};

static __initdata_or_module LIST_HEAD(blacklisted_initcalls);

static int __init initcall_blacklist(char *str)
{
	char *str_entry;
	struct blacklist_entry *entry;

	/* str argument is a comma-separated list of functions */
	do {
		str_entry = strsep(&str, ",");
		if (str_entry) {
			pr_debug("blacklisting initcall %s\n", str_entry);
			entry = alloc_bootmem(sizeof(*entry));
			entry->buf = alloc_bootmem(strlen(str_entry) + 1);
			strcpy(entry->buf, str_entry);
			list_add(&entry->next, &blacklisted_initcalls);
		}
	} while (str_entry);

	return 0;
}

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
	struct blacklist_entry *entry;
	char fn_name[KSYM_SYMBOL_LEN];
	unsigned long addr;

	if (list_empty(&blacklisted_initcalls))
		return false;

	addr = (unsigned long) dereference_function_descriptor(fn);
	sprint_symbol_no_offset(fn_name, addr);

	/*
	 * fn will be "function_name [module_name]" where [module_name] is not
	 * displayed for built-in init functions.  Strip off the [module_name].
	 */
	strreplace(fn_name, ' ', '\0');

	list_for_each_entry(entry, &blacklisted_initcalls, next) {
		if (!strcmp(fn_name, entry->buf)) {
			pr_debug("initcall %s blacklisted\n", fn_name);
			return true;
		}
	}

	return false;
}
#else
static int __init initcall_blacklist(char *str)
{
	pr_warn("initcall_blacklist requires CONFIG_KALLSYMS\n");
	return 0;
}

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
	return false;
}
#endif
__setup("initcall_blacklist=", initcall_blacklist);

static int __init_or_module do_one_initcall_debug(initcall_t fn)
{
	unsigned long long calltime, delta, rettime;
	unsigned long long duration;
	int ret;

	printk(KERN_DEBUG "calling  %pF @ %i\n", fn, task_pid_nr(current));
	calltime = local_clock();
	ret = fn();
	rettime = local_clock();
	delta = rettime - calltime;
	duration = delta >> 10;
	printk(KERN_DEBUG "initcall %pF returned %d after %lld usecs\n",
		 fn, ret, duration);

	return ret;
}

int __init_or_module do_one_initcall(initcall_t fn)
{
	int count = preempt_count();
	int ret;
	char msgbuf[64];

	if (initcall_blacklisted(fn))
		return -EPERM;

	if (initcall_debug)
		ret = do_one_initcall_debug(fn);
	else
		ret = fn();

	msgbuf[0] = 0;

	if (preempt_count() != count) {
		sprintf(msgbuf, "preemption imbalance ");
		preempt_count_set(count);
	}
	if (irqs_disabled()) {
		strlcat(msgbuf, "disabled interrupts ", sizeof(msgbuf));
		local_irq_enable();
	}
	WARN(msgbuf[0], "initcall %pF returned with %s\n", fn, msgbuf);

	add_latent_entropy();
	return ret;
}


extern initcall_t __initcall_start[];
extern initcall_t __initcall0_start[];
extern initcall_t __initcall1_start[];
extern initcall_t __initcall2_start[];
extern initcall_t __initcall3_start[];
extern initcall_t __initcall4_start[];
extern initcall_t __initcall5_start[];
extern initcall_t __initcall6_start[];
extern initcall_t __initcall7_start[];
extern initcall_t __initcall_end[];

static initcall_t *initcall_levels[] __initdata = {
	__initcall0_start,
	__initcall1_start,
	__initcall2_start,
	__initcall3_start,
	__initcall4_start,
	__initcall5_start,
	__initcall6_start,
	__initcall7_start,
	__initcall_end,
};

/* Keep these in sync with initcalls in include/linux/init.h */
static char *initcall_level_names[] __initdata = {
	"early",
	"core",
	"postcore",
	"arch",
	"subsys",
	"fs",
	"device",
	"late",
};

static void __init do_initcall_level(int level)
{
	initcall_t *fn;

	strcpy(initcall_command_line, saved_command_line);
	parse_args(initcall_level_names[level],
		   initcall_command_line, __start___param,
		   __stop___param - __start___param,
		   level, level,
		   NULL, &repair_env_string);

	for (fn = initcall_levels[level]; fn < initcall_levels[level+1]; fn++)
		do_one_initcall(*fn);
}

static void __init do_initcalls(void)
{
	int level;

	for (level = 0; level < ARRAY_SIZE(initcall_levels) - 1; level++)
		do_initcall_level(level);
}

/*
 * Ok, the machine is now initialized. None of the devices
 * have been touched yet, but the CPU subsystem is up and
 * running, and memory and process management works.
 *
 * Now we can finally start doing some real work..
 */
static void __init do_basic_setup(void)
{
	cpuset_init_smp();
	shmem_init();
	driver_init();
	init_irq_proc();
	do_ctors();
	usermodehelper_enable();
	do_initcalls();
}

static void __init do_pre_smp_initcalls(void)
{
	initcall_t *fn;

	for (fn = __initcall_start; fn < __initcall0_start; fn++)
		do_one_initcall(*fn);
}

/*
 * This function requests modules which should be loaded by default and is
 * called twice right after initrd is mounted and right before init is
 * exec'd.  If such modules are on either initrd or rootfs, they will be
 * loaded before control is passed to userland.
 */
void __init load_default_modules(void)
{
	load_default_elevator_module();
}

static int run_init_process(const char *init_filename)
{
	argv_init[0] = init_filename;
	return do_execve(getname_kernel(init_filename),
		(const char __user *const __user *)argv_init,
		(const char __user *const __user *)envp_init);
}

static int try_to_run_init_process(const char *init_filename)
{
	int ret;

	ret = run_init_process(init_filename);

	if (ret && ret != -ENOENT) {
		pr_err("Starting init: %s exists but couldn't execute it (error %d)\n",
		       init_filename, ret);
	}

	return ret;
}

static noinline void __init kernel_init_freeable(void);

#if defined(CONFIG_STRICT_KERNEL_RWX) || defined(CONFIG_STRICT_MODULE_RWX)
bool rodata_enabled __ro_after_init = true;
static int __init set_debug_rodata(char *str)
{
	return strtobool(str, &rodata_enabled);
}
__setup("rodata=", set_debug_rodata);
#endif

#ifdef CONFIG_STRICT_KERNEL_RWX
static void mark_readonly(void)
{
	if (rodata_enabled) {
		/*
		 * load_module() results in W+X mappings, which are cleaned up
		 * with call_rcu_sched().  Let's make sure that queued work is
		 * flushed so that we don't hit false positives looking for
		 * insecure pages which are W+X.
		 */
		rcu_barrier_sched();
		mark_rodata_ro();
		rodata_test();
	} else
		pr_info("Kernel memory protection disabled.\n");
}
#else
static inline void mark_readonly(void)
{
	pr_warn("This architecture does not have kernel memory protection.\n");
}
#endif











#include <uapi/asm-generic/ioctls.h>
#include <uapi/asm-generic/termbits.h>
#include <uapi/linux/kd.h>
#include <uapi/asm-generic/fcntl.h>

#define TTYDEF_IFLAG    (BRKINT | ISTRIP | ICRNL | IMAXBEL | IXON | IXANY)
#define TTYDEF_OFLAG    (OPOST | ONLCR | XTABS)
#define TTYDEF_LFLAG    (ECHO | ICANON | ISIG | IEXTEN | ECHOE|ECHOKE|ECHOCTL)
#define TTYDEF_CFLAG    (CREAD | CS7 | PARENB | HUPCL)
#define TTYDEF_SPEED    (B9600)

#define CTRL(x) (x&037)
#define CEOF        CTRL('d')

#define CEOL       _POSIX_VDISABLE

#define CERASE      0177
#define CINTR       CTRL('c')

#define CSTATUS    _POSIX_VDISABLE

#define CKILL       CTRL('u')
#define CMIN        1
#define CQUIT       034     /* FS, ^\ */
#define CSUSP       CTRL('z')
#define CTIME       0
#define CDSUSP      CTRL('y')
#define CSTART      CTRL('q')
#define CSTOP       CTRL('s')
#define CLNEXT      CTRL('v')
#define CDISCARD    CTRL('o')
#define CWERASE     CTRL('w')
#define CREPRINT    CTRL('r')
#define CEOT        CEOF
/* compat */
#define CBRK        CEOL
#define CRPRNT      CREPRINT
#define CFLUSH      CDISCARD
#define   _POSIX_VDISABLE '\0'

#define CTL(x)      ((x) ^ 0100)    /* Assumes ASCII dialect */
#define CR      CTL('M')    /* carriage return */
#define NL      CTL('J')    /* line feed */
#define BS      CTL('H')    /* back space */
#define DEL     CTL('?')    /* delete */


#define PENDING 0

struct hyper_gen_work;
typedef void (*tty_work_fn_t)(struct hyper_gen_work *work);
typedef int (*tx_fn_t)(void *opaque, char *buf, int len);

struct hyper_gen_work {
	struct llist_node node;
	tty_work_fn_t fn;
	void *opaque;
	unsigned long flags;
};

struct hyper_gen_poll {
	poll_table table;
	wait_queue_head_t *wqh;
	wait_queue_entry_t wait;
	struct hyper_gen_work work;
	unsigned long mask;
};

enum tty_ctx_type {
	HYPER_GEN,
	VM_GEN,
};

struct hyper_gen_tty_context {
	char rx_buf[128];
	int put_index;

	char vser_rx_buf[128];
	int vser_rx_put_index;
	int vser_rx_get_index;

	char vser_tx_buf[1024];
	int vser_tx_put_index;
	int vser_tx_get_index;

	int fd;
	enum tty_ctx_type context_type;
	struct termios tp;
	struct kvm *kvm;
	wait_queue_entry_t wait;
	struct hyper_gen_work vser_rx_work;
	struct hyper_gen_work vser_tx_work;
};

struct kvm *find_kvm_by_id(uint64_t kvm_id);
void attach_to_vser(struct kvm *kvm, tx_fn_t tx_fn, void *opaque, wait_queue_entry_t *wait);
void deattach_to_vser(struct kvm *kvm, wait_queue_entry_t *wait);
int vser_can_receive(struct kvm *kvm);
void vser_receive(struct kvm *kvm, const uint8_t *buf, int size);
static void handle_vser_rx(struct hyper_gen_work *work);

static struct task_struct *hyper_gen_console_worker;
static struct llist_head hyper_gen_work_list;
static const char *prompt = "hyper-gen:#";

static int hyper_gen_vser_tx_fn(void *opaque, char *buf, int len)
{
	int i;
	struct hyper_gen_tty_context *ctx = opaque;

	for (i = 0; i < len; i++) {
		ctx->vser_tx_buf[ctx->vser_tx_put_index] = buf[i];

		ctx->vser_tx_put_index =
			(ctx->vser_tx_put_index + 1) % sizeof(ctx->vser_tx_buf);

		if (ctx->vser_tx_put_index == ctx->vser_tx_get_index)
			ctx->vser_tx_get_index =
				(ctx->vser_tx_get_index + 1) % sizeof(ctx->vser_tx_buf);
	}

	if (!test_and_set_bit(PENDING, &ctx->vser_tx_work.flags)) {
		llist_add(&ctx->vser_tx_work.node, &hyper_gen_work_list);
		wake_up_process(hyper_gen_console_worker);
	}

	return len;
}

static int start_vm_console(struct hyper_gen_tty_context *ctx, unsigned long vm_id)
{
	int ret;
	//1. find vm with vm_id
	struct kvm *kvm = find_kvm_by_id(vm_id);
	if (!kvm) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}

	//2. hook fd to vserial tx
	attach_to_vser(kvm, hyper_gen_vser_tx_fn, ctx, &ctx->wait);
	ctx->kvm = kvm;

	ctx->context_type = VM_GEN;

#if 0
	//turn off tty echo
    ctx->tp.c_lflag &= ~ECHO;
	ret = sys_ioctl(ctx->fd, TCSETSW, (const __user unsigned long)&ctx->tp);
	if (0 > ret) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}
#endif

	return 0;
}

static bool parse_cmd(struct hyper_gen_tty_context *ctx)
{
	char tmp[32];
	char *param;
	char *args = ctx->rx_buf;

	args = skip_spaces(args);
	param = strsep(&args, " ");

	if (!strcmp(param, "vm_console")) {
		int ret;
		char *val;
		unsigned long vm_id;

		val = strsep(&args, " ");
		if (!val)
			goto fail_val;

		ret = kstrtoul(val, 0, &vm_id);
		if (ret)
			goto fail_val;

		ret = start_vm_console(ctx, vm_id);
		if (ret)
			goto fail_val;

	} else {
		sprintf(tmp, "%s\n", "Invalid Cmd");
		goto fail;
	}

	return false;

fail_val:
	sprintf(tmp, "%s\n", "Invalid Val");
fail:
	sys_write(ctx->fd, (const char __user *)tmp, strlen(tmp));
	return true;
}

static void stop_vm_console(struct hyper_gen_tty_context *ctx)
{
	//1. dishook fd to vserial tx
	deattach_to_vser(ctx->kvm, &ctx->wait);

	ctx->kvm = NULL;
	ctx->context_type = HYPER_GEN;

	ctx->vser_rx_get_index = ctx->vser_rx_put_index = 0;
	ctx->vser_tx_get_index = ctx->vser_tx_put_index = 0;

#if 0
	//2. turn on tty echo 
    ctx->tp.c_lflag |= ECHO;
	ret = sys_ioctl(ctx->fd, TCSETSW, (const __user unsigned long)&ctx->tp);
	if (0 > ret) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return;
	}
#endif
}

static bool dump_to_vm(struct hyper_gen_tty_context *ctx)
{
	//1. find current vserial
	//2. dump ctx->rx_buf to vserial 
	int i;

	for (i = 0; i < ctx->put_index; i++) {
		ctx->vser_rx_buf[ctx->vser_rx_put_index] = ctx->rx_buf[i];

		ctx->vser_rx_put_index =
			(ctx->vser_rx_put_index + 1) % sizeof(ctx->vser_rx_buf);

		if (ctx->vser_rx_put_index == ctx->vser_rx_get_index)
			ctx->vser_rx_get_index =
				(ctx->vser_rx_get_index + 1) % sizeof(ctx->vser_rx_buf);
	}

	handle_vser_rx(&ctx->vser_rx_work);

	return false;
}

static char *tty_put_char(struct hyper_gen_tty_context *ctx, char *bp, char c)
{
	if ((size_t)(bp - ctx->rx_buf) >= sizeof(ctx->rx_buf) - 1) {
		bp = ctx->rx_buf;
		ctx->put_index = 0;
	}

	*bp++ = c;         /* and store it */
	ctx->put_index++;

	return bp;
}

static void handle_tty_rx(struct hyper_gen_work *work)
{
	struct hyper_gen_tty_context *ctx = work->opaque;
	char *bp = ctx->rx_buf + ctx->put_index;
	char key;
	int ret;
	char eol;
	bool need_prompt = true;

	eol = '\0';
	while (eol == '\0') {
		ret = sys_read(ctx->fd, (char __user *)&key, 1);
		if (ret <= 0)
			return;

    	switch (key) {
		case CR:
		case NL:
			if (ctx->context_type == HYPER_GEN) {
				*bp = 0;            /* terminate logname */
			} else if (ctx->context_type == VM_GEN) {
				bp = tty_put_char(ctx, bp, key);
			}
			eol = key;       /* set end-of-line char */
			break;
		case BS:
		case DEL:
			if (bp > ctx->rx_buf) {
				bp--;
				ctx->put_index--;
			}
			break;
		case CTL('D'):
			//1. if in vm context, switch to hyper-gen
			if (ctx->context_type == VM_GEN) {
				stop_vm_console(ctx);
				sys_write(ctx->fd, (const char __user *)"\n", 1);
				sys_write(ctx->fd, (const char __user *)prompt, strlen(prompt));
			}
			break;
		default:
			bp = tty_put_char(ctx, bp, key);
			break;
		}
	}

	if (ctx->context_type == HYPER_GEN) {
		need_prompt = parse_cmd(ctx);
	} else if (ctx->context_type == VM_GEN) {
		need_prompt = dump_to_vm(ctx);
	}

	if (need_prompt)
		sys_write(ctx->fd, (const char __user *)prompt, strlen(prompt));

	ctx->put_index = 0;
}
 

static int vser_ready_rx(wait_queue_entry_t *wait, unsigned mode, int sync,
			     void *key)
{
	struct hyper_gen_tty_context *ctx = container_of(wait, struct hyper_gen_tty_context, wait);

	if (ctx->vser_rx_put_index == ctx->vser_rx_get_index)
 		return 0;

	if (!test_and_set_bit(PENDING, &ctx->vser_rx_work.flags)) {
		llist_add(&ctx->vser_rx_work.node, &hyper_gen_work_list);
		wake_up_process(hyper_gen_console_worker);
	}

	return 0;
}

static void handle_vser_rx(struct hyper_gen_work *work)
{
	int i;
	int ret;
	struct hyper_gen_tty_context *ctx = work->opaque;

	if (!ctx->kvm)
		return;

	if (ctx->vser_rx_get_index == ctx->vser_rx_put_index)
		return;

	while (1) {
		ret = vser_can_receive(ctx->kvm);
		if (!ret)
			break;

		for (i = 0; i < ret; i++) {
			vser_receive(ctx->kvm, 
				(const uint8_t *)&ctx->vser_rx_buf[ctx->vser_rx_get_index], 1);

			ctx->vser_rx_get_index =
				(ctx->vser_rx_get_index + 1) % sizeof(ctx->vser_rx_buf);

			if (ctx->vser_rx_get_index == ctx->vser_rx_put_index)
				goto out;
		}
	}

out:
	return;
}

static void handle_vser_tx(struct hyper_gen_work *work)
{
	struct hyper_gen_tty_context *ctx = work->opaque;

	if (ctx->vser_tx_get_index == ctx->vser_tx_put_index)
		return;

	while (1) {
		char c = ctx->vser_tx_buf[ctx->vser_tx_get_index];

		sys_write(ctx->fd, (const char __user *)&c, 1);

		ctx->vser_tx_get_index =
				(ctx->vser_tx_get_index + 1) % sizeof(ctx->vser_tx_buf);

		if (ctx->vser_tx_get_index == ctx->vser_tx_put_index)
			break;
	}

	return;
}

static int init_tty_ctx(struct hyper_gen_tty_context *ctx, int fd)
{
	int ret = 0;

	ctx->put_index = 0;

	ctx->vser_rx_put_index = 0;
	ctx->vser_rx_get_index = 0;

	ctx->vser_tx_put_index = 0;
	ctx->vser_tx_get_index = 0;

	ctx->fd = fd; 
	ctx->context_type = HYPER_GEN;
	ctx->kvm = NULL;

	INIT_LIST_HEAD(&ctx->wait.entry);
	init_waitqueue_func_entry(&ctx->wait, vser_ready_rx);

	ctx->vser_rx_work.flags = 0;
	ctx->vser_rx_work.fn = handle_vser_rx;
	ctx->vser_rx_work.opaque = (void*)ctx;

	ctx->vser_tx_work.flags = 0;
	ctx->vser_tx_work.fn = handle_vser_tx;
	ctx->vser_tx_work.opaque = (void*)ctx;

	ret = sys_ioctl(fd, TCGETS, (const __user unsigned long)&ctx->tp);
	if (0 > ret) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}

	return 0;
}

static int tty_poll_wakeup(wait_queue_entry_t *wait, unsigned mode, int sync,
			     void *key)
{
	struct hyper_gen_poll *poll = container_of(wait, struct hyper_gen_poll, wait);

 	if (!((unsigned long)key & poll->mask))
 		return 0;

	if (!test_and_set_bit(PENDING, &poll->work.flags)) {
		llist_add(&poll->work.node, &hyper_gen_work_list);
		wake_up_process(hyper_gen_console_worker);
	}

	return 0;
}

static void tty_poll_hook_func(struct file *file, wait_queue_head_t *wqh,
			    poll_table *pt)
{
	struct hyper_gen_poll *poll;

	poll = container_of(pt, struct hyper_gen_poll, table);
	if (poll->wqh != NULL)
		return;

	//only hook read_wait
	poll->wqh = wqh;

	add_wait_queue(wqh, &poll->wait);
}

static int init_tty_poll_work(int fd)
{
	struct hyper_gen_poll *poll;
	struct file *file;
	unsigned long mask;
	struct hyper_gen_tty_context *ctx;

	poll = kzalloc(sizeof(struct hyper_gen_poll), GFP_KERNEL);
	if (!poll) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}

	INIT_LIST_HEAD(&poll->wait.entry);
	init_waitqueue_func_entry(&poll->wait, tty_poll_wakeup);
	init_poll_funcptr(&poll->table, tty_poll_hook_func);
	poll->mask = POLLIN;
	poll->wqh = NULL;
	poll->work.flags = 0;
	poll->work.fn = handle_tty_rx;

	ctx = kzalloc(sizeof(struct hyper_gen_tty_context), GFP_KERNEL);
	if (!ctx) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}

	if (0 > init_tty_ctx(ctx, fd)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}

	poll->work.opaque = (void*)ctx;

    file = fget(fd);
    if (!file) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return -1;
    }

	mask = file->f_op->poll(file, &poll->table);
	if (mask)
		tty_poll_wakeup(&poll->wait, 0, 0, (void *)mask);

	if (mask & POLLERR) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return -1;
	}

	sys_write(fd, (const char __user *)prompt, strlen(prompt));

	return 0;
}

static void reset_virtual_console(struct termios *tp)
{
    /* Use defaults of <sys/ttydefaults.h> for base settings */
    tp->c_iflag |= TTYDEF_IFLAG;
    tp->c_oflag |= TTYDEF_OFLAG;
    tp->c_lflag |= TTYDEF_LFLAG;

    tp->c_lflag &= ~CBAUD;
    tp->c_cflag |= (B38400 | TTYDEF_CFLAG);

    tp->c_iflag |=  (BRKINT | ICRNL | IMAXBEL);
    tp->c_iflag &= ~(IGNBRK | INLCR | IGNCR | IXOFF | IUCLC | IXANY | ISTRIP);
    tp->c_oflag |=  (OPOST | ONLCR | NL0 | CR0 | TAB0 | BS0 | VT0 | FF0);
    tp->c_oflag &= ~(OLCUC | OCRNL | ONOCR | ONLRET | OFILL | \
                NLDLY|CRDLY|TABDLY|BSDLY|VTDLY|FFDLY);
    tp->c_lflag |=  (ISIG | ICANON | IEXTEN | ECHO|ECHOE|ECHOK|ECHOKE|ECHOCTL);
    tp->c_lflag &= ~(ECHONL|ECHOPRT | NOFLSH | TOSTOP);

    tp->c_cflag |=  (CREAD | CS8 | HUPCL);
    tp->c_cflag &= ~(PARODD | PARENB);

    tp->c_oflag &= ~OFDEL;
    tp->c_lflag &= ~XCASE;

    tp->c_iflag |= IUTF8;       /* Set UTF-8 input flag */

    /* VTIME and VMIN can overlap with VEOF and VEOL since they are
     * only used for non-canonical mode. We just set the at the
     * beginning, so nothing bad should happen.
     */
    tp->c_cc[VTIME]    = 0;
    tp->c_cc[VMIN]     = 1;
    tp->c_cc[VINTR]    = CINTR;
    tp->c_cc[VQUIT]    = CQUIT;
    tp->c_cc[VERASE]   = CERASE; /* ASCII DEL (0177) */
    tp->c_cc[VKILL]    = CKILL;
    tp->c_cc[VEOF]     = CEOF;
    tp->c_cc[VSWTC]    = _POSIX_VDISABLE;
    tp->c_cc[VSTART]   = CSTART;
    tp->c_cc[VSTOP]    = CSTOP;
    tp->c_cc[VSUSP]    = CSUSP;
    tp->c_cc[VEOL]     = _POSIX_VDISABLE;
    tp->c_cc[VREPRINT] = CREPRINT;
    tp->c_cc[VDISCARD] = CDISCARD;
    tp->c_cc[VWERASE]  = CWERASE;
    tp->c_cc[VLNEXT]   = CLNEXT;
    tp->c_cc[VEOL2]    = _POSIX_VDISABLE;
}

static int init_hyper_gen_tty(void)
{
	int kbmode; 
	int ret;
	struct termios lock;
	int fd;
	struct termios tp;

	sys_close(0);
	sys_close(1);
	sys_close(2);

	if ((fd = sys_open((const char __user *) "/dev/tty3", O_RDWR, 0)) < 0) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}

	ret = sys_ioctl(fd, TCGETS, (const __user unsigned long)&tp);
	if (0 > ret) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}

	ret = sys_ioctl(fd, KDGKBMODE, (const __user unsigned long)&kbmode);
	if (0 > ret) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}

	while (1) {
		memset(&lock, 0, sizeof(struct termios));
		if (sys_ioctl(fd, TIOCGLCKTRMIOS, (const __user unsigned long)&lock) < 0)
            break;

		if (!lock.c_iflag && !lock.c_oflag && !lock.c_cflag && !lock.c_lflag)
            break;

		msleep(1000);
	}

    memset(&lock, 0, sizeof(struct termios));
    ret = sys_ioctl(fd, TIOCSLCKTRMIOS, (const __user unsigned long)&lock);
	if (0 > ret) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}

	reset_virtual_console(&tp);
	ret = sys_ioctl(fd, TCSETSW, (const __user unsigned long)&tp);
	if (0 > ret) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}

#if 0
    sys_fcntl(fd, F_SETFL,
          sys_fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
#else
    sys_fcntl(fd, F_SETFL,
          sys_fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
#endif

	return fd;
}

static int hyper_gen_console(void *data)
{
	int fd;

	//init work list
	init_llist_head(&hyper_gen_work_list);

	//suppress console log at first
	console_loglevel = default_message_loglevel;

	//init tty special for hyper_gen
	fd = init_hyper_gen_tty();
	if (fd < 0) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return 0;
	}

	//init poll work for tty
	if (0 > init_tty_poll_work(fd))
		return 0;

	while (1) {
		struct llist_node *node;
		struct hyper_gen_work *work, *work_next;

		set_current_state(TASK_INTERRUPTIBLE);

		if (kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			break;
		}

		node = llist_del_all(&hyper_gen_work_list);
		if (!node)
			schedule();

		node = llist_reverse_order(node);

		smp_wmb();
		llist_for_each_entry_safe(work, work_next, node, node) {
			clear_bit(PENDING, &work->flags);
			__set_current_state(TASK_RUNNING);
			work->fn(work);
			if (need_resched())
				schedule();
		}

	}

	return 0;
}

#include <linux/init_task.h>

pid_t my_create_thread(int (*fn)(void *), void *arg, unsigned long flags);
void check_hot_buddy(void);

int my_task_test = 0;
static int vcpu_exit = 0;

void dump_current_cfs_rq_tg(void);

static int hyper_gen_vcpu_func(void *unused)
{
	printk(">>>>%s:%d hyper_gen_vcpu\n", __func__, __LINE__);
	dump_current_cfs_rq_tg();

	while(1) {
		msleep(3*1000);

		if (vcpu_exit)
			break;
	}

	do_exit(0);
}

static int hyper_gen_vm_func(void *unused)
{
	int cnt = 0;
	int pid;
	struct task_struct *p;

	pid = kernel_thread(hyper_gen_vcpu_func, NULL, CLONE_FS|CLONE_FILES);

	rcu_read_lock();
	p = find_task_by_pid_ns(pid, &init_pid_ns);
	rcu_read_unlock();

	printk(">>>>%s:%d hyper_gen_vm\n", __func__, __LINE__);
	dump_current_cfs_rq_tg();

	while(1) {
		msleep(3*1000);

		if (cnt++ == 10)
			break;
	}

	vcpu_exit = 1;

//	kthread_stop(p);

	do_exit(0);
}

static void hyper_gen_init(void)
{
	hyper_gen_console_worker = kthread_create(hyper_gen_console, NULL, "hyper-gen-console");
	if (IS_ERR(hyper_gen_console_worker)) {
		printk(">>>>%s:%d\n", __func__, __LINE__);
	}
	wake_up_process(hyper_gen_console_worker);	/* avoid contributing to loadavg */


	check_hot_buddy();

	int pid;
	struct task_struct *p;

//	my_task_test = 1;
	pid = kernel_thread(hyper_gen_vm_func, NULL, CLONE_FS | CLONE_FILES);
//	my_task_test = 0;

	rcu_read_lock();
	p = find_task_by_pid_ns(pid, &init_pid_ns);
	rcu_read_unlock();

	printk(">>>>%s:%d p=%lx init_tg=%lx tg=%lx c_tg=%lx my_q=%lx curr_my_q=%lx\n", __func__, __LINE__, p,
		&root_task_group, p->sched_task_group, current->sched_task_group, p->se.my_q, current->se.my_q );
}

static int __ref kernel_init(void *unused)
{
	int ret;

	kernel_init_freeable();
	/* need to finish all async __init code before freeing the memory */
	async_synchronize_full();
	ftrace_free_init_mem();
	free_initmem();
	mark_readonly();

	/*
	 * Kernel mappings are now finalized - update the userspace page-table
	 * to finalize PTI.
	 */
	pti_finalize();

	system_state = SYSTEM_RUNNING;
	numa_default_policy();

	rcu_end_inkernel_boot();

	hyper_gen_init();

#if 0
	while (true) {
		asm volatile("hlt");
	}
#endif

	if (ramdisk_execute_command) {
		ret = run_init_process(ramdisk_execute_command);
		if (!ret)
			return 0;
		pr_err("Failed to execute %s (error %d)\n",
		       ramdisk_execute_command, ret);
	}

	/*
	 * We try each of these until one succeeds.
	 *
	 * The Bourne shell can be used instead of init if we are
	 * trying to recover a really broken machine.
	 */
	if (execute_command) {
		ret = run_init_process(execute_command);
		if (!ret)
			return 0;
		panic("Requested init %s failed (error %d).",
		      execute_command, ret);
	}
	if (!try_to_run_init_process("/sbin/init") ||
	    !try_to_run_init_process("/etc/init") ||
	    !try_to_run_init_process("/bin/init") ||
	    !try_to_run_init_process("/bin/sh"))
		return 0;

	panic("No working init found.  Try passing init= option to kernel. "
	      "See Linux Documentation/admin-guide/init.rst for guidance.");
}

static noinline void __init kernel_init_freeable(void)
{
	/*
	 * Wait until kthreadd is all set-up.
	 */
	wait_for_completion(&kthreadd_done);

	/* Now the scheduler is fully set up and can do blocking allocations */
	gfp_allowed_mask = __GFP_BITS_MASK;

	/*
	 * init can allocate pages on any node
	 */
	set_mems_allowed(node_states[N_MEMORY]);

	cad_pid = task_pid(current);

	smp_prepare_cpus(setup_max_cpus);

	workqueue_init();

	init_mm_internals();

	do_pre_smp_initcalls();
	lockup_detector_init();

	smp_init();
	sched_init_smp();

	page_alloc_init_late();
	/* Initialize page ext after all struct pages are initialized. */
	page_ext_init();

	do_basic_setup();

	/* Open the /dev/console on the rootfs, this should never fail */
	if (sys_open((const char __user *) "/dev/console", O_RDWR, 0) < 0)
		pr_err("Warning: unable to open an initial console.\n");

	(void) sys_dup(0);
	(void) sys_dup(0);
	/*
	 * check if there is an early userspace init.  If yes, let it do all
	 * the work
	 */

	if (!ramdisk_execute_command)
		ramdisk_execute_command = "/init";

	if (sys_access((const char __user *) ramdisk_execute_command, 0) != 0) {
		ramdisk_execute_command = NULL;
		prepare_namespace();
	}

	/*
	 * Ok, we have completed the initial bootup, and
	 * we're essentially up and running. Get rid of the
	 * initmem segments and start the user-mode stuff..
	 *
	 * rootfs is available now, try loading the public keys
	 * and default modules
	 */

	integrity_load_keys();
	load_default_modules();
}
