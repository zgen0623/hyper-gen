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
#include <uapi/asm/stat.h>

#define NUMBER_OF_MAJORS 4096
#define PARTITION_SCSI_DEVICE (1 << 0)

struct dev_type_def {
    int max_partitions; /* 0 means LVM won't use this major number. */
    int flags;
};           
        
struct dev_types {
    int md_major;
    int blkext_major;
    int drbd_major;
    int device_mapper_major;
    int emcpower_major;
    int power2_major;
    int dasd_major;
    struct dev_type_def dev_type_array[NUMBER_OF_MAJORS];
};

typedef struct {
    const char name[15];
    const int8_t max_partitions;
    const char *desc;
} dev_known_type_t;

static const dev_known_type_t _dev_known_types[] = {
    {"sd", 16, "SCSI disk"},
    {"ide", 64, "IDE disk"},
    {"md", 1, "Multiple Disk (MD/SoftRAID)"},
    {"loop", 1, "Loop device"},
    {"ramdisk", 1, "RAM disk"},
    {"device-mapper", 1, "Mapped device"},
    {"mdp", 1, "Partitionable MD"},
    {"dasd", 4, "DASD disk (IBM S/390, zSeries)"},
    {"dac960", 8, "DAC960"},
    {"nbd", 16, "Network Block Device"},
    {"ida", 16, "Compaq SMART2"},
    {"cciss", 16, "Compaq CCISS array"},
    {"ubd", 16, "User-mode virtual block device"},
    {"ataraid", 16, "ATA Raid"},
    {"drbd", 16, "Distributed Replicated Block Device (DRBD)"},
    {"emcpower", 16, "EMC Powerpath"},
    {"power2", 16, "EMC Powerpath"},
    {"i2o_block", 16, "i2o Block Disk"},
    {"iseries/vd", 8, "iSeries disks"},
    {"gnbd", 1, "Network block device"},
    {"aoe", 16, "ATA over Ethernet"},
    {"xvd", 16, "Xen virtual block device"},
    {"vdisk", 8, "SUN's LDOM virtual block device"},
    {"ps3disk", 16, "PlayStation 3 internal disk"},
    {"virtblk", 8, "VirtIO disk"},
    {"mmc", 16, "MMC block device"},
    {"blkext", 1, "Extended device partitions"},
    {"fio", 16, "Fusion IO"},
    {"mtip32xx", 16, "Micron PCIe SSD"},
    {"vtms", 16, "Violin Memory"},
    {"skd", 16, "STEC"},
    {"scm", 8, "Storage Class Memory (IBM S/390)"},
    {"bcache", 1, "bcache block device cache"},
    {"nvme", 64, "NVM Express"},
    {"zvol", 16, "ZFS Zvols"},
    {"", 0, ""}
};



static void parse_one_dt(char *line, struct dev_types *dts)
{
	int i = 0, j;
    unsigned long line_maj = 0;
    static int blocksection = 0;
	int ret;
	int dev_len = 0;

	line = skip_spaces(line);

    /* Find the start of the device major name */
    while (line[i] != ' ' && line[i] != '\0')
        i++;

    while (line[i] == ' ') {
		line[i] = '\0';
        i++;
	}

    ret = kstrtoul(line, 0, &line_maj);
//	printk(">>>%s:%d ret=%d line_maj=%lu line=%s\n", __func__, __LINE__,ret, line_maj, line);

    if (ret != 0 || line_maj >= NUMBER_OF_MAJORS)
        line_maj &= (NUMBER_OF_MAJORS - 1);

    if (!line_maj) {
        blocksection = (line[0] == 'B') ? 1 : 0;
        return;
    }

    /* We only want block devices ... */
    if (!blocksection)
        return;


//	printk(">>>%s:%d %s\n", __func__, __LINE__, line);

    /* Look for md device */
    if (!strncmp("md", line + i, 2) && !(*(line + i + 2)))
        dts->md_major = line_maj;

    /* Look for blkext device */
    if (!strncmp("blkext", line + i, 6) && !(*(line + i + 6)))
        dts->blkext_major = line_maj;

    /* Look for drbd device */
    if (!strncmp("drbd", line + i, 4) && !(*(line + i + 4)))
        dts->drbd_major = line_maj;

    /* Look for DASD */
    if (!strncmp("dasd", line + i, 4) && !(*(line + i + 4)))
        dts->dasd_major = line_maj;

    /* Look for EMC powerpath */
    if (!strncmp("emcpower", line + i, 8) && !(*(line + i + 8)))
        dts->emcpower_major = line_maj;

    if (!strncmp("power2", line + i, 6) && !(*(line + i + 6)))
        dts->power2_major = line_maj;

    /* Look for device-mapper device */
    /* FIXME Cope with multiple majors */
    if (!strncmp("device-mapper", line + i, 13) && !(*(line + i + 13)))
        dts->device_mapper_major = line_maj;

    /* Major is SCSI device */
    if (!strncmp("sd", line + i, 2) && !(*(line + i + 2)))
        dts->dev_type_array[line_maj].flags |= PARTITION_SCSI_DEVICE;

    /* Go through the valid device names and if there is a
       match store max number of partitions */
    for (j = 0; _dev_known_types[j].name[0]; j++) {
        dev_len = strlen(_dev_known_types[j].name);
        if (dev_len <= strlen(line + i) &&
            !strncmp(_dev_known_types[j].name, line + i, dev_len) &&
            (line_maj < NUMBER_OF_MAJORS)) {
            	dts->dev_type_array[line_maj].max_partitions =
                	_dev_known_types[j].max_partitions;
            break;
        }
    }
}

static struct dev_types *create_dev_types(void)
{
	struct dev_types *dts = NULL;
	char *buf;
	int fd = -1;
	int ret;
	char *lines;
	char *line;

	buf = kmalloc(1024, GFP_KERNEL);
	if (!buf) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		goto fail_2;
	}

	dts = kzalloc(sizeof(struct dev_types), GFP_KERNEL);
	if (!dts) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		goto fail_2;
	}

	if ((fd = sys_open((const char __user *)"/proc/devices", O_RDONLY, 0)) < 0) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		goto fail_1;
	}

	while (1) {
		ret = sys_read(fd, (char __user *)buf, 1024);
		if (ret <= 0)
			break;

		lines = buf;

		while (1) {
			line = strsep(&lines, "\n");
			if (!lines)
				break;

			parse_one_dt(line, dts);
		}
	}

	sys_close(fd);
	kfree(buf);

	return dts;

fail_1:
	kfree(dts);
fail_2:
	kfree(buf);
	return NULL;
}

static void parse_init(void)
{
	int ret;

	ret = sys_mount("devtmpfs", "/dev", "devtmpfs", MS_SILENT, NULL);
	if (ret)
		printk(">>>%s:%d\n", __func__, __LINE__);

	ret = sys_mkdir("/sys", 0777);
	if (ret)
		printk(">>>%s:%d\n", __func__, __LINE__);

	ret = sys_mount("sysfs", "/sys", "sysfs", MS_MGC_VAL, NULL);
	if (ret)
		printk(">>>%s:%d\n", __func__, __LINE__);

	ret = sys_mkdir("/proc", 0777);
	if (ret)
		printk(">>>%s:%d\n", __func__, __LINE__);

	ret = sys_mount("proc", "/proc", "proc", MS_MGC_VAL, NULL);
	if (ret)
		printk(">>>%s:%d\n", __func__, __LINE__);
}

#define ID_LEN 32

typedef enum {
    DEV_EXT_NONE,
    DEV_EXT_UDEV,
    DEV_EXT_NUM
} dev_ext_t;

struct dev_ext {
    int enabled;
    dev_ext_t src;
    void *handle;
};

struct hyper_rootdev_device {
//    struct dm_list aliases; /* struct dm_str_list */
	struct list_head list;
    dev_t dev;

    /* private */
    int fd; 
    int open_count;
    int error_count;
    int max_error_count;
    int phys_block_size;
    int block_size;
    int read_ahead;
    uint32_t flags;
    uint64_t end;
 //   struct dm_list open_list;
    struct dev_ext ext;

    char pvid[ID_LEN + 1]; 
    //char _padding[7];
	char *path;
};

struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[1];
};

static void _collapse_slashes(char *str)
{
    char *ptr;
    int was_slash = 0;

    for (ptr = str; *ptr; ptr++) {
        if (*ptr == '/') {
            if (was_slash)
                continue;

            was_slash = 1;
        } else
            was_slash = 0;
        *str++ = *ptr;
    }

    *str = *ptr;
}

static void prepare_dev_list(struct list_head *dev_head)
{
	int fd;
	char *buf;
	struct linux_dirent *dirent;
	int ret;

	if ((fd = sys_open((const char __user *)"/dev",
			O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY, 0)) < 0) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return;
	}

	buf = kmalloc(1024, GFP_KERNEL);
	if (!buf) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		goto fail_1;
	}

	while (1) {
		dirent = (struct linux_dirent *)buf;
		ret = sys_getdents(fd, (struct linux_dirent __user *)dirent, 1024);
		if (ret <= 0)
			break;

		while (1) {
			if ((char *)dirent >= buf + ret)
				break;

			if (dirent->d_name[0] != '.') {
				struct __old_kernel_stat tinfo;
    			char *path;

				path = kmalloc(4 + strlen(dirent->d_name) + 2, GFP_KERNEL);
				sprintf(path, "/dev/%s", dirent->d_name);

				_collapse_slashes(path);

				if (sys_stat(path, (struct __old_kernel_stat __user *)&tinfo) < 0) {
					printk(">>>%s:%d\n", __func__, __LINE__);
					kfree(path);
					goto out;
				}

				if (!S_ISDIR(tinfo.st_mode) && S_ISBLK(tinfo.st_mode)) {
					struct hyper_rootdev_device *dev = NULL;
					int found = 0;

					list_for_each_entry(dev, dev_head, list) {
						if (dev->dev == tinfo.st_rdev)
							found = 1;
					}

					if (!found) {
						dev = kzalloc(sizeof(struct hyper_rootdev_device), GFP_KERNEL);
						dev->dev = tinfo.st_rdev;
						dev->path = path;

						INIT_LIST_HEAD(&dev->list);
						list_add(&dev->list, dev_head);

						printk(">>>%s:%d path=%s\n", __func__, __LINE__, path);
					}
				}
            }
out:
			dirent = (void *)dirent + dirent->d_reclen;
		}
	}

fail_1:
	kfree(buf);
	sys_close(fd);
	return;
}

void hyper_gen_parse_root_dev(char *orignal_root_name)
{
	struct dev_types *dts;
	struct list_head head;
	struct hyper_rootdev_device *dev, *tmp;

	parse_init();

	dts = create_dev_types();
	if (!dts)
		return;


	INIT_LIST_HEAD(&head);
	prepare_dev_list(&head);





#if 0
	list_for_each_entry(dev, &head, list) {
	}

	list_for_each_entry_safe(dev, tmp, &head, list) {
			list_del_init(&dev->list);
	}
#endif





	kfree(dts);
}
