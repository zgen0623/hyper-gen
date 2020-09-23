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
#define MPATH_PREFIX "mpath-"

#define ID_LEN 32

#define MAPPER_CTRL_MINOR 236
#define MISC_MAJOR 10
#define DM_CONTROL_NODE "control"

#define LVM_MAJOR(dev)    ((dev & 0xfff00) >> 8)
#define LVM_MINOR(dev)    ((dev & 0xff) | ((dev >> 12) & 0xfff00))
#define LVM_MKDEV(ma,mi)  ((mi & 0xff) | (ma << 8) | ((mi & ~0xff) << 12))

#define SECTOR_SHIFT 9L
#define BLKSIZE_SHIFT SECTOR_SHIFT
#define MD_RESERVED_BYTES (64 * 1024ULL)
#define MD_RESERVED_SECTORS (MD_RESERVED_BYTES / 512)
#define MD_NEW_SIZE_SECTORS(x) ((x & ~(MD_RESERVED_SECTORS - 1)) \
                - MD_RESERVED_SECTORS)
#define MD_SB_MAGIC 0xa92b4efc

#define PART_MAGIC 0xAA55
#define PART_MAGIC_OFFSET 0x1FE
#define PART_OFFSET 0x1BE

#define SECTOR_SIZE ( 1L << SECTOR_SHIFT )

#define LABEL_SCAN_SECTORS 4L
#define LABEL_SCAN_SIZE (LABEL_SCAN_SECTORS << SECTOR_SHIFT)
#define LABEL_ID "LABELONE"
#define LABEL_SIZE SECTOR_SIZE  /* Think very carefully before changing this */
#define INITIAL_CRC 0xf597a6cf

#define LVM2_LABEL "LVM2 001"

#define CACHE_INVALID   0x00000001

#define MDA_HEADER_SIZE 512
#define FMTT_MAGIC "\040\114\126\115\062\040\170\133\065\101\045\162\060\116\052\076"
#define FMTT_VERSION 1

#define DM_UUID_LEN 129

#define DEFAULT_PV_MIN_SIZE_KB 2048

#define MDA_IGNORED      0x00000001
#define RAW_LOCN_IGNORED 0x00000001
#define NAME_LEN 128

typedef enum {
    MD_MINOR_VERSION_MIN,
    MD_MINOR_V0 = MD_MINOR_VERSION_MIN,
    MD_MINOR_V1,
    MD_MINOR_V2,
    MD_MINOR_VERSION_MAX = MD_MINOR_V2
} md_minor_version_t;

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

struct part {
        uint8_t skip[PART_OFFSET];
        struct partition part[4];
        uint16_t magic;
} __attribute__((packed)); /* sizeof() == SECTOR_SIZE */


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
	uint64_t size;
};

struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[1];
};


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


struct label_header {
    int8_t id[8];       /* LABELONE */ 
    uint64_t sector_xl; /* Sector number of this label */
    uint32_t crc_xl;    /* From next field to end of sector */
    uint32_t offset_xl; /* Offset from start of struct to contents */
    int8_t type[8];     /* LVM2 001 */
} __attribute__ ((packed)); 

struct label {
    char type[8];
    uint64_t sector;
//    struct labeller *labeller;
    struct hyper_rootdev_device *dev;
    void *info;
};

/* One per VG */
struct lvmcache_vginfo {
   // struct dm_list list;    /* Join these vginfos together */
	struct list_head list;

//    struct dm_list infos;   /* List head for lvmcache_infos */
	struct list_head infos;

//    const struct format_type *fmt;
    char *vgname;       /* "" == orphan */
    uint32_t status;
    char vgid[ID_LEN + 1];
    char _padding[7];
    struct lvmcache_vginfo *next; /* Another VG with same name? */
    char *creation_host;
    char *lock_type;
    uint32_t mda_checksum;
    size_t mda_size;
    size_t vgmetadata_size;
    char *vgmetadata;   /* Copy of VG metadata as format_text string */
//    struct dm_config_tree *cft; /* Config tree created from vgmetadata */
                    /* Lifetime is directly tied to vgmetadata */
 //   struct volume_group *cached_vg;
    unsigned holders;
    unsigned vg_use_count;  /* Counter of vg reusage */
    unsigned precommitted;  /* Is vgmetadata live or precommitted? */
    unsigned cached_vg_invalidated; /* Signal to regenerate cached_vg */
    unsigned preferred_duplicates; /* preferred duplicate pvs have been set */
};


struct lvmcache_info {
//    struct dm_list list;    /* Join VG members together */
	struct list_head list;

 //   struct dm_list mdas;    /* list head for metadata areas */
	struct list_head mdas;

  //  struct dm_list das; /* list head for data areas */
	struct list_head das;

   // struct dm_list bas; /* list head for bootloader areas */
	struct list_head bas;

    struct lvmcache_vginfo *vginfo; /* NULL == unknown */

    struct label *label;

 //   const struct format_type *fmt;
    struct hyper_rootdev_device *dev;
    uint64_t device_size;   /* Bytes */ 
    uint32_t status;
}; 

struct pv_node {
	char *pvid;
	struct lvmcache_info *info;
	struct list_head list;
};

struct disk_locn {
    uint64_t offset;    /* Offset in bytes to start sector */
    uint64_t size;      /* Bytes */
} __attribute__ ((packed));


struct pv_header {
    int8_t pv_uuid[ID_LEN];

    /* This size can be overridden if PV belongs to a VG */
    uint64_t device_size_xl;    /* Bytes */

    /* NULL-terminated list of data areas followed by */
    /* NULL-terminated list of metadata area headers */
    struct disk_locn disk_areas_xl[0];  /* Two lists */
} __attribute__ ((packed));

struct pv_header_extension {
    uint32_t version;
    uint32_t flags;
    /* NULL-terminated list of bootloader areas */
    struct disk_locn bootloader_areas_xl[0];
} __attribute__ ((packed));

struct _update_mda_baton {
    struct lvmcache_info *info;
    struct label *label;
};

struct data_area_list {
  //  struct dm_list list;
	struct list_head list;
    struct disk_locn disk_locn;
};

struct metadata_area {
    //struct dm_list list;
	struct list_head list;
 //   struct metadata_area_ops *ops;
    void *metadata_locn;
    uint32_t status;
};

struct device_area {
    struct hyper_rootdev_device *dev;
    uint64_t start;     /* Bytes */
    uint64_t size;      /* Bytes */
}; 

struct raw_locn {
    uint64_t offset;    /* Offset in bytes to start sector */
    uint64_t size;      /* Bytes */
    uint32_t checksum;
    uint32_t flags;
} __attribute__ ((packed));


struct mda_context {
    struct device_area area;
    uint64_t free_sectors;
    struct raw_locn rlocn;  /* Store inbetween write and commit */
}; 


struct mda_header {
    uint32_t checksum_xl;   /* Checksum of rest of mda_header */
    int8_t magic[16];   /* To aid scans for metadata */
    uint32_t version;
    uint64_t start;     /* Absolute start byte of mda_header */
    uint64_t size;      /* Size of metadata area */
    
    struct raw_locn raw_locns[0];   /* NULL-terminated list */
} __attribute__ ((packed));

struct id {
    int8_t uuid[ID_LEN];
};

struct lvmcache_vgsummary {
    const char *vgname;
    struct id vgid;
    uint64_t vgstatus;
    char *creation_host;
    const char *lock_type;
    uint32_t mda_checksum;
    size_t mda_size;
}; 


void *my_dm_open(void);
void my_get_dm_version(uint32_t *version);
int my_dm_get_uuid_by_dev(dev_t dev, char *uuid, int length);


static uint32_t _dm_device_major = 0;
static void *dm_ctl_priv = NULL;
static unsigned _dm_version_minor = 0;
static unsigned _dm_version_patchlevel = 0;

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

static struct list_head pv_head;
static struct list_head vginfo_head;



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
    if (!strncmp("device-mapper", line + i, 13) && !(*(line + i + 13))) {
//		printk(">>>%s:%d dm maj=%lx\n", __func__, __LINE__, line_maj);
        dts->device_mapper_major = line_maj;
	}

    /* Major is SCSI device */
    if (!strncmp("sd", line + i, 2) && !(*(line + i + 2))) {
//		printk(">>>%s:%d sd maj=%lx\n", __func__, __LINE__, line_maj);
        dts->dev_type_array[line_maj].flags |= PARTITION_SCSI_DEVICE;
	}

    /* Go through the valid device names and if there is a
       match store max number of partitions */
    for (j = 0; _dev_known_types[j].name[0]; j++) {
        dev_len = strlen(_dev_known_types[j].name);
        if (dev_len <= strlen(line + i) &&
            !strncmp(_dev_known_types[j].name, line + i, dev_len) &&
            (line_maj < NUMBER_OF_MAJORS)) {
//				printk(">>>%s:%d dev=%s maj=%lx\n", __func__, __LINE__, line + i, line_maj);

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

static void init_dev(struct hyper_rootdev_device *dev)
{
	if ((dev->fd = sys_open((const char __user *)dev->path,
			O_RDONLY|O_NOATIME , 0777)) < 0) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return;
	}

    if (sys_ioctl(dev->fd, BLKGETSIZE64, (uint64_t)&dev->size) < 0) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return;
    }
    dev->size >>= BLKSIZE_SHIFT;    /* Convert to sectors */

    if (sys_ioctl(dev->fd, BLKBSZGET, (uint64_t)&dev->block_size) < 0) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return;
    }

    /* BLKPBSZGET is available in kernel >= 2.6.32 only */
    if (sys_ioctl(dev->fd, BLKPBSZGET, (uint64_t)&dev->phys_block_size) < 0) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return;
    }
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

						init_dev(dev);

						INIT_LIST_HEAD(&dev->list);
						list_add(&dev->list, dev_head);

			//			printk(">>>%s:%d path=%s dev_t=%x\n", __func__, __LINE__, path, dev->dev);
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

static int major_is_scsi_device(struct dev_types *dt, int major)
{       
    if (major >= NUMBER_OF_MAJORS)
        return 0;
    
    return (dt->dev_type_array[major].flags & PARTITION_SCSI_DEVICE) ? 1 : 0;
}

static char *basename(char *hname)
{
    char *split;
    
    hname = strim((char *)hname);
    for (split = strstr(hname, "//"); split; split = strstr(hname, "//"))
        hname = split + 2;
    
    return hname;
} 

static int dev_get_primary_dev(struct dev_types *dt, struct hyper_rootdev_device *dev, dev_t *result)
{
    int major = (int) LVM_MAJOR(dev->dev);
    int minor = (int) LVM_MINOR(dev->dev);
	char *ptr; 
    char buffer[64];
	struct __old_kernel_stat info;
	int fd = -1;
    int parts, residue, size, ret = 0;
	char *path = kmalloc(PATH_MAX, GFP_KERNEL);
	char *temp_path = kmalloc(PATH_MAX, GFP_KERNEL);

    if ((parts = dt->dev_type_array[major].max_partitions) > 1) {
        if ((residue = minor % parts)) {
            *result = LVM_MKDEV((dev_t)major, (dev_t)(minor - residue));
            ret = 2;
        } else {
            *result = dev->dev;
            ret = 1; /* dev is not a partition! */
        }
        goto out;
    }

    /* check if dev is a partition */
    snprintf(path, PATH_MAX, "/sys/dev/block/%d:%d/partition", major, minor);
    if (sys_stat(path, (struct __old_kernel_stat __user *)&info) < 0) {
        *result = dev->dev;
        ret = 1;
        goto out; /* dev is not a partition! */
    }

	//dirname(path)
	ptr = strrchr(path,'/');
	*ptr = '\0';
    if ((size = sys_readlink((const char __user *)path, 
			(char __user *)temp_path, sizeof(temp_path) - 1)) < 0)
        goto out;

    temp_path[size] = '\0';

	//dirname(temp_path)
	ptr = strrchr(temp_path,'/');
	*ptr = '\0';

    snprintf(path, PATH_MAX, "/sys/block/%s/dev",
            basename(temp_path));

    /* finally, parse 'dev' attribute and create corresponding dev_t */
    if (sys_stat(path, (struct __old_kernel_stat __user *)&info) == -1) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        goto out;
	}

	if ((fd = sys_open((const char __user *)path, O_RDONLY, 0)) < 0) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		goto out;
	}

	ret = sys_read(fd, (char __user *)buffer, sizeof(buffer));
	if (ret <= 0) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		goto out;
	}

    if (sscanf(buffer, "%d:%d", &major, &minor) != 2) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        goto out;
    }

    *result = LVM_MKDEV((dev_t)major, (dev_t)minor);
    ret = 2;

out:
    if (fd >= 0)
		sys_close(fd);

	kfree(path);
	kfree(temp_path);

    return ret;
}

static const char *_get_sysfs_name_by_devt(dev_t devno,
                      char *buf, size_t buf_size)
{
    const char *name = NULL;
	char *path = kmalloc(PATH_MAX, GFP_KERNEL);
    int size;

    if (snprintf(path, PATH_MAX, "/sys/dev/block/%d:%d",
            (int) LVM_MAJOR(devno), (int) LVM_MINOR(devno)) < 0)
        goto out;

    if ((size = sys_readlink((const char __user *)path,
			(char __user *)buf, buf_size - 1)) < 0)
        goto out;

    buf[size] = '\0';
    if (!(name = strrchr(buf, '/')))
        goto out;

    name++;

out:
	kfree(path);
    return name;
}

static const char *_get_sysfs_name(struct hyper_rootdev_device *dev)
{
    const char *name;

    if (!(name = strrchr(dev->path, '/')))
        return NULL;

    name++;

    if (!*name)
        return NULL;

    return name;
}

static int _get_parent_mpath(const char *dir, char *name, int max_size)
{
	int fd;
	char *buf = NULL;
	struct linux_dirent *dirent;
	int ret;
	int r = 0;

	if ((fd = sys_open((const char __user *)dir,
			O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY, 0)) < 0) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return 0;
	}

	buf = kmalloc(1024, GFP_KERNEL);
	if (!buf) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		goto out;
	}

    *name = '\0';

	while (1) {
		dirent = (struct linux_dirent *)buf;
		ret = sys_getdents(fd, (struct linux_dirent __user *)dirent, 1024);
		if (ret <= 0)
			break;

		while (1) {
			if ((char *)dirent >= buf + ret)
				break;

			if (strcmp(dirent->d_name, ".") && strcmp(dirent->d_name, "..")) {
        		if (*name) {
            		r = 0;
            		goto out;
        		}

        		strncpy(name, dirent->d_name, max_size);
        		r = 1;
			}

			dirent = (void *)dirent + dirent->d_reclen;
		}
	}

out:
	sys_close(fd);
	kfree(buf);

    return r;
}

static int _get_sysfs_string(const char *path, char *buffer, int max_size)
{
    int r = 0;
	int fd = -1;

	if ((fd = sys_open((const char __user *)path, O_RDONLY, 0)) < 0) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		goto out;
	}

	r = sys_read(fd, (char __user *)buffer, max_size);
	if (r <= 0) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		goto out;
	}

	r = 1;

out:
	if (fd >= 0)
		sys_close(fd);

    return r;
}


static int _get_sysfs_get_major_minor(const char *kname, int *major, int *minor)
{
	char *path = kmalloc(PATH_MAX, GFP_KERNEL);
    char buffer[64];
	int ret = 0;

    snprintf(path, PATH_MAX, "/sys/block/%s/dev", kname);

    if (!_get_sysfs_string(path, buffer, sizeof(buffer)))
        goto out;

    if (sscanf(buffer, "%d:%d", major, minor) != 2) {
        printk(">>>%s:%d Failed to parse major minor from %s\n",
			__func__, __LINE__, buffer);
        goto out;
    }

out:
	kfree(path);
    return ret;
}

static int lvm_dm_prefix_check(int major, int minor, const char *prefix)
{
    int r;
	char uuid[DM_UUID_LEN];
	dev_t dev;

	dev = LVM_MKDEV((dev_t)major, (dev_t)minor);
	
	r = my_dm_get_uuid_by_dev(dev, uuid, DM_UUID_LEN);
	if (r < 0)
		return 0;

    r = strncasecmp(uuid, prefix, strlen(prefix));

    return r ? 0 : 1;
}

static int dev_is_mpath(struct dev_types *dt, struct hyper_rootdev_device *dev)
{
    const char *name;
	struct __old_kernel_stat info;
	char *path = kmalloc(PATH_MAX, GFP_KERNEL);
	char *parent_name = kmalloc(PATH_MAX, GFP_KERNEL);
    int major = LVM_MAJOR(dev->dev);
    int minor = LVM_MINOR(dev->dev);
    dev_t primary_dev;
	int ret = 0;

    /* Limit this filter only to SCSI devices */
    if (!major_is_scsi_device(dt, LVM_MAJOR(dev->dev)))
        goto out;

    switch (dev_get_primary_dev(dt, dev, &primary_dev)) {
    case 2: /* The dev is partition. */
        if (!(name = _get_sysfs_name_by_devt(primary_dev,
				parent_name, sizeof(parent_name))))
            goto out;
        break;
    case 1: /* The dev is already a primary dev. Just continue with the dev. */
        if (!(name = _get_sysfs_name(dev)))
            goto out;
        break;
    default: /* 0, error. */
        printk(">>>%s:%d Failed to get primary device for %d:%d\n",
			__func__, __LINE__, major, minor);
        goto out;
    }

    if (snprintf(path, PATH_MAX, "/sys/block/%s/holders", name) < 0) {
        printk(">>>%s:%d Sysfs path to check mpath is too long.\n", __func__, __LINE__);
        goto out;
    }

    /* also will filter out partitions */
    if (sys_stat(path, (struct __old_kernel_stat __user *)&info))
        goto out;

    if (!S_ISDIR(info.st_mode)) {
        printk(">>>%s:%d Path %s is not a directory.\n", __func__, __LINE__, path);
        goto out;
    }

    if (!_get_parent_mpath(path, parent_name, sizeof(parent_name)))
        goto out;

    if (!_get_sysfs_get_major_minor(parent_name, &major, &minor))
        goto out;

    if (major != dt->device_mapper_major)
        goto out;

    ret = lvm_dm_prefix_check(major, minor, MPATH_PREFIX);

out:
	kfree(path);
	kfree(parent_name);
	return ret;
}

static int dev_read(struct hyper_rootdev_device *dev,
			uint64_t offset, size_t size, void *buffer)
{
    int ret;
    uint64_t mask, delta;
    unsigned int block_size = 0;
    ssize_t n = 0;
    size_t total = 0;
	uint64_t align_offset;
	size_t align_size = 0;
	void *align_buffer;
	void *buf_ptr;
	void *buf_ref;

	block_size =
		(dev->block_size == -1) ? PAGE_SIZE : dev->block_size;

    mask = block_size - 1;

	align_offset = offset;
	align_size = size;

    /* adjust the start */
    delta = align_offset & mask;
    if (delta) {
        align_offset = align_offset - delta;
        align_size = align_size + delta;
    }

    /* adjust the end */
    delta = (align_offset + align_size) & mask;
    if (delta) {
        align_size += block_size - delta;
	}

	buf_ref = align_buffer = kmalloc(align_size + block_size, GFP_KERNEL);
	if (!buf_ref)
		return 0;

    if (((uintptr_t) align_buffer) & mask)
        align_buffer = (char *)(((uintptr_t)align_buffer + mask) & ~mask);

    if (sys_lseek(dev->fd, align_offset, SEEK_SET) == (off_t) -1)
        return 0;

	buf_ptr = align_buffer;
    while (total < align_size) {
        do
            n = sys_read(dev->fd, (char __user *)buf_ptr, align_size - total);
        while (n < 0);

        if (n <= 0)
            break;

        total += n;
        buf_ptr += n;
    }

    memcpy(buffer, align_buffer + (offset - align_offset), size);

	kfree(buf_ref);

    return total;
}

static uint64_t _v1_sb_offset(uint64_t size, md_minor_version_t minor_version)
{
    uint64_t sb_offset;

    switch(minor_version) {
    case MD_MINOR_V0:
        sb_offset = (size - 8 * 2) & ~(4 * 2 - 1ULL);
        break;
    case MD_MINOR_V1:
        sb_offset = 0;
        break;
    case MD_MINOR_V2:
        sb_offset = 4 * 2;
        break;
    default:
        printk(">>>%s:%d WARNING: Unknown minor version %d\n",
             __func__, __LINE__, minor_version);
        return 0;
    }

    sb_offset <<= SECTOR_SHIFT;

    return sb_offset;
}


static int dev_is_md(struct hyper_rootdev_device *dev)
{
    int ret = 1;
    md_minor_version_t minor;
    uint64_t size, sb_offset;
	uint32_t md_magic;
 
	size = dev->size;

    if (size < MD_RESERVED_SECTORS * 2) {
        ret = 0;
		goto out;
	}

    /* Check if it is an md component device. */
    /* Version 0.90.0 */
    sb_offset = MD_NEW_SIZE_SECTORS(size) << SECTOR_SHIFT;
	if (dev_read(dev, sb_offset, sizeof(uint32_t), &md_magic)) {
		if (md_magic == MD_SB_MAGIC)
			goto out;
	}

    minor = MD_MINOR_VERSION_MIN;
    /* Version 1, try v1.0 -> v1.2 */
    do {
        sb_offset = _v1_sb_offset(size, minor);

		if (dev_read(dev, sb_offset, sizeof(uint32_t), &md_magic)) {
			if (md_magic == MD_SB_MAGIC)
				goto out;
		}
    } while (++minor <= MD_MINOR_VERSION_MAX);

    ret = 0;

out:
	return ret;
}

static int _is_partitionable(struct dev_types *dt, struct hyper_rootdev_device *dev)
{
    int parts;
	int major = LVM_MAJOR(dev->dev);
	int minor = LVM_MINOR(dev->dev);

    if (major >= NUMBER_OF_MAJORS)
		parts = 0;
	else
		parts = dt->dev_type_array[major].max_partitions;

    if (major == dt->device_mapper_major)
        return 1;

    /* All MD devices are partitionable via blkext (as of 2.6.28) */
    if (major == dt->md_major)
        return 1;

    if ((parts <= 1) || (minor % parts))
        return 0;

    return 1;
}

static int dev_is_partitioned(struct dev_types *dt, struct hyper_rootdev_device *dev)
{
    int r = 0;
    unsigned p;
	struct part buf;

    if (!_is_partitionable(dt, dev))
        return 0;

    /* Unpartitioned DASD devices are not supported. */
    if ((LVM_MAJOR(dev->dev) == dt->dasd_major))
        return 1;

    if (!dev_read(dev, 0UL, sizeof(buf), &buf))
        return 0;

    /* Check for msdos partition table */
    if (buf.magic == PART_MAGIC) {
        for (p = 0; p < 4; ++p) {
            /* Table is invalid if boot indicator not 0 or 0x80 */
            if (buf.part[p].boot_ind & 0x7f) {
                r = 0;
                break;
            }
            /* Must have at least one non-empty partition */
            if (buf.part[p].nr_sects)
                r = 1;
        }
    }

    return r;
}


static int check_pv_min_size(struct hyper_rootdev_device *dev)
{
    uint64_t size;
    int ret = 0;

    /* Check it's not too small */
    if (!dev->size)
        goto out;

    if (dev->size < (DEFAULT_PV_MIN_SIZE_KB * 1024L >> SECTOR_SHIFT))
        goto out;

    ret = 1;
out:

    return ret;
}

static int my_filter(struct dev_types *dts, struct hyper_rootdev_device *dev)
{
    if (dev_is_mpath(dts, dev)) {
        printk(">>>%s:%d Skipping dev_name=%s\n",
            __func__, __LINE__, dev->path);
        return 0;
    }

    if (dev_is_md(dev)) {
        printk(">>>%s:%d Skipping dev_name=%s\n",
            __func__, __LINE__, dev->path);
        return 0;
    }

	if (!check_pv_min_size(dev)){
        printk(">>>%s:%d Skipping dev_name=%s\n",
            __func__, __LINE__, dev->path);
        return 0;
	}


	if (!dts->dev_type_array[LVM_MAJOR(dev->dev)].max_partitions) {
        printk(">>>%s:%d Skipping dev_name=%s dev=%lx major=%lx\n",
            __func__, __LINE__, dev->path, dev->dev, LVM_MAJOR(dev->dev));
        return 0;
    }

    if (dev_is_partitioned(dts, dev)) {
        printk(">>>%s:%d Skipping dev_name=%s\n",
            __func__, __LINE__, dev->path);
        return 0;
    }

    printk(">>>%s:%d Accept dev_name=%s\n", __func__, __LINE__, dev->path);

    return 1;
}

static int open_control(struct dev_types *dt)
{
	uint32_t version[3];

    if (dm_ctl_priv)
        return 0;

    if (!(dm_ctl_priv = my_dm_open())) {
        printk(">>>%s:%d\n", __func__, __LINE__);
        return 1;
	}

	version[0] = 4; 
	version[0] = 0; 
	version[0] = 0; 

	my_get_dm_version(version);

    _dm_version_minor = version[1];
    _dm_version_patchlevel = version[2];

	_dm_device_major = dt->device_mapper_major;

    return 0;
}


static int find_lvm2_label(struct hyper_rootdev_device *dev, char *buf,
                       uint64_t *label_sector)
{
    struct label_header *lh;
    struct lvmcache_info *info;
    uint64_t sector;
    int found = 0;
	char *readbuf;

	readbuf = kmalloc(LABEL_SCAN_SIZE, GFP_KERNEL);
	if (!readbuf)
		goto out;

    if (!dev_read(dev, 0,
              LABEL_SCAN_SIZE, readbuf)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        goto out;
    }

    /* Scan a few sectors for a valid label */
    for (sector = 0; sector < LABEL_SCAN_SECTORS;
         	sector += LABEL_SIZE >> SECTOR_SHIFT) {
        lh = (struct label_header *) (readbuf +
                          (sector << SECTOR_SHIFT));

        if (!strncmp((char *)lh->id, LABEL_ID, sizeof(lh->id))) {
            if (le64_to_cpu(lh->sector_xl) != sector)
                continue;

            if (found)
                continue;
        }

		if (!strncmp((char *)lh->type, LVM2_LABEL, sizeof(lh->type))) {
			printk(">>>%s:%d %s lvm2 label detected at sector %d\n", __func__, __LINE__,
                         dev->path, sector);

			if (found)
				continue;

			memcpy(buf, lh, LABEL_SIZE);

			if (label_sector)
				*label_sector = sector;

			found = 1;
			break;
		}
    }

out:
	kfree(readbuf);

    return found;
}


static int lvmcache_update_pvid(struct lvmcache_info *info, const char *pvid)
{
    /*
     * Nothing to do if already stored with same pvid.
     */
	struct pv_node *pv, *tmp;

	list_for_each_entry(pv, &pv_head, list)
		if (pv->info == info && !strcmp(pv->pvid, pvid))
			return 1;

    if (*info->dev->pvid) {
		list_for_each_entry_safe(pv, tmp, &pv_head, list) {
        	if(!strcmp(pv->pvid, info->dev->pvid)) {
				list_del_init(&pv->list);
				kfree(pv);
			}
		}
	}

    strncpy(info->dev->pvid, pvid, sizeof(info->dev->pvid));

	pv = kmalloc(sizeof(struct pv_node), GFP_KERNEL);

	INIT_LIST_HEAD(&pv->list);
	list_add(&pv->list, &pv_head);

    return 1;
}

static struct lvmcache_info *lvmcache_add(struct dev_types *dt, const char *pvid,
                   struct hyper_rootdev_device *dev)
{
    struct label *label;
    struct lvmcache_info *info;
    char pvid_s[ID_LEN + 1] __attribute__((aligned(8)));

    strncpy(pvid_s, pvid, sizeof(pvid_s) - 1);
    pvid_s[sizeof(pvid_s) - 1] = '\0';

	if (!(label = kzalloc(sizeof(struct label), GFP_KERNEL)))
        return NULL;

	strncpy(label->type, LVM2_LABEL, sizeof(label->type));

	if (!(info = kzalloc(sizeof(struct lvmcache_info), GFP_KERNEL))) {
        kfree(label);
        return NULL;
    }

    label->info = info;
    info->label = label;
    info->dev = dev;

	INIT_LIST_HEAD(&info->list);
	INIT_LIST_HEAD(&info->mdas);
	INIT_LIST_HEAD(&info->das);
	INIT_LIST_HEAD(&info->bas);

//    info->fmt = labeller->fmt;
    info->status |= CACHE_INVALID;

    if (!lvmcache_update_pvid(info, pvid_s)) {
        kfree(info);
        kfree(label);
        return NULL;
    }

    return info;
}


static int raw_read_mda_header(struct mda_header *mdah, struct device_area *dev_area)
{
    struct raw_locn *rl;

    if (!dev_read(dev_area->dev, dev_area->start, MDA_HEADER_SIZE, mdah))
        return 0;

    mdah->version = le32_to_cpu(mdah->version);
    mdah->start = le64_to_cpu(mdah->start);
    mdah->size = le64_to_cpu(mdah->size);

    rl = &mdah->raw_locns[0];
    while (rl->offset) {
        rl->checksum = le32_to_cpu(rl->checksum);
        rl->offset = le64_to_cpu(rl->offset);
        rl->size = le64_to_cpu(rl->size);
        rl++;
    }

    if (strncmp((char *)mdah->magic, FMTT_MAGIC, sizeof(mdah->magic)))
        return 0;

    if (mdah->version != FMTT_VERSION)
        return 0;

    if (mdah->start != dev_area->start)
        return 0;

    return 1;
}

static int validate_name(const char *n) 
{
    register char c;
    register int len = 0;

    if (!n || !*n)
        return 0;

    /* Hyphen used as VG-LV separator - ambiguity if LV starts with it */
    if (*n == '-')
        return 0;

    if ((*n == '.') && (!n[1] || (n[1] == '.' && !n[2]))) /* ".", ".." */
        return 0;

    while ((len++, c = *n++))
        if (!isalnum(c) && c != '.' && c != '_' && c != '-' && c != '+')
            return 0;

    if (len > NAME_LEN)
        return 0;

    return 1;
}

static int lvmcache_lookup_mda(struct lvmcache_vgsummary *vgsummary)
{
    struct lvmcache_vginfo *vginfo;

    if (!vgsummary->mda_size)
        return 0;

	list_for_each_entry(vginfo, &vginfo_head, list) {
        if (vgsummary->mda_checksum == vginfo->mda_checksum &&
            vgsummary->mda_size == vginfo->mda_size) {
            vgsummary->vgname = vginfo->vgname;
            vgsummary->creation_host = vginfo->creation_host;
            vgsummary->vgstatus = vginfo->status;

            /* vginfo->vgid has 1 extra byte then vgsummary->vgid */
            memcpy(&vgsummary->vgid, vginfo->vgid, sizeof(vgsummary->vgid));

            return 1;
        }
    }

    return 0;
}

static int dev_read_circular(struct hyper_rootdev_device *dev,
				uint64_t offset, size_t len,
				uint64_t offset2, size_t len2, char *buf)
{            
    if (!dev_read(dev, offset, len, buf))
        return 0;
    
    if (!len2)
        return 1;
    
    if (!dev_read(dev, offset2, len2, buf + len))
        return 0;

    return 1;
}

typedef enum {
    DM_CFG_INT,
    DM_CFG_FLOAT,
    DM_CFG_STRING,
    DM_CFG_EMPTY_ARRAY
} dm_config_value_type_t;

struct dm_config_value {
    dm_config_value_type_t type;

    union {
        int64_t i;
        float f;
        double d;           /* Unused. */
        const char *str;
    } v;

    struct dm_config_value *next;   /* For arrays */
    uint32_t format_flags;
};

struct dm_config_node {
    const char *key;
    struct dm_config_node *parent, *sib, *child;
    struct dm_config_value *v;
    int id;
};

#define SECTION_B_CHAR '{'
#define SECTION_E_CHAR '}'

enum {
    TOK_INT,
    TOK_FLOAT,
    TOK_STRING,     /* Single quotes */
    TOK_STRING_ESCAPED, /* Double quotes */
    TOK_STRING_BARE,    /* No quotes */
    TOK_EQ,
    TOK_SECTION_B,
    TOK_SECTION_E,
    TOK_ARRAY_B,
    TOK_ARRAY_E,
    TOK_IDENTIFIER,
    TOK_COMMA,
    TOK_EOF
};

struct parser {
    const char *fb, *fe;        /* file limits */

    int t;          /* token limits and type */
    const char *tb, *te;

    int line;       /* line number we are on */
};

static void eat_space(struct parser *p)
{
    while (p->tb != p->fe) {
        if (*p->te == '#')
            while ((p->te != p->fe) && (*p->te != '\n') && (*p->te))
                ++p->te;

        else if (!isspace(*p->te))
            break;

        while ((p->te != p->fe) && isspace(*p->te)) {
            if (*p->te == '\n')
                ++p->line;
            ++p->te;
        }

        p->tb = p->te;
    }
}

static void get_token(struct parser *p, int tok_prev)
{
    int values_allowed = 0;
    const char *te;

    p->tb = p->te;
    eat_space(p);
    if (p->tb == p->fe || !*p->tb) {
        p->t = TOK_EOF;
        return;
    }

    /* Should next token be interpreted as value instead of identifier? */
    if (tok_prev == TOK_EQ || tok_prev == TOK_ARRAY_B ||
        tok_prev == TOK_COMMA)
        values_allowed = 1;

    p->t = TOK_INT;     /* fudge so the fall through for
                   floats works */

    te = p->te;
    switch (*te) {
    case SECTION_B_CHAR:
        p->t = TOK_SECTION_B;
        te++;
        break;

    case SECTION_E_CHAR:
        p->t = TOK_SECTION_E;
        te++;
        break;
    case '[':
        p->t = TOK_ARRAY_B;
        te++;
        break;

    case ']':
        p->t = TOK_ARRAY_E;
        te++;
        break;

    case ',':
        p->t = TOK_COMMA;
        te++;
        break;

    case '=':
        p->t = TOK_EQ;
        te++;
        break;

    case '"':
        p->t = TOK_STRING_ESCAPED;
        te++;
        while ((te != p->fe) && (*te) && (*te != '"')) {
            if ((*te == '\\') && (te + 1 != p->fe) &&
                *(te + 1))
                te++;
            te++;
        }

        if ((te != p->fe) && (*te))
            te++;
        break;

    case '\'':
        p->t = TOK_STRING;
        te++;
        while ((te != p->fe) && (*te) && (*te != '\''))
            te++;

        if ((te != p->fe) && (*te))
            te++;
        break;
    case '.':
        p->t = TOK_FLOAT;
        /* Fall through */
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
    case '+':
    case '-':
        if (values_allowed) {
            while (++te != p->fe) {
                if (!isdigit((int) *te)) {
                    if (*te == '.') {
                        if (p->t != TOK_FLOAT) {
                            p->t = TOK_FLOAT;
                            continue;
                        }
                    }
                    break;
                }
            }
            break;
        }
        /* fall through */

    default:
        p->t = TOK_IDENTIFIER;
        while ((te != p->fe) && (*te) && !isspace(*te) &&
               (*te != '#') && (*te != '=') &&
               (*te != SECTION_B_CHAR) &&
               (*te != SECTION_E_CHAR))
            te++;
        if (values_allowed)
            p->t = TOK_STRING_BARE;
        break;
    }

    p->te = te;
}

static char *_dup_tok(const char *b, const char *e)
{
	size_t len;
	char *str;

    len = e - b;

	str = kmalloc(len + 1, GFP_KERNEL);
    if (!str) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return NULL;
    }

    memcpy(str, b, len);
    str[len] = '\0';

    return str;
}

static char *_dup_string_tok(struct parser *p)
{
    char *str;

    p->tb++, p->te--;   /* strip "'s */

    if (p->te < p->tb) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return NULL;
    }

    if (!(str = _dup_tok(p->tb, p->te)))
        return NULL;

    p->te++;

    return str;
}

static void dm_unescape_double_quotes(char *src)
{   
    char *out;
    char s, n;
	const char orig_char = '\"';
	const char quote_char = '\\';
    
    /* Optimise for the common case where no changes are needed. */
    while ((s = *src++)) {
        if (s == quote_char &&
            ((n = *src) == orig_char || n == quote_char)) {
            out = src++; 
            *(out - 1) = n;
            
            while ((s = *src++)) {
                if (s == quote_char &&
                    ((n = *src) == orig_char || n == quote_char)) {
                    s = n;
                    src++;
                }
                *out = s;
                out++;
            }
            
            *out = '\0';
            return;
        }
    }
}

static int match_aux(struct parser *p, int t)
{
    if (p->t != t) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
	}

    get_token(p, t);
    return 1;
}

static const int sep = '/';
static int _tok_match(const char *str, const char *b, const char *e)
{
    while (*str && (b != e))
        if (*str++ != *b++)
            return 0;

    return !(*str || (b != e));
}

static struct dm_config_node *_make_node(const char *key_b, const char *key_e,
                     struct dm_config_node *parent)
{
    struct dm_config_node *n;

    if (!(n = kzalloc(sizeof(struct dm_config_node), GFP_KERNEL)))
        return NULL;

    n->key = _dup_tok(key_b, key_e);
    if (parent) {
        n->parent = parent;
        n->sib = parent->child;
        parent->child = n;
    }

    return n;
}


static struct dm_config_node *_find_or_make_node(struct dm_config_node *parent,
                         const char *path, int create)
{
    const char *e;
    struct dm_config_node *cn = parent ? parent->child : NULL;
    struct dm_config_node *cn_found = NULL;

    while (create || cn) {
        /* trim any leading slashes */
        while (*path && (*path == sep))
            path++;

        /* find the end of this segment */
        for (e = path; *e && (*e != sep); e++) ;

        /* hunt for the node */
        cn_found = NULL;

        while (cn) {
            if (_tok_match(cn->key, path, e))
                if (!cn_found)
                    cn_found = cn;

            cn = cn->sib;
        }

        if (!cn_found)
            if (!(cn_found = _make_node(path, e, parent)))
                return NULL;

        if (cn_found && *e) {
            parent = cn_found;
            cn = cn_found->child;
        } else
            return cn_found;

        path = e;
    }

    return NULL;
}

static struct dm_config_value *_type(struct parser *p)
{
    /* [+-]{0,1}[0-9]+ | [0-9]*\.[0-9]* | ".*" */
    struct dm_config_value *v;
    char *str;
	long long res;
	int ret;
	int i;

    v = kzalloc(sizeof(struct dm_config_value), GFP_KERNEL);
    if (!v) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return NULL;
    }

    switch (p->t) {
    case TOK_INT:
        v->type = DM_CFG_INT;

		str = kmalloc(p->te - p->tb + 1, GFP_KERNEL);
		for (i = 0; i < p->te -p->tb; i++)
			str[i] = p->tb[i];

		str[i] = 0;

		ret = kstrtoll(str, 0, &res);
		if (ret)
			printk(">>>%s:%d str=%s\n", __func__, __LINE__, str);

		kfree(str);

		v->v.i = res;

        match_aux(p, TOK_INT);
        break;

    case TOK_FLOAT:
        v->type = DM_CFG_FLOAT;
        //v->v.f = strtod(p->tb, NULL);   /* FIXME: check error */
		printk(">>>%s:%d kernel not support float\n", __func__, __LINE__);
        match_aux(p, TOK_FLOAT);
        break;

    case TOK_STRING:
        v->type = DM_CFG_STRING;

        if (!(v->v.str = _dup_string_tok(p)))
            return NULL;

        match_aux(p, TOK_STRING);
        break;

    case TOK_STRING_BARE:
        v->type = DM_CFG_STRING;

        if (!(v->v.str = _dup_tok(p->tb, p->te)))
            return NULL;

        match_aux(p, TOK_STRING_BARE);
        break;

    case TOK_STRING_ESCAPED:
        v->type = DM_CFG_STRING;

        if (!(str = _dup_string_tok(p)))
            return NULL;

        dm_unescape_double_quotes(str);
        v->v.str = str;
        match_aux(p, TOK_STRING_ESCAPED);
        break;

    default:
		printk(">>>%s:%d\n", __func__, __LINE__);
        return NULL;
    }
    return v;
}

static struct dm_config_value *_value(struct parser *p)
{
    struct dm_config_value *h = NULL, *l, *ll = NULL;

    if (p->t == TOK_ARRAY_B) {
        match_aux(p, TOK_ARRAY_B);

        while (p->t != TOK_ARRAY_E) {
            if (!(l = _type(p)))
                return NULL;

            if (!h)
                h = l;
            else
                ll->next = l;

            ll = l;

            if (p->t == TOK_COMMA)
                match_aux(p, TOK_COMMA);
        }

        match_aux(p, TOK_ARRAY_E);
        /*
         * Special case for an empty array.
         */
        if (!h) {
    		if (!(h = kzalloc(sizeof(struct dm_config_value), GFP_KERNEL))) {
				printk(">>>%s:%d\n", __func__, __LINE__);
                return NULL;
            }

            h->type = DM_CFG_EMPTY_ARRAY;
        }
    } else
        if (!(h = _type(p)))
            return NULL;

    return h;
}

static struct dm_config_node *_section(struct parser *p, struct dm_config_node *parent)
{
    struct dm_config_node *root;
    struct dm_config_value *value;
    char *str;

//	printk(">>>%s:%d t=%x\n", __func__, __LINE__, p->t);

    if (p->t == TOK_STRING_ESCAPED) {
//		printk(">>>%s:%d\n", __func__, __LINE__);
        if (!(str = _dup_string_tok(p)))
            return NULL;

		dm_unescape_double_quotes(str);
        match_aux(p, TOK_STRING_ESCAPED);
    } else if (p->t == TOK_STRING) {
//		printk(">>>%s:%d\n", __func__, __LINE__);
        if (!(str = _dup_string_tok(p)))
            return NULL;

        match_aux(p, TOK_STRING);
    } else {
//		printk(">>>%s:%d\n", __func__, __LINE__);
        if (!(str = _dup_tok(p->tb, p->te)))
            return NULL;
        
        match_aux(p, TOK_IDENTIFIER);
    }

//	printk(">>>%s:%d t=%x\n", __func__, __LINE__, p->t);

    if (!strlen(str)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return NULL;
    }

    root = _find_or_make_node(parent, str, 1);

//	printk(">>>%s:%d str=%s root=%lx\n", __func__, __LINE__, str, root);

    if (p->t == TOK_SECTION_B) {
//		printk(">>>%s:%d\n", __func__, __LINE__);
        match_aux(p, TOK_SECTION_B);

        while (p->t != TOK_SECTION_E)
            if (!(_section(p, root)))
                return NULL;

        match_aux(p, TOK_SECTION_E);
    } else {
//		printk(">>>%s:%d\n", __func__, __LINE__);
        match_aux(p, TOK_EQ);

        if (!(value = _value(p)))
            return NULL;

        root->v = value;
    }
//		printk(">>>%s:%d\n", __func__, __LINE__);

    return root;
}

static struct dm_config_node *_file(struct parser *p)
{
    struct dm_config_node root = { 0 };
    root.key = "<root>";

    while (p->t != TOK_EOF)
        if (!_section(p, &root))
            return NULL;

    return root.child;
}

static struct dm_config_node *_config_reverse(struct dm_config_node *head)
{
    struct dm_config_node *left = head, *middle = NULL, *right = NULL;

    while (left) {
        right = middle;
        middle = left;
        left = left->sib;
        middle->sib = right;
        middle->child = _config_reverse(middle->child);
    }

    return middle;
}

static int dm_config_parse(const char *start,
				const char *end, struct dm_config_node **root)
{
    /* TODO? if (start == end) return 1; */
	struct dm_config_node *ret;
    struct parser *p;

    if (!(p = kzalloc(sizeof(*p), GFP_KERNEL)))
        return 0;

    p->fb = start;
    p->fe = end;
    p->tb = p->te = p->fb;
    p->line = 1;

    get_token(p, TOK_SECTION_E);
    if (!(ret = _file(p)))
        return 0;

    *root = _config_reverse(ret);

    return 1;
}

static int config_file_read_fd(struct hyper_rootdev_device *dev,
            off_t offset, size_t size, off_t offset2, size_t size2,
			struct dm_config_node **root)
{
    char *fb, *fe; 
    int r = 0; 
    char *buf = NULL;

    if (!(buf = kmalloc(size + size2, GFP_KERNEL)))
        return 0;

    if (!dev_read_circular(dev, (uint64_t) offset, size,
                       (uint64_t) offset2, size2, buf))
        goto out;

	//printk(">>>%s:%d size=%lx size2=%lx\n", __func__, __LINE__, size, size2); 

    fb = buf;
    fe = fb + size + size2;

	//parse config content from dev
    if (!dm_config_parse(fb, fe, root))
        goto out;

    r = 1;

out:
    kfree(buf);

    return r;
}

static const struct dm_config_node *dm_config_find_node(const void *start,
		const char *path)
{
    struct dm_config_node dummy = { .child = (void *) start };

    return _find_or_make_node(&dummy, path, 0);
}

#define CONTENTS_FIELD "contents"
#define CONTENTS_VALUE "Text Format Volume Group"
#define FORMAT_VERSION_FIELD "version"
#define FORMAT_VERSION_VALUE 1

static int check_version(struct dm_config_node *root)
{
    const struct dm_config_node *cn;
    const struct dm_config_value *cv;

    if (!(cn = dm_config_find_node(root, CONTENTS_FIELD))) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    cv = cn->v;
    if (!cv || cv->type != DM_CFG_STRING || strcmp(cv->v.str, CONTENTS_VALUE)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    /*
     * Check the version number.
     */
    if (!(cn = dm_config_find_node(root, FORMAT_VERSION_FIELD))) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    cv = cn->v;
    if (!cv || cv->type != DM_CFG_INT || cv->v.i != FORMAT_VERSION_VALUE) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    return 1;
}

typedef const struct dm_config_node *node_lookup_fn(const void *start, const char *path);

static const char *_find_config_str(const void *start, node_lookup_fn find_fn,
                    const char *path, const char *fail, int allow_empty)
{
    const struct dm_config_node *n = find_fn(start, path);

    /* Empty strings are ignored if allow_empty is set */
    if (n && n->v) {
        if ((n->v->type == DM_CFG_STRING) &&
            (allow_empty || (*n->v->v.str)))
            return n->v->v.str;
    }

    return fail;
}

const char *dm_config_find_str_allow_empty(const struct dm_config_node *cn,
                       const char *path, const char *fail)
{
    return _find_config_str(cn, dm_config_find_node, path, fail, 1);
}

static char *dm_pool_strdup(const char *str)
{   
    char *ret = kmalloc(strlen(str) + 1, GFP_KERNEL);

    if (ret)
        strcpy(ret, str);
    
    return ret;
}

static int dm_config_get_str(const struct dm_config_node *cn, const char *path,
              const char **result)
{       
    const struct dm_config_node *n;

    n = dm_config_find_node(cn, path);
        
    if (!n || !n->v || n->v->type != DM_CFG_STRING)
        return 0;

    if (result)
        *result = n->v->v.str;

    return 1;
}

static int id_read_format(struct id *id, const char *buffer)
{   
    int out = 0;
    
    /* just strip out any dashes */
    while (*buffer) {
        if (*buffer == '-') {
            buffer++;
            continue;
        }
        
        if (out >= ID_LEN) {
			printk(">>>%s:%d\n", __func__, __LINE__);
            return 0;
        }
        
        id->uuid[out++] = *buffer++;
    }
    
    if (out != ID_LEN) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }
    
//    return id_valid(id);
    return 1;
}

static int _read_id(struct id *id, const struct dm_config_node *cn, const char *path)
{
    const char *uuid;

    if (!dm_config_get_str(cn, path, &uuid)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    if (!id_read_format(id, uuid)) {
        //log_error("Invalid uuid.");
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    return 1;
}

static int dm_config_get_list(const struct dm_config_node *cn, const char *path,
               const struct dm_config_value **result)
{   
    const struct dm_config_node *n;
    
    n = dm_config_find_node(cn, path);

    if (!n || !n->v)
        return 0;

    if (result)
        *result = n->v;

    return 1;
}

#define UINT64_C(c)   c ## UL

#define PARTIAL_VG      UINT64_C(0x0000000000000001)    /* VG */
#define EXPORTED_VG     UINT64_C(0x0000000000000002)    /* VG PV */
#define RESIZEABLE_VG       UINT64_C(0x0000000000000004)    /* VG */
    
/* May any free extents on this PV be used or must they be left free? */
#define ALLOCATABLE_PV      UINT64_C(0x0000000000000008)    /* PV */
#define ARCHIVED_VG     ALLOCATABLE_PV      /* VG, reuse same bit */
    
//#define SPINDOWN_LV       UINT64_C(0x0000000000000010)    /* LV */
//#define BADBLOCK_ON       UINT64_C(0x0000000000000020)    /* LV */
#define VISIBLE_LV      UINT64_C(0x0000000000000040)    /* LV */
#define FIXED_MINOR     UINT64_C(0x0000000000000080)    /* LV */

#define LVM_READ        UINT64_C(0x0000000000000100)    /* LV, VG */
#define LVM_WRITE       UINT64_C(0x0000000000000200)    /* LV, VG */
#define LVM_WRITE_LOCKED    UINT64_C(0x0020000000000000)    /* LV, VG */

#define CLUSTERED       UINT64_C(0x0000000000000400)    /* VG */
#define SNAPSHOT        UINT64_C(0x0000000000001000)    /* LV - internal use only */
#define PVMOVE          UINT64_C(0x0000000000002000)    /* VG LV SEG */
#define LOCKED          UINT64_C(0x0000000000004000)    /* LV */
#define MIRRORED        UINT64_C(0x0000000000008000)    /* LV - internal use only */
#define VIRTUAL         UINT64_C(0x0000000000010000)    /* LV - internal use only */
#define MIRROR          UINT64_C(0x0002000000000000)    /* LV - Internal use only */
#define MIRROR_LOG      UINT64_C(0x0000000000020000)    /* LV - Internal use only */
#define MIRROR_IMAGE        UINT64_C(0x0000000000040000)    /* LV - Internal use only */

#define LV_NOTSYNCED        UINT64_C(0x0000000000080000)    /* LV */
#define LV_REBUILD      UINT64_C(0x0000000000100000)    /* LV */
//#define PRECOMMITTED      UINT64_C(0x0000000000200000)    /* VG - internal use only */
#define CONVERTING      UINT64_C(0x0000000000400000)    /* LV */

#define MISSING_PV      UINT64_C(0x0000000000800000)    /* PV */
#define PARTIAL_LV      UINT64_C(0x0000000001000000)    /* LV - derived flag, not */

#define SPINDOWN_LV             UINT64_C(0x00000010)    /* LV */
#define BADBLOCK_ON         UINT64_C(0x00000020)    /* LV */
//#define VIRTUAL           UINT64_C(0x00010000)    /* LV - internal use only */
#define PRECOMMITTED        UINT64_C(0x00200000)    /* VG - internal use only */
#define POSTORDER_FLAG      UINT64_C(0x02000000) /* Not real flags, reserved for  */
#define POSTORDER_OPEN_FLAG UINT64_C(0x04000000) /* temporary use inside vg_read_internal. */
#define VIRTUAL_ORIGIN      UINT64_C(0x08000000)    /* LV - internal use only */

#define SHARED              UINT64_C(0x00000800)    /* VG */



#define RAID            UINT64_C(0x0000000100000000)    /* LV - Internal use only */
#define RAID_META       UINT64_C(0x0000000200000000)    /* LV - Internal use only */
#define RAID_IMAGE      UINT64_C(0x0000000400000000)    /* LV - Internal use only */
    
#define THIN_VOLUME     UINT64_C(0x0000001000000000)    /* LV - Internal use only */
#define THIN_POOL       UINT64_C(0x0000002000000000)    /* LV - Internal use only */
#define THIN_POOL_DATA      UINT64_C(0x0000004000000000)    /* LV - Internal use only */
#define THIN_POOL_METADATA  UINT64_C(0x0000008000000000)    /* LV - Internal use only */
#define POOL_METADATA_SPARE UINT64_C(0x0000010000000000)    /* LV - Internal use only */
#define LV_WRITEMOSTLY      UINT64_C(0x0000020000000000)    /* LV (RAID1) */
    
#define LV_ACTIVATION_SKIP  UINT64_C(0x0000040000000000)    /* LV */
#define LV_NOSCAN       UINT64_C(0x0000080000000000)    /* LV - internal use only - the LV
                                    should not be scanned */
#define LV_TEMPORARY        UINT64_C(0x0000100000000000)    /* LV - internal use only - the LV
                                    is supposed to be created and
                                    removed or reactivated with
                                    this flag dropped during single
                                    LVM command execution. */
#define LV_PENDING_DELETE   UINT64_C(0x0004000000000000)    /* LV - Internal use only */
#define LV_REMOVED      UINT64_C(0x0040000000000000)    /* LV - Internal use only
                                   This flag is used to mark an LV once it has
                                   been removed from the VG. It might still
                                   be referenced on internal lists of LVs.
                                   Any remaining references should check for
                                   this flag and ignore the LV is set.
                                   FIXME: Remove this flag once we have indexed
                                      vg->removed_lvs for quick lookup.
                                */
#define LV_ERROR_WHEN_FULL  UINT64_C(0x0008000000000000)    /* LV - error when full */
#define PV_ALLOCATION_PROHIBITED    UINT64_C(0x0010000000000000)    /* PV - internal use only - allocation prohibited
                                    e.g. to prohibit allocation of a RAID image
                                    on a PV already holing an image of the RAID set */

#define LV_ERROR_WHEN_FULL  UINT64_C(0x0008000000000000)    /* LV - error when full */
#define PV_ALLOCATION_PROHIBITED    UINT64_C(0x0010000000000000)    /* PV - internal use only - allocation prohibited
                                    e.g. to prohibit allocation of a RAID image
                                    on a PV already holing an image of the RAID set */
#define LOCKD_SANLOCK_LV    UINT64_C(0x0080000000000000)    /* LV - Internal use only */

#define MERGING         UINT64_C(0x0000000010000000)    /* LV SEG */
#define REPLICATOR      UINT64_C(0x0000000020000000)    /* LV -internal use only for replicator */
#define REPLICATOR_LOG      UINT64_C(0x0000000040000000)    /* LV -internal use only for replicator-dev */
#define UNLABELLED_PV       UINT64_C(0x0000000080000000)    /* PV -this PV had no label written yet */

#define CACHE_POOL      UINT64_C(0x0000200000000000)    /* LV - Internal use only */
#define CACHE_POOL_DATA     UINT64_C(0x0000400000000000)    /* LV - Internal use only */
#define CACHE_POOL_METADATA UINT64_C(0x0000800000000000)    /* LV - Internal use only */
#define CACHE           UINT64_C(0x0001000000000000)    /* LV - Internal use only */



enum {
    COMPATIBLE_FLAG = 0x0,
    VG_FLAGS,
    PV_FLAGS,
    LV_FLAGS,
    STATUS_FLAG = 0x8,
};

struct flag {
    const uint64_t mask;
    const char *description;
    int kind;
};

static const struct flag _vg_flags[] = {
    {EXPORTED_VG, "EXPORTED", STATUS_FLAG},
    {RESIZEABLE_VG, "RESIZEABLE", STATUS_FLAG},
    {PVMOVE, "PVMOVE", STATUS_FLAG},
    {LVM_READ, "READ", STATUS_FLAG},
    {LVM_WRITE, "WRITE", STATUS_FLAG},
    {LVM_WRITE_LOCKED, "WRITE_LOCKED", COMPATIBLE_FLAG},
    {CLUSTERED, "CLUSTERED", STATUS_FLAG},
    {SHARED, "SHARED", STATUS_FLAG},
    {PARTIAL_VG, NULL, 0},
    {PRECOMMITTED, NULL, 0},
    {ARCHIVED_VG, NULL, 0},
    {0, NULL, 0}
};

static const struct flag _pv_flags[] = {
    {ALLOCATABLE_PV, "ALLOCATABLE", STATUS_FLAG},
    {EXPORTED_VG, "EXPORTED", STATUS_FLAG},
    {MISSING_PV, "MISSING", COMPATIBLE_FLAG},
    {UNLABELLED_PV, NULL, 0},
    {0, NULL, 0}
};

static const struct flag _lv_flags[] = {
    {LVM_READ, "READ", STATUS_FLAG},
    {LVM_WRITE, "WRITE", STATUS_FLAG},
    {LVM_WRITE_LOCKED, "WRITE_LOCKED", COMPATIBLE_FLAG},
    {FIXED_MINOR, "FIXED_MINOR", STATUS_FLAG},
    {VISIBLE_LV, "VISIBLE", STATUS_FLAG},
    {PVMOVE, "PVMOVE", STATUS_FLAG},
    {LOCKED, "LOCKED", STATUS_FLAG},
    {LV_NOTSYNCED, "NOTSYNCED", STATUS_FLAG},
    {LV_REBUILD, "REBUILD", STATUS_FLAG},
    {LV_WRITEMOSTLY, "WRITEMOSTLY", STATUS_FLAG},
    {LV_ACTIVATION_SKIP, "ACTIVATION_SKIP", COMPATIBLE_FLAG},
    {LV_ERROR_WHEN_FULL, "ERROR_WHEN_FULL", COMPATIBLE_FLAG},
    {LV_NOSCAN, NULL, 0},
    {LV_TEMPORARY, NULL, 0},
    {POOL_METADATA_SPARE, NULL, 0},
    {LOCKD_SANLOCK_LV, NULL, 0},
    {RAID, NULL, 0},
    {RAID_META, NULL, 0},
    {RAID_IMAGE, NULL, 0},
    {MIRROR, NULL, 0},
    {MIRROR_IMAGE, NULL, 0},
    {MIRROR_LOG, NULL, 0},
    {MIRRORED, NULL, 0},
    {VIRTUAL, NULL, 0},
    {SNAPSHOT, NULL, 0},
    {MERGING, NULL, 0},
    {CONVERTING, NULL, 0},
    {PARTIAL_LV, NULL, 0},
    {POSTORDER_FLAG, NULL, 0},
    {VIRTUAL_ORIGIN, NULL, 0},
    {REPLICATOR, NULL, 0},
    {REPLICATOR_LOG, NULL, 0},
    {THIN_VOLUME, NULL, 0},
    {THIN_POOL, NULL, 0},
    {THIN_POOL_DATA, NULL, 0},
    {THIN_POOL_METADATA, NULL, 0},
    {CACHE, NULL, 0},
    {CACHE_POOL, NULL, 0},
    {CACHE_POOL_DATA, NULL, 0},
    {CACHE_POOL_METADATA, NULL, 0},
    {LV_PENDING_DELETE, NULL, 0}, /* FIXME Display like COMPATIBLE_FLAG */
    {LV_REMOVED, NULL, 0},
    {0, NULL, 0}
};

static const struct flag *_get_flags(int type)
{
    switch (type & ~STATUS_FLAG) {
    case VG_FLAGS:
        return _vg_flags;

    case PV_FLAGS:
        return _pv_flags;

    case LV_FLAGS:
        return _lv_flags;
    }

	printk(">>>%s:%d\n", __func__, __LINE__);
    return NULL;
}

static int read_flags(uint64_t *status, int type, const struct dm_config_value *cv)
{
    int f;
    uint64_t s = 0;
    const struct flag *flags;

    if (!(flags = _get_flags(type)))
        return 0;

    if (cv->type == DM_CFG_EMPTY_ARRAY)
        goto out;

    while (cv) {
        if (cv->type != DM_CFG_STRING) {
           // log_error("Status value is not a string.");
			printk(">>>%s:%d\n", __func__, __LINE__);
            return 0;
        }

        for (f = 0; flags[f].description; f++)
            if (!strcmp(flags[f].description, cv->v.str)) {
                s |= flags[f].mask;
                break;
            }

        if (type == VG_FLAGS && !strcmp(cv->v.str, "PARTIAL")) {
            /*
             * Exception: We no longer write this flag out, but it
             * might be encountered in old backup files, so restore
             * it in that case. It is never part of live metadata
             * though, so only vgcfgrestore needs to be concerned
             * by this case.
             */
            s |= PARTIAL_VG;
        } else if (!flags[f].description && (type & STATUS_FLAG)) {
            //log_error("Unknown status flag '%s'.", cv->v.str);
			printk(">>>%s:%d\n", __func__, __LINE__);
            return 0;
        }

        cv = cv->next;
    }

out:
    *status |= s;
    return 1;
}

static int _read_flag_config(const struct dm_config_node *n, uint64_t *status, int type)
{
    const struct dm_config_value *cv;
    *status = 0;

    if (!dm_config_get_list(n, "status", &cv)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    if (!(read_flags(status, type | STATUS_FLAG, cv))) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    if (dm_config_get_list(n, "flags", &cv)) {
        if (!(read_flags(status, type, cv))) {
			printk(">>>%s:%d\n", __func__, __LINE__);
            return 0;
        }
    }

    return 1;
}


static int read_vgname(struct dm_config_node *root,
            struct lvmcache_vgsummary *vgsummary)
{
    const struct dm_config_node *vgn;

    vgsummary->creation_host =
        dm_pool_strdup(dm_config_find_str_allow_empty(root, "creation_host", ""));

    /* skip any top-level values */
    for (vgn = root; (vgn && vgn->v); vgn = vgn->sib) ;

    if (!vgn) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    if (!(vgsummary->vgname = dm_pool_strdup(vgn->key)))
        return 0;

    vgn = vgn->child;

    if (!_read_id(&vgsummary->vgid, vgn, "id")) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    if (!_read_flag_config(vgn, &vgsummary->vgstatus, VG_FLAGS)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    dm_config_get_str(vgn, "lock_type", &vgsummary->lock_type);

    return 1;
}



static int text_vgname_import(struct hyper_rootdev_device *dev,
               off_t offset, uint32_t size,
               off_t offset2, uint32_t size2,
               struct lvmcache_vgsummary *vgsummary)
{
    int r = 0;
	struct dm_config_node *root;

    if (!config_file_read_fd(dev, offset, size,
                     offset2, size2, &root))
        goto out;

    /*
     * Find a set of version functions that can read this file
     */
    if (!check_version(root))
        goto out;

    if (!read_vgname(root, vgsummary))
        goto out;

    r = 1;

out:
    return r;
}

static int id_write_format(const struct id *id, char *buffer, size_t size)
{
	int i, tot;
    static const unsigned group_size[] = { 6, 4, 4, 4, 4, 4, 6 };
    
    /* split into groups separated by dashes */
    if (size < (32 + 6 + 1)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }
        
    for (i = 0, tot = 0; i < 7; i++) {
        memcpy(buffer, id->uuid + tot, group_size[i]);
        buffer += group_size[i];
        tot += group_size[i];
        *buffer++ = '-';
    }

    *--buffer = '\0';

    return 1;
}


static int vgname_from_mda(struct mda_header *mdah, struct device_area *dev_area,
            struct lvmcache_vgsummary *vgsummary, uint64_t *mda_free_sectors)
{
    struct raw_locn *rlocn;
    uint32_t wrap = 0;
    unsigned int len = 0;
    char buf[NAME_LEN + 1] __attribute__((aligned(8)));
    char uuid[64] __attribute__((aligned(8)));
    uint64_t buffer_size, current_usage;
    unsigned used_cached_metadata = 0;

    *mda_free_sectors = ((dev_area->size - MDA_HEADER_SIZE) / 2) >> SECTOR_SHIFT;

    rlocn = mdah->raw_locns;

    if (!rlocn->offset)
        return 0;

    /* Do quick check for a vgname */
    if (!dev_read(dev_area->dev, dev_area->start + rlocn->offset,
              NAME_LEN, buf))
        return 0;

    while (buf[len] && !isspace(buf[len]) && buf[len] != '{' &&
           len < (NAME_LEN - 1))
        len++;

    buf[len] = '\0';

    /* Ignore this entry if the characters aren't permissible */
    if (!validate_name(buf))
        return 0;

    /* We found a VG - now check the metadata */
    if (rlocn->offset + rlocn->size > mdah->size)
        wrap = (uint32_t) ((rlocn->offset + rlocn->size) - mdah->size);

    if (wrap > rlocn->offset)
        return 0;

    /* Did we see this metadata before? */
    vgsummary->mda_checksum = rlocn->checksum;
    vgsummary->mda_size = rlocn->size;

    if (lvmcache_lookup_mda(vgsummary))
        used_cached_metadata = 1;

    /* FIXME 64-bit */
	if (!vgsummary->vgname)
    	if (!text_vgname_import(dev_area->dev,
                (off_t)(dev_area->start + rlocn->offset),
                (uint32_t)(rlocn->size - wrap),
                (off_t)(dev_area->start + MDA_HEADER_SIZE),
                wrap, vgsummary))
        	return 0;

    /* Ignore this entry if the characters aren't permissible */
    if (!validate_name(vgsummary->vgname))
        return 0;

    if (!id_write_format((struct id *)&vgsummary->vgid, uuid, sizeof(uuid)))
        return 0;

    current_usage = (rlocn->size + SECTOR_SIZE - UINT64_C(1)) -
                 (rlocn->size + SECTOR_SIZE - UINT64_C(1)) % SECTOR_SIZE;
    buffer_size = mdah->size - MDA_HEADER_SIZE;

    if (current_usage * 2 >= buffer_size)
        *mda_free_sectors = UINT64_C(0);
    else
        *mda_free_sectors = ((buffer_size - 2 * current_usage) / 2) >> SECTOR_SHIFT;

    return 1;
}

static int lvmcache_update_vgname_and_id(struct lvmcache_info *info, struct lvmcache_vgsummary *vgsummary)
{
    const char *vgname = vgsummary->vgname;
    const char *vgid = (char *)&vgsummary->vgid;
    struct lvmcache_vginfo *vginfo;

    /* If moving PV from orphan to real VG, always mark it valid */
    info->status &= ~CACHE_INVALID;

    if (!(vginfo = kzalloc(sizeof(*vginfo), GFP_KERNEL))) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    vginfo->vgname = vgname;

	INIT_LIST_HEAD(&vginfo->list);
	INIT_LIST_HEAD(&vginfo->infos);

    list_add(&vginfo->list, &vginfo_head);

    list_add(&info->list, &vginfo->infos);
    info->vginfo = vginfo;

    strncpy(vginfo->vgid, vgid, ID_LEN);
    vginfo->vgid[ID_LEN] = '\0';

    vginfo->status = vgsummary->vgstatus;
    vginfo->creation_host = vgsummary->creation_host;
    vginfo->lock_type = vgsummary->lock_type;

    vginfo->mda_checksum = vgsummary->mda_checksum;
    vginfo->mda_size = vgsummary->mda_size;

	printk(">>>%s:%d Added new vginfo\n", __func__, __LINE__);

    return 1;
}

static int update_mda(struct metadata_area *mda, void *baton)
{
    struct _update_mda_baton *p = baton;
    struct mda_context *mdac = (struct mda_context *)mda->metadata_locn;
    struct mda_header *mdah;
    struct lvmcache_vgsummary vgsummary = { 0 };
	unsigned mda_ignored;
    unsigned old_mda_ignored;

	if (!(mdah = kmalloc(MDA_HEADER_SIZE, GFP_KERNEL)))
		goto out;

    if (!raw_read_mda_header(mdah, &mdac->area)) {
		kfree(mdah);
		goto out;
    }

	mda_ignored = (mdah->raw_locns[0].flags & RAW_LOCN_IGNORED ? 1 : 0);
    old_mda_ignored = (mda->status & MDA_IGNORED);
                   
    if (mda_ignored && !old_mda_ignored)
        mda->status |= MDA_IGNORED;
    else if (!mda_ignored && old_mda_ignored)
        mda->status &= ~MDA_IGNORED;

    if (mda->status & MDA_IGNORED)
        return 1;

    if (vgname_from_mda(mdah, &mdac->area, &vgsummary,
                 &mdac->free_sectors) &&
        !lvmcache_update_vgname_and_id(p->info, &vgsummary))
        return 0;

out:
    return 1;
}

static int lvm2_read(struct dev_types *dt, struct hyper_rootdev_device *dev, void *buf,
         struct label **label)
{                         
    struct label_header *lh = (struct label_header *) buf;
    struct pv_header *pvhdr;
    struct pv_header_extension *pvhdr_ext;
    struct lvmcache_info *info;
    struct disk_locn *dlocn_xl;
    uint64_t offset;
    uint32_t ext_version;
    struct _update_mda_baton baton;
    struct metadata_area *mda, *tmp;

    /*
     * PV header base
     */
    pvhdr = (struct pv_header *) ((char *) buf + le32_to_cpu(lh->offset_xl));
    
    if (!(info = lvmcache_add(dt, (char *)pvhdr->pv_uuid, dev)))
        return 0;

    *label = info->label;

	info->device_size = le64_to_cpu(pvhdr->device_size_xl);

    /* Data areas holding the PEs */
    dlocn_xl = pvhdr->disk_areas_xl;
    while ((offset = le64_to_cpu(dlocn_xl->offset))) {
		struct data_area_list *dal;

		dal = kmalloc(sizeof(struct data_area_list), GFP_KERNEL);
		if (dal) {
    		dal->disk_locn.offset = offset;
    		dal->disk_locn.size = le64_to_cpu(dlocn_xl->size);

			INIT_LIST_HEAD(&dal->list);
			list_add(&dal->list, &info->das);
		}

        dlocn_xl++;
    }

    /* Metadata area headers */
    dlocn_xl++;
    while ((offset = le64_to_cpu(dlocn_xl->offset))) {
		struct metadata_area *mdal;
	//	struct mda_lists *mda_lists = (struct mda_lists *) fmt->private;
		struct mda_context *mdac;

		if (!(mdal = kmalloc(sizeof(struct metadata_area), GFP_KERNEL)))
            goto local_fail;
        
		if (!(mdac = kmalloc(sizeof(struct mda_context), GFP_KERNEL))) {
            kfree(mdal);
            goto local_fail;
        }

	//	mdal->ops = mda_lists->raw_ops;
		mdal->metadata_locn = mdac;
		mdal->status = 0;

		mdac->area.dev = dev;
		mdac->area.start = offset;
		mdac->area.size = le64_to_cpu(dlocn_xl->size);
		mdac->free_sectors = 0;
		memset(&mdac->rlocn, 0, sizeof(mdac->rlocn));

		INIT_LIST_HEAD(&mdal->list);
		list_add(&mdal->list, &info->mdas);

local_fail:
        dlocn_xl++;
    }

    dlocn_xl++;

    /*
     * PV header extension
     */
    pvhdr_ext = (struct pv_header_extension *) ((char *) dlocn_xl);
    if (!(ext_version = le32_to_cpu(pvhdr_ext->version)))
        goto out;


    /* Bootloader areas */
    dlocn_xl = pvhdr_ext->bootloader_areas_xl;
    while ((offset = le64_to_cpu(dlocn_xl->offset))) {
		struct data_area_list *dal;

		dal = kmalloc(sizeof(struct data_area_list), GFP_KERNEL);
		if (dal) {
    		dal->disk_locn.offset = offset;
    		dal->disk_locn.size = le64_to_cpu(dlocn_xl->size);

			INIT_LIST_HEAD(&dal->list);
			list_add(&dal->list, &info->bas);
		}

        dlocn_xl++;
    }

out:
    baton.info = info;
    baton.label = *label;

	list_for_each_entry_safe(mda, tmp, &info->mdas, list)
        if (!update_mda(mda, &baton))
            break;

	info->status &= ~CACHE_INVALID;

    return 1;
}


void hyper_gen_parse_root_dev(char *orignal_root_name)
{
	struct dev_types *dts;
	struct list_head dev_head;
	struct hyper_rootdev_device *dev, *tmp;

	parse_init();

	dts = create_dev_types();
	if (!dts)
		return;

	INIT_LIST_HEAD(&dev_head);
	prepare_dev_list(&dev_head);

	open_control(dts);

	INIT_LIST_HEAD(&pv_head);
	INIT_LIST_HEAD(&vginfo_head);

	list_for_each_entry(dev, &dev_head, list) {
        if (my_filter(dts, dev)) {
    		char buf[LABEL_SIZE] __attribute__((aligned(8)));
    		uint64_t sector;
    		int r = 0;
			struct label *label;

			if ((r = find_lvm2_label(dev, buf, &sector))) {
				if ((r = lvm2_read(dts, dev, buf, &label)) && label) {
					label->dev = dev;
					label->sector = sector;
				}
			}
        }
	}


#if 0
	list_for_each_entry_safe(dev, tmp, &head, list) {
			list_del_init(&dev->list);
	}
#endif


	kfree(dts);

	return;
}
