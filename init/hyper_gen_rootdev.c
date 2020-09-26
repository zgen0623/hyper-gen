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
#include <uapi/linux/dm-ioctl.h>

#define DM_EXISTS_FLAG 0x00000004
#define DM_SKIP_BDGET_FLAG  (1 << 9) /* In */

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
#define MDA_INCONSISTENT 0x00000002
#define MDA_FAILED       0x00000004

#define RAW_LOCN_IGNORED 0x00000001
#define NAME_LEN 128


#define lv_is_pvmove(lv)    (((lv)->status & PVMOVE) ? 1 : 0)
#define lv_is_mirror_log(lv)    (((lv)->status & MIRROR_LOG) ? 1 : 0)
#define lv_is_mirror_image(lv)  (((lv)->status & MIRROR_IMAGE) ? 1 : 0)

#define SEG_ONLY_EXCLUSIVE  0x0000000000010000ULL /* In cluster only exlusive activation */
#define seg_only_exclusive(seg) ((seg)->segtype->flags & SEG_ONLY_EXCLUSIVE ? 1 : 0)

#define LCK_LV      0x00000008U /* Logical Volume */
#define LCK_READ    0x00000001U /* LCK$_CRMODE (Activate) */
#define LCK_EXCL    0x00000005U /* LCK$_EXMODE (Exclusive) */
#define LCK_HOLD    0x00000020U /* Hold lock when returns? */
#define LCK_CLUSTER_VG  0x00000080U /* VG is clustered */
#define LCK_LOCAL   0x00000040U /* Don't propagate to other nodes */

#define LCK_LV_EXCLUSIVE    (LCK_LV | LCK_EXCL)
#define LCK_LV_ACTIVATE     (LCK_LV | LCK_READ)

#define seg_is_replicator_dev(seg) ((seg)->segtype->flags & 0x0000000000000200ULL ? 1 : 0)
#define vg_is_clustered(vg) ((vg)->status & CLUSTERED)

#define LCK_LV_CLUSTERED(lv)    \
    (vg_is_clustered((lv)->vg) ? LCK_CLUSTER_VG : 0)

#define lv_is_cache_pool(lv)    (((lv)->status & CACHE_POOL) ? 1 : 0)
#define lv_is_thin_type(lv) (((lv)->status & (THIN_POOL | THIN_VOLUME | THIN_POOL_DATA | THIN_POOL_METADATA)) ? 1 : 0)

#define DM_MAX_TYPE_NAME 16
#define DM_NAME_LEN 128

#define UUID_PREFIX "LVM-"

#define LCK_NONBLOCK    0x00000010U /* Don't block waiting for lock? */

#define SECTION_B_CHAR '{'
#define SECTION_E_CHAR '}'

typedef enum {
    INFO,   /* DM_DEVICE_INFO ioctl */
    STATUS, /* DM_DEVICE_STATUS ioctl */
    MKNODES
} info_type_t;


typedef enum {
    PRELOAD,
    ACTIVATE,
    DEACTIVATE,
    SUSPEND,
    SUSPEND_WITH_LOCKFS,
    CLEAN
} action_t;

struct dev_manager {
    void *target_state;
    uint32_t pvmove_mirror_count;
    int flush_required;
    int activation;                 /* building activation tree */
    int suspend;            /* building suspend tree */
    int skip_external_lv;

    struct list_head pending_delete;  /* str_list of dlid(s) with pending delete */

    unsigned track_pending_delete;
    unsigned track_pvmove_deps;
    
    char *vg_name;
};

struct dm_info {
    int exists;
    int suspended;
    int live_table;
    int inactive_table;     
    int32_t open_count;
    uint32_t event_nr;
    uint32_t major;
    uint32_t minor;     /* minor device number */
    int read_only;      /* 0:read-write; 1:read-only */
    int32_t target_count;
    int deferred_remove;
    int internal_suspend;
};

struct load_properties {
    int read_only;
    uint32_t major;
    uint32_t minor;

    uint32_t read_ahead;
    uint32_t read_ahead_flags;

    unsigned segment_count;
    int size_changed;

   // struct dm_list segs;
    struct list_head segs;

    const char *new_name;
    unsigned immediate_dev_node;

    unsigned delay_resume_if_new;

    unsigned send_messages;
    /* Skip suspending node's children, used when sending messages to thin-pool */
    int skip_suspend;
};


struct dm_tree;
struct dm_tree_node;
typedef enum {
    DM_NODE_CALLBACK_PRELOADED,   /* Node has preload deps */
    DM_NODE_CALLBACK_DEACTIVATED, /* Node is deactivated */
} dm_node_callback_t;


typedef int (*dm_node_callback_fn) (struct dm_tree_node *node,
                    dm_node_callback_t type, void *cb_data);

struct dm_tree_node {
    struct dm_tree *dtree;

    const char *name;
    const char *uuid;
    struct dm_info info;

	dev_t dev;
	struct list_head dev_hash_list;
	struct list_head uuid_hash_list;


//    struct dm_list uses;        /* Nodes this node uses */
    struct list_head uses;        /* Nodes this node uses */
    //struct dm_list used_by;     /* Nodes that use this node */
    struct list_head used_by;     /* Nodes that use this node */

    int activation_priority;    /* 0 gets activated first */
    int implicit_deps;      /* 1 device only implicitly referenced */

    uint16_t udev_flags;        /* Udev control flags */

    void *context;          /* External supplied context */

    struct load_properties props;   /* For creation/table (re)load */

    struct dm_tree_node *presuspend_node;

    /* Callback */
    dm_node_callback_fn callback;
    void *callback_data;

//    struct dm_list activated;   /* Head of activated nodes for preload revert */
    struct list_head activated;   /* Head of activated nodes for preload revert */
    //struct dm_list activated_list;  /* List of activated nodes for preload revert */
    struct list_head activated_list;  /* List of activated nodes for preload revert */
};


struct dm_tree {
//    struct dm_pool *mem;

//    struct dm_hash_table *devs;
    struct list_head devs;

//	struct dm_hash_table *uuids;
	struct list_head uuids;

    struct dm_tree_node root;

    int skip_lockfs;        /* 1 skips lockfs (for non-snapshots) */
    int no_flush;           /* 1 sets noflush (mirrors/multipath) */
    int retry_remove;       /* 1 retries remove if not successful */
    uint32_t cookie;
    char buf[DM_NAME_LEN + 32]; /* print buffer for device_name (major:minor) */
    const char **optional_uuid_suffixes;    /* uuid suffixes ignored when matching */
};


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



struct text_fid_context {
    char *raw_metadata_buf;
    uint32_t raw_metadata_buf_size;
};

struct format_instance {
 //   unsigned ref_count; /* Refs to this fid from VG and PV structs */
//    struct dm_pool *mem;

 //   uint32_t type; 
  //  const struct format_type *fmt;
    
    /*
     * Each mda in a vg is on exactly one of the below lists.
     * MDAs on the 'in_use' list will be read from / written to
     * disk, while MDAs on the 'ignored' list will not be read
     * or written to.
     */
    /* FIXME: Try to use the index only. Remove these lists. */
	char *vgname;

//    struct dm_list metadata_areas_in_use;
	struct list_head metadata_areas_in_use;
  //  struct dm_list metadata_areas_ignored;
    struct list_head metadata_areas_ignored;

   // struct dm_hash_table *metadata_areas_index;
    struct list_head metadata_areas_index;

    struct text_fid_context fid_ctx;
};

struct id {
    char uuid[ID_LEN];
};

struct volume_group;
struct logical_volume;
struct lv_segment;
struct dm_config_node;
struct lvmcache_vginfo;

struct lv_activate_opts {
    int exclusive;
    int origin_only;
    int no_merging;
    int send_messages;
    int skip_in_use;
    unsigned revert;
    unsigned read_only;
    unsigned noscan;
    unsigned temporary;
};
struct dm_tree_node;

struct segtype_handler {
    const char *(*name) (const struct lv_segment *seg);
    const char *(*target_name) (const struct lv_segment *seg,
                    const struct lv_activate_opts *laopts);
    int (*text_import_area_count) (const struct dm_config_node *sn,
                       uint32_t *area_count);
    int (*text_import) (struct lv_segment *seg,
                const struct dm_config_node *sn,
                struct list_head *pv_hash);
    int (*merge_segments) (struct lv_segment *seg1,
                   struct lv_segment *seg2);
    int (*add_target_line) (struct dev_manager *dm,
                struct lv_segment *seg,
                struct dm_tree_node *node, uint64_t len);
#if 0
    int (*target_status_compatible) (const char *type);
    int (*check_transient_status) (struct lv_segment *seg, char *params);
    int (*target_percent) (void **target_state,
                   dm_percent_t *percent,
                   struct dm_pool * mem,
                   struct cmd_context *cmd,
                   struct lv_segment *seg, char *params,
                   uint64_t *total_numerator,
                   uint64_t *total_denominator);
    int (*target_present) (struct cmd_context *cmd,
                   const struct lv_segment *seg,
                   unsigned *attributes);
    int (*modules_needed) (struct dm_pool *mem,
                   const struct lv_segment *seg,
                   struct dm_list *modules);
    void (*destroy) (struct segment_type * segtype);
    int (*target_monitored) (struct lv_segment *seg, int *pending);
    int (*target_monitor_events) (struct lv_segment *seg, int events);
    int (*target_unmonitor_events) (struct lv_segment *seg, int events);
#endif
};


struct segment_type {
    //struct dm_list list;        /* Internal */
    struct list_head list;        /* Internal */
    
    uint64_t flags;
    uint32_t parity_devs;       /* Parity drives required by segtype */
                
    struct segtype_handler *ops;
    const char *name;
    
    void *library;          /* lvm_register_segtype() sets this. */
    void *private;          /* For the segtype handler to use. */
}; 

struct physical_volume {
    struct id id;
    struct id old_id;       /* Set during pvchange -u. */
    struct hyper_rootdev_device *dev;
  //  const struct format_type *fmt;
    struct format_instance *fid;

    /*
     * vg_name and vgid are used before the parent VG struct exists.
     * FIXME: Investigate removal/substitution with 'vg' fields.
     */
    const char *vg_name;
    struct id vgid;
    struct volume_group *vg;

    uint64_t status;
    uint64_t size;

    /* bootloader area */
    uint64_t ba_start;
    uint64_t ba_size;

    /* physical extents */
    uint32_t pe_size;
    uint64_t pe_start;
    uint32_t pe_count;
    uint32_t pe_alloc_count;
    unsigned long pe_align;
    unsigned long pe_align_offset;
    uint64_t is_labelled:1;

        /* NB. label_sector is valid whenever is_labelled is true */
    uint64_t label_sector;

//    struct dm_list segments;    /* Ordered pv_segments covering complete PV */
    struct list_head segments;    /* Ordered pv_segments covering complete PV */

 //   struct dm_list tags;
    struct list_head tags;

	char *pvn_key;
    struct list_head list;
};


struct pv_segment {
  //  struct dm_list list;    /* Member of pv->segments: ordered list
   //              * covering entire data area on this PV */
	struct list_head list;
        
    struct physical_volume *pv;
    uint32_t pe;
    uint32_t len;
            
    struct lv_segment *lvseg;   /* NULL if free space */
    uint32_t lv_area;   /* Index to area in LV segment */
};  

typedef enum {
    AREA_UNASSIGNED,
    AREA_PV,
    AREA_LV
} area_type_t;

struct lv_segment_area {
    area_type_t type;
    union {
        struct {
            struct pv_segment *pvseg;
        } pv;
        struct {
            struct logical_volume *lv;
            uint32_t le;
        } lv;
    } u;
};

struct lv_segment {
    //struct dm_list list;
    struct list_head list;
    struct logical_volume *lv;

    const struct segment_type *segtype;
    uint32_t le;
    uint32_t len;

    uint64_t status;

    /* FIXME Fields depend on segment type */
    uint32_t stripe_size;   /* For stripe and RAID - in sectors */
    uint32_t writebehind;   /* For RAID (RAID1 only) */
    uint32_t min_recovery_rate; /* For RAID */
    uint32_t max_recovery_rate; /* For RAID */
    uint32_t area_count;
    uint32_t area_len;
    uint32_t chunk_size;    /* For snapshots/thin_pool.  In sectors. */

    struct logical_volume *origin;  /* snap and thin */
    struct logical_volume *merge_lv; /* thin, merge descendent lv into this ancestor */
    struct logical_volume *cow;

    //struct dm_list origin_list;
    struct list_head origin_list;

    uint32_t region_size;   /* For mirrors, replicators - in sectors */
    uint32_t extents_copied;
    struct logical_volume *log_lv;
    struct lv_segment *pvmove_source_seg;
    void *segtype_private;

    //struct dm_list tags;
    struct list_head tags;

    struct lv_segment_area *areas;
    struct lv_segment_area *meta_areas; /* For RAID */

    struct logical_volume *metadata_lv; /* For thin_pool */
    uint64_t transaction_id;        /* For thin_pool, thin */
    unsigned zero_new_blocks;       /* For thin_pool */
 //   thin_discards_t discards;       /* For thin_pool */

    //struct dm_list thin_messages;       /* For thin_pool */
    struct list_head thin_messages;       /* For thin_pool */

    struct logical_volume *external_lv; /* For thin */
    struct logical_volume *pool_lv;     /* For thin, cache */

    uint32_t device_id;         /* For thin, 24bit */
    uint64_t feature_flags;         /* For cache_pool */
    const char *policy_name;        /* For cache_pool */
    struct dm_config_node *policy_settings; /* For cache_pool */
    unsigned cleaner_policy;        /* For cache */

    struct logical_volume *replicator;/* For replicator-devs - link to replicator LV */
    struct logical_volume *rlog_lv; /* For replicators */
    const char *rlog_type;      /* For replicators */
    uint64_t rdevice_index_highest; /* For replicators */
    unsigned rsite_index_highest;   /* For replicators */
};

union lvid {
    struct id id[2];
    char s[2 * sizeof(struct id) + 1 + 7];
};

typedef enum {
    ALLOC_INVALID,
    ALLOC_CONTIGUOUS,
    ALLOC_CLING,
    ALLOC_CLING_BY_TAGS,    /* Internal - never written or displayed. */
    ALLOC_NORMAL,
    ALLOC_ANYWHERE,
    ALLOC_INHERIT
} alloc_policy_t;


struct logical_volume {
    union lvid lvid;
    const char *name;

    struct volume_group *vg;

    uint64_t status;
    alloc_policy_t alloc;
  //  struct profile *profile;
    uint32_t read_ahead;
    int32_t major;
    int32_t minor;

    uint64_t size;      /* Sectors visible */
    uint32_t le_count;  /* Logical extents visible */

    uint32_t origin_count;
    uint32_t external_count;

   // struct dm_list snapshot_segs;
    struct list_head snapshot_segs;

    struct lv_segment *snapshot;


//    struct replicator_device *rdevice;/* For replicator-devs, rimages, slogs - reference to rdevice */
   // struct dm_list rsites;  /* For replicators - all sites */
    struct list_head rsites;  /* For replicators - all sites */

  //  struct dm_list segments;
    struct list_head segments;

    //struct dm_list tags;
    struct list_head tags;

    //struct dm_list segs_using_this_lv;
    struct list_head segs_using_this_lv;

    uint64_t timestamp;
    unsigned new_lock_args:1;
    const char *hostname;
    const char *lock_args;

    struct list_head list;
};



struct volume_group {
 //   struct cmd_context *cmd;
 //   struct dm_pool *vgmem;
    struct format_instance *fid;
//    const struct format_type *original_fmt; /* Set when processing backup files */
    struct lvmcache_vginfo *vginfo;

 //   struct dm_list *cmd_vgs;/* List of wanted/locked and opened VGs */
    struct list_head *cmd_vgs;/* List of wanted/locked and opened VGs */

    uint32_t cmd_missing_vgs;/* Flag marks missing VG */
    uint32_t seqno;     /* Metadata sequence number */
    unsigned skip_validate_lock_args : 1;

    struct volume_group *vg_ondisk;
 //   struct dm_config_tree *cft_precommitted; /* Precommitted metadata */
    struct volume_group *vg_precommitted; /* Parsed from cft */

    alloc_policy_t alloc;
 //   struct profile *profile;
    uint64_t status;

    struct id id;
    const char *name;
    const char *old_name;       /* Set during vgrename and vgcfgrestore */
    const char *system_id;
    char *lvm1_system_id;
    const char *lock_type;
    const char *lock_args;
    uint32_t extent_size;
    uint32_t extent_count;
    uint32_t free_count;

    uint32_t max_lv;
    uint32_t max_pv;

    /* physical volumes */
    uint32_t pv_count;
 //   struct dm_list pvs;
    struct list_head pvs;

    //struct dm_list pvs_to_create;
    struct list_head pvs_to_create;

  //  struct dm_list pvs_outdated;
    struct list_head pvs_outdated;

    //struct dm_list lvs;
    struct list_head lvs;

//    struct dm_list tags;
    struct list_head tags;

    //struct dm_list removed_lvs;
    struct list_head removed_lvs;

    /*
     * List of removed physical volumes by pvreduce.
     * They have to get cleared on vg_commit.
     */
    //struct dm_list removed_pvs;
    struct list_head removed_pvs;

    uint32_t open_mode; /* FIXME: read or write - check lock type? */

    /*
     * Store result of the last vg_read().
     * 0 for success else appropriate FAILURE_* bits set.
     */
    uint32_t read_status;
    uint32_t mda_copies; /* target number of mdas for this VG */

//    struct dm_hash_table *hostnames; /* map of creation hostnames */
    struct logical_volume *pool_metadata_spare_lv; /* one per VG */
    struct logical_volume *sanlock_lv; /* one per VG */
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
    struct volume_group *cached_vg;
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

struct lvmcache_vgsummary {
    const char *vgname;
    struct id vgid;
    uint64_t vgstatus;
    char *creation_host;
    const char *lock_type;
    uint32_t mda_checksum;
    size_t mda_size;
}; 

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


int my_dev_create(struct dm_ioctl *param);
void *my_dm_open(void);
void my_get_dm_version(uint32_t *version);
int my_dm_get_uuid_by_dev(dev_t dev, char *uuid, int length);
static struct dm_tree_node *_create_dm_tree_node(struct dm_tree *dtree,
                         const char *name,
                         const char *uuid,
                         struct dm_info *info,
                         void *context,
                         uint16_t udev_flags);
static int _add_to_toplevel(struct dm_tree_node *node);
static int _add_to_bottomlevel(struct dm_tree_node *node);
static int _uuid_prefix_matches(const char *uuid, const char *uuid_prefix, size_t uuid_prefix_len);
static void *dm_alloc(size_t length, bool zero);
static void dm_free(void *ptr);


static uint32_t _dm_device_major = 0;

static char *real_root_dev_name;
static char *vgname;
static char *lvname;

static void **dm_alloc_array = NULL;
static uint32_t dm_alloc_array_size = 0;
static uint32_t dm_alloc_array_cnt = 0;


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
static struct list_head segtypes_head;
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
		goto fail;
	}

//	dts = kzalloc(sizeof(struct dev_types), GFP_KERNEL);
	dts = dm_alloc(sizeof(struct dev_types), true);
	if (!dts) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		goto fail;
	}

	if ((fd = sys_open((const char __user *)"/proc/devices", O_RDONLY, 0)) < 0) {
		printk(">>>%s:%d\n", __func__, __LINE__);
//		kfree(dts);
		dm_free(dts);
		dts = NULL;
		goto fail;
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

fail:
	if (fd >= 0)
		sys_close(fd);
	kfree(buf);
	return dts;
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
	int fd = -1;
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
		goto fail;
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

		//		path = kmalloc(4 + strlen(dirent->d_name) + 2, GFP_KERNEL);
				path = dm_alloc(4 + strlen(dirent->d_name) + 2, false);
				sprintf(path, "/dev/%s", dirent->d_name);

				_collapse_slashes(path);

				if (sys_stat(path, (struct __old_kernel_stat __user *)&tinfo) < 0) {
					printk(">>>%s:%d\n", __func__, __LINE__);
		//			kfree(path);
					dm_free(path);
					goto out;
				}

				if (!S_ISDIR(tinfo.st_mode) && S_ISBLK(tinfo.st_mode)) {
					struct hyper_rootdev_device *dev = NULL;
					int found = 0;

					list_for_each_entry(dev, dev_head, list)
						if (dev->dev == tinfo.st_rdev)
							found = 1;

					if (!found) {
			//			dev = kzalloc(sizeof(struct hyper_rootdev_device), GFP_KERNEL);
						dev = dm_alloc(sizeof(struct hyper_rootdev_device), true);
						dev->dev = tinfo.st_rdev;
						dev->path = path;

						init_dev(dev);

						INIT_LIST_HEAD(&dev->list);
						list_add(&dev->list, dev_head);

						printk(">>>%s:%d path=%s dev_t=%x\n", __func__, __LINE__, path, dev->dev);
					}
				}
            }
out:
			dirent = (void *)dirent + dirent->d_reclen;
		}
	}

fail:
	kfree(buf);
	if (fd >= 0)
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
	int fd = -1;
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
	if (fd >= 0)
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

    if (((uintptr_t) align_buffer) & mask) {
        align_buffer = (char *)(((uintptr_t)align_buffer + mask) & ~mask);
	}

    if (sys_lseek(dev->fd, align_offset, SEEK_SET) == (off_t) -1)
		goto out;

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

out:
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

static int lvm2_find_label(struct hyper_rootdev_device *dev, char *buf,
                       uint64_t *label_sector)
{
    struct label_header *lh;
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
		if (!strcmp(pv->pvid, pvid))
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

//	pv = kmalloc(sizeof(struct pv_node), GFP_KERNEL);
	pv = dm_alloc(sizeof(struct pv_node), false);

	pv->info = info;
	pv->pvid = info->dev->pvid;

	INIT_LIST_HEAD(&pv->list);
	list_add(&pv->list, &pv_head);

	printk(">>>%s:%d Added a new pv\n", __func__, __LINE__);

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

//	if (!(label = kzalloc(sizeof(struct label), GFP_KERNEL)))
	if (!(label = dm_alloc(sizeof(struct label), true)))
        return NULL;

	strncpy(label->type, LVM2_LABEL, sizeof(label->type));

//	if (!(info = kzalloc(sizeof(struct lvmcache_info), GFP_KERNEL))) {
	if (!(info = dm_alloc(sizeof(struct lvmcache_info), true))) {
       // kfree(label);
        dm_free(label);
        return NULL;
    }

    label->info = info;
    info->label = label;
    info->dev = dev;

	INIT_LIST_HEAD(&info->list);
	INIT_LIST_HEAD(&info->mdas);
	INIT_LIST_HEAD(&info->das);
	INIT_LIST_HEAD(&info->bas);

    info->status |= CACHE_INVALID;

    if (!lvmcache_update_pvid(info, pvid_s)) {
     //   kfree(info);
		dm_free(info);
      //  kfree(label);
		dm_free(label);
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

//	str = kmalloc(len + 1, GFP_KERNEL);
	str = dm_alloc(len + 1, false);
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

  //  if (!(n = kzalloc(sizeof(struct dm_config_node), GFP_KERNEL)))
    if (!(n = dm_alloc(sizeof(struct dm_config_node), true)))
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

 //   v = kzalloc(sizeof(struct dm_config_value), GFP_KERNEL);
    v = dm_alloc(sizeof(struct dm_config_value), true);
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
   // 		if (!(h = kzalloc(sizeof(struct dm_config_value), GFP_KERNEL))) {
    		if (!(h = dm_alloc(sizeof(struct dm_config_value), true))) {
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

    if (p->t == TOK_STRING_ESCAPED) {
        if (!(str = _dup_string_tok(p)))
            return NULL;

		dm_unescape_double_quotes(str);
        match_aux(p, TOK_STRING_ESCAPED);
    } else if (p->t == TOK_STRING) {
        if (!(str = _dup_string_tok(p)))
            return NULL;

        match_aux(p, TOK_STRING);
    } else {
        if (!(str = _dup_tok(p->tb, p->te)))
            return NULL;
        
        match_aux(p, TOK_IDENTIFIER);
    }

    if (!strlen(str)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return NULL;
    }

    root = _find_or_make_node(parent, str, 1);

    if (p->t == TOK_SECTION_B) {
        match_aux(p, TOK_SECTION_B);

        while (p->t != TOK_SECTION_E)
            if (!(_section(p, root)))
                return NULL;

        match_aux(p, TOK_SECTION_E);
    } else {
        match_aux(p, TOK_EQ);

        if (!(value = _value(p)))
            return NULL;

        root->v = value;
    }

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

 //   if (!(p = kzalloc(sizeof(*p), GFP_KERNEL)))
    if (!(p = dm_alloc(sizeof(*p), true)))
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
 //   char *ret = kmalloc(strlen(str) + 1, GFP_KERNEL);
    char *ret = dm_alloc(strlen(str) + 1, false);

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

	list_for_each_entry(vginfo, &vginfo_head, list) {
        if (!strcmp(vgname, vginfo->vgname) &&
				!strncmp(vgid, vginfo->vgid, ID_LEN)) {
    		list_add(&info->list, &vginfo->infos);
    		info->vginfo = vginfo;
			return 1;
        }
    }

//    if (!(vginfo = kzalloc(sizeof(*vginfo), GFP_KERNEL))) {
    if (!(vginfo = dm_alloc(sizeof(*vginfo), true))) {
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

//	if (!(mdah = kmalloc(MDA_HEADER_SIZE, GFP_KERNEL)))
	if (!(mdah = dm_alloc(MDA_HEADER_SIZE, false)))
		goto out;

    if (!raw_read_mda_header(mdah, &mdac->area)) {
//		kfree(mdah);
		dm_free(mdah);
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

static int lvm2_label_read(struct dev_types *dt, struct hyper_rootdev_device *dev, void *buf,
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

//		dal = kmalloc(sizeof(struct data_area_list), GFP_KERNEL);
		dal = dm_alloc(sizeof(struct data_area_list), false);
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
		struct mda_context *mdac;

		//if (!(mdal = kmalloc(sizeof(struct metadata_area), GFP_KERNEL)))
		if (!(mdal = dm_alloc(sizeof(struct metadata_area), false)))
            goto local_fail;
        
	//	if (!(mdac = kmalloc(sizeof(struct mda_context), GFP_KERNEL))) {
		if (!(mdac = dm_alloc(sizeof(struct mda_context), false))) {
         //   kfree(mdal);
            dm_free(mdal);
            goto local_fail;
        }

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

//		dal = kmalloc(sizeof(struct data_area_list), GFP_KERNEL);
		dal = dm_alloc(sizeof(struct data_area_list), false);
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

static int fid_add_mdas(struct format_instance *fid, struct list_head *mdas,
         const char *key, size_t key_len)
{   
    struct metadata_area *mda;
	struct metadata_area *new_mdal;
	struct mda_context *new_mdac;
    
	list_for_each_entry(mda, mdas, list) {
	//	if (!(new_mdal = kmalloc(sizeof(struct metadata_area), GFP_KERNEL)))
		if (!(new_mdal = dm_alloc(sizeof(struct metadata_area), false)))
            continue;

    	memcpy(new_mdal, mda, sizeof(*mda));
        
//		if (!(new_mdac = kmalloc(sizeof(struct mda_context), GFP_KERNEL))) {
		if (!(new_mdac = dm_alloc(sizeof(struct mda_context), false))) {
          //  kfree(new_mdal);
            dm_free(new_mdal);
            continue;
        }
		memcpy(new_mdac, mda->metadata_locn, sizeof(*new_mdac));

		new_mdal->metadata_locn = new_mdac;
    	INIT_LIST_HEAD(&new_mdal->list);

		if (new_mdal->status & MDA_IGNORED) {
			list_add(&new_mdal->list, &fid->metadata_areas_ignored);
			printk(">>>%s:%d Added a ignored mda\n", __func__, __LINE__);
		} else {
			list_add(&new_mdal->list, &fid->metadata_areas_in_use);
			printk(">>>%s:%d Added a in-use mda\n", __func__, __LINE__);
		}

    }

    return 1;
}

static int _create_vg_text_instance(struct format_instance *fid)
{
    struct lvmcache_vginfo *vginfo;
    struct lvmcache_info *info;
	int found = 0;

	list_for_each_entry(vginfo, &vginfo_head, list) {
        if (!strcmp(fid->vgname, vginfo->vgname)) {
			found = 1;
			break;
        }
    }

	if (!found)
		goto out;


	list_for_each_entry(info, &vginfo->infos, list)
        if (!fid_add_mdas(fid, &info->mdas, info->dev->pvid, ID_LEN))
            goto out; 

out:
    return 1;
}


static struct raw_locn *_find_vg_rlocn(struct device_area *dev_area,
                       struct mda_header *mdah,
                       const char *vgname)
{
    size_t len;
    char vgnamebuf[NAME_LEN + 2] __attribute__((aligned(8)));
    struct raw_locn *rlocn, *rlocn_precommitted;

    rlocn = mdah->raw_locns;    /* Slot 0 */
    rlocn_precommitted = rlocn + 1; /* Slot 1 */

    /* Do not check non-existent metadata. */
    if (!rlocn->offset && !rlocn->size)
        return NULL;

    if (!*vgname)
        return rlocn;

    if (!dev_read(dev_area->dev, dev_area->start + rlocn->offset,
              sizeof(vgnamebuf), vgnamebuf))
        goto bad;

    if (!strncmp(vgnamebuf, vgname, len = strlen(vgname)) &&
        (isspace(vgnamebuf[len]) || vgnamebuf[len] == '{'))
        return rlocn;

bad:
	printk(">>>%s:%d\n", __func__, __LINE__);

    return NULL;
}

static struct volume_group *alloc_vg(const char *vg_name)
{
    struct volume_group *vg;

 //   if (!(vg = kzalloc(sizeof(*vg), GFP_KERNEL))) {
    if (!(vg = dm_alloc(sizeof(*vg), true))) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return NULL;
	}

	vg->name = vg_name;
    vg->system_id = "";
    vg->alloc = ALLOC_NORMAL;
	INIT_LIST_HEAD(&vg->pvs);
	INIT_LIST_HEAD(&vg->pvs_to_create);
	INIT_LIST_HEAD(&vg->pvs_outdated);
	INIT_LIST_HEAD(&vg->lvs);
	INIT_LIST_HEAD(&vg->tags);
	INIT_LIST_HEAD(&vg->removed_lvs);
	INIT_LIST_HEAD(&vg->removed_pvs);

    return vg;
}

static int dm_config_get_uint32(const struct dm_config_node *cn, const char *path,
             uint32_t *result)
{
    const struct dm_config_node *n;

    n = dm_config_find_node(cn, path);

    if (!n || !n->v || n->v->type != DM_CFG_INT)
        return 0;

    if (result)
        *result = n->v->v.i;

    return 1;
}

static int dm_config_get_uint64(const struct dm_config_node *cn, const char *path,
             uint64_t *result)
{
    const struct dm_config_node *n;

    n = dm_config_find_node(cn, path);

    if (!n || !n->v || n->v->type != DM_CFG_INT)
        return 0;

    if (result)
        *result = (uint64_t) n->v->v.i;

    return 1;
}

#define _read_int32(root, path, result) \
    dm_config_get_uint32(root, path, (uint32_t *) result) 
             
#define _read_uint32(root, path, result) \
    dm_config_get_uint32(root, path, result)

#define _read_uint64(root, path, result) \
    dm_config_get_uint64(root, path, result)

static int dm_config_get_section(const struct dm_config_node *cn, const char *path,
              const struct dm_config_node **result)
{
    const struct dm_config_node *n;
    
    n = dm_config_find_node(cn, path);
    if (!n || n->v)
        return 0;
            
    if (result)
        *result = n;

    return 1;
}

static int dm_config_has_node(const struct dm_config_node *cn, const char *path)
{       
    return dm_config_find_node(cn, path) ? 1 : 0;
} 

struct str_node {
	char *str;
	struct list_head list;
};

static int str_list_match_item(const struct list_head *sll, const char *str)
{
	struct str_node *node;

	list_for_each_entry(node, sll, list)
        if (!strcmp(str, node->str))
        	return 1;

    return 0;
}

static int str_list_add_no_dup_check(struct list_head *sll, const char *str)
{
	struct str_node *node;
    
    if (!str)
        return 0;
    
//	node = kmalloc(sizeof(struct str_node), GFP_KERNEL);
	node = dm_alloc(sizeof(struct str_node), false);
	if (!node)
		return 0;
    
    node->str = str;

    list_add(&node->list, sll);
    
    return 1;
}

static int str_list_add(struct list_head *sll, const char *str)
{       
    if (!str)
        return 0;
        
    /* Already in list? */
    if (str_list_match_item(sll, str))
        return 1;

	return str_list_add_no_dup_check(sll, str);
}

static int _read_str_list(struct list_head *list, const struct dm_config_value *cv)
{
    if (cv->type == DM_CFG_EMPTY_ARRAY)
        return 1;

    while (cv) {
        if (cv->type != DM_CFG_STRING) {
			printk(">>>%s:%d\n", __func__, __LINE__);
          //  log_error("Found an item that is not a string");
            return 0;
        }

        if (!str_list_add(list, dm_pool_strdup(cv->v.str)))
            return 0;

        cv = cv->next;
    }

    return 1;
}

typedef int (*section_fn) (struct format_instance *fid,
               struct volume_group *vg, const struct dm_config_node *pvn,
               const struct dm_config_node *vgn,
               struct list_head *pv_hash,
               struct list_head *lv_hash,
               unsigned *scan_done_once,
               unsigned report_missing_devices);


static int _read_sections(struct format_instance *fid,
              const char *section, section_fn fn,
              struct volume_group *vg, const struct dm_config_node *vgn,
              struct list_head *pv_hash,
              struct list_head *lv_hash,
              int optional,
              unsigned *scan_done_once)
{
    const struct dm_config_node *n;
    /* Only report missing devices when doing a scan */
    unsigned report_missing_devices = scan_done_once ? !*scan_done_once : 1;

    if (!dm_config_get_section(vgn, section, &n)) {
        if (!optional) {
            //log_error("Couldn't find section '%s'.", section);
			printk(">>>%s:%d\n", __func__, __LINE__);
            return 0;
        }

        return 1;
    }

    for (n = n->child; n; n = n->sib) {
        if (!fn(fid, vg, n, vgn, pv_hash, lv_hash,
            	scan_done_once, report_missing_devices))
            return 0;
    }

    return 1;
}

static struct pv_segment *_alloc_pv_segment(struct physical_volume *pv,
                        uint32_t pe, uint32_t len,
                        struct lv_segment *lvseg,
                        uint32_t lv_area)
{
    struct pv_segment *peg;

//    if (!(peg = kzalloc(sizeof(*peg), GFP_KERNEL))) {
    if (!(peg = dm_alloc(sizeof(*peg), true))) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return NULL;
    }   
              
    peg->pv = pv;
    peg->pe = pe;
    peg->len = len;
    peg->lvseg = lvseg;
    peg->lv_area = lv_area;
    
    INIT_LIST_HEAD(&peg->list);
    
    return peg;
} 

static int alloc_pv_segment_whole_pv(struct physical_volume *pv)
{           
    struct pv_segment *peg;
        
    if (!pv->pe_count)
        return 1;
                
    /* FIXME Cope with holes in PVs */
    if (!(peg = _alloc_pv_segment(pv, 0, pv->pe_count, NULL, 0)))
        return 0;
                 
    list_add(&peg->list, &pv->segments);

    return 1;
}

struct pv_list {
    struct list_head list;
    struct physical_volume *pv;
    struct list_head *mdas;   /* Metadata areas */
    struct list_head *pe_ranges;  /* Ranges of PEs e.g. for allocation */
}; 

static int _read_pv(struct format_instance *fid,
			struct volume_group *vg, const struct dm_config_node *pvn,
            const struct dm_config_node *vgn __attribute__((unused)),
            struct list_head *pv_hash,
            struct list_head *lv_hash __attribute__((unused)),
            unsigned *scan_done_once,
            unsigned report_missing_devices)
{
    struct physical_volume *pv;
    struct pv_list *pvl;
    const struct dm_config_value *cv;
    uint64_t size, ba_start;
	struct pv_node *pv_node;
	int found = 0;
    int outdated = !strcmp(pvn->parent->key, "outdated_pvs");

//    if (!(pvl = kzalloc(sizeof(*pvl), GFP_KERNEL)) ||
    if (!(pvl = dm_alloc(sizeof(*pvl), true)))
		return 0;

  //  if (!(pvl->pv = kzalloc(sizeof(*pvl->pv), GFP_KERNEL)))
    if (!(pvl->pv = dm_alloc(sizeof(*pvl->pv), true))) {
		dm_free(pvl);
        return 0;
	}

    pv = pvl->pv;

	INIT_LIST_HEAD(&pv->list);
	pv->pvn_key = pvn->key;
	list_add(&pv->list, pv_hash);

    if (!(pvn = pvn->child)) {
  //      log_error("Empty pv section.");
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    if (!_read_id(&pv->id, pvn, "id")) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        //log_error("Couldn't read uuid for physical volume.");
        return 0;
    }

    pv->is_labelled = 1; /* All format_text PVs are labelled. */

	list_for_each_entry(pv_node, &pv_head, list)
		if (!strcmp(pv_node->pvid, pv->id.uuid)) {
			pv->dev = pv_node->info->dev;
			found = 1;
		}

	if (!found)
		printk(">>>%s:%d\n", __func__, __LINE__);

    if (!(pv->vg_name = dm_pool_strdup(vg->name)))
        return 0;

    memcpy(&pv->vgid, &vg->id, sizeof(vg->id));

    if (!outdated && !_read_flag_config(pvn, &pv->status, PV_FLAGS)) {
        //log_error("Couldn't read status flags for physical volume.");
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    if (!pv->dev)
        pv->status |= MISSING_PV;

    if ((pv->status & MISSING_PV) && pv->dev) {
        pv->status &= ~MISSING_PV;
        //log_info("Recovering a previously MISSING PV %s with no MDAs.",
         //    pv_dev_name(pv));
		printk(">>>%s:%d\n", __func__, __LINE__);
    }

    /* Late addition */
    if (dm_config_has_node(pvn, "dev_size") &&
        !_read_uint64(pvn, "dev_size", &pv->size)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        //log_error("Couldn't read dev size for physical volume.");
        return 0;
    }

    if (!outdated && !_read_uint64(pvn, "pe_start", &pv->pe_start)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        //log_error("Couldn't read extent start value (pe_start) "
         //     "for physical volume.");
        return 0;
    }

    if (!outdated && !_read_int32(pvn, "pe_count", &pv->pe_count)) {
        //log_error("Couldn't find extent count (pe_count) for "
         //     "physical volume.");
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    /* Bootloader area is not compulsory - just log_debug for the record if found. */
    ba_start = size = 0;
    _read_uint64(pvn, "ba_start", &ba_start);
    _read_uint64(pvn, "ba_size", &size);

    if (ba_start && size) {
        pv->ba_start = ba_start;
        pv->ba_size = size;
    } else if ((!ba_start && size) || (ba_start && !size)) {
        //log_error("Found incomplete bootloader area specification "
         //     "for PV %s in metadata.", pv_dev_name(pv));
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    //dm_list_init(&pv->tags);
	INIT_LIST_HEAD(&pv->tags);
    //dm_list_init(&pv->segments);
	INIT_LIST_HEAD(&pv->segments);

    /* Optional tags */
    if (dm_config_get_list(pvn, "tags", &cv) &&
        !(_read_str_list(&pv->tags, cv))) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        //log_error("Couldn't read tags for physical volume %s in %s.",
         //     pv_dev_name(pv), vg->name);
        return 0;
    }

    pv->pe_size = vg->extent_size;

    pv->pe_alloc_count = 0;
    pv->pe_align = 0;

    /* Fix up pv size if missing or impossibly large */
    if ((!pv->size || pv->size > (1ULL << 62)) && pv->dev) {
		pv->size = pv->dev->size;

        size = pv->pe_count * (uint64_t) vg->extent_size + pv->pe_start;
        if (size > pv->size)
			printk(">>>%s:%d\n", __func__, __LINE__);
           // log_warn("WARNING: Physical Volume %s is too large "
            //     "for underlying device", pv_dev_name(pv));
    }

    if (!alloc_pv_segment_whole_pv(pv))
        return 0;

    vg->extent_count += pv->pe_count;
    vg->free_count += pv->pe_count;

	INIT_LIST_HEAD(&pvl->list);

	printk(">>>%s:%d Added one pv key=%s\n", __func__, __LINE__, pv->pvn_key);

    if (outdated)
        list_add(&pvl->list, &vg->pvs_outdated);
    else {
		list_add(&pvl->list, &vg->pvs);
		vg->pv_count++;
		pvl->pv->vg = vg;
		pvl->pv->fid = vg->fid;
	}

    return 1;
}

static struct logical_volume *alloc_lv(void)
{   
    struct logical_volume *lv;

 //   if (!(lv = kzalloc(sizeof(*lv), GFP_KERNEL))) {
    if (!(lv = dm_alloc(sizeof(*lv), true))) {
      //  log_error("Unable to allocate logical volume structure");
		printk(">>>%s:%d\n", __func__, __LINE__);
        return NULL; 
    }   

    INIT_LIST_HEAD(&lv->snapshot_segs);
    INIT_LIST_HEAD(&lv->segments);
    INIT_LIST_HEAD(&lv->tags);
    INIT_LIST_HEAD(&lv->segs_using_this_lv);
    INIT_LIST_HEAD(&lv->rsites);
    
    return lv;
}

static const struct {
    alloc_policy_t alloc;
    const char str[14]; /* must be changed when size extends 13 chars */
    const char repchar;
} _policies[] = {
    {ALLOC_CONTIGUOUS, "contiguous", 'c'},
	{ALLOC_CLING, "cling", 'l'},
	{ALLOC_CLING_BY_TAGS, "cling_by_tags", 't'},
	{ALLOC_NORMAL, "normal", 'n'},
	{ALLOC_ANYWHERE, "anywhere", 'a'},
	{ALLOC_INHERIT, "inherit", 'i'}
};

static alloc_policy_t get_alloc_from_string(const char *str)
{   
    int i;
        
    /* cling_by_tags is part of cling */
    if (!strcmp("cling_by_tags", str))
        return ALLOC_CLING;
    
    for (i = 0; i < 6; i++)
        if (!strcmp(_policies[i].str, str))
            return _policies[i].alloc;
                   
    /* Special case for old metadata */
    if (!strcmp("next free", str))
        return ALLOC_NORMAL;

    return ALLOC_INVALID;
}

#define UINT32_MAX     (4294967295U)
#define DM_READ_AHEAD_AUTO UINT32_MAX   /* Use kernel default readahead */
#define DM_READ_AHEAD_NONE 0        /* Disable readahead */

#define DM_READ_AHEAD_MINIMUM_FLAG  0x1 /* Value supplied is minimum */

struct lv_list {
    struct list_head list;
    struct logical_volume *lv;
};

static int link_lv_to_vg(struct volume_group *vg, struct logical_volume *lv)
{
    struct lv_list *lvl;

  //  if (!(lvl = kzalloc(sizeof(*lvl), GFP_KERNEL)))
    if (!(lvl = dm_alloc(sizeof(*lvl), true)))
        return 0;

	INIT_LIST_HEAD(&lvl->list);

    lvl->lv = lv;
    lv->vg = vg;

    list_add(&lvl->list, &vg->lvs);

    lv->status &= ~LV_REMOVED;

    return 1;
}


#define lv_is_thin_volume(lv)   (((lv)->status & THIN_VOLUME) ? 1 : 0)
#define lv_is_thin_pool(lv) (((lv)->status & THIN_POOL) ? 1 : 0)
#define lv_is_external_origin(lv)   (((lv)->external_count > 0) ? 1 : 0)
#define lv_is_thin_pool_data(lv)    (((lv)->status & THIN_POOL_DATA) ? 1 : 0)
#define lv_is_thin_pool_metadata(lv)    (((lv)->status & THIN_POOL_METADATA) ? 1 : 0)
#define lv_is_cache_pool_data(lv)   (((lv)->status & CACHE_POOL_DATA) ? 1 : 0)
#define lv_is_cache_pool_metadata(lv)   (((lv)->status & CACHE_POOL_METADATA) ? 1 : 0)


static int lv_is_origin(const struct logical_volume *lv)
{
    return lv->origin_count ? 1 : 0;
}

static int lv_is_cow(const struct logical_volume *lv)
{
    /* Make sure a merging thin origin isn't confused as a cow LV */
    return (!lv_is_thin_volume(lv) && !lv_is_origin(lv) && lv->snapshot) ? 1 : 0;
}

/* Given a cow LV, return its origin */
static struct logical_volume *origin_from_cow(const struct logical_volume *lv)
{
    if (lv->snapshot)
        return lv->snapshot->origin;

    return NULL;
}

static int lv_is_virtual_origin(const struct logical_volume *lv)
{
    return (lv->status & VIRTUAL_ORIGIN) ? 1 : 0;
}

static struct lv_segment *find_snapshot(const struct logical_volume *lv)
{
    return lv->snapshot;
}

static int lv_is_merging_cow(const struct logical_volume *snapshot)
{
    struct lv_segment *snap_seg = find_snapshot(snapshot);

    /* checks lv_segment's status to see if cow is merging */
    return (snap_seg && (snap_seg->status & MERGING)) ? 1 : 0;
}

#define lv_is_merging(lv)   (((lv)->status & MERGING) ? 1 : 0)

static int lv_is_merging_origin(const struct logical_volume *origin)
{
    return lv_is_merging(origin);
}


static int lv_is_visible(const struct logical_volume *lv)
{       
    if (lv->status & SNAPSHOT)
        return 0;
        
    return lv->status & VISIBLE_LV ? 1 : 0;
}
#define LOCKD_SANLOCK_LV_NAME "lvmlock"

static int _read_lvnames(struct format_instance *fid __attribute__((unused)),
             struct volume_group *vg, const struct dm_config_node *lvn,
             const struct dm_config_node *vgn __attribute__((unused)),
             struct list_head *pv_hash __attribute__((unused)),
             struct list_head *lv_hash,
             unsigned *scan_done_once __attribute__((unused)),
             unsigned report_missing_devices __attribute__((unused)))
{
    struct logical_volume *lv;
    const char *str;
    const struct dm_config_value *cv;
    const char *hostname;
    uint64_t timestamp = 0, lvstatus;

    if (!(lv = alloc_lv()))
        return 0;

    if (!(lv->name = dm_pool_strdup(lvn->key)))
        return 0;

    if (!(lvn = lvn->child)) {
       // log_error("Empty logical volume section.");
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    if (!_read_flag_config(lvn, &lvstatus, LV_FLAGS)) {
        //log_error("Couldn't read status flags for logical volume %s.",
         //     lv->name);
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    if (lvstatus & LVM_WRITE_LOCKED) {
        lvstatus |= LVM_WRITE;
        lvstatus &= ~LVM_WRITE_LOCKED;
    }

    lv->status = lvstatus;

    if (dm_config_has_node(lvn, "creation_time")) {
        if (!_read_uint64(lvn, "creation_time", &timestamp)) {
			printk(">>>%s:%d\n", __func__, __LINE__);
           // log_error("Invalid creation_time for logical volume %s.",
            //      lv->name);
            return 0;
        }
        if (!dm_config_get_str(lvn, "creation_host", &hostname)) {
			printk(">>>%s:%d\n", __func__, __LINE__);
            //log_error("Couldn't read creation_host for logical volume %s.",
             //     lv->name);
            return 0;
        }
    } else if (dm_config_has_node(lvn, "creation_host")) {
		printk(">>>%s:%d\n", __func__, __LINE__);
       // log_error("Missing creation_time for logical volume %s.",
        //      lv->name);
        return 0;
    }

    if (dm_config_get_str(lvn, "lock_args", &str))
        if (!(lv->lock_args = dm_pool_strdup(str)))
            return 0;

    lv->alloc = ALLOC_INHERIT;
    if (dm_config_get_str(lvn, "allocation_policy", &str)) {
        lv->alloc = get_alloc_from_string(str);
        if (lv->alloc == ALLOC_INVALID) {
       //     log_warn("WARNING: Ignoring unrecognised allocation policy %s for LV %s", str, lv->name);
            lv->alloc = ALLOC_INHERIT;
        }
    }

    if (!_read_int32(lvn, "read_ahead", &lv->read_ahead))
        /* If not present, choice of auto or none is configurable */
        lv->read_ahead = -1;
    else {
        switch (lv->read_ahead) {
        case 0:
            lv->read_ahead = DM_READ_AHEAD_AUTO;
            break;
        case (uint32_t) -1:
            lv->read_ahead = DM_READ_AHEAD_NONE;
            break;
        default:
            ;
        }
    }

    /* Optional tags */
    if (dm_config_get_list(lvn, "tags", &cv) &&
        !(_read_str_list(&lv->tags, cv))) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

	INIT_LIST_HEAD(&lv->list);
	list_add(&lv->list, lv_hash);

	printk(">>>%s:%d Added one lv name=%s\n", __func__, __LINE__, lv->name);

    if (!link_lv_to_vg(vg, lv))
        return 0;

    if (!lv_is_visible(lv) && strstr(lv->name, "_pmspare")) {
        if (vg->pool_metadata_spare_lv) {
			printk(">>>%s:%d\n", __func__, __LINE__);
            return 0;
        }

        lv->status |= POOL_METADATA_SPARE;
        vg->pool_metadata_spare_lv = lv;
    }

    if (!lv_is_visible(lv) && !strcmp(lv->name, LOCKD_SANLOCK_LV_NAME)) {
        lv->status |= LOCKD_SANLOCK_LV;
        vg->sanlock_lv = lv;
    }

    return 1;
}

#define SEG_TYPE_NAME_STRIPED       "striped"
#define SEG_CAN_SPLIT       0x0000000000000001ULL
#define SEG_AREAS_STRIPED   0x0000000000000002ULL
#define SEG_AREAS_MIRRORED  0x0000000000000004ULL
#define SEG_FORMAT1_SUPPORT 0x0000000000000010ULL

static struct segment_type *get_segtype_from_string(const char *str)
{
    struct segment_type *segtype;

    //dm_list_iterate_items(segtype, &segtypes_head, list)
	list_for_each_entry(segtype, &segtypes_head, list)
        if (!strcmp(segtype->name, str))
            return segtype;

	printk(">>>%s:%d cannot support segtype=%s\n", __func__, __LINE__, str);

	return NULL;
}

static struct lv_segment *alloc_lv_segment(
					struct segment_type *segtype,
                    struct logical_volume *lv,
                    uint32_t le,
					uint32_t len,
                    uint32_t area_count,
                    uint32_t area_len)
{
    struct lv_segment *seg;
    uint32_t areas_sz = area_count * sizeof(*seg->areas);

//    if (!(seg = kzalloc(sizeof(*seg), GFP_KERNEL)))
    if (!(seg = dm_alloc(sizeof(*seg), true)))
        return NULL;

 //   if (!(seg->areas = kzalloc(areas_sz, GFP_KERNEL))) {
    if (!(seg->areas = dm_alloc(areas_sz, GFP_KERNEL))) {
//		kfree(seg);
		dm_free(seg);
        return NULL;
    }

    seg->segtype = segtype;
    seg->lv = lv;
    seg->le = le;
    seg->len = len;
    seg->area_count = area_count;
    seg->area_len = area_len;

    INIT_LIST_HEAD(&seg->tags);
    INIT_LIST_HEAD(&seg->thin_messages);

    return seg;
}

static void _insert_segment(struct logical_volume *lv, struct lv_segment *seg)
{                        
    struct lv_segment *comp;

	list_for_each_entry(comp, &lv->segments, list) {
        if (comp->le > seg->le) {
            list_add_tail(&seg->list, &comp->list);
            return; 
        }
    }

    lv->le_count += seg->len;

    list_add(&seg->list, &lv->segments);
}  

static int _read_segment(struct logical_volume *lv, const struct dm_config_node *sn,
             struct list_head *pv_hash)
{
    uint32_t area_count = 0u;
    struct lv_segment *seg;
    const struct dm_config_node *sn_child = sn->child;
    const struct dm_config_value *cv;
    uint32_t start_extent, extent_count;
    struct segment_type *segtype;
    const char *segtype_str;

    if (!sn_child) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        //log_error("Empty segment section.");
        return 0;
    }

    if (!_read_int32(sn_child, "start_extent", &start_extent)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        //log_error("Couldn't read 'start_extent' for segment '%s' "
         //     "of logical volume %s.", sn->key, lv->name);
        return 0;
    }

    if (!_read_int32(sn_child, "extent_count", &extent_count)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        //log_error("Couldn't read 'extent_count' for segment '%s' "
         //     "of logical volume %s.", sn->key, lv->name);
        return 0;
    }

    segtype_str = SEG_TYPE_NAME_STRIPED;

    if (!dm_config_get_str(sn_child, "type", &segtype_str)) {
   //     log_error("Segment type must be a string.");
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    if (!(segtype = get_segtype_from_string(segtype_str)))
        return 0;

    if (segtype->ops->text_import_area_count &&
        !segtype->ops->text_import_area_count(sn_child, &area_count))
        return 0; 


    if (!(seg = alloc_lv_segment(segtype, lv, start_extent,
                     extent_count, area_count,
                     extent_count))) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        //log_error("Segment allocation failed");
        return 0;
    }

    if (seg->segtype->ops->text_import &&
        !seg->segtype->ops->text_import(seg, sn_child, pv_hash))
        return 0;

    /* Optional tags */
    if (dm_config_get_list(sn_child, "tags", &cv) &&
        !(_read_str_list(&seg->tags, cv))) {
		printk(">>>%s:%d\n", __func__, __LINE__);
       // log_error("Couldn't read tags for a segment of %s/%s.",
        //      lv->vg->name, lv->name);
        return 0;
    }


	printk(">>>%s:%d Added one lvseg\n", __func__, __LINE__);

    /*
     * Insert into correct part of segment list.
     */
    _insert_segment(lv, seg);

#if 0
    if (seg_is_mirror(seg))
        lv->status |= MIRROR;

    if (seg_is_mirrored(seg))
        lv->status |= MIRRORED;

    if (seg_is_raid(seg))
        lv->status |= RAID;

    if (seg_is_virtual(seg))
        lv->status |= VIRTUAL;

    if (!seg_is_raid(seg) && _is_converting(lv))
        lv->status |= CONVERTING;
#endif

    return 1;
}

static int _merge(struct lv_segment *first, struct lv_segment *second)
{
    if (!first || !second || first->segtype != second->segtype ||
        !first->segtype->ops->merge_segments)
        return 0;

    return first->segtype->ops->merge_segments(first, second);
}

static int _read_segments(struct logical_volume *lv, const struct dm_config_node *lvn,
              struct list_head *pv_hash)
{
    const struct dm_config_node *sn;
    int count = 0, seg_count;
	struct lv_segment *tmp, *seg, *prev = NULL;

    for (sn = lvn; sn; sn = sn->sib) {
        if (!sn->v) {
            if (!_read_segment(lv, sn, pv_hash))
                return 0;

            count++;
        }

        if ((lv->status & SNAPSHOT) && count > 1) {
			printk(">>>%s:%d\n", __func__, __LINE__);
           // log_error("Only one segment permitted for snapshot");
            return 0;
        }
    }

    if (!_read_int32(lvn, "segment_count", &seg_count)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
       // log_error("Couldn't read segment count for logical volume %s.",
        //      lv->name);
        return 0;
    }

    if (seg_count != count) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        //log_error("segment_count and actual number of segments "
         //     "disagree for logical volume %s.", lv->name);
        return 0;
    }

    /*
     * Check there are no gaps or overlaps in the lv.
     */
//    if (!check_lv_segments(lv, 0))
 //       return 0;


	list_for_each_entry_safe(seg, tmp, &lv->segments, list) {
        if (_merge(prev, seg))
			list_del_init(&seg->list);
        else
			prev = seg;
	}  

    return 1;
}

static int _read_lvsegs(struct format_instance *fid,
            struct volume_group *vg, const struct dm_config_node *lvn,
            const struct dm_config_node *vgn __attribute__((unused)),
            struct list_head *pv_hash,
            struct list_head *lv_hash,
            unsigned *scan_done_once __attribute__((unused)),
            unsigned report_missing_devices __attribute__((unused)))
{
    struct logical_volume *lv = NULL;
	int found = 0;

	list_for_each_entry(lv, lv_hash, list) {
		if (!strcmp(lv->name, lvn->key)) {
			found = 1;
			break;
		}
	}

	if (!found) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
	}

#if 0
    if (!(lv = dm_hash_lookup(lv_hash, lvn->key))) {
       // log_error("Lost logical volume reference %s", lvn->key);
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }
#endif

    if (!(lvn = lvn->child)) {
        //log_error("Empty logical volume section.");
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    /* FIXME: read full lvid */
    if (!_read_id(&lv->lvid.id[1], lvn, "id")) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        //log_error("Couldn't read uuid for logical volume %s.",
         //     lv->name);
        return 0;
    }

    memcpy(&lv->lvid.id[0], &lv->vg->id, sizeof(lv->lvid.id[0]));

    if (!_read_segments(lv, lvn, pv_hash))
        return 0;

    lv->size = (uint64_t) lv->le_count * (uint64_t) vg->extent_size;
    lv->minor = -1;
    lv->major = -1;

    if (lv->status & FIXED_MINOR) {
        if (!_read_int32(lvn, "minor", &lv->minor)) {
			printk(">>>%s:%d\n", __func__, __LINE__);
           // log_error("Couldn't read minor number for logical "
            //      "volume %s.", lv->name);
            return 0;
        }

        if (!dm_config_has_node(lvn, "major"))
            /* If major is missing, pick default */
            lv->major = _dm_device_major;
        else if (!_read_int32(lvn, "major", &lv->major)) {
            //log_warn("WARNING: Couldn't read major number for logical "
             //    "volume %s.", lv->name);
			printk(">>>%s:%d\n", __func__, __LINE__);
            lv->major = _dm_device_major;
        }

#if 0
        if (!validate_major_minor(vg->cmd, fid->fmt, lv->major, lv->minor)) {
			printk(">>>%s:%d\n", __func__, __LINE__);
            //log_warn("WARNING: Ignoring invalid major, minor number for "
             //    "logical volume %s.", lv->name);
            lv->major = lv->minor = -1;
        }
#endif
    }

    return 1;
}

static void vg_set_fid(struct volume_group *vg,
         struct format_instance *fid)
{
    struct pv_list *pvl;

    if (fid == vg->fid)
        return;

//    if (fid)
 //       fid->ref_count++;

    //dm_list_iterate_items(pvl, &vg->pvs)
	list_for_each_entry(pvl, &vg->pvs, list)
     //   pv_set_fid(pvl->pv, fid);
    	pvl->pv->fid = fid;

//    dm_list_iterate_items(pvl, &vg->removed_pvs)
 //       pv_set_fid(pvl->pv, fid);

  //  if (vg->fid)
   //     vg->fid->fmt->ops->destroy_instance(vg->fid);

    vg->fid = fid;
}


static struct volume_group *_read_vg(struct format_instance *fid,
                     struct dm_config_node *root)
{
    const struct dm_config_node *vgn;
    const struct dm_config_value *cv;
    const char *str, *format_str, *system_id;
    struct volume_group *vg;
    unsigned scan_done_once = 0;
    uint64_t vgstatus;
	struct list_head pv_hash;
	struct list_head lv_hash;

    /* skip any top-level values */
    for (vgn = root; (vgn && vgn->v); vgn = vgn->sib) ;

    if (!vgn) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return NULL;
    }

    if (!(vg = alloc_vg(vgn->key)))
        return NULL;

	INIT_LIST_HEAD(&pv_hash);
	INIT_LIST_HEAD(&lv_hash);

    vgn = vgn->child;

    /* A backup file might be a backup of a different format */
#if 0
    if (dm_config_get_str(vgn, "format", &format_str) &&
        !(vg->original_fmt = get_format_by_name(fid->fmt->cmd, format_str))) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        goto bad;
    }
#endif

    if (dm_config_get_str(vgn, "lock_type", &str))
        if (!(vg->lock_type = dm_pool_strdup(str)))
            goto bad;


    if (dm_config_get_str(vgn, "lock_args", &str))
        if (!(vg->lock_args = dm_pool_strdup(str)))
            goto bad;


    if (!_read_id(&vg->id, vgn, "id")) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        goto bad;
    }


    if (!_read_int32(vgn, "seqno", &vg->seqno)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        goto bad;
    }

    if (!_read_flag_config(vgn, &vgstatus, VG_FLAGS)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        goto bad;
    }

    if (dm_config_get_str(vgn, "system_id", &system_id)) {
        if (!(vgstatus & LVM_WRITE_LOCKED)) {
         //   if (!(vg->lvm1_system_id = kzalloc(NAME_LEN + 1, GFP_KERNEL)))
            if (!(vg->lvm1_system_id = dm_alloc(NAME_LEN + 1, true)))
                goto bad;

            strncpy(vg->lvm1_system_id, system_id, NAME_LEN);
        } else if (!(vg->system_id = dm_pool_strdup(system_id))) {
			printk(">>>%s:%d\n", __func__, __LINE__);
            goto bad;
        }
    }

    if (vgstatus & LVM_WRITE_LOCKED) {
        vgstatus |= LVM_WRITE;
        vgstatus &= ~LVM_WRITE_LOCKED;
    }
    vg->status = vgstatus;

    if (!_read_int32(vgn, "extent_size", &vg->extent_size)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        goto bad;
    }

    if (!_read_int32(vgn, "max_lv", &vg->max_lv)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        goto bad;
    }

    if (!_read_int32(vgn, "max_pv", &vg->max_pv)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        goto bad;
    }

    if (dm_config_get_str(vgn, "allocation_policy", &str)) {
        vg->alloc = get_alloc_from_string(str);
        if (vg->alloc == ALLOC_INVALID) {
			printk(">>>%s:%d\n", __func__, __LINE__);
            vg->alloc = ALLOC_NORMAL;
        }
    }

    if (!_read_uint32(vgn, "metadata_copies", &vg->mda_copies))
        vg->mda_copies = 0;


    if (!_read_sections(fid, "physical_volumes", _read_pv, vg,
                vgn, &pv_hash, &lv_hash, 0, &scan_done_once)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        goto bad;
    }

    if (dm_config_has_node(vgn, "outdated_pvs"))
		printk(">>>%s:%d\n", __func__, __LINE__);


    /* Optional tags */
    if (dm_config_get_list(vgn, "tags", &cv) &&
        	!(_read_str_list(&vg->tags, cv))) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        goto bad;
    }


    if (!_read_sections(fid, "logical_volumes", _read_lvnames, vg,
                vgn, &pv_hash, &lv_hash, 1, NULL)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        goto bad;
    }

    if (!_read_sections(fid, "logical_volumes", _read_lvsegs, vg,
                vgn, &pv_hash, &lv_hash, 1, NULL)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        goto bad;
    }

    vg_set_fid(vg, fid);

    return vg;

bad:
    return NULL;
}

struct cached_vg_fmtdata {
        uint32_t cached_mda_checksum;
        size_t cached_mda_size;
};

static struct volume_group *text_vg_import_fd(struct format_instance *fid,
                       struct cached_vg_fmtdata **vg_fmtdata,
                       unsigned *use_previous_vg,
                       struct hyper_rootdev_device *dev,
                       off_t offset, uint32_t size,
                       off_t offset2, uint32_t size2,
                       uint32_t checksum)
{
    struct volume_group *vg = NULL;
	struct dm_config_node *root;
    int skip_parse;

    if (vg_fmtdata && !*vg_fmtdata &&
   //     	!(*vg_fmtdata = kzalloc(sizeof(struct cached_vg_fmtdata), GFP_KERNEL))) {
        	!(*vg_fmtdata = dm_alloc(sizeof(struct cached_vg_fmtdata), true))) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return NULL;
    }

    /* Does the metadata match the already-cached VG? */
    skip_parse = vg_fmtdata &&
             ((*vg_fmtdata)->cached_mda_checksum == checksum) &&
             ((*vg_fmtdata)->cached_mda_size == (size + size2));

	if (!skip_parse)
    	if (!config_file_read_fd(dev, offset, size,
                     offset2, size2, &root))
        	goto out;

    if (skip_parse) {
        if (use_previous_vg)
            *use_previous_vg = 1;
        goto out;
    }

    if (check_version(root))
    	if (!(vg = _read_vg(fid, root)))
        	goto out;

    if (vg && vg_fmtdata && *vg_fmtdata) {
        (*vg_fmtdata)->cached_mda_size = (size + size2);
        (*vg_fmtdata)->cached_mda_checksum = checksum;
    }

    if (use_previous_vg)
        *use_previous_vg = 0;

out:
    return vg;
}


static struct volume_group *_vg_read_raw(struct format_instance *fid,
                     struct metadata_area *mda,
                     struct cached_vg_fmtdata **vg_fmtdata,
                     unsigned *use_previous_vg)
{   
    struct mda_context *mdac = (struct mda_context *) mda->metadata_locn;
    struct volume_group *vg = NULL;
    struct raw_locn *rlocn;
    struct mda_header *mdah;
    uint32_t wrap = 0;
	struct device_area *area = &mdac->area;

	if (!(mdah = kmalloc(MDA_HEADER_SIZE, GFP_KERNEL)))
		goto out;

    if (!raw_read_mda_header(mdah, area))
        goto out;

    if (!(rlocn = _find_vg_rlocn(area, mdah, fid->vgname))) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        goto out;
    }

    if (rlocn->offset + rlocn->size > mdah->size)
        wrap = (uint32_t) ((rlocn->offset + rlocn->size) - mdah->size);

    if (wrap > rlocn->offset) {
       // log_error("VG %s metadata too large for circular buffer",
        //      vgname);
		printk(">>>%s:%d\n", __func__, __LINE__);
        goto out;
    }

    vg = text_vg_import_fd(fid, vg_fmtdata, use_previous_vg, area->dev,
                     (off_t) (area->start + rlocn->offset),
                     (uint32_t) (rlocn->size - wrap),
                     (off_t) (area->start + MDA_HEADER_SIZE),
                     wrap, rlocn->checksum);
out:
	kfree(mdah);
    
    return vg;
}

#define SEG_TYPE_NAME_LINEAR        "linear"

static const char *_striped_name(const struct lv_segment *seg)
{   
    return (seg->area_count == 1) ? SEG_TYPE_NAME_LINEAR : seg->segtype->name;
} 

static int _striped_text_import_area_count(const struct dm_config_node *sn, uint32_t *area_count)
{   
    if (!dm_config_get_uint32(sn, "stripe_count", area_count)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    return 1;
}

static struct logical_volume *find_lv(const struct volume_group *vg,
                   const char *lv_name)
{       
    struct lv_list *lvl = NULL;
    const char *ptr;
	int found = 0;

    /* Use last component */
    if ((ptr = strrchr(lv_name, '/')))
        ptr++;
    else
        ptr = lv_name;

	list_for_each_entry(lvl, &vg->lvs, list)
        if (!strcmp(lvl->lv->name, ptr)) {
			found = 1;
            break;
		}

    return found ? lvl->lv : NULL;
} 

#define seg_pvseg(seg, s)   (seg)->areas[(s)].u.pv.pvseg
#define seg_dev(seg, s)     (seg)->areas[(s)].u.pv.pvseg->pv->dev
#define seg_pe(seg, s)      (seg)->areas[(s)].u.pv.pvseg->pe
#define seg_le(seg, s)      (seg)->areas[(s)].u.lv.le
#define seg_metale(seg, s)  (seg)->meta_areas[(s)].u.lv.le

#define seg_type(seg, s)    (seg)->areas[(s)].type
#define seg_pv(seg, s)      (seg)->areas[(s)].u.pv.pvseg->pv
#define seg_lv(seg, s)      (seg)->areas[(s)].u.lv.lv
#define seg_metalv(seg, s)  (seg)->meta_areas[(s)].u.lv.lv
#define seg_metatype(seg, s)    (seg)->meta_areas[(s)].type


static struct pv_segment null_pv_segment = {
    .pv = NULL,
    .pe = 0,
}; 

static struct pv_segment *find_peg_by_pe(const struct physical_volume *pv,
                     uint32_t pe)
{
    struct pv_segment *pvseg;

    /* search backwards to optimise mostly used last segment split */
    list_for_each_entry_reverse(pvseg, &pv->segments, list)
        if (pe >= pvseg->pe && pe < pvseg->pe + pvseg->len)
            return pvseg;

    return NULL;
}

static struct pv_segment *_pv_split_segment(struct physical_volume *pv,
                        struct pv_segment *peg,
                        uint32_t pe)
{
    struct pv_segment *peg_new;

    if (!(peg_new = _alloc_pv_segment(peg->pv, pe,
                      peg->len + peg->pe - pe,
                      NULL, 0)))
        return NULL;

    peg->len = peg->len - peg_new->len;

    list_add(&peg_new->list, &peg->list);

    if (peg->lvseg) {
        peg->pv->pe_alloc_count -= peg_new->len;
        peg->lvseg->lv->vg->free_count += peg_new->len;
    }

    return peg_new;
}


static int pv_split_segment(struct physical_volume *pv, uint32_t pe,
             struct pv_segment **pvseg_allocated)
{
    struct pv_segment *pvseg, *pvseg_new = NULL;

    if (pe == pv->pe_count)
        goto out;

    if (!(pvseg = find_peg_by_pe(pv, pe))) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        //log_error("Segment with extent %" PRIu32 " in PV %s not found",
         //     pe, pv_dev_name(pv));
        return 0;
    }

    /* This is a peg start already */
    if (pe == pvseg->pe) {
        pvseg_new = pvseg;
        goto out;
    }

    if (!(pvseg_new = _pv_split_segment(pv, pvseg, pe)))
        return 0;
out:
    if (pvseg_allocated)
        *pvseg_allocated = pvseg_new;

    return 1;
}


static struct pv_segment *assign_peg_to_lvseg(struct physical_volume *pv,
                       uint32_t pe, uint32_t area_len,
                       struct lv_segment *seg,
                       uint32_t area_num)
{   
    struct pv_segment *peg = NULL;
    
    /* Missing format1 PV */
    if (!pv)
        return &null_pv_segment;
    
    if (!pv_split_segment(pv, pe, &peg) ||
        !pv_split_segment(pv, pe + area_len, NULL))
        return NULL;
    
    if (!peg) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        //log_error("Missing PV segment on %s at %u.",
         //     pv_dev_name(pv), pe);
        return NULL;
    }
    
    peg->lvseg = seg;
    peg->lv_area = area_num;
    
    peg->pv->pe_alloc_count += area_len;
    peg->lvseg->lv->vg->free_count -= area_len;
    
    return peg;
}


static int set_lv_segment_area_pv(struct lv_segment *seg, uint32_t area_num,
               struct physical_volume *pv, uint32_t pe)
{                           
    seg->areas[area_num].type = AREA_PV;

	printk(">>>%s:%d\n", __func__, __LINE__);
                
    if (!(seg_pvseg(seg, area_num) =
          assign_peg_to_lvseg(pv, pe, seg->area_len, seg, area_num)))
        return 0; 
                  
    return 1;
} 

struct seg_list {
    struct list_head list;
    unsigned count;
    struct lv_segment *seg;
};      

static int add_seg_to_segs_using_this_lv(struct logical_volume *lv,
                  struct lv_segment *seg)
{
    struct seg_list *sl;

	list_for_each_entry(sl, &lv->segs_using_this_lv, list) {
        if (sl->seg == seg) {
            sl->count++;
            return 1;
        }
    }

//    if (!(sl = kzalloc(sizeof(*sl), GFP_KERNEL))) {
    if (!(sl = dm_alloc(sizeof(*sl), true))) {
//        log_error("Failed to allocate segment list");
        return 0;
    }

	INIT_LIST_HEAD(&sl->list);

    sl->count = 1;
    sl->seg = seg;
    list_add(&sl->list, &lv->segs_using_this_lv);

    return 1;
}


static int set_lv_segment_area_lv(struct lv_segment *seg, uint32_t area_num,
               struct logical_volume *lv, uint32_t le,
               uint64_t status)
{
#if 0
    if (status & RAID_META) {
        seg->meta_areas[area_num].type = AREA_LV;
        seg_metalv(seg, area_num) = lv;
        if (le) { 
            log_error(INTERNAL_ERROR "Meta le != 0");
            return 0;
        }
        seg_metale(seg, area_num) = 0;
    } else {
#endif
        seg->areas[area_num].type = AREA_LV;
        seg_lv(seg, area_num) = lv;
        seg_le(seg, area_num) = le;
 //   }

    lv->status |= status;

	printk(">>>%s:%d\n", __func__, __LINE__);

    if (!add_seg_to_segs_using_this_lv(lv, seg))
        return 0;

    return 1;
}

static int text_import_areas(struct lv_segment *seg, const struct dm_config_node *sn,
              const struct dm_config_value *cv, struct list_head *pv_hash,
              uint64_t status)
{
    unsigned int s;
    struct logical_volume *lv1;
    struct physical_volume *pv;
	int found = 0;

    if (!seg->area_count) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        //log_error("Zero areas not allowed for segment %s", seg_name);
        return 0;
    }

    for (s = 0; cv && s < seg->area_count; s++, cv = cv->next) {
        /* first we read the pv */
        if (cv->type != DM_CFG_STRING) {
			printk(">>>%s:%d\n", __func__, __LINE__);
           // log_error("Bad volume name in areas array for segment %s.", seg_name);
            return 0;
        }

        if (!cv->next) {
			printk(">>>%s:%d\n", __func__, __LINE__);
            //log_error("Missing offset in areas array for segment %s.", seg_name);
            return 0;
        }

        if (cv->next->type != DM_CFG_INT) {
			printk(">>>%s:%d\n", __func__, __LINE__);
            //log_error("Bad offset in areas array for segment %s.", seg_name);
            return 0;
        }

		list_for_each_entry(pv, pv_hash, list) {
			if (!strcmp(cv->v.str, pv->pvn_key)) {
				found = 1;
				break;
			}
		}

		if (found) {
            if (!set_lv_segment_area_pv(seg, s, pv, (uint32_t)cv->next->v.i))
                return 0;
		} else if ((lv1 = find_lv(seg->lv->vg, cv->v.str))){
            if (!set_lv_segment_area_lv(seg, s, lv1,
                            (uint32_t)cv->next->v.i,
                            status))
                return 0;
		} else {
			printk(">>>%s:%d\n", __func__, __LINE__);
            //log_error("Couldn't find volume '%s' "
             //     "for segment '%s'.",
              //    cv->v.str ? : "NULL", seg_name);
            return 0;
		}

        cv = cv->next;
    }

    /*
     * Check we read the correct number of stripes.
     */
    if (cv || (s < seg->area_count)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        //log_error("Incorrect number of areas in area array "
         //     "for segment '%s'.", seg_name);
        return 0;
    }

    return 1;
}

static int _striped_text_import(struct lv_segment *seg, const struct dm_config_node *sn,
            struct list_head *pv_hash)
{   
    const struct dm_config_value *cv;
    
    if ((seg->area_count != 1) &&
        !dm_config_get_uint32(sn, "stripe_size", &seg->stripe_size)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        //log_error("Couldn't read stripe_size for segment %s "
         //     "of logical volume %s.", dm_config_parent_name(sn), seg->lv->name);
        return 0;
    }

    if (!dm_config_get_list(sn, "stripes", &cv)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        //log_error("Couldn't find stripes array for segment %s "
         //     "of logical volume %s.", dm_config_parent_name(sn), seg->lv->name);
        return 0;
    }

    seg->area_len /= seg->area_count;

    return text_import_areas(seg, sn, cv, pv_hash, 0);
}

static int list_size(struct list_head *head)
{
	int cnt = 0;
	struct list_head *tmp;

	list_for_each(tmp, head)
		cnt++;

	return cnt;
}

struct dm_str_list {
    struct list_head list;
    const char *str;
};

static int str_list_lists_equal(const struct list_head *sll, const struct list_head *sll2)
{           
    struct dm_str_list *sl;
    struct dm_str_list *sl2;

    if (list_size(sll) != list_size(sll2))
        return 0;

	list_for_each_entry(sl, sll, list)
		list_for_each_entry(sl2, sll2, list)
			if (strcmp(sl2->str, sl->str))
        		return 0;

    return 1;
} 

static int _striped_segments_compatible(struct lv_segment *first,
                struct lv_segment *second)
{
    uint32_t width;
    unsigned s;

    if ((first->area_count != second->area_count) ||
        (first->stripe_size != second->stripe_size))
        return 0;

    for (s = 0; s < first->area_count; s++) {
        if ((seg_type(first, s) != AREA_PV) ||
            (seg_type(second, s) != AREA_PV))
            return 0;

        width = first->area_len;

        if ((seg_pv(first, s) !=
             seg_pv(second, s)) ||
            (seg_pe(first, s) + width !=
             seg_pe(second, s)))
            return 0;
    }

    if (!str_list_lists_equal(&first->tags, &second->tags))
        return 0;

    return 1;
}

static void merge_pv_segments(struct pv_segment *peg1, struct pv_segment *peg2)
{
    peg1->len += peg2->len;
    
   // dm_list_del(&peg2->list);
	list_del_init(&peg2->list);
}

static int _striped_merge_segments(struct lv_segment *seg1, struct lv_segment *seg2)
{
    uint32_t s;

    if (!_striped_segments_compatible(seg1, seg2))
        return 0;

    seg1->len += seg2->len;
    seg1->area_len += seg2->area_len;

    for (s = 0; s < seg1->area_count; s++)
        if (seg_type(seg1, s) == AREA_PV)
            merge_pv_segments(seg_pvseg(seg1, s),
                      seg_pvseg(seg2, s));

    return 1;
}

enum {
    SEG_CACHE,
    SEG_CRYPT,
    SEG_ERROR,
    SEG_LINEAR,
    SEG_MIRRORED,
    SEG_REPLICATOR,
    SEG_REPLICATOR_DEV,
    SEG_SNAPSHOT,
    SEG_SNAPSHOT_ORIGIN,
    SEG_SNAPSHOT_MERGE,
    SEG_STRIPED,
    SEG_ZERO,
    SEG_THIN_POOL,
    SEG_THIN,
    SEG_RAID1,
    SEG_RAID10,
    SEG_RAID4,
    SEG_RAID5_LA,
    SEG_RAID5_RA,
    SEG_RAID5_LS,
    SEG_RAID5_RS,
    SEG_RAID6_ZR,
    SEG_RAID6_NR,
    SEG_RAID6_NC,
};

struct load_segment {
//    struct dm_list list;
    struct list_head list;

    unsigned type;

    uint64_t size;

    unsigned area_count;        /* Linear + Striped + Mirrored + Crypt + Replicator */
//    struct dm_list areas;       /* Linear + Striped + Mirrored + Crypt + Replicator */
    struct list_head areas;       /* Linear + Striped + Mirrored + Crypt + Replicator */

    uint32_t stripe_size;       /* Striped + raid */

    int persistent;         /* Snapshot */
    uint32_t chunk_size;        /* Snapshot */
    struct dm_tree_node *cow;   /* Snapshot */
    struct dm_tree_node *origin;    /* Snapshot + Snapshot origin + Cache */
    struct dm_tree_node *merge; /* Snapshot */

    struct dm_tree_node *log;   /* Mirror + Replicator */
    uint32_t region_size;       /* Mirror + raid */
    unsigned clustered;     /* Mirror */
    unsigned mirror_area_count; /* Mirror */
    uint32_t flags;         /* Mirror + raid + Cache */
    char *uuid;         /* Clustered mirror log */

    const char *policy_name;    /* Cache */
    unsigned policy_argc;       /* Cache */
    struct dm_config_node *policy_settings; /* Cache */

    const char *cipher;     /* Crypt */
    const char *chainmode;      /* Crypt */
    const char *iv;         /* Crypt */
    uint64_t iv_offset;     /* Crypt */
    const char *key;        /* Crypt */

    const char *rlog_type;      /* Replicator */
//    struct dm_list rsites;      /* Replicator */
    struct list_head rsites;      /* Replicator */

    unsigned rsite_count;       /* Replicator */
    unsigned rdevice_count;     /* Replicator */
    struct dm_tree_node *replicator;/* Replicator-dev */
    uint64_t rdevice_index;     /* Replicator-dev */

    uint64_t rebuilds;      /* raid */
    uint64_t writemostly;       /* raid */
    uint32_t writebehind;       /* raid */
    uint32_t max_recovery_rate; /* raid kB/sec/disk */
    uint32_t min_recovery_rate; /* raid kB/sec/disk */

    struct dm_tree_node *metadata;  /* Thin_pool + Cache */
    struct dm_tree_node *pool;  /* Thin_pool, Thin */
    struct dm_tree_node *external;  /* Thin */

   // struct dm_list thin_messages;   /* Thin_pool */
    struct list_head thin_messages;   /* Thin_pool */

    uint64_t transaction_id;    /* Thin_pool */
    uint64_t low_water_mark;    /* Thin_pool */
    uint32_t data_block_size;       /* Thin_pool + cache */
    unsigned skip_block_zeroing;    /* Thin_pool */
    unsigned ignore_discard;    /* Thin_pool target vsn 1.1 */
    unsigned no_discard_passdown;   /* Thin_pool target vsn 1.1 */
    unsigned error_if_no_space; /* Thin pool target vsn 1.10 */
    unsigned read_only;     /* Thin pool target vsn 1.3 */
    uint32_t device_id;     /* Thin */
};

static struct load_segment *_add_segment(struct dm_tree_node *dnode, unsigned type, uint64_t size)
{
    struct load_segment *seg;

   // if (!(seg = kzalloc(sizeof(*seg), GFP_KERNEL)))
    if (!(seg = dm_alloc(sizeof(*seg), true)))
        return NULL;

    seg->type = type;
    seg->size = size;

    INIT_LIST_HEAD(&seg->areas);
    INIT_LIST_HEAD(&seg->list);

    list_add(&seg->list, &dnode->props.segs);

    dnode->props.segment_count++;

    return seg;
}



static int dm_tree_node_add_linear_target(struct dm_tree_node *node,
                   uint64_t size)
{       
    if (!_add_segment(node, SEG_LINEAR, size))
        return 0;

    return 1;    
}

static int dm_tree_node_add_striped_target(struct dm_tree_node *node,
                    uint64_t size,
                    uint32_t stripe_size)
{   
    struct load_segment *seg;

    if (!(seg = _add_segment(node, SEG_STRIPED, size)))
        return 0;

    seg->stripe_size = stripe_size;

    return 1;
}

static char *build_dm_uuid(const struct logical_volume *lv,
            const char *layer);

static struct dm_tree_node *dm_tree_find_node_by_uuid(struct dm_tree *dtree,
                           const char *uuid)
{
    struct dm_tree_node *node;
	int found = 0;

    if (!uuid || !*uuid)
        return &dtree->root;

	list_for_each_entry(node, &dtree->uuids, uuid_hash_list) {
		if (!strcmp(node->uuid, uuid)) {
			found = 1;
			break;
		}
	}

	if (found)
		return node;

	return NULL;
}

static int _nodes_are_linked(const struct dm_tree_node *parent,
                 const struct dm_tree_node *child);

static int _link_nodes(struct dm_tree_node *parent,
               struct dm_tree_node *child);

static int dm_tree_node_num_children(const struct dm_tree_node *node, uint32_t inverted)
{
    if (inverted) {
        if (_nodes_are_linked(&node->dtree->root, node))
            return 0;
        return list_size(&node->used_by);
    }

    if (_nodes_are_linked(node, &node->dtree->root))
        return 0;

    return list_size(&node->uses);
}

struct dm_tree_link {
    struct list_head list;
    struct dm_tree_node *node;
};


static void _unlink(struct list_head *head, struct dm_tree_node *node)
{
    struct dm_tree_link *dlink, *tmp;


	list_for_each_entry_safe(dlink, tmp, head, list)
        if (dlink->node == node) {
			list_del_init(&dlink->list);
            break;
        }
}

static void _unlink_nodes(struct dm_tree_node *parent,
              struct dm_tree_node *child)
{
    if (!_nodes_are_linked(parent, child))
        return;

    _unlink(&parent->uses, child);
    _unlink(&child->used_by, parent);
}


static void _remove_from_toplevel(struct dm_tree_node *node)
{
    _unlink_nodes(&node->dtree->root, node);
}

static void _remove_from_bottomlevel(struct dm_tree_node *node)
{
    _unlink_nodes(node, &node->dtree->root);
}

static int _link_tree_nodes(struct dm_tree_node *parent, struct dm_tree_node *child)
{
    /* Don't link to root node if child already has a parent */
    if (parent == &parent->dtree->root) {
        if (dm_tree_node_num_children(child, 1))
            return 1;
    } else
        _remove_from_toplevel(child);

    if (child == &child->dtree->root) {
        if (dm_tree_node_num_children(parent, 0))
            return 1;
    } else
        _remove_from_bottomlevel(parent);

    return _link_nodes(parent, child);
}

static struct dm_tree_node *_find_dm_tree_node(struct dm_tree *dtree,
                           uint32_t major, uint32_t minor)
{
	struct dm_tree_node *node;
	int found = 0;
    dev_t dev = MKDEV((dev_t)major, (dev_t)minor);

	list_for_each_entry(node, &dtree->devs, dev_hash_list) {
		if (node->dev == dev) {
			found = 1;
			break;
		}
	}

	if (found)
		return node;

	return NULL;
}



static struct dm_tree_node *_add_dev(struct dm_tree *dtree,
                     struct dm_tree_node *parent,
                     uint32_t major, uint32_t minor,
                     uint16_t udev_flags,
                     int implicit_deps)
{
    struct dm_info info;
    const char *name = NULL;
    const char *uuid = NULL;
    struct dm_tree_node *node = NULL;
    int new = 0;

    /* Already in tree? */
    if (!(node = _find_dm_tree_node(dtree, major, minor))) {
        name = "";
        uuid = "";
        info.major = major;
        info.minor = minor;

        if (!(node = _create_dm_tree_node(dtree, name, uuid, &info,
                          NULL, udev_flags)))
            goto out;

		printk(">>>%s:%d Added seg node name=%s uuid=%s dev=%lx major=%lu minor=%lu\n",
			__func__, __LINE__, node->name, node->uuid, node->dev, major, minor);

        new = 1;
        node->implicit_deps = implicit_deps;
    } else if (!implicit_deps && node->implicit_deps) {
        node->udev_flags = udev_flags;
        node->implicit_deps = 0;
    }

    if (!_link_tree_nodes(parent, node)) {
        node = NULL;
        goto out;
    }

    /* If node was already in tree, no need to recurse. */
    if (!new)
        goto out;

    /* Can't recurse if not a mapped device or there are no dependencies */
    if (!_add_to_bottomlevel(node))
        node = NULL;

out:
    return node;
}


static struct list_head *dm_list_last(const struct list_head *head)
{
    return (list_empty(head) ? NULL : head->next);
}  

#define dm_list_struct_base(v, t, head) \
    ((t *)((const char *)(v) - (const char *)&((t *) 0)->head))

#define dm_list_item(v, t) dm_list_struct_base((v), t, list)

struct seg_area {
//    struct dm_list list;
    struct list_head list;

    struct dm_tree_node *dev_node;

    uint64_t offset;

    unsigned rsite_index;       /* Replicator site index */
    struct dm_tree_node *slog;  /* Replicator sync log node */
    uint64_t region_size;       /* Replicator sync log size */
    uint32_t flags;         /* Replicator sync log flags */
};

static int _add_area(struct dm_tree_node *node,
		struct load_segment *seg, struct dm_tree_node *dev_node, uint64_t offset)
{
    struct seg_area *area;

//    if (!(area = kzalloc(sizeof (*area), GFP_KERNEL)))
    if (!(area = dm_alloc(sizeof (*area), true)))
        return 0;

    area->dev_node = dev_node;
    area->offset = offset;
	INIT_LIST_HEAD(&area->list);

    list_add(&area->list, &seg->areas);
    seg->area_count++;

    return 1;
}

static int dm_tree_node_add_target_area(struct dm_tree_node *node,
                 const char *dev_name,
                 const char *uuid,
                 uint64_t offset)
{
    struct load_segment *seg;
    struct dm_tree_node *dev_node;

    if ((!dev_name || !*dev_name) && (!uuid || !*uuid)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }


    if (uuid) {
        if (!(dev_node = dm_tree_find_node_by_uuid(node->dtree, uuid))) {
           // log_error("Couldn't find area uuid %s.", uuid);
			printk(">>>%s:%d\n", __func__, __LINE__);
            return 0;
        }

        if (!_link_tree_nodes(node, dev_node))
            return 0;
    } else {
		struct __old_kernel_stat info;

		if (sys_stat(dev_name, (struct __old_kernel_stat __user *)&info) < 0) {
			printk(">>>%s:%d\n", __func__, __LINE__);
			return 0;
		}

        if (!S_ISBLK(info.st_mode)) {
			printk(">>>%s:%d\n", __func__, __LINE__);
            //log_error("Device %s is not a block device.", dev_name);
            return 0;
        }

        /* FIXME Check correct macro use */
        if (!(dev_node = _add_dev(node->dtree, node, LVM_MAJOR(info.st_rdev),
                     LVM_MINOR(info.st_rdev), 0, 0)))
            return 0;
    }

    if (!node->props.segment_count) {
		printk(">>>%s:%d\n", __func__, __LINE__);
       // log_error(INTERNAL_ERROR "Attempt to add target area to missing segment.");
        return 0;
    }

    seg = dm_list_item(dm_list_last(&node->props.segs), struct load_segment);

    if (!_add_area(node, seg, dev_node, offset))
        return 0;

    return 1;
}




static int add_areas_line(struct dev_manager *dm, struct lv_segment *seg,
           struct dm_tree_node *node, uint32_t start_area,
           uint32_t areas)
{
    uint64_t extent_size = seg->lv->vg->extent_size;
    uint32_t s;
    char *dlid;
    const char *name;
    unsigned num_error_areas = 0;
    unsigned num_existing_areas = 0;

    for (s = start_area; s < areas; s++) {
        if ((seg_type(seg, s) == AREA_PV &&
             (!seg_pvseg(seg, s) || !seg_pv(seg, s) || !seg_dev(seg, s) ||
               !(name = seg_dev(seg, s)->path) || !*name)) ||
            (seg_type(seg, s) == AREA_LV && !seg_lv(seg, s))) {
            num_error_areas++;
        } else if (seg_type(seg, s) == AREA_PV) {
            if (!dm_tree_node_add_target_area(node, seg_dev(seg, s)->path, NULL,
                    (seg_pv(seg, s)->pe_start + (extent_size * seg_pe(seg, s)))))
                return 0;

            num_existing_areas++;
        } else if (seg_type(seg, s) == AREA_LV) {
            if (!(dlid = build_dm_uuid(seg_lv(seg, s), NULL)))
                return 0;

            if (!dm_tree_node_add_target_area(node, NULL, dlid, extent_size * seg_le(seg, s)))
                return 0;
        } else {
			printk(">>>%s:%d\n", __func__, __LINE__);
            //log_error(INTERNAL_ERROR "Unassigned area found in LV %s.",
             //     seg->lv->name);
            return 0;
        }
    }

    if (num_error_areas) {
        /* Thins currently do not support partial activation */
        if (lv_is_thin_type(seg->lv)) {
			printk(">>>%s:%d\n", __func__, __LINE__);
         //   log_error("Cannot activate %s%s: pool incomplete.",
          //        seg->lv->vg->name, seg->lv->name);
            return 0;
        }
    }

    return 1;
}




static int _striped_add_target_line(struct dev_manager *dm,
                struct lv_segment *seg,
                struct dm_tree_node *node, uint64_t len)
{   
    if (!seg->area_count) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return 0;
    }

    if (seg->area_count == 1) {
        if (!dm_tree_node_add_linear_target(node, len))
            return 0;
    } else if (!dm_tree_node_add_striped_target(node, len,
                          seg->stripe_size))
        return 0;
    
    return add_areas_line(dm, seg, node, 0u, seg->area_count);
}


static struct segtype_handler _striped_ops = {
    .name = _striped_name,
 //   .display = _striped_display,
    .text_import_area_count = _striped_text_import_area_count,
    .text_import = _striped_text_import,
//    .text_export = _striped_text_export,
    .merge_segments = _striped_merge_segments,
    .add_target_line = _striped_add_target_line,
  //  .target_present = _striped_target_present,
  //  .destroy = _striped_destroy,
};

static int _lv_is_exclusive(struct logical_volume *lv)
{
    struct lv_segment *seg;

    /* Some seg types require exclusive activation */
    /* FIXME Scan recursively */
    //dm_list_iterate_items(seg, &lv->segments)
	list_for_each_entry(seg, &lv->segments, list)
        if (seg_only_exclusive(seg))
            return 1;
    
    /* Origin has no seg type require exlusiveness */
    return lv_is_origin(lv);
} 


static struct dm_tree *dm_tree_create(void)
{   
    struct dm_tree *dtree;
        
   // if(!(dtree = kzalloc(sizeof(*dtree), GFP_KERNEL)))
    if(!(dtree = dm_alloc(sizeof(*dtree), true)))
		return NULL;
    
    dtree->root.dtree = dtree;

    INIT_LIST_HEAD(&dtree->root.uses);
    INIT_LIST_HEAD(&dtree->root.used_by);
    INIT_LIST_HEAD(&dtree->root.activated);

    dtree->skip_lockfs = 0;
    dtree->no_flush = 0;
    dtree->optional_uuid_suffixes = NULL;


    INIT_LIST_HEAD(&dtree->devs);
    INIT_LIST_HEAD(&dtree->uuids);

    return dtree;
}

static struct lv_segment *first_seg(const struct logical_volume *lv) 
{
    struct lv_segment *seg;

	list_for_each_entry(seg, &lv->segments, list)
        return seg; 

    return NULL;
}

static const char *lv_layer(const struct logical_volume *lv)
{       
    if (lv_is_thin_pool(lv))
        return "tpool"; 
    
    return NULL;
} 

#define lv_is_cache(lv)     (((lv)->status & CACHE) ? 1 : 0)
#define lv_is_pending_delete(lv) (((lv)->status & LV_PENDING_DELETE) ? 1 : 0)


static const char *uuid_suffix_list[] =
		{ "pool", "cdata", "cmeta", "tdata", "tmeta", NULL};

static struct dm_tree *_create_partial_dtree(struct dev_manager *dm,
		const struct logical_volume *lv)
{   
    struct dm_tree *dtree;

    if (!(dtree = dm_tree_create()))
        return NULL;
    
	dtree->optional_uuid_suffixes = &uuid_suffix_list[0];
    
    return dtree;
}

#if 0
struct dm_tree_node *dm_tree_find_node(struct dm_tree *dtree,
                       uint32_t major,
                       uint32_t minor)
{   
    if (!major && !minor)
        return &dtree->root;
    
    return _find_dm_tree_node(dtree, major, minor);
} 
#endif

static void _count_chars(const char *str, size_t *len, int *count,
             const int c1, const int c2)
{
    const char *ptr;

    for (ptr = str; *ptr; ptr++, (*len)++)
        if (*ptr == c1 || *ptr == c2)
            (*count)++;
}

static void _quote_characters(char **out, const char *src,
                  const int orig_char, const int quote_char,
                  int quote_quote_char)
{
    while (*src) {
        if (*src == orig_char ||
            (*src == quote_char && quote_quote_char))
            *(*out)++ = quote_char;

        *(*out)++ = *src++;
    }
}

static void _quote_hyphens(char **out, const char *src)
{
    _quote_characters(out, src, '-', '-', 0);
}

static char *dm_build_dm_name(const char *vgname,
               const char *lvname, const char *layer)
{
    size_t len = 1;
    int hyphens = 1;
    char *r, *out;

    _count_chars(vgname, &len, &hyphens, '-', 0);
    _count_chars(lvname, &len, &hyphens, '-', 0);

    len += hyphens;

//    if (!(r = kmalloc(len, GFP_KERNEL)))
    if (!(r = dm_alloc(len, false)))
        return NULL;

    out = r;
    _quote_hyphens(&out, vgname);
    *out++ = '-';
    _quote_hyphens(&out, lvname);

    *out = '\0';

    return r;
}

struct lv_layer {
    const struct logical_volume *lv; 
    const char *old_name;
};

static int read_only_lv(const struct logical_volume *lv)
{
    return !(lv->status & LVM_WRITE);
}

static struct dm_tree_node *_create_dm_tree_node(struct dm_tree *dtree,
                         const char *name,
                         const char *uuid,
                         struct dm_info *info,
                         void *context,
                         uint16_t udev_flags)
{
    struct dm_tree_node *node;
    dev_t dev;

   // if (!(node = kzalloc(sizeof(*node), GFP_KERNEL)))
    if (!(node = dm_alloc(sizeof(*node), true)))
        return NULL;

    node->dtree = dtree;

    node->name = name;
    node->uuid = uuid;
    node->info = *info;
    node->context = context;
    node->udev_flags = udev_flags;

    INIT_LIST_HEAD(&node->uses);
    INIT_LIST_HEAD(&node->used_by);
    INIT_LIST_HEAD(&node->activated);
    INIT_LIST_HEAD(&node->props.segs);

    INIT_LIST_HEAD(&node->dev_hash_list);
    INIT_LIST_HEAD(&node->uuid_hash_list);

    dev = LVM_MKDEV((dev_t)info->major, (dev_t)info->minor);
	node->dev = dev;

	list_add(&node->dev_hash_list, &dtree->devs);

	if (*uuid)
		list_add(&node->uuid_hash_list, &dtree->uuids);

    return node;
}

static int _link(struct list_head *list, struct dm_tree_node *node)
{   
    struct dm_tree_link *dlink;
    
   // if (!(dlink = kzalloc(sizeof(*dlink), GFP_KERNEL))) {
    if (!(dlink = dm_alloc(sizeof(*dlink), true))) {
      //  log_error("dtree link allocation failed");
        return 0;
    }

	INIT_LIST_HEAD(&dlink->list);
    
    dlink->node = node;
    list_add(&dlink->list, list);
    
    return 1;
}

static int _nodes_are_linked(const struct dm_tree_node *parent,
                 const struct dm_tree_node *child)
{
    struct dm_tree_link *dlink;

	list_for_each_entry(dlink, &parent->uses, list)
        if (dlink->node == child)
            return 1;

    return 0;
}

static int _link_nodes(struct dm_tree_node *parent,
               struct dm_tree_node *child)
{
    if (_nodes_are_linked(parent, child))
        return 1;

    if (!_link(&parent->uses, child))
        return 0;

    if (!_link(&child->used_by, parent))
        return 0;

    return 1;
}

static int _add_to_toplevel(struct dm_tree_node *node)
{
    return _link_nodes(&node->dtree->root, node);
}

static int _add_to_bottomlevel(struct dm_tree_node *node)
{
    return _link_nodes(node, &node->dtree->root);
}

static struct dm_tree_node *dm_tree_add_new_dev_with_udev_flags(struct dm_tree *dtree,
                             const char *name,
                             const char *uuid,
                             uint32_t major,
                             uint32_t minor,
                             int read_only,
                             int clear_inactive,
                             void *context,
                             uint16_t udev_flags)
{
    struct dm_tree_node *dnode;
    struct dm_info info = { 0 };
    const char *name2;
    const char *uuid2;

    /* Do we need to add node to tree? */
    if (!(name2 = dm_pool_strdup(name)))
        return NULL;

    if (!(uuid2 = dm_pool_strdup(uuid)))
        return NULL;

    if (!(dnode = _create_dm_tree_node(dtree, name2, uuid2, &info,
                           context, 0)))
        return NULL;

	printk(">>>%s:%d Added lv node name=%s uuid=%s dev=%lx\n",
		__func__, __LINE__, dnode->name, dnode->uuid, dnode->dev);

    /* Attach to root node until a table is supplied */
    if (!_add_to_toplevel(dnode) || !_add_to_bottomlevel(dnode))
        return NULL;

    dnode->props.major = major;
    dnode->props.minor = minor;

    dnode->props.read_only = read_only ? 1 : 0;
    dnode->props.read_ahead = DM_READ_AHEAD_AUTO;
    dnode->props.read_ahead_flags = 0;

    dnode->context = context;

    return dnode;
}

static int _add_new_lv_to_dtree(struct dev_manager *dm, struct dm_tree *dtree,
                const struct logical_volume *lv, struct lv_activate_opts *laopts,
                const char *layer);


static int _add_segment_to_dtree(struct dev_manager *dm,
                 struct dm_tree *dtree,
                 struct dm_tree_node *dnode,
                 struct lv_segment *seg,
                 struct lv_activate_opts *laopts)
{
    uint32_t s;
    uint64_t extent_size;

    /* Add any LVs used by this segment */
    for (s = 0; s < seg->area_count; ++s)
        if ((seg_type(seg, s) == AREA_LV) &&
               !_add_new_lv_to_dtree(dm, dtree, seg_lv(seg, s), laopts, NULL))
            return 0;

    extent_size = seg->lv->vg->extent_size;
	if (!seg->segtype->ops->add_target_line(dm, seg, dnode, extent_size * seg->len))
        return 0;

    return 1;
}


static int _dev_read_ahead_dev(struct hyper_rootdev_device *dev, uint32_t *read_ahead)
{
    long read_ahead_long;

    if (dev->read_ahead != -1) {
        *read_ahead = (uint32_t) dev->read_ahead;
        return 1;
    }

    if (sys_ioctl(dev->fd, BLKRAGET, (uint64_t)&read_ahead_long) < 0)
        return 0;

    *read_ahead = (uint32_t) read_ahead_long;
    dev->read_ahead = read_ahead_long;

    return 1;
}

static int _lv_read_ahead_single(struct logical_volume *lv, void *data)
{
    struct lv_segment *seg = first_seg(lv);
    uint32_t seg_read_ahead = 0, *read_ahead = data;

    if (seg && seg->area_count && seg_type(seg, 0) == AREA_PV)
		_dev_read_ahead_dev(seg_pv(seg, 0)->dev, &seg_read_ahead);

    if (seg_read_ahead > *read_ahead)
        *read_ahead = seg_read_ahead;

    return 1;
}


static int _add_new_lv_to_dtree(struct dev_manager *dm, struct dm_tree *dtree,
                const struct logical_volume *lv, struct lv_activate_opts *laopts,
                const char *layer)
{
    struct lv_segment *seg;
    struct lv_layer *lvlayer;
    struct dm_tree_node *dnode;
    char *name, *dlid;
    uint32_t max_stripe_size = 0;
    uint32_t read_ahead = lv->read_ahead;
    uint32_t read_ahead_flags = 0;

    if (!(name = dm_build_dm_name(lv->vg->name, lv->name, NULL)))
        return 0;

    if (!(dlid = build_dm_uuid(lv, NULL)))
        return 0;

//    if (!(lvlayer = kzalloc(sizeof(*lvlayer), GFP_KERNEL)))
    if (!(lvlayer = dm_alloc(sizeof(*lvlayer), true)))
        return 0;

    lvlayer->lv = lv;

    if (!(dnode = dm_tree_add_new_dev_with_udev_flags(dtree, name, dlid,
                         (uint32_t) lv->major,
                         (uint32_t) lv->minor,
                         read_only_lv(lv), 0, lvlayer, 0)))
        return 0;

    /* Store existing name so we can do rename later */
    lvlayer->old_name = "";

    /* Create table */
    dm->pvmove_mirror_count = 0u;

    /* Add 'real' segments for LVs */
	list_for_each_entry(seg, &lv->segments, list) {
        if (!_add_segment_to_dtree(dm, dtree, dnode, seg, laopts))
            return 0;

        if (max_stripe_size < seg->stripe_size * seg->area_count)
            max_stripe_size = seg->stripe_size * seg->area_count;
    }


    if (read_ahead == DM_READ_AHEAD_AUTO) {
        read_ahead = max_stripe_size * 2;

        if (!read_ahead)
			_lv_read_ahead_single(lv, &read_ahead);

        read_ahead_flags = DM_READ_AHEAD_MINIMUM_FLAG;
    }

    dnode->props.read_ahead = read_ahead;
    dnode->props.read_ahead_flags = read_ahead_flags;

    return 1;
}


static int dm_task_get_info(struct dm_ioctl *param, struct dm_info *info)
{
    memset(info, 0, sizeof(*info));

    info->exists = param->flags & DM_EXISTS_FLAG ? 1 : 0;
    if (!info->exists)
        return 1; 
                  
    info->suspended = param->flags & DM_SUSPEND_FLAG ? 1 : 0;
    info->read_only = param->flags & DM_READONLY_FLAG ? 1 : 0;
    info->live_table = param->flags & DM_ACTIVE_PRESENT_FLAG ? 1 : 0;
    info->inactive_table = param->flags & DM_INACTIVE_PRESENT_FLAG ? 1 : 0;
    info->deferred_remove = param->flags & DM_DEFERRED_REMOVE;
    info->internal_suspend = (param->flags & DM_INTERNAL_SUSPEND_FLAG) ? 1 : 0;
    info->target_count = param->target_count;
    info->open_count = param->open_count;
    info->event_nr = param->event_nr;
    info->major = LVM_MAJOR(param->dev);
    info->minor = LVM_MINOR(param->dev);

    return 1;
}

static int _create_node(struct dm_tree_node *dnode)
{
    int r = 0;
	struct dm_ioctl param = { 0 };
	struct dm_info *info;

	printk(">>>%s:%d name=%s uuid=%s dev=%lx major=%lx ro=%d\n", __func__, __LINE__,
		dnode->name, dnode->uuid, dnode->dev, dnode->props.major, dnode->props.read_only);

	strncpy(param.name, dnode->name, sizeof(param.name));
	strncpy(param.uuid, dnode->uuid, sizeof(param.uuid));
	//param.uuid = dnode->uuid;
	param.flags = DM_EXISTS_FLAG | DM_SKIP_BDGET_FLAG;

	if (dnode->props.read_only)
		param.flags |= DM_READONLY_FLAG;

	my_dev_create(&param);

	r = dm_task_get_info(&param, &dnode->info);

    return r;
}

#define EMIT_PARAMS(p, str...)\
do {\
    int w;\
    if ((w = snprintf(params + p, paramsize - (size_t) p, str)) < 0) \
        return -1;\
    p += w;\
} while (0)


static int dm_format_dev(char *buf, int bufsize, uint32_t dev_major,
          uint32_t dev_minor)
{             
    int r;    
        
    if (bufsize < 8)
        return 0;
    
    r = snprintf(buf, (size_t) bufsize, "%u:%u", dev_major, dev_minor);
    if (r < 0 || r > bufsize - 1)
        return 0;

    return 1;
}

static int _build_dev_string(char *devbuf, size_t bufsize, struct dm_tree_node *node)
{
    int r;    
        
    if (bufsize < 8)
        return 0;

	dev_t dev = node->dev;

//	printk(">>>%s:%d major=%lx minor=%lx\n", __func__, __LINE__, LVM_MAJOR(dev), LVM_MINOR(dev));
    
    r = snprintf(devbuf, (size_t)bufsize, "%u:%u", LVM_MAJOR(dev), LVM_MINOR(dev));
    if (r < 0 || r > bufsize - 1)
        return 0;

    return 1;
} 

struct dm_task {
    struct target *head, *tail;
};

#define DM_FORMAT_DEV_BUFSIZE   13  /* Minimum bufsize to handle worst case. */

static int _emit_areas_line(struct load_segment *seg, char *params,
                size_t paramsize, int *pos)
{
    struct seg_area *area;
    char devbuf[DM_FORMAT_DEV_BUFSIZE];
    unsigned first_time = 1;
    const char *logtype, *synctype;

//    dm_list_iterate_items(area, &seg->areas) {
	list_for_each_entry(area, &seg->areas, list) {
        if (!_build_dev_string(devbuf, sizeof(devbuf), area->dev_node))
            return 0;

        EMIT_PARAMS(*pos, "%s%s %llu", first_time ? "" : " ",
                    devbuf, area->offset);

        first_time = 0;
    }

    return 1;
}

struct target {
    uint64_t start;
    uint64_t length;
    char *type;
    char *params;
        
    struct target *next;
};

static struct target *create_target(uint64_t start, uint64_t len, const char *type,
                 const char *params)
{   
    struct target *t;
    
//    if (!(t = kzalloc(sizeof(*t), GFP_KERNEL)))
    if (!(t = dm_alloc(sizeof(*t), true)))
        return NULL;

    if (!(t->params = dm_pool_strdup(params)))
        goto bad;

    if (!(t->type = dm_pool_strdup(type)))
        goto bad;

    t->start = start;
    t->length = len;

    return t;

bad:
    kfree(t->params);
    kfree(t->type);
    kfree(t);

    return NULL;
}


static int dm_task_add_target(struct dm_task *dmt, uint64_t start, uint64_t size,
               const char *ttype, const char *params)
{               
    struct target *t = create_target(start, size, ttype, params);
    if (!t)
        return 0; 

    if (!dmt->head)
        dmt->head = dmt->tail = t;
    else {
        dmt->tail->next = t;
        dmt->tail = t;
    }
             
    return 1;
}

static const struct {
    unsigned type;
    const char target[16];
} _dm_segtypes[] = {
    { SEG_CACHE, "cache" },
    { SEG_CRYPT, "crypt" },
    { SEG_ERROR, "error" },
    { SEG_LINEAR, "linear" },
    { SEG_MIRRORED, "mirror" },
    { SEG_REPLICATOR, "replicator" },
    { SEG_REPLICATOR_DEV, "replicator-dev" },
    { SEG_SNAPSHOT, "snapshot" },
    { SEG_SNAPSHOT_ORIGIN, "snapshot-origin" },
    { SEG_SNAPSHOT_MERGE, "snapshot-merge" },
    { SEG_STRIPED, "striped" },
    { SEG_ZERO, "zero"},
    { SEG_THIN_POOL, "thin-pool"},
    { SEG_THIN, "thin"},
    { SEG_RAID1, "raid1"},
    { SEG_RAID10, "raid10"},
    { SEG_RAID4, "raid4"},
    { SEG_RAID5_LA, "raid5_la"},
    { SEG_RAID5_RA, "raid5_ra"},
    { SEG_RAID5_LS, "raid5_ls"},
    { SEG_RAID5_RS, "raid5_rs"},
    { SEG_RAID6_ZR, "raid6_zr"},
    { SEG_RAID6_NR, "raid6_nr"},
    { SEG_RAID6_NC, "raid6_nc"},

    /*
     * WARNING: Since 'raid' target overloads this 1:1 mapping table
     * for search do not add new enum elements past them!
     */
    { SEG_RAID5_LS, "raid5"}, /* same as "raid5_ls" (default for MD also) */
    { SEG_RAID6_ZR, "raid6"}, /* same as "raid6_zr" */
};



static int _emit_segment_line(struct dm_task *dmt, uint32_t major,
                  uint32_t minor, struct load_segment *seg,
                  uint64_t *seg_start, char *params,
                  size_t paramsize)
{
    int pos = 0;
    int r;

    switch(seg->type) {
    case SEG_STRIPED:
        EMIT_PARAMS(pos, "%u %u ", seg->area_count, seg->stripe_size);
    case SEG_LINEAR:
        if ((r = _emit_areas_line(seg, params, paramsize, &pos)) <= 0)
            return r;

        if (!params[0]) {
			printk(">>>%s:%d\n", __func__, __LINE__);
            return 0;
        }   
        break;
    } 

    if (!dm_task_add_target(dmt, *seg_start, seg->size,
                _dm_segtypes[seg->type].target, params))
        return 0;

    *seg_start += seg->size;

    return 1;
}

#define MAX_TARGET_PARAMSIZE 50000

static int _emit_segment(struct dm_task *dmt, uint32_t major, uint32_t minor,
             struct load_segment *seg, uint64_t *seg_start)
{
    char *params;
    size_t paramsize = 4096;
    int ret;

    do {
        if (!(params = kmalloc(paramsize, GFP_KERNEL))) {
			printk(">>>%s:%d\n", __func__, __LINE__);
            return 0;
        }

        params[0] = '\0';
        ret = _emit_segment_line(dmt, major, minor, seg, seg_start,
                     params, paramsize);
        kfree(params);

        if (ret >= 0)
            return ret;

        paramsize *= 2;
    } while (paramsize < MAX_TARGET_PARAMSIZE);

	printk(">>>%s:%d\n", __func__, __LINE__);
    return 0;
}

static char *_align(char *ptr, unsigned int a)
{   
    register unsigned long agn = --a;

    return (char *) (((unsigned long) ptr + agn) & ~agn);
}

#define ALIGNMENT 8

static char *_add_target(struct target *t, char *out, char *end)
{
    char *out_sp = out;
    struct dm_target_spec sp;
    size_t sp_size = sizeof(struct dm_target_spec);
    unsigned int backslash_count = 0;
    int len;
    char *pt;

    sp.status = 0;
    sp.sector_start = t->start;
    sp.length = t->length;
    strncpy(sp.target_type, t->type, sizeof(sp.target_type) - 1);
    sp.target_type[sizeof(sp.target_type) - 1] = '\0';

    out += sp_size;
    pt = t->params;

    while (*pt)
        if (*pt++ == '\\')
            backslash_count++;

    len = strlen(t->params) + backslash_count;

    if ((out >= end) || (out + len + 1) >= end) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return NULL;
    }

    if (backslash_count) {
        /* replace "\" with "\\" */
        pt = t->params;
        do {
            if (*pt == '\\')
                *out++ = '\\';
            *out++ = *pt++;
        } while (*pt);
        *out++ = '\0';
    } else {
        strcpy(out, t->params);
        out += len + 1;
    }

    /* align next block */
    out = _align(out, ALIGNMENT);

    sp.next = out - out_sp;
    memcpy(out_sp, &sp, sp_size);

    return out;
}


int table_load(struct file *filp, struct dm_ioctl *param, size_t param_size);

static int _load_node(struct dm_tree_node *dnode)
{
    int r = 0;
    struct load_segment *seg;
    uint64_t seg_start = 0, existing_table_size;
	struct dm_ioctl *dmi;
	struct dm_task dmt;
	struct target *t;
	int count = 0;
	char *b, *e;

	printk(">>>%s:%d name=%s uuid=%s dev=%lx major=%lx minor=%lx\n", __func__, __LINE__,
		dnode->name, dnode->uuid, dnode->dev, dnode->info.major, dnode->info.minor);

	dmt.head = NULL;
	dmt.tail = NULL;

	list_for_each_entry(seg, &dnode->props.segs, list)
        if (!_emit_segment(&dmt, dnode->info.major, dnode->info.minor,
                   seg, &seg_start))
            goto out;

	size_t len = sizeof(struct dm_ioctl);

    for (t = dmt.head; t; t = t->next) {
        len += sizeof(struct dm_target_spec);
        len += strlen(t->params) + 1 + ALIGNMENT;
        count++;
    }

    if (len < 16 * 1024)
        len = 16 * 1024;

	//dmi = kvmalloc(param_kernel->data_size, GFP_KERNEL | __GFP_HIGH);
    if (!(dmi = kvmalloc(len, GFP_KERNEL | __GFP_HIGH)))
        goto out;

	memset(dmi, 0, len);

    dmi->version[0] = 4;
    dmi->version[1] = 0;
    dmi->version[2] = 0;

    dmi->data_size = len;
    dmi->data_start = sizeof(struct dm_ioctl);


    dmi->flags |= DM_PERSISTENT_DEV_FLAG;
    dmi->dev = LVM_MKDEV((dev_t)_dm_device_major, (dev_t)dnode->info.minor);

    dmi->target_count = count;

    b = (char *)(dmi + 1);
    e = (char *)dmi + len;

    for (t = dmt.head; t; t = t->next)
        if (!(b = _add_target(t, b, e)))
            goto out;

	dmi->flags = DM_EXISTS_FLAG | DM_SKIP_BDGET_FLAG;
	if (dnode->props.read_only)
		dmi->flags |= DM_READONLY_FLAG;


	if ((r = table_load(NULL, dmi, len))) {
		printk(">>>%s:%d r=%d\n", __func__, __LINE__, r);
		r = 0;
		goto out;
	}

    r = dm_task_get_info(dmi, &dnode->info);

	dnode->props.size_changed = 1;
    dnode->props.segment_count = 0;

out:
	kvfree(dmi);

    return r;
}





static int dm_tree_preload_children(struct dm_tree_node *dnode,
                 const char *uuid_prefix,
                 size_t uuid_prefix_len)
{
    int r = 1, node_created = 0;
    void *handle = NULL;
	struct dm_tree_link *link;
    struct dm_tree_node *child;
    struct dm_info newinfo;
    int update_devs_flag = 0;

    /* Preload children first */
	list_for_each_entry(link, &dnode->uses, list) {
		child = link->node;

        /* Skip existing non-device-mapper devices */
        if (!child->info.exists && child->info.major)
            continue;

        if (child->info.exists &&
            !_uuid_prefix_matches(child->uuid, uuid_prefix, uuid_prefix_len))
            continue;

        if (dm_tree_node_num_children(child, 0))
            if (!dm_tree_preload_children(child, uuid_prefix, uuid_prefix_len))
                return 0;

        /* FIXME Cope if name exists with no uuid? */
        if (!(node_created = _create_node(child)))
            return 0;

        if (!child->info.inactive_table &&
            child->props.segment_count &&
            !_load_node(child)) {
			printk(">>>error %s:%d \n ", __func__, __LINE__);
            return 0;
        }

       /* Propagate device size change change */
        if (child->props.size_changed > 0 && !dnode->props.size_changed)
            dnode->props.size_changed = 1;
        else if (child->props.size_changed < 0)
            dnode->props.size_changed = -1;

        /* Resume device immediately if it has parents and its size changed */
        if (!dm_tree_node_num_children(child, 1) || !child->props.size_changed)
            continue;

        if (!child->info.inactive_table && !child->info.suspended)
            continue;

		printk(">>>error %s:%d\n", __func__, __LINE__);
    }

    return r;
}

static const char *dm_tree_node_get_uuid(const struct dm_tree_node *node)
{
    return node->info.exists ? node->uuid : "";
}

static int _uuid_prefix_matches(const char *uuid, const char *uuid_prefix, size_t uuid_prefix_len)
{
    const char *default_uuid_prefix = UUID_PREFIX;
    size_t default_uuid_prefix_len = strlen(default_uuid_prefix);

    if (!uuid_prefix)
        return 1;

    if (!strncmp(uuid, uuid_prefix, uuid_prefix_len))
        return 1;

    /* Handle transition: active device uuids might be missing the prefix */
    if (uuid_prefix_len <= 4)
        return 0;

    if (!strncmp(uuid, default_uuid_prefix, default_uuid_prefix_len))
        return 0;

    if (strncmp(uuid_prefix, default_uuid_prefix, default_uuid_prefix_len))
        return 0;

    if (!strncmp(uuid, uuid_prefix + default_uuid_prefix_len, uuid_prefix_len - default_uuid_prefix_len))
        return 1;

    return 0;
}

static const char *dm_tree_node_get_name(const struct dm_tree_node *node)
{
    return node->info.exists ? node->name : "";
}


int do_resume(struct dm_ioctl *param);

static int _resume_node(const char *name, uint32_t major, uint32_t minor,
            uint32_t read_ahead, uint32_t read_ahead_flags,
            struct dm_info *newinfo, uint32_t *cookie,
            uint16_t udev_flags, int already_suspended)
{
    int r = 0;
	struct dm_ioctl dmi;
	struct dm_info *info;

//	printk(">>>%s:%d name=%s uuid=%s dev=%lx major=%lx ro=%d\n", __func__, __LINE__,
//		dnode->name, dnode->uuid, dnode->dev, dnode->props.major, dnode->props.read_only);

	memset(&dmi, 0, sizeof(dmi));

    dmi.version[0] = 4;
    dmi.version[1] = 0;
    dmi.version[2] = 0;

    dmi.flags |= DM_PERSISTENT_DEV_FLAG;
    dmi.dev = LVM_MKDEV((dev_t)_dm_device_major, (dev_t)minor);

	dmi.flags = DM_EXISTS_FLAG | DM_SKIP_BDGET_FLAG;

	r = do_resume(&dmi);
	if (r) {
		printk(">>>%s:%d fail to resume lv r=%d\n", __func__, __LINE__, r);
		r = 0;
		goto out;
	}

    r = dm_task_get_info(&dmi, newinfo);

out:

    return r;
}

static int dm_tree_activate_children(struct dm_tree_node *dnode,
                 const char *uuid_prefix,
                 size_t uuid_prefix_len)
{
    int r = 1;
    int resolvable_name_conflict;
    void *handle = NULL;
    struct dm_tree_node *child = dnode;
    struct dm_info newinfo;
    const char *name;
    const char *uuid;
	struct dm_tree_link *link;

    /* Activate children first */
	list_for_each_entry(link, &dnode->uses, list) {
		child = link->node;
        if (!(uuid = dm_tree_node_get_uuid(child)))
            continue;

        if (!_uuid_prefix_matches(uuid, uuid_prefix, uuid_prefix_len))
            continue;

        if (dm_tree_node_num_children(child, 0))
            if (!dm_tree_activate_children(child, uuid_prefix, uuid_prefix_len))
                return 0;
    }

    handle = NULL;
	list_for_each_entry(link, &dnode->uses, list) {
			child = link->node;

            if (!(uuid = dm_tree_node_get_uuid(child)))
                continue;

            if (!_uuid_prefix_matches(uuid, uuid_prefix, uuid_prefix_len))
                continue;

            if (!(name = dm_tree_node_get_name(child)))
                continue;

            if (!child->info.inactive_table && !child->info.suspended)
                continue;

		//	printk(">>>%s:%d name=%s uuid=%s dev=%lx major=%lx minor=%lx ro=%d\n", __func__, __LINE__,
		//		child->name, child->uuid, child->dev, child->info.major, child->info.minor);

            if (!_resume_node(child->name, child->info.major, child->info.minor,
                      child->props.read_ahead, child->props.read_ahead_flags,
                      &newinfo, &child->dtree->cookie, child->udev_flags, child->info.suspended)) {
				printk(">>>error %s:%d\n", __func__, __LINE__);

                r = 0;
                continue;
            }

            /* Update cached info */
            child->info = newinfo;

			if (child->context) {
				struct logical_volume *lv;
    			struct lv_layer *lvlayer = child->context;

				lv = lvlayer->lv;
				if (!strcmp(lv->name, lvname))
					sprintf(real_root_dev_name, "/dev/dm-%d", child->info.minor);
			}
	}

    return r;
}


static int _tree_action(struct dev_manager *dm, const struct logical_volume *lv,
            struct lv_activate_opts *laopts, action_t action)
{
    const size_t DLID_SIZE = ID_LEN + sizeof(UUID_PREFIX) - 1;
    struct dm_tree *dtree;
    struct dm_tree_node *root;
    char *dlid;
    int r = 0;

    /* Some targets may build bigger tree for activation */
    dm->activation = action == ACTIVATE;
    dm->suspend = 0;

    if (!(dtree = _create_partial_dtree(dm, lv)))
        return 0;

    root = &dtree->root;

    if (!(dlid = build_dm_uuid(lv, NULL)))
        goto out;

//	printk(">>>%s:%d lv uuid=%s\n", __func__, __LINE__, dlid);

    switch(action) {
#if 0
    case CLEAN:
        if (retry_deactivation())
            dm_tree_retry_remove(root);

        /* Deactivate any unused non-toplevel nodes */
        if (!_clean_tree(dm, root, laopts->origin_only ? dlid : NULL))
            goto out;
        break;
#endif
	case ACTIVATE:
        /* Add all required new devices to tree */
        if (!_add_new_lv_to_dtree(dm, dtree, lv, laopts, NULL))
            goto out;

        /* Preload any devices required before any suspensions */
        if (!dm_tree_preload_children(root, dlid, DLID_SIZE))
            goto out;

        if (root->props.size_changed < 0)
            dm->flush_required = 1;

        /* Currently keep the code require flush for any
         * non 'thin pool/volume, mirror' or with any size change */
        if (!lv_is_thin_volume(lv))
            dm->flush_required = 1;

#if 1
        if (action == ACTIVATE) {
            if (!dm_tree_activate_children(root, dlid, DLID_SIZE))
                goto out;

      //      if (!_create_lv_symlinks(dm, root))
	//			printk(">>>%s:%d\n", __func__, __LINE__);
               // log_warn("Failed to create symlinks for %s.", lv->name);
        }
#endif

        break;
    default:
		printk(">>>%s:%d\n", __func__, __LINE__);
        //log_error(INTERNAL_ERROR "_tree_action: Action %u not supported.", action);
        goto out;
    }

    r = 1;

out:
    /* Save fs cookie for udev settle, do not wait here */
out_no_root:
  //  dm_tree_free(dtree);

    return r;
}

static char *dm_build_dm_uuid(const char *uuid_prefix, const char *lvid, const char *layer)
{           
    char *dmuuid;
    size_t len;
            
    if (!layer)
        layer = "";
            
    len = strlen(uuid_prefix) + strlen(lvid) + strlen(layer) + 2;
            
//    if (!(dmuuid = kmalloc(len, GFP_KERNEL))) {
    if (!(dmuuid = dm_alloc(len, false))) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return NULL;
    }

    sprintf(dmuuid, "%s%s%s%s", uuid_prefix, lvid, (*layer) ? "-" : "", layer);

    return dmuuid;
}

static struct lv_segment *get_only_segment_using_this_lv(const struct logical_volume *lv)
{   
    struct seg_list *sl;
    
    if (!lv)
        return NULL;
    
	list_for_each_entry(sl, &lv->segs_using_this_lv, list) {
        /* Needs to be he only item in list */
        if (!(&lv->segs_using_this_lv == sl->list.next))
            break;
        
        if (sl->count != 1)
            return NULL;
        
        return sl->seg;
    }
          
    return NULL;
} 

static int lv_is_cache_origin(const struct logical_volume *lv)
{
    struct lv_segment *seg;

    /* Make sure there's exactly one segment in segs_using_this_lv! */ 
    if (list_empty(&lv->segs_using_this_lv) ||
        (list_size(&lv->segs_using_this_lv) > 1))
        return 0;

    seg = get_only_segment_using_this_lv(lv); 

    return seg && lv_is_cache(seg->lv) && !lv_is_pending_delete(seg->lv) && (seg_lv(seg, 0) == lv);
}

static char *build_dm_uuid(const struct logical_volume *lv,
            const char *layer)
{           
    const char *lvid = lv->lvid.s;
    
    if (!layer) {
        layer = lv_is_cache_origin(lv) ? "real" :
            (lv_is_cache(lv) && lv_is_pending_delete(lv)) ? "real" :
            lv_is_cache_pool_data(lv) ? "cdata" :
            lv_is_cache_pool_metadata(lv) ? "cmeta" :
            lv_is_thin_pool(lv) ? "pool" :
            lv_is_thin_pool_data(lv) ? "tdata" :
            lv_is_thin_pool_metadata(lv) ? "tmeta" :
            NULL;
    } 
    
    return dm_build_dm_uuid(UUID_PREFIX, lvid, layer);
} 

static int lv_active_change(struct logical_volume *lv)
{
	int excl;
    struct lv_activate_opts laopts;
    struct dev_manager *dm;
	uint32_t flags = LCK_HOLD | LCK_LOCAL;
	int r = 0;

	if (_lv_is_exclusive(lv))
		flags |= LCK_LV_EXCLUSIVE;
	else
		flags |= LCK_LV_ACTIVATE;

    flags |= LCK_NONBLOCK;

	if (LCK_EXCL == (flags & LCK_EXCL))
		excl = 1;
	else
		excl = 0;

	memset(&laopts, 0, sizeof(struct lv_activate_opts));

    laopts.exclusive = excl;
    laopts.noscan = lv->status & LV_NOSCAN ? 1 : 0;
    laopts.temporary = lv->status & LV_TEMPORARY ? 1 : 0;

	if (!(dm = kzalloc(sizeof(struct dev_manager), GFP_KERNEL)))
		goto out;

	dm->vg_name = lv->vg->name;
    dm->track_pvmove_deps = 1;
    INIT_LIST_HEAD(&dm->pending_delete);
    
    if (!_tree_action(dm, lv, &laopts, ACTIVATE))
        r = 0;;
    
#if 0
    if (!_tree_action(dm, lv, &laopts, CLEAN))
        return 0;
#endif

out:
	kfree(dm);
    return r;
}


static int lv_is_replicator_dev(const struct logical_volume *lv)
{
    return ((lv->status & REPLICATOR) &&
        !list_empty(&lv->segments) &&
        seg_is_replicator_dev(first_seg(lv)));
}

static int find_replicator_vgs(const struct logical_volume *lv)
{
    struct replicator_site *rsite;
    int ret = 1;

    if (!lv_is_replicator_dev(lv))
        return 1;

    ret = 0;
#if 0
    dm_list_iterate_items(rsite, &first_seg(lv)->replicator->rsites) {
//      fprintf(stderr, ">>>%s:%d\n", __func__, __LINE__);
        if (!rsite->vg_name || !lv->vg->cmd_vgs ||
            cmd_vg_lookup(lv->vg->cmd_vgs, rsite->vg_name, NULL))
            continue;

        ret = 0;
        /* Using cmd memory pool for cmd_vg list allocation */
        if (!cmd_vg_add(lv->vg->cmd->mem, lv->vg->cmd_vgs,
                rsite->vg_name, NULL, 0)) {
            lv->vg->cmd_missing_vgs = 0; /* do not retry */
            stack;
            break;
        }   

//      log_debug_metadata("VG: %s added as missing.", rsite->vg_name);
        lv->vg->cmd_missing_vgs++;
    }   
#endif

    return ret;
}


static char *_unquote(char *component)
{   
    char *c = component;
    char *o = c;
    char *r;
    
    while (*c) {
        if (*(c + 1)) {
            if (*c == '-') { 
                if (*(c + 1) == '-')
                    c++;
                else
                    break;
            }
        }
        *o = *c;
        o++;
        c++;
    }
    
    r = (*c) ? c + 1 : c;
    *o = '\0';
    
    return r;
}

static char *root_name = NULL;

static int parse_vg_lv_name(char *orignal_root_name)
{
	char *ptr, *start;

	root_name = kmalloc(strlen(orignal_root_name) + 1, GFP_KERNEL);
	if (!root_name)
		return 0;

	strcpy(root_name, orignal_root_name);

	if (strncmp(root_name, "/dev/", 5)) {
		kfree(root_name);
		return 0;
	}

	start = orignal_root_name + 5;

    if (!(ptr = strchr(start, '/'))) {
		kfree(root_name);
		return 0;
	}

	*ptr = '\0';

	if (!strcmp(start, "mapper")) {
		vgname = ptr + 1;
		_unquote(lvname = _unquote(vgname));
	} else {
		vgname = start;
		lvname = ptr + 1;
	}

	real_root_dev_name = orignal_root_name;

	return 1;
}

static int enlarge_dm_alloc_array(void)
{
	void *tmp;
	size_t old_len = dm_alloc_array_size;
	size_t new_len = dm_alloc_array_size + PAGE_SIZE;

   	if (!(tmp = kvmalloc(new_len, GFP_KERNEL | __GFP_HIGH)))
       	return -1;

	memset(tmp, 0, new_len);
	memcpy(tmp, dm_alloc_array, old_len);

	kvfree(dm_alloc_array);
	dm_alloc_array = tmp;
	dm_alloc_array_size = new_len;

	return 0;
}

static void *dm_alloc(size_t length, bool zero)
{
	void *ptr = NULL;

	if (!dm_alloc_array)
		if (0 > enlarge_dm_alloc_array())
			goto out;

	if (zero)
		ptr = kzalloc(length, GFP_KERNEL);
	else
		ptr = kmalloc(length, GFP_KERNEL);

	if (!ptr)
		goto out;

	dm_alloc_array[dm_alloc_array_cnt++] = ptr;

	if (dm_alloc_array_cnt * sizeof(void*) == dm_alloc_array_size)
		if (0 > enlarge_dm_alloc_array())
			BUG();

out:
	return ptr;
}

static void dm_free(void *ptr)
{
	int i;
	void *tmp;

	for (i = 0; i < dm_alloc_array_cnt; i++) {
		tmp = dm_alloc_array[i];
		if (ptr == tmp) {
			kfree(tmp);
			dm_alloc_array[i] = NULL;
		}
	}
}

static void free_dm_memory(void)
{
	int i;
	void *ptr;

	for (i = 0; i < dm_alloc_array_cnt; i++) {
		ptr = dm_alloc_array[i];
		if (ptr)
			kfree(ptr);
	}

	kvfree(dm_alloc_array);
}

static void parse_lvm_root_dev(void)
{
	struct dev_types *dts;
	struct list_head dev_head;
	struct hyper_rootdev_device *dev;
	struct format_instance fid;
	struct volume_group *vg = NULL, *correct_vg = NULL;
	struct metadata_area *mda;
	unsigned use_previous_vg;
	struct cached_vg_fmtdata *vg_fmtdata = NULL;
	struct segment_type *segtype;
    struct lv_list *lvl = NULL;

	parse_init();

	dts = create_dev_types();
	if (!dts)
		return;

	INIT_LIST_HEAD(&dev_head);
	prepare_dev_list(&dev_head);

	_dm_device_major = dts->device_mapper_major;

	INIT_LIST_HEAD(&pv_head);
	INIT_LIST_HEAD(&vginfo_head);

	list_for_each_entry(dev, &dev_head, list) {
        if (my_filter(dts, dev)) {
    		char buf[LABEL_SIZE] __attribute__((aligned(8)));
    		uint64_t sector;
    		int r = 0;
			struct label *label;

			if ((r = lvm2_find_label(dev, buf, &sector))) {
				if ((r = lvm2_label_read(dts, dev, buf, &label)) && label) {
					label->dev = dev;
					label->sector = sector;
				}
			}
        }
	}

	fid.vgname = vgname;

	INIT_LIST_HEAD(&fid.metadata_areas_in_use);
	INIT_LIST_HEAD(&fid.metadata_areas_ignored);
	INIT_LIST_HEAD(&fid.metadata_areas_index);

    _create_vg_text_instance(&fid);

	INIT_LIST_HEAD(&segtypes_head);
    segtype = dm_alloc(sizeof(*segtype), true);
	if (!segtype) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		goto out;
	}

    segtype->ops = &_striped_ops;
    segtype->name = SEG_TYPE_NAME_STRIPED;
    segtype->flags =
        SEG_CAN_SPLIT | SEG_AREAS_STRIPED | SEG_FORMAT1_SUPPORT;
	INIT_LIST_HEAD(&segtype->list);

	list_add(&segtype->list, &segtypes_head);


	list_for_each_entry(mda, &fid.metadata_areas_in_use, list) {
        use_previous_vg = 0;

        if (!(vg = _vg_read_raw(&fid, mda, &vg_fmtdata, &use_previous_vg))
                && !use_previous_vg) {
            vg_fmtdata = NULL;
            continue;
        }

        /* Use previous VG because checksum matches */
        if (!vg) {
            vg = correct_vg;
            continue;
        }

        if (!correct_vg) {
            correct_vg = vg;
            continue;
        }

        /* FIXME Also ensure contents same - checksum compare? */
        if (correct_vg->seqno != vg->seqno) {
            if (vg->seqno > correct_vg->seqno)
                correct_vg = vg;
            else
                mda->status |= MDA_INCONSISTENT;
        }

        if (vg != correct_vg)
            vg_fmtdata = NULL;
    }

	if (!vg) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		goto out;
	}

	list_for_each_entry(lvl, &vg->lvs, list) {
		struct logical_volume *lv = lvl->lv;
		struct logical_volume *origin;

		if (lv->status & SNAPSHOT)
            continue;

		if (strcmp(lv->name, lvname))
            continue;

		if (lv_is_pvmove(lv))
			continue;

		if (lv_is_mirror_log(lv))
			continue;

		if (lv_is_mirror_image(lv))
			continue;

		if (lv_is_pending_delete(lv))
			continue;

		if (lv_is_external_origin(lv))
			continue;

		if (lv_is_origin(lv))
			continue;

		if (lv_is_merging_origin(lv))
			continue;

		if (lv_is_cow(lv))
			continue;

		if (lv_is_thin_pool(lv)) {
			printk(">>>%s:%d thin pool LV is not support\n", __func__, __LINE__);
			continue;
		}

		if (lv_is_cache_pool(lv)) {
			printk(">>>%s:%d cache pool LV is not support\n", __func__, __LINE__);
			continue;
		}

		if (lv_is_cache(lv)) {
			printk(">>>%s:%d cache LV is not support\n", __func__, __LINE__);
			continue;
		}

		if ((lv->vg->status & PRECOMMITTED)) {
			printk(">>>%s:%d precommitted VG is not support\n", __func__, __LINE__);
			continue;
		}

		if (!lv_is_visible(lv) && !lv_is_virtual_origin(lv))
			continue;

		if (!find_replicator_vgs(lv))
			continue;

		lv_active_change(lv);
	}


out:
	list_for_each_entry(dev, &dev_head, list) {
		if (dev->fd >= 0)
			sys_close(dev->fd);
	}

	free_dm_memory();

	kfree(root_name);

	return;
}

void hyper_gen_parse_root_dev(char *orignal_root_name)
{
	if (parse_vg_lv_name(orignal_root_name))
		parse_lvm_root_dev();
}
