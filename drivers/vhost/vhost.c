/* Copyright (C) 2009 Red Hat, Inc.
 * Copyright (C) 2006 Rusty Russell IBM Corporation
 *
 * Author: Michael S. Tsirkin <mst@redhat.com>
 *
 * Inspiration, some code, and most witty comments come from
 * Documentation/virtual/lguest/lguest.c, by Rusty Russell
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 * Generic code for virtio server in host kernel.
 */

#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/uio.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/kthread.h>
#include <linux/cgroup.h>
#include <linux/module.h>
#include <linux/sort.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/interval_tree_generic.h>
#include <linux/nospec.h>

#include "vhost.h"

void __must_check vhost_inject_virq_kvm(uint64_t kvm_id, void *irq_priv);
void * __must_check vhost_alloc_irq_entry_kvm(uint64_t kvm_id, int virq);

void * __must_check vhost_alloc_notify_evt_(uint64_t evt_id,
				struct wait_queue_entry *entry, uint64_t kvm_id);
void vhost_free_notify_evt_(uint64_t evt_id, uint64_t kvm_id);


static ushort max_mem_regions = 64;
module_param(max_mem_regions, ushort, 0444);
MODULE_PARM_DESC(max_mem_regions,
	"Maximum number of memory regions in memory map. (default: 64)");
static int max_iotlb_entries = 2048;
module_param(max_iotlb_entries, int, 0444);
MODULE_PARM_DESC(max_iotlb_entries,
	"Maximum number of iotlb entries. (default: 2048)");

enum {
	VHOST_MEMORY_F_LOG = 0x1,
};

#define vhost_used_event(vq) ((__virtio16 *)&vq->avail->ring[vq->num])
#define vhost_avail_event(vq) ((__virtio16 *)&vq->used->ring[vq->num])

INTERVAL_TREE_DEFINE(struct vhost_umem_node,
		     rb, __u64, __subtree_last,
		     START, LAST, static inline, vhost_umem_interval_tree);

#ifdef CONFIG_VHOST_CROSS_ENDIAN_LEGACY
static void vhost_disable_cross_endian(struct vhost_virtqueue *vq)
{
	vq->user_be = !virtio_legacy_is_little_endian();
}

static void vhost_enable_cross_endian_big(struct vhost_virtqueue *vq)
{
	vq->user_be = true;
}

static void vhost_enable_cross_endian_little(struct vhost_virtqueue *vq)
{
	vq->user_be = false;
}

static void vhost_init_is_le(struct vhost_virtqueue *vq)
{
	/* Note for legacy virtio: user_be is initialized at reset time
	 * according to the host endianness. If userspace does not set an
	 * explicit endianness, the default behavior is native endian, as
	 * expected by legacy virtio.
	 */
	vq->is_le = vhost_has_feature(vq, VIRTIO_F_VERSION_1) || !vq->user_be;
}
#else
static void vhost_disable_cross_endian(struct vhost_virtqueue *vq)
{
}

static void vhost_init_is_le(struct vhost_virtqueue *vq)
{
	vq->is_le = vhost_has_feature(vq, VIRTIO_F_VERSION_1)
		|| virtio_legacy_is_little_endian();
}
#endif /* CONFIG_VHOST_CROSS_ENDIAN_LEGACY */

static void vhost_reset_is_le(struct vhost_virtqueue *vq)
{
	vhost_init_is_le(vq);
}

struct vhost_flush_struct {
	struct vhost_work work;
	struct completion wait_event;
};

static void vhost_flush_work(struct vhost_work *work)
{
	struct vhost_flush_struct *s;

	s = container_of(work, struct vhost_flush_struct, work);
	complete(&s->wait_event);
}

static void vhost_poll_func(struct file *file, wait_queue_head_t *wqh,
			    poll_table *pt)
{
	struct vhost_poll *poll;

	poll = container_of(pt, struct vhost_poll, table);
	poll->wqh = wqh;
	add_wait_queue(wqh, &poll->wait);
}

int vhost_poll_wakeup(wait_queue_entry_t *wait, unsigned mode, int sync,
			     void *key)
{
	struct vhost_poll *poll = container_of(wait, struct vhost_poll, wait);

 	if (!((unsigned long)key & poll->mask))
 		return 0;

	vhost_poll_queue(poll);

	return 0;
}

void vhost_work_init(struct vhost_work *work, vhost_work_fn_t fn)
{
	clear_bit(VHOST_WORK_QUEUED, &work->flags);
	work->fn = fn;
	init_waitqueue_head(&work->done);
}
EXPORT_SYMBOL_GPL(vhost_work_init);

/* Init poll structure */
void vhost_poll_init(struct vhost_poll *poll, vhost_work_fn_t fn,
		     unsigned long mask, struct vhost_dev *dev)
{
	init_waitqueue_func_entry(&poll->wait, vhost_poll_wakeup);
	init_poll_funcptr(&poll->table, vhost_poll_func);
	poll->mask = mask;
	poll->dev = dev;
	poll->wqh = NULL;
	poll->evt_id = 0;

	vhost_work_init(&poll->work, fn);
}
EXPORT_SYMBOL_GPL(vhost_poll_init);

/* Start polling a file. We add ourselves to file's wait queue. The caller must
 * keep a reference to a file until after vhost_poll_stop is called. */
int vhost_poll_start(struct vhost_poll *poll, struct file *file)
{
	unsigned long mask;
	int ret = 0;

	if (poll->wqh)
		return 0;

	mask = file->f_op->poll(file, &poll->table);
	if (mask)
		vhost_poll_wakeup(&poll->wait, 0, 0, (void *)mask);

	if (mask & POLLERR) {
		vhost_poll_stop(poll);
		ret = -EINVAL;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(vhost_poll_start);

static void my_vhost_poll_start(struct vhost_poll *poll, struct vhost_virtqueue *vq)
{
	vq->notify_priv = vhost_alloc_notify_evt_(vq->evt_id, &poll->wait, vq->kvm_id);
}

/* Stop polling a file. After this function returns, it becomes safe to drop the
 * file reference. You must also flush afterwards. */
void vhost_poll_stop(struct vhost_poll *poll)
{
	if (poll->wqh) {
		remove_wait_queue(poll->wqh, &poll->wait);
		poll->wqh = NULL;
	}
}
EXPORT_SYMBOL_GPL(vhost_poll_stop);

static void my_vhost_poll_stop(struct vhost_virtqueue *vq)
{
	vq->notify_status = -1;
	kfree(vq->notify_priv);
	vq->notify_priv = NULL;
}

void vhost_work_flush(struct vhost_dev *dev, struct vhost_work *work)
{
	struct vhost_flush_struct flush;

	if (dev->worker) {
		init_completion(&flush.wait_event);
		vhost_work_init(&flush.work, vhost_flush_work);

		vhost_work_queue(dev, &flush.work);
		wait_for_completion(&flush.wait_event);
	}
}
EXPORT_SYMBOL_GPL(vhost_work_flush);

/* Flush any work that has been scheduled. When calling this, don't hold any
 * locks that are also used by the callback. */
void vhost_poll_flush(struct vhost_poll *poll)
{
	vhost_work_flush(poll->dev, &poll->work);
}
EXPORT_SYMBOL_GPL(vhost_poll_flush);

void vhost_work_queue(struct vhost_dev *dev, struct vhost_work *work)
{
	if (!dev->worker)
		return;

	if (!test_and_set_bit(VHOST_WORK_QUEUED, &work->flags)) {
		/* We can only add the work to the list after we're
		 * sure it was not in the list.
		 * test_and_set_bit() implies a memory barrier.
		 */
		llist_add(&work->node, &dev->work_list);
		wake_up_process(dev->worker);
	}
}
EXPORT_SYMBOL_GPL(vhost_work_queue);

/* A lockless hint for busy polling code to exit the loop */
bool vhost_has_work(struct vhost_dev *dev)
{
	return !llist_empty(&dev->work_list);
}
EXPORT_SYMBOL_GPL(vhost_has_work);

void vhost_poll_queue(struct vhost_poll *poll)
{
	vhost_work_queue(poll->dev, &poll->work);
}
EXPORT_SYMBOL_GPL(vhost_poll_queue);

static void __vhost_vq_meta_reset(struct vhost_virtqueue *vq)
{
	int j;

	for (j = 0; j < VHOST_NUM_ADDRS; j++)
		vq->meta_iotlb[j] = NULL;
}

static void vhost_vq_meta_reset(struct vhost_dev *d)
{
	int i;

	for (i = 0; i < d->nvqs; ++i)
		__vhost_vq_meta_reset(d->vqs[i]);
}

static void vhost_vq_reset(struct vhost_dev *dev,
			   struct vhost_virtqueue *vq)
{
	vq->notify_status = -1;
	vq->signal_type = -1;
	vq->num = 1;
	vq->desc = NULL;
	vq->avail = NULL;
	vq->used = NULL;
	vq->last_avail_idx = 0;
	vq->avail_idx = 0;
	vq->last_used_idx = 0;
	vq->signalled_used = 0;
	vq->signalled_used_valid = false;
	vq->used_flags = 0;
	vq->log_used = false;
	vq->log_addr = -1ull;
	vq->private_data = NULL;
	vq->acked_features = 0;
	vq->log_base = NULL;
	vq->error_ctx = NULL;
	vq->error = NULL;
	vq->call_ctx = NULL;
	vq->call = NULL;
	vq->log_ctx = NULL;
	vhost_reset_is_le(vq);
	vhost_disable_cross_endian(vq);
	vq->busyloop_timeout = 0;
	vq->umem = NULL;
	vq->iotlb = NULL;
	__vhost_vq_meta_reset(vq);
}

static int vhost_worker(void *data)
{
	struct vhost_dev *dev = data;
	struct vhost_work *work, *work_next;
	struct llist_node *node;

	for (;;) {
		/* mb paired w/ kthread_stop */
		set_current_state(TASK_INTERRUPTIBLE);

		if (kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			break;
		}

		node = llist_del_all(&dev->work_list);
		if (!node)
			schedule();

		node = llist_reverse_order(node);
		/* make sure flag is seen after deletion */
		smp_wmb();
		llist_for_each_entry_safe(work, work_next, node, node) {
			clear_bit(VHOST_WORK_QUEUED, &work->flags);
			__set_current_state(TASK_RUNNING);
			work->fn(work);
			if (need_resched())
				schedule();
		}
	}

	return 0;
}

static void vhost_vq_free_iovecs(struct vhost_virtqueue *vq)
{
	kfree(vq->indirect);
	vq->indirect = NULL;
	kfree(vq->log);
	vq->log = NULL;
	kfree(vq->heads);
	vq->heads = NULL;
}

/* Helper to allocate iovec buffers for all vqs. */
static long vhost_dev_alloc_iovecs(struct vhost_dev *dev)
{
	struct vhost_virtqueue *vq;
	int i;

	for (i = 0; i < dev->nvqs; ++i) {
		vq = dev->vqs[i];
		vq->indirect = kmalloc(sizeof *vq->indirect * UIO_MAXIOV,
				       GFP_KERNEL);
		vq->log = kmalloc(sizeof *vq->log * UIO_MAXIOV, GFP_KERNEL);
		vq->heads = kmalloc(sizeof *vq->heads * UIO_MAXIOV, GFP_KERNEL);
		if (!vq->indirect || !vq->log || !vq->heads)
			goto err_nomem;
	}
	return 0;

err_nomem:
	for (; i >= 0; --i)
		vhost_vq_free_iovecs(dev->vqs[i]);
	return -ENOMEM;
}

static void vhost_dev_free_iovecs(struct vhost_dev *dev)
{
	int i;

	for (i = 0; i < dev->nvqs; ++i)
		vhost_vq_free_iovecs(dev->vqs[i]);
}

bool vhost_exceeds_weight(struct vhost_virtqueue *vq,
			  int pkts, int total_len)
{
	struct vhost_dev *dev = vq->dev;

	if ((dev->byte_weight && total_len >= dev->byte_weight) ||
	    pkts >= dev->weight) {
		vhost_poll_queue(&vq->poll);
		return true;
	}

	return false;
}
EXPORT_SYMBOL_GPL(vhost_exceeds_weight);

void vhost_dev_init(struct vhost_dev *dev,
		    struct vhost_virtqueue **vqs, int nvqs,
		    int weight, int byte_weight)
{
	struct vhost_virtqueue *vq;
	int i;

	dev->vqs = vqs;
	dev->nvqs = nvqs;
	mutex_init(&dev->mutex);
	dev->log_ctx = NULL;
	dev->log_file = NULL;
	dev->owned = 0;
	dev->umem = NULL;
	dev->iotlb = NULL;
	dev->worker = NULL;
	dev->weight = weight;
	dev->byte_weight = byte_weight;
	init_llist_head(&dev->work_list);
	init_waitqueue_head(&dev->wait);
	INIT_LIST_HEAD(&dev->read_list);
	INIT_LIST_HEAD(&dev->pending_list);
	spin_lock_init(&dev->iotlb_lock);

	for (i = 0; i < dev->nvqs; ++i) {
		vq = dev->vqs[i];
		vq->log = NULL;
		vq->indirect = NULL;
		vq->heads = NULL;
		vq->dev = dev;
		vq->irq_priv = NULL;
		vq->notify_priv = NULL;
		mutex_init(&vq->mutex);
		vhost_vq_reset(dev, vq);
		if (vq->handle_kick)
			vhost_poll_init(&vq->poll, vq->handle_kick,
					POLLIN, dev);
	}
}
EXPORT_SYMBOL_GPL(vhost_dev_init);

/* Caller should have device mutex */
long vhost_dev_set_owner(struct vhost_dev *dev)
{
	struct task_struct *worker;
	int err;

	if (dev->owned)
		return -EBUSY;

	dev->owned = true;

	/* No owner, become one */
	worker = kthread_create(vhost_worker, dev, "vhost-%d", current->pid);

	if (IS_ERR(worker)) {
		err = PTR_ERR(worker);
		goto err_worker;
	}

	dev->worker = worker;
	wake_up_process(worker);	/* avoid contributing to loadavg */

	err = vhost_dev_alloc_iovecs(dev);
	if (err)
		goto err_cgroup;

	return 0;
err_cgroup:
	kthread_stop(worker);
	dev->worker = NULL;
err_worker:
	return err;
}
EXPORT_SYMBOL_GPL(vhost_dev_set_owner);

struct vhost_umem *vhost_dev_reset_owner_prepare(void)
{
	return kvzalloc(sizeof(struct vhost_umem), GFP_KERNEL);
}
EXPORT_SYMBOL_GPL(vhost_dev_reset_owner_prepare);

/* Caller should have device mutex */
void vhost_dev_reset_owner(struct vhost_dev *dev, struct vhost_umem *umem)
{
	int i;

	vhost_dev_cleanup(dev, true);

	/* Restore memory to default empty mapping. */
	INIT_LIST_HEAD(&umem->umem_list);
	dev->umem = umem;
	/* We don't need VQ locks below since vhost_dev_cleanup makes sure
	 * VQs aren't running.
	 */
	for (i = 0; i < dev->nvqs; ++i)
		dev->vqs[i]->umem = umem;
}
EXPORT_SYMBOL_GPL(vhost_dev_reset_owner);

void vhost_dev_stop(struct vhost_dev *dev)
{
	int i;

	for (i = 0; i < dev->nvqs; ++i) {
		if (dev->vqs[i]->notify_status > 0 && dev->vqs[i]->handle_kick) {
			my_vhost_poll_stop(dev->vqs[i]);
			vhost_poll_flush(&dev->vqs[i]->poll);
		}
	}
}
EXPORT_SYMBOL_GPL(vhost_dev_stop);

static void vhost_umem_free(struct vhost_umem *umem,
			    struct vhost_umem_node *node)
{
	vhost_umem_interval_tree_remove(node, &umem->umem_tree);
	list_del(&node->link);
	kfree(node);
	umem->numem--;
}

static void vhost_umem_clean(struct vhost_umem *umem)
{
	struct vhost_umem_node *node, *tmp;

	if (!umem)
		return;

	list_for_each_entry_safe(node, tmp, &umem->umem_list, link)
		vhost_umem_free(umem, node);

	kvfree(umem);
}

static void vhost_clear_msg(struct vhost_dev *dev)
{
	struct vhost_msg_node *node, *n;

	spin_lock(&dev->iotlb_lock);

	list_for_each_entry_safe(node, n, &dev->read_list, node) {
		list_del(&node->node);
		kfree(node);
	}

	list_for_each_entry_safe(node, n, &dev->pending_list, node) {
		list_del(&node->node);
		kfree(node);
	}

	spin_unlock(&dev->iotlb_lock);
}

/* Caller should have device mutex if and only if locked is set */
void vhost_dev_cleanup(struct vhost_dev *dev, bool locked)
{
	int i;

	for (i = 0; i < dev->nvqs; ++i) {
		if (dev->vqs[i]->error_ctx)
			eventfd_ctx_put(dev->vqs[i]->error_ctx);
		if (dev->vqs[i]->error)
			fput(dev->vqs[i]->error);
		if (dev->vqs[i]->call_ctx)
			eventfd_ctx_put(dev->vqs[i]->call_ctx);
		if (dev->vqs[i]->call)
			fput(dev->vqs[i]->call);

		if (dev->vqs[i]->notify_status > 0) 
			my_vhost_poll_stop(dev->vqs[i]);
		if (dev->vqs[i]->irq_priv != NULL) {
			kfree(dev->vqs[i]->irq_priv);
			dev->vqs[i]->irq_priv = NULL;
		}

		vhost_vq_reset(dev, dev->vqs[i]);
	}
	vhost_dev_free_iovecs(dev);
	if (dev->log_ctx)
		eventfd_ctx_put(dev->log_ctx);
	dev->log_ctx = NULL;
	if (dev->log_file)
		fput(dev->log_file);
	dev->log_file = NULL;
	dev->owned = 0;
	/* No one will access memory at this point */
	vhost_umem_clean(dev->umem);
	dev->umem = NULL;
	vhost_umem_clean(dev->iotlb);
	dev->iotlb = NULL;
	vhost_clear_msg(dev);
	wake_up_interruptible_poll(&dev->wait, POLLIN | POLLRDNORM);
	WARN_ON(!llist_empty(&dev->work_list));
	if (dev->worker) {
		kthread_stop(dev->worker);
		dev->worker = NULL;
	}
}
EXPORT_SYMBOL_GPL(vhost_dev_cleanup);

static inline void *vhost_vq_meta_fetch(struct vhost_virtqueue *vq,
					       u64 addr, unsigned int size,
					       int type)
{
	const struct vhost_umem_node *node = vq->meta_iotlb[type];

	if (!node)
		return NULL;

	return (void *)(uintptr_t)(node->userspace_addr + addr - node->start);
}

static int translate_desc(struct vhost_virtqueue *vq, u64 addr, u32 len,
			  struct iovec iov[], int iov_size, int access);

static void vhost_dev_lock_vqs(struct vhost_dev *d)
{
	int i = 0;
	for (i = 0; i < d->nvqs; ++i)
		mutex_lock_nested(&d->vqs[i]->mutex, i);
}

static void vhost_dev_unlock_vqs(struct vhost_dev *d)
{
	int i = 0;
	for (i = 0; i < d->nvqs; ++i)
		mutex_unlock(&d->vqs[i]->mutex);
}

static int vhost_new_umem_range(struct vhost_umem *umem,
				u64 start, u64 size, u64 end,
				u64 userspace_addr, int perm)
{
	struct vhost_umem_node *tmp, *node;

	if (!size)
		return -EFAULT;

	node = kmalloc(sizeof(*node), GFP_ATOMIC);
	if (!node)
		return -ENOMEM;

	if (umem->numem == max_iotlb_entries) {
		tmp = list_first_entry(&umem->umem_list, typeof(*tmp), link);
		vhost_umem_free(umem, tmp);
	}

	node->start = start;
	node->size = size;
	node->last = end;
	node->userspace_addr = userspace_addr;
	node->perm = perm;
	INIT_LIST_HEAD(&node->link);
	list_add_tail(&node->link, &umem->umem_list);
	vhost_umem_interval_tree_insert(node, &umem->umem_tree);
	umem->numem++;

	return 0;
}

static void vhost_del_umem_range(struct vhost_umem *umem,
				 u64 start, u64 end)
{
	struct vhost_umem_node *node;

	while ((node = vhost_umem_interval_tree_iter_first(&umem->umem_tree,
							   start, end)))
		vhost_umem_free(umem, node);
}

static void vhost_iotlb_notify_vq(struct vhost_dev *d,
				  struct vhost_iotlb_msg *msg)
{
	struct vhost_msg_node *node, *n;

	spin_lock(&d->iotlb_lock);

	list_for_each_entry_safe(node, n, &d->pending_list, node) {
		struct vhost_iotlb_msg *vq_msg = &node->msg.iotlb;
		if (msg->iova <= vq_msg->iova &&
		    msg->iova + msg->size - 1 >= vq_msg->iova &&
		    vq_msg->type == VHOST_IOTLB_MISS) {
			vhost_poll_queue(&node->vq->poll);
			list_del(&node->node);
			kfree(node);
		}
	}

	spin_unlock(&d->iotlb_lock);
}

static int umem_access_ok(u64 uaddr, u64 size, int access)
{
	return 0;
}

static int vhost_process_iotlb_msg(struct vhost_dev *dev,
				   struct vhost_iotlb_msg *msg)
{
	int ret = 0;

	mutex_lock(&dev->mutex);
	vhost_dev_lock_vqs(dev);
	switch (msg->type) {
	case VHOST_IOTLB_UPDATE:
		if (!dev->iotlb) {
			ret = -EFAULT;
			break;
		}
		if (umem_access_ok(msg->uaddr, msg->size, msg->perm)) {
			ret = -EFAULT;
			break;
		}
		vhost_vq_meta_reset(dev);
		if (vhost_new_umem_range(dev->iotlb, msg->iova, msg->size,
					 msg->iova + msg->size - 1,
					 msg->uaddr, msg->perm)) {
			ret = -ENOMEM;
			break;
		}
		vhost_iotlb_notify_vq(dev, msg);
		break;
	case VHOST_IOTLB_INVALIDATE:
		if (!dev->iotlb) {
			ret = -EFAULT;
			break;
		}
		vhost_vq_meta_reset(dev);
		vhost_del_umem_range(dev->iotlb, msg->iova,
				     msg->iova + msg->size - 1);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	vhost_dev_unlock_vqs(dev);
	mutex_unlock(&dev->mutex);

	return ret;
}
ssize_t vhost_chr_write_iter(struct vhost_dev *dev,
			     struct iov_iter *from)
{
	struct vhost_msg_node node;
	unsigned size = sizeof(struct vhost_msg);
	size_t ret;
	int err;

	if (iov_iter_count(from) < size)
		return 0;
	ret = copy_from_iter(&node.msg, size, from);
	if (ret != size)
		goto done;

	switch (node.msg.type) {
	case VHOST_IOTLB_MSG:
		err = vhost_process_iotlb_msg(dev, &node.msg.iotlb);
		if (err)
			ret = err;
		break;
	default:
		ret = -EINVAL;
		break;
	}

done:
	return ret;
}
EXPORT_SYMBOL(vhost_chr_write_iter);

unsigned int vhost_chr_poll(struct file *file, struct vhost_dev *dev,
			    poll_table *wait)
{
	unsigned int mask = 0;

	poll_wait(file, &dev->wait, wait);

	if (!list_empty(&dev->read_list))
		mask |= POLLIN | POLLRDNORM;

	return mask;
}
EXPORT_SYMBOL(vhost_chr_poll);

ssize_t vhost_chr_read_iter(struct vhost_dev *dev, struct iov_iter *to,
			    int noblock)
{
	DEFINE_WAIT(wait);
	struct vhost_msg_node *node;
	ssize_t ret = 0;
	unsigned size = sizeof(struct vhost_msg);

	if (iov_iter_count(to) < size)
		return 0;

	while (1) {
		if (!noblock)
			prepare_to_wait(&dev->wait, &wait,
					TASK_INTERRUPTIBLE);

		node = vhost_dequeue_msg(dev, &dev->read_list);
		if (node)
			break;
		if (noblock) {
			ret = -EAGAIN;
			break;
		}
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}
		if (!dev->iotlb) {
			ret = -EBADFD;
			break;
		}

		schedule();
	}

	if (!noblock)
		finish_wait(&dev->wait, &wait);

	if (node) {
		ret = copy_to_iter(&node->msg, size, to);

		if (ret != size || node->msg.type != VHOST_IOTLB_MISS) {
			kfree(node);
			return ret;
		}

		vhost_enqueue_msg(dev, &dev->pending_list, node);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(vhost_chr_read_iter);

static int vhost_iotlb_miss(struct vhost_virtqueue *vq, u64 iova, int access)
{
	struct vhost_dev *dev = vq->dev;
	struct vhost_msg_node *node;
	struct vhost_iotlb_msg *msg;

	node = vhost_new_msg(vq, VHOST_IOTLB_MISS);
	if (!node)
		return -ENOMEM;

	msg = &node->msg.iotlb;
	msg->type = VHOST_IOTLB_MISS;
	msg->iova = iova;
	msg->perm = access;

	vhost_enqueue_msg(dev, &dev->read_list, node);

	return 0;
}

int vq_iotlb_prefetch(struct vhost_virtqueue *vq)
{
	return 1;
}
EXPORT_SYMBOL_GPL(vq_iotlb_prefetch);

/* Can we log writes? */
/* Caller should have device mutex but not vq mutex */
int vhost_log_access_ok(struct vhost_dev *dev)
{
	return 1;
}
EXPORT_SYMBOL_GPL(vhost_log_access_ok);

/* Verify access for write logging. */
/* Caller should have vq mutex and device mutex */
static int vq_log_access_ok(struct vhost_virtqueue *vq,
			    void __user *log_base)
{
	return 1;
}

/* Can we start vq? */
/* Caller should have vq mutex and device mutex */
int vhost_vq_access_ok(struct vhost_virtqueue *vq)
{
	return 1;
}
EXPORT_SYMBOL_GPL(vhost_vq_access_ok);

static struct vhost_umem *vhost_umem_alloc(void)
{
	struct vhost_umem *umem = kvzalloc(sizeof(*umem), GFP_KERNEL);

	if (!umem)
		return NULL;

	umem->umem_tree = RB_ROOT_CACHED;
	umem->numem = 0;
	INIT_LIST_HEAD(&umem->umem_list);

	return umem;
}

static long my_vhost_set_memory(struct vhost_dev *d, struct vhost_memory *mem)
{
	struct vhost_memory *newmem;
	struct vhost_memory_region *region;
	struct vhost_umem *newumem, *oldumem;
	unsigned long size = offsetof(struct vhost_memory, regions);
	int i;

	if (mem->padding) {
		printk(">>>>%s:%d\n", __func__, __LINE__);
		return -EOPNOTSUPP;
	}

	if (mem->nregions > max_mem_regions) {
		printk(">>>>%s:%d\n", __func__, __LINE__);
		return -E2BIG;
	}

	newmem = kvzalloc(size + mem->nregions * sizeof(*mem->regions), GFP_KERNEL);
	if (!newmem) {
		printk(">>>>%s:%d\n", __func__, __LINE__);
		return -ENOMEM;
	}

	memcpy(newmem, mem,
			   size + mem->nregions * sizeof *mem->regions);

	newumem = vhost_umem_alloc();
	if (!newumem) {
		kvfree(newmem);
		printk(">>>>%s:%d\n", __func__, __LINE__);
		return -ENOMEM;
	}

	for (region = newmem->regions;
	     region < newmem->regions + mem->nregions;
	     region++) {
		if (vhost_new_umem_range(newumem,
					 region->guest_phys_addr,
					 region->memory_size,
					 region->guest_phys_addr +
					 region->memory_size - 1,
					 region->userspace_addr,
					 VHOST_ACCESS_RW)) {
			printk(">>>>%s:%d\n", __func__, __LINE__);
			goto err;
		}
	}

	oldumem = d->umem;
	d->umem = newumem;

	/* All memory accesses are done under some VQ mutex. */
	for (i = 0; i < d->nvqs; ++i) {
		mutex_lock(&d->vqs[i]->mutex);
		d->vqs[i]->umem = newumem;
		mutex_unlock(&d->vqs[i]->mutex);
	}

	kvfree(newmem);
	vhost_umem_clean(oldumem);
	return 0;

err:
	vhost_umem_clean(newumem);
	kvfree(newmem);
	return -EFAULT;
}

long vhost_vring_ioctl(struct vhost_dev *d, int ioctl, void __user *argp)
{
	return 0;
}
EXPORT_SYMBOL_GPL(vhost_vring_ioctl);

long my_vhost_vring_ioctl(struct vhost_dev *d, int ioctl, void *argp)
{
	bool pollstart = false, pollstop = false;
	u32 *idxp = argp;
	struct vhost_virtqueue *vq;
	struct vhost_vring_state *s;
	struct vhost_vring_file *f;
	struct vhost_vring_addr *a;
	u32 idx;
	long r = 0;

	idx = *idxp;
	if (idx >= d->nvqs)
		return -ENOBUFS;

	idx = array_index_nospec(idx, d->nvqs);
	vq = d->vqs[idx];

	mutex_lock(&vq->mutex);

	switch (ioctl) {
	case VHOST_SET_VRING_NUM:
		/* Resizing ring with an active backend?
		 * You don't want to do that. */
		if (vq->private_data) {
			r = -EBUSY;
			break;
		}
		s = argp;
		if (!s->num || s->num > 0xffff || (s->num & (s->num - 1))) {
			r = -EINVAL;
			break;
		}
		vq->num = s->num;
		break;
	case VHOST_SET_VRING_BASE:
		/* Moving base with an active backend?
		 * You don't want to do that. */
		if (vq->private_data) {
			r = -EBUSY;
			break;
		}
		s = argp;
		if (s->num > 0xffff) {
			r = -EINVAL;
			break;
		}
		vq->last_avail_idx = s->num;
		/* Forget the cached index value. */
		vq->avail_idx = vq->last_avail_idx;
		break;
	case VHOST_GET_VRING_BASE:
		s = argp;
		s->index = idx;
		s->num = vq->last_avail_idx;
		break;
	case VHOST_SET_VRING_ADDR:
		a = argp;
		if (a->flags & ~(0x1 << VHOST_VRING_F_LOG)) {
				printk(">>>>%s:%d\n", __func__, __LINE__);
			r = -EOPNOTSUPP;
			break;
		}

		/* For 32bit, verify that the top 32bits of the user
		   data are set to zero. */
		if ((u64)(unsigned long)a->desc_user_addr != a->desc_user_addr ||
		    (u64)(unsigned long)a->used_user_addr != a->used_user_addr ||
		    (u64)(unsigned long)a->avail_user_addr != a->avail_user_addr) {
				printk(">>>>%s:%d\n", __func__, __LINE__);
			r = -EFAULT;
			break;
		}

		/* Make sure it's safe to cast pointers to vring types. */
		BUILD_BUG_ON(__alignof__ *vq->avail > VRING_AVAIL_ALIGN_SIZE);
		BUILD_BUG_ON(__alignof__ *vq->used > VRING_USED_ALIGN_SIZE);
		if ((a->avail_user_addr & (VRING_AVAIL_ALIGN_SIZE - 1)) ||
		    (a->used_user_addr & (VRING_USED_ALIGN_SIZE - 1)) ||
		    (a->log_guest_addr & (VRING_USED_ALIGN_SIZE - 1))) {
				printk(">>>>%s:%d\n", __func__, __LINE__);
			r = -EINVAL;
			break;
		}

		/* We only verify access here if backend is configured.
		 * If it is not, we don't as size might not have been setup.
		 * We will verify when backend is configured. */
		vq->log_used = !!(a->flags & (0x1 << VHOST_VRING_F_LOG));
		vq->desc = (void *)(unsigned long)a->desc_user_addr;
		vq->avail = (void *)(unsigned long)a->avail_user_addr;
		vq->log_addr = a->log_guest_addr;
		vq->used = (void *)(unsigned long)a->used_user_addr;

		break;
	case VHOST_SET_VRING_KICK:
		f = argp;

		if (vq->notify_status != f->fd) {
			if (f->fd == 0)
				pollstop = true;
			else if (f->fd == 1)
				pollstart = true;
		} else {
			if (f->fd == 1) {
				pollstop = true;
				pollstart = true;
			}
		}

		if (pollstop && vq->handle_kick)
			my_vhost_poll_stop(vq);

		vq->notify_status = f->fd;
		vq->evt_id = f->evt_id;
		vq->kvm_id = f->kvm_id;

		//printk(">>>>>>%s:%d [%d] fd=%d prev_fd=%d evt=%d poll=%d\n",__func__, __LINE__,
		//	idx, f->fd, vq->notify_status, f->evt_id, pollstart);

		vq->poll.evt_id = f->evt_id;

		if (pollstart && vq->handle_kick)
			my_vhost_poll_start(&vq->poll, vq);
		break;
	case VHOST_SET_VRING_CALL:
		f = argp;

		vq->signal_type = f->fd;
		vq->kvm_id = f->kvm_id;

		if (f->fd == 2) {
			if (vq->irq_priv)
				kfree(vq->irq_priv);
			vq->irq_priv = vhost_alloc_irq_entry_kvm(f->kvm_id, f->virq);
		}

//		printk(">>>>>>%s:%d [%d] fd=%d virq=%d kvm_id=%d\n",__func__, __LINE__,idx, f->fd, f->virq, f->kvm_id);
		break;
	case VHOST_SET_VRING_BUSYLOOP_TIMEOUT:
		s = argp;
		vq->busyloop_timeout = s->num;
		break;
	case VHOST_GET_VRING_BUSYLOOP_TIMEOUT:
		s = argp;
		s->index = idx;
		s->num = vq->busyloop_timeout;
		break;
	default:
		r = -ENOIOCTLCMD;
	}

	mutex_unlock(&vq->mutex);

	if (pollstop && vq->handle_kick)
		vhost_poll_flush(&vq->poll);

	return r;
}

int vhost_init_device_iotlb(struct vhost_dev *d, bool enabled)
{
	struct vhost_umem *niotlb, *oiotlb;
	int i;

	niotlb = vhost_umem_alloc();
	if (!niotlb)
		return -ENOMEM;

	oiotlb = d->iotlb;
	d->iotlb = niotlb;

	for (i = 0; i < d->nvqs; ++i) {
		struct vhost_virtqueue *vq = d->vqs[i];

		mutex_lock(&vq->mutex);
		vq->iotlb = niotlb;
		__vhost_vq_meta_reset(vq);
		mutex_unlock(&vq->mutex);
	}

	vhost_umem_clean(oiotlb);

	return 0;
}
EXPORT_SYMBOL_GPL(vhost_init_device_iotlb);

/* Caller must have device mutex */
long vhost_dev_ioctl(struct vhost_dev *d, unsigned int ioctl, void __user *argp)
{
	return 0;
}
EXPORT_SYMBOL_GPL(vhost_dev_ioctl);

long my_vhost_dev_ioctl(struct vhost_dev *d, unsigned int ioctl, void *argp)
{
	u64 p;
	long r = 0;
	int i;

	/* If you are not the owner, you can become one */
	if (ioctl == VHOST_SET_OWNER) {
		r = vhost_dev_set_owner(d);
		goto done;
	}

	switch (ioctl) {
	case VHOST_SET_MEM_TABLE:
		r = my_vhost_set_memory(d, argp);
		break;
	case VHOST_SET_LOG_BASE:
		p = *(uint64_t*)argp;
		for (i = 0; i < d->nvqs; ++i) {
			struct vhost_virtqueue *vq;
			void *base = (void *)p;
			vq = d->vqs[i];
			mutex_lock(&vq->mutex);
			/* If ring is inactive, will check when it's enabled. */
			if (vq->private_data && !vq_log_access_ok(vq, base))
				r = -EFAULT;
			else
				vq->log_base = base;
			mutex_unlock(&vq->mutex);
		}
		break;
	case VHOST_SET_LOG_FD:
	default:
		r = -ENOIOCTLCMD;
		break;
	}
done:
	return r;
}

/* TODO: This is really inefficient.  We need something like get_user()
 * (instruction directly accesses the data, with an exception table entry
 * returning -EFAULT). See Documentation/x86/exception-tables.txt.
 */
static int set_bit_to_user(int nr, void __user *addr)
{
	unsigned long log = (unsigned long)addr;
	struct page *page;
	void *base;
	int bit = nr + (log % PAGE_SIZE) * 8;
	int r;

	r = get_user_pages_fast(log, 1, 1, &page);
	if (r < 0)
		return r;
	BUG_ON(r != 1);
	base = kmap_atomic(page);
	set_bit(bit, base);
	kunmap_atomic(base);
	set_page_dirty_lock(page);
	put_page(page);
	return 0;
}

static int log_write(void __user *log_base,
		     u64 write_address, u64 write_length)
{
	u64 write_page = write_address / VHOST_PAGE_SIZE;
	int r;

	if (!write_length)
		return 0;
	write_length += write_address % VHOST_PAGE_SIZE;
	for (;;) {
		u64 base = (u64)(unsigned long)log_base;
		u64 log = base + write_page / 8;
		int bit = write_page % 8;
		if ((u64)(unsigned long)log != log)
			return -EFAULT;
		r = set_bit_to_user(bit, (void __user *)(unsigned long)log);
		if (r < 0)
			return r;
		if (write_length <= VHOST_PAGE_SIZE)
			break;
		write_length -= VHOST_PAGE_SIZE;
		write_page += 1;
	}
	return r;
}

static int log_write_hva(struct vhost_virtqueue *vq, u64 hva, u64 len)
{
	struct vhost_umem *umem = vq->umem;
	struct vhost_umem_node *u;
	u64 start, end, l, min;
	int r;
	bool hit = false;

	while (len) {
		min = len;
		/* More than one GPAs can be mapped into a single HVA. So
		 * iterate all possible umems here to be safe.
		 */
		list_for_each_entry(u, &umem->umem_list, link) {
			if (u->userspace_addr > hva - 1 + len ||
			    u->userspace_addr - 1 + u->size < hva)
				continue;
			start = max(u->userspace_addr, hva);
			end = min(u->userspace_addr - 1 + u->size,
				  hva - 1 + len);
			l = end - start + 1;
			r = log_write(vq->log_base,
				      u->start + start - u->userspace_addr,
				      l);
			if (r < 0)
				return r;
			hit = true;
			min = min(l, min);
		}

		if (!hit)
			return -EFAULT;

		len -= min;
		hva += min;
	}

	return 0;
}

static int log_used(struct vhost_virtqueue *vq, u64 used_offset, u64 len)
{
	struct iovec iov[64];
	int i, ret;

	if (!vq->iotlb)
		return log_write(vq->log_base, vq->log_addr + used_offset, len);

	ret = translate_desc(vq, (uintptr_t)vq->used + used_offset,
			     len, iov, 64, VHOST_ACCESS_WO);
	if (ret < 0)
		return ret;

	for (i = 0; i < ret; i++) {
		ret = log_write_hva(vq,	(uintptr_t)iov[i].iov_base,
				    iov[i].iov_len);
		if (ret)
			return ret;
	}

	return 0;
}

int vhost_log_write(struct vhost_virtqueue *vq, struct vhost_log *log,
		    unsigned int log_num, u64 len, struct iovec *iov, int count)
{
	int i, r;

	/* Make sure data written is seen before log. */
	smp_wmb();

	if (vq->iotlb) {
		for (i = 0; i < count; i++) {
			r = log_write_hva(vq, (uintptr_t)iov[i].iov_base,
					  iov[i].iov_len);
			if (r < 0)
				return r;
		}
		return 0;
	}

	for (i = 0; i < log_num; ++i) {
		u64 l = min(log[i].len, len);
		r = log_write(vq->log_base, log[i].addr, l);
		if (r < 0)
			return r;
		len -= l;
		if (!len) {
			if (vq->log_ctx)
				eventfd_signal(vq->log_ctx, 1);
			return 0;
		}
	}
	/* Length written exceeds what we have stored. This is a bug. */
	BUG();
	return 0;
}
EXPORT_SYMBOL_GPL(vhost_log_write);

static int vhost_update_used_flags(struct vhost_virtqueue *vq)
{
	void *used;

	vq->used->flags = cpu_to_vhost16(vq, vq->used_flags);

	if (unlikely(vq->log_used)) {
		/* Make sure the flag is seen before log. */
		smp_wmb();
		/* Log used flag write. */
		used = &vq->used->flags;
		log_used(vq, (used - (void *)vq->used),
			 sizeof vq->used->flags);
		if (vq->log_ctx)
			eventfd_signal(vq->log_ctx, 1);
	}
	return 0;
}

static int vhost_update_avail_event(struct vhost_virtqueue *vq, u16 avail_event)
{
	*vhost_avail_event(vq) = cpu_to_vhost16(vq, vq->avail_idx);

	if (unlikely(vq->log_used)) {
		void *used;
		/* Make sure the event is seen before log. */
		smp_wmb();
		/* Log avail event write */
		used = vhost_avail_event(vq);
		log_used(vq, (used - (void *)vq->used),
			 sizeof *vhost_avail_event(vq));
		if (vq->log_ctx)
			eventfd_signal(vq->log_ctx, 1);
	}
	return 0;
}

int vhost_vq_init_access(struct vhost_virtqueue *vq)
{
	__virtio16 last_used_idx;
	int r;
	bool is_le = vq->is_le;

	if (!vq->private_data)
		return 0;

	vhost_init_is_le(vq);

	r = vhost_update_used_flags(vq);
	if (r)
		goto err;

	vq->signalled_used_valid = false;

	last_used_idx = vq->used->idx;

	vq->last_used_idx = vhost16_to_cpu(vq, last_used_idx);
	return 0;

err:
	vq->is_le = is_le;
	return r;
}
EXPORT_SYMBOL_GPL(vhost_vq_init_access);

static int translate_desc(struct vhost_virtqueue *vq, u64 addr, u32 len,
			  struct iovec iov[], int iov_size, int access)
{
	const struct vhost_umem_node *node;
	struct vhost_dev *dev = vq->dev;
	struct vhost_umem *umem = dev->iotlb ? dev->iotlb : dev->umem;
	struct iovec *_iov;
	u64 s = 0;
	int ret = 0;

	while ((u64)len > s) {
		u64 size;
		if (unlikely(ret >= iov_size)) {
			ret = -ENOBUFS;
			break;
		}

		node = vhost_umem_interval_tree_iter_first(&umem->umem_tree,
							addr, addr + len - 1);
		if (node == NULL || node->start > addr) {
			if (umem != dev->iotlb) {
				ret = -EFAULT;
				break;
			}
			ret = -EAGAIN;
			break;
		} else if (!(node->perm & access)) {
			ret = -EPERM;
			break;
		}

		_iov = iov + ret;
		size = node->size - addr + node->start;

		_iov->iov_len = min((u64)len - s, size);
		_iov->iov_base = (void *)(unsigned long)
			(node->userspace_addr + addr - node->start);
		s += size;
		addr += size;
		++ret;
	}

	if (ret == -EAGAIN)
		vhost_iotlb_miss(vq, addr, access);
	return ret;
}

/* Each buffer in the virtqueues is actually a chain of descriptors.  This
 * function returns the next descriptor in the chain,
 * or -1U if we're at the end. */
static unsigned next_desc(struct vhost_virtqueue *vq, struct vring_desc *desc)
{
	unsigned int next;

	/* If this descriptor says it doesn't chain, we're done. */
	if (!(desc->flags & cpu_to_vhost16(vq, VRING_DESC_F_NEXT)))
		return -1U;

	/* Check they're not leading us off end of descriptors. */
	next = vhost16_to_cpu(vq, desc->next);
	/* Make sure compiler knows to grab that: we don't want it changing! */
	/* We will use the result as an index in an array, so most
	 * architectures only need a compiler barrier here. */
	read_barrier_depends();

	return next;
}

void my_iov_iter_init(struct iov_iter *i, int direction,
			const struct iovec *iov, unsigned long nr_segs,
			size_t count);

static int get_indirect(struct vhost_virtqueue *vq,
			struct iovec iov[], unsigned int iov_size,
			unsigned int *out_num, unsigned int *in_num,
			struct vhost_log *log, unsigned int *log_num,
			struct vring_desc *indirect)
{
	struct vring_desc desc;
	unsigned int i = 0, count, found = 0;
	u32 len = vhost32_to_cpu(vq, indirect->len);
	struct iov_iter from;
	int ret, access;

	/* Sanity check */
	if (unlikely(len % sizeof desc)) {
		printk(">>>>>%s:%d\n", __func__, __LINE__);
		vq_err(vq, "Invalid length in indirect descriptor: "
		       "len 0x%llx not multiple of 0x%zx\n",
		       (unsigned long long)len,
		       sizeof desc);
		return -EINVAL;
	}

	ret = translate_desc(vq, vhost64_to_cpu(vq, indirect->addr), len, vq->indirect,
			     UIO_MAXIOV, VHOST_ACCESS_RO);
	if (unlikely(ret < 0)) {
		printk(">>>>>%s:%d\n", __func__, __LINE__);
		if (ret != -EAGAIN)
			vq_err(vq, "Translation failure %d in indirect.\n", ret);
		return ret;
	}

	my_iov_iter_init(&from, READ, vq->indirect, ret, len);

	/* We will use the result as an address to read from, so most
	 * architectures only need a compiler barrier here. */
	read_barrier_depends();

	count = len / sizeof desc;
	/* Buffers are chained via a 16 bit next field, so
	 * we can have at most 2^16 of these. */
	if (unlikely(count > USHRT_MAX + 1)) {
		printk(">>>>>%s:%d\n", __func__, __LINE__);
		vq_err(vq, "Indirect buffer length too big: %d\n",
		       indirect->len);
		return -E2BIG;
	}

	do {
		unsigned iov_count = *in_num + *out_num;
		if (unlikely(++found > count)) {
			printk(">>>>>%s:%d\n", __func__, __LINE__);
			vq_err(vq, "Loop detected: last one at %u "
			       "indirect size %u\n",
			       i, count);
			return -EINVAL;
		}
		if (unlikely(!copy_from_iter_full(&desc, sizeof(desc), &from))) {
			printk(">>>>>%s:%d\n", __func__, __LINE__);
			vq_err(vq, "Failed indirect descriptor: idx %d, %zx\n",
			       i, (size_t)vhost64_to_cpu(vq, indirect->addr) + i * sizeof desc);
			return -EINVAL;
		}

		if (unlikely(desc.flags & cpu_to_vhost16(vq, VRING_DESC_F_INDIRECT))) {
			printk(">>>>>%s:%d\n", __func__, __LINE__);
			vq_err(vq, "Nested indirect descriptor: idx %d, %zx\n",
			       i, (size_t)vhost64_to_cpu(vq, indirect->addr) + i * sizeof desc);
			return -EINVAL;
		}

		if (desc.flags & cpu_to_vhost16(vq, VRING_DESC_F_WRITE))
			access = VHOST_ACCESS_WO;
		else
			access = VHOST_ACCESS_RO;

		ret = translate_desc(vq, vhost64_to_cpu(vq, desc.addr),
				     vhost32_to_cpu(vq, desc.len), iov + iov_count,
				     iov_size - iov_count, access);
		if (unlikely(ret < 0)) {
			printk(">>>>>%s:%d\n", __func__, __LINE__);
			if (ret != -EAGAIN)
				vq_err(vq, "Translation failure %d indirect idx %d\n",
					ret, i);
			return ret;
		}
		/* If this is an input descriptor, increment that count. */
		if (access == VHOST_ACCESS_WO) {
			*in_num += ret;
			if (unlikely(log && ret)) {
				log[*log_num].addr = vhost64_to_cpu(vq, desc.addr);
				log[*log_num].len = vhost32_to_cpu(vq, desc.len);
				++*log_num;
			}
		} else {
			/* If it's an output descriptor, they're all supposed
			 * to come before any input descriptors. */
			if (unlikely(*in_num)) {
				printk(">>>>>%s:%d\n", __func__, __LINE__);
				vq_err(vq, "Indirect descriptor "
				       "has out after in: idx %d\n", i);
				return -EINVAL;
			}
			*out_num += ret;
		}
	} while ((i = next_desc(vq, &desc)) != -1);
	return 0;
}

/* This looks in the virtqueue and for the first available buffer, and converts
 * it to an iovec for convenient access.  Since descriptors consist of some
 * number of output then some number of input descriptors, it's actually two
 * iovecs, but we pack them into one and note how many of each there were.
 *
 * This function returns the descriptor number found, or vq->num (which is
 * never a valid descriptor number) if none was found.  A negative code is
 * returned on error. */
int vhost_get_vq_desc(struct vhost_virtqueue *vq,
		      struct iovec iov[], unsigned int iov_size,
		      unsigned int *out_num, unsigned int *in_num,
		      struct vhost_log *log, unsigned int *log_num)
{
	struct vring_desc desc;
	unsigned int i, head, found = 0;
	u16 last_avail_idx;
	__virtio16 avail_idx;
	__virtio16 ring_head;
	int ret, access;

	/* Check it isn't doing very strange things with descriptor numbers. */
	last_avail_idx = vq->last_avail_idx;

	if (vq->avail_idx == vq->last_avail_idx) {
		avail_idx = vq->avail->idx;
		vq->avail_idx = vhost16_to_cpu(vq, avail_idx);

		if (unlikely((u16)(vq->avail_idx - last_avail_idx) > vq->num)) {
			printk(">>>>>%s:%d\n", __func__, __LINE__);
			vq_err(vq, "Guest moved used index from %u to %u",
				last_avail_idx, vq->avail_idx);
			return -EFAULT;
		}

		/* If there's nothing new since last we looked, return
		 * invalid.
		 */
		if (vq->avail_idx == last_avail_idx) {
		//	printk(">>>>>%s:%d\n", __func__, __LINE__);
			return vq->num;
		}

		/* Only get avail ring entries after they have been
		 * exposed by guest.
		 */
		smp_rmb();
	}

	/* Grab the next descriptor number they're advertising, and increment
	 * the index we've seen. */
	ring_head = vq->avail->ring[last_avail_idx & (vq->num - 1)];

	head = vhost16_to_cpu(vq, ring_head);

	/* If their number is silly, that's an error. */
	if (unlikely(head >= vq->num)) {
		printk(">>>>>%s:%d\n", __func__, __LINE__);
		vq_err(vq, "Guest says index %u > %u is available",
		       head, vq->num);
		return -EINVAL;
	}

	/* When we start there are none of either input nor output. */
	*out_num = *in_num = 0;
	if (unlikely(log))
		*log_num = 0;

	i = head;
	do {
		unsigned iov_count = *in_num + *out_num;
		if (unlikely(i >= vq->num)) {
			printk(">>>>>%s:%d\n", __func__, __LINE__);
			vq_err(vq, "Desc index is %u > %u, head = %u",
			       i, vq->num, head);
			return -EINVAL;
		}
		if (unlikely(++found > vq->num)) {
			printk(">>>>>%s:%d\n", __func__, __LINE__);
			vq_err(vq, "Loop detected: last one at %u "
			       "vq size %u head %u\n",
			       i, vq->num, head);
			return -EINVAL;
		}

		memcpy(&desc, vq->desc + i, sizeof desc);

		if (desc.flags & cpu_to_vhost16(vq, VRING_DESC_F_INDIRECT)) {
			ret = get_indirect(vq, iov, iov_size,
					   out_num, in_num,
					   log, log_num, &desc);
			if (unlikely(ret < 0)) {
				printk(">>>>>%s:%d\n", __func__, __LINE__);
				if (ret != -EAGAIN)
					vq_err(vq, "Failure detected "
						"in indirect descriptor at idx %d\n", i);
				return ret;
			}
			continue;
		}

		if (desc.flags & cpu_to_vhost16(vq, VRING_DESC_F_WRITE))
			access = VHOST_ACCESS_WO;
		else
			access = VHOST_ACCESS_RO;
		ret = translate_desc(vq, vhost64_to_cpu(vq, desc.addr),
				     vhost32_to_cpu(vq, desc.len), iov + iov_count,
				     iov_size - iov_count, access);
		if (unlikely(ret < 0)) {
			printk(">>>>>%s:%d\n", __func__, __LINE__);
			if (ret != -EAGAIN)
				vq_err(vq, "Translation failure %d descriptor idx %d\n",
					ret, i);
			return ret;
		}
		if (access == VHOST_ACCESS_WO) {
			/* If this is an input descriptor,
			 * increment that count. */
			*in_num += ret;
			if (unlikely(log && ret)) {
				log[*log_num].addr = vhost64_to_cpu(vq, desc.addr);
				log[*log_num].len = vhost32_to_cpu(vq, desc.len);
				++*log_num;
			}
		} else {
			/* If it's an output descriptor, they're all supposed
			 * to come before any input descriptors. */
			if (unlikely(*in_num)) {
				printk(">>>>>%s:%d\n", __func__, __LINE__);
				vq_err(vq, "Descriptor has out after in: "
				       "idx %d\n", i);
				return -EINVAL;
			}
			*out_num += ret;
		}
	} while ((i = next_desc(vq, &desc)) != -1);

	/* On success, increment avail index. */
	vq->last_avail_idx++;

	/* Assume notifications from guest are disabled at this point,
	 * if they aren't we would need to update avail_event index. */
	BUG_ON(!(vq->used_flags & VRING_USED_F_NO_NOTIFY));
	return head;
}
EXPORT_SYMBOL_GPL(vhost_get_vq_desc);

/* Reverse the effect of vhost_get_vq_desc. Useful for error handling. */
void vhost_discard_vq_desc(struct vhost_virtqueue *vq, int n)
{
	vq->last_avail_idx -= n;
}
EXPORT_SYMBOL_GPL(vhost_discard_vq_desc);

/* After we've used one of their buffers, we tell them about it.  We'll then
 * want to notify the guest, using eventfd. */
int vhost_add_used(struct vhost_virtqueue *vq, unsigned int head, int len)
{
	struct vring_used_elem heads = {
		cpu_to_vhost32(vq, head),
		cpu_to_vhost32(vq, len)
	};

	return vhost_add_used_n(vq, &heads, 1);
}
EXPORT_SYMBOL_GPL(vhost_add_used);

static int __vhost_add_used_n(struct vhost_virtqueue *vq,
			    struct vring_used_elem *heads,
			    unsigned count)
{
	struct vring_used_elem *used;
	u16 old, new;
	int start;

	start = vq->last_used_idx & (vq->num - 1);
	used = vq->used->ring + start;
	if (count == 1) {
		used->id = heads[0].id;
		used->len = heads[0].len;
	} else {
		memcpy(used, heads, count * sizeof *used);
	}

	if (unlikely(vq->log_used)) {
		/* Make sure data is seen before log. */
		smp_wmb();
		/* Log used ring entry write. */
		log_used(vq, ((void *)used - (void *)vq->used),
			 count * sizeof *used);
	}

	old = vq->last_used_idx;
	new = (vq->last_used_idx += count);
	/* If the driver never bothers to signal in a very long while,
	 * used index might wrap around. If that happens, invalidate
	 * signalled_used index we stored. TODO: make sure driver
	 * signals at least once in 2^16 and remove this. */
	if (unlikely((u16)(new - vq->signalled_used) < (u16)(new - old)))
		vq->signalled_used_valid = false;
	return 0;
}

/* After we've used one of their buffers, we tell them about it.  We'll then
 * want to notify the guest, using eventfd. */
int vhost_add_used_n(struct vhost_virtqueue *vq, struct vring_used_elem *heads,
		     unsigned count)
{
	int start, n, r;

	start = vq->last_used_idx & (vq->num - 1);
	n = vq->num - start;
	if (n < count) {
		r = __vhost_add_used_n(vq, heads, n);
		if (r < 0)
			return r;
		heads += n;
		count -= n;
	}
	r = __vhost_add_used_n(vq, heads, count);

	/* Make sure buffer is written before we update index. */
	smp_wmb();
	vq->used->idx = cpu_to_vhost16(vq, vq->last_used_idx);

	if (unlikely(vq->log_used)) {
		/* Make sure used idx is seen before log. */
		smp_wmb();
		/* Log used index update. */
		log_used(vq, offsetof(struct vring_used, idx),
			 sizeof vq->used->idx);
		if (vq->log_ctx)
			eventfd_signal(vq->log_ctx, 1);
	}
	return r;
}
EXPORT_SYMBOL_GPL(vhost_add_used_n);

static bool vhost_notify(struct vhost_dev *dev, struct vhost_virtqueue *vq)
{
	__u16 old, new;
	__virtio16 event;
	bool v;
	/* Flush out used index updates. This is paired
	 * with the barrier that the Guest executes when enabling
	 * interrupts. */
	smp_mb();

	if (vhost_has_feature(vq, VIRTIO_F_NOTIFY_ON_EMPTY) &&
	    unlikely(vq->avail_idx == vq->last_avail_idx))
		return true;

	if (!vhost_has_feature(vq, VIRTIO_RING_F_EVENT_IDX)) {
		__virtio16 flags;
		flags = vq->avail->flags;
		return !(flags & cpu_to_vhost16(vq, VRING_AVAIL_F_NO_INTERRUPT));
	}

	old = vq->signalled_used;
	v = vq->signalled_used_valid;
	new = vq->signalled_used = vq->last_used_idx;
	vq->signalled_used_valid = true;

	if (unlikely(!v))
		return true;

	event = *vhost_used_event(vq);

	return vring_need_event(vhost16_to_cpu(vq, event), new, old);
}

/* This actually signals the guest, using eventfd. */
void vhost_signal(struct vhost_dev *dev, struct vhost_virtqueue *vq)
{
	//inject virq to kvm dirctory 
	switch (vq->signal_type) {
	case 0:
		//do nothing
		break;
	case 1:
		//mark masked notifiter pending
		if (vhost_notify(dev, vq))
			atomic_set(&vq->signaled, 1);
		break;
	case 2:
		//inject virq to specified kvm
		if (vhost_notify(dev, vq)) {
			vhost_inject_virq_kvm(vq->kvm_id, vq->irq_priv);
		}
		break;
	default: break;
	}
}
EXPORT_SYMBOL_GPL(vhost_signal);

/* And here's the combo meal deal.  Supersize me! */
void vhost_add_used_and_signal(struct vhost_dev *dev,
			       struct vhost_virtqueue *vq,
			       unsigned int head, int len)
{
	vhost_add_used(vq, head, len);
	vhost_signal(dev, vq);
}
EXPORT_SYMBOL_GPL(vhost_add_used_and_signal);

/* multi-buffer version of vhost_add_used_and_signal */
void vhost_add_used_and_signal_n(struct vhost_dev *dev,
				 struct vhost_virtqueue *vq,
				 struct vring_used_elem *heads, unsigned count)
{
	vhost_add_used_n(vq, heads, count);
	vhost_signal(dev, vq);
}
EXPORT_SYMBOL_GPL(vhost_add_used_and_signal_n);

/* return true if we're sure that avaiable ring is empty */
bool vhost_vq_avail_empty(struct vhost_dev *dev, struct vhost_virtqueue *vq)
{
	__virtio16 avail_idx;

	if (vq->avail_idx != vq->last_avail_idx)
		return false;

	avail_idx = vq->avail->idx;

	vq->avail_idx = vhost16_to_cpu(vq, avail_idx);

	return vq->avail_idx == vq->last_avail_idx;
}
EXPORT_SYMBOL_GPL(vhost_vq_avail_empty);

/* OK, now we need to know about added descriptors. */
bool vhost_enable_notify(struct vhost_dev *dev, struct vhost_virtqueue *vq)
{
	__virtio16 avail_idx;
	int r;

	if (!(vq->used_flags & VRING_USED_F_NO_NOTIFY))
		return false;

	vq->used_flags &= ~VRING_USED_F_NO_NOTIFY;
	if (!vhost_has_feature(vq, VIRTIO_RING_F_EVENT_IDX)) {
		r = vhost_update_used_flags(vq);
		if (r) {
			vq_err(vq, "Failed to enable notification at %p: %d\n",
			       &vq->used->flags, r);
			return false;
		}
	} else {
		r = vhost_update_avail_event(vq, vq->avail_idx);
		if (r) {
			vq_err(vq, "Failed to update avail event index at %p: %d\n",
			       vhost_avail_event(vq), r);
			return false;
		}
	}
	/* They could have slipped one in as we were doing that: make
	 * sure it's written, then check again. */
	smp_mb();

	avail_idx = vq->avail->idx;

	return vhost16_to_cpu(vq, avail_idx) != vq->avail_idx;
}
EXPORT_SYMBOL_GPL(vhost_enable_notify);

/* We don't need to be notified again. */
void vhost_disable_notify(struct vhost_dev *dev, struct vhost_virtqueue *vq)
{
	int r;

	if (vq->used_flags & VRING_USED_F_NO_NOTIFY)
		return;

	vq->used_flags |= VRING_USED_F_NO_NOTIFY;
	if (!vhost_has_feature(vq, VIRTIO_RING_F_EVENT_IDX)) {
		r = vhost_update_used_flags(vq);
		if (r)
			vq_err(vq, "Failed to enable notification at %p: %d\n",
			       &vq->used->flags, r);
	}
}
EXPORT_SYMBOL_GPL(vhost_disable_notify);

/* Create a new message. */
struct vhost_msg_node *vhost_new_msg(struct vhost_virtqueue *vq, int type)
{
	struct vhost_msg_node *node = kmalloc(sizeof *node, GFP_KERNEL);
	if (!node)
		return NULL;

	/* Make sure all padding within the structure is initialized. */
	memset(&node->msg, 0, sizeof node->msg);
	node->vq = vq;
	node->msg.type = type;
	return node;
}
EXPORT_SYMBOL_GPL(vhost_new_msg);

void vhost_enqueue_msg(struct vhost_dev *dev, struct list_head *head,
		       struct vhost_msg_node *node)
{
	spin_lock(&dev->iotlb_lock);
	list_add_tail(&node->node, head);
	spin_unlock(&dev->iotlb_lock);

	wake_up_interruptible_poll(&dev->wait, POLLIN | POLLRDNORM);
}
EXPORT_SYMBOL_GPL(vhost_enqueue_msg);

struct vhost_msg_node *vhost_dequeue_msg(struct vhost_dev *dev,
					 struct list_head *head)
{
	struct vhost_msg_node *node = NULL;

	spin_lock(&dev->iotlb_lock);
	if (!list_empty(head)) {
		node = list_first_entry(head, struct vhost_msg_node,
					node);
		list_del(&node->node);
	}
	spin_unlock(&dev->iotlb_lock);

	return node;
}
EXPORT_SYMBOL_GPL(vhost_dequeue_msg);
