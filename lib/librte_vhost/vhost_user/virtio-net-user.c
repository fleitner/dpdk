/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_log.h>

#include "virtio-net.h"
#include "virtio-net-user.h"
#include "vhost-net-user.h"
#include "vhost-net.h"

struct orig_region_map {
	int fd;
	uint64_t mapped_address;
	uint64_t mapped_size;
	uint64_t blksz;
};

#define orig_region(ptr, nregions) \
	((struct orig_region_map *)RTE_PTR_ADD((ptr), \
		sizeof(struct virtio_memory) + \
		sizeof(struct virtio_memory_regions) * (nregions)))

static uint64_t
get_blk_size(int fd)
{
	struct stat stat;

	fstat(fd, &stat);
	return (uint64_t)stat.st_blksize;
}

static void
free_mem_region(struct virtio_memory *dev_mem)
{
	struct orig_region_map *region;
	unsigned int idx;
	uint64_t alignment;

	if (!dev_mem)
		return;

	region = orig_region(dev_mem, dev_mem->nregions);
	for (idx = 0; idx < dev_mem->nregions; idx++) {
		if (region[idx].mapped_address) {
			alignment = region[idx].blksz;
			munmap((void *)(uintptr_t)
				RTE_ALIGN_FLOOR(
					region[idx].mapped_address, alignment),
				RTE_ALIGN_CEIL(
					region[idx].mapped_size, alignment));
			close(region[idx].fd);
		}
	}
}

int
user_set_mem_table(struct vhost_device_ctx ctx, struct VhostUserMsg *pmsg)
{
	struct VhostUserMemory memory = pmsg->payload.memory;
	struct virtio_memory_regions *pregion;
	uint64_t mapped_address, mapped_size;
	struct virtio_net *dev;
	unsigned int idx = 0;
	struct orig_region_map *pregion_orig;
	uint64_t alignment;
	struct virtio_memory *dev_mem = NULL;

	/* unmap old memory regions one by one*/
	dev = get_device(ctx);
	if (dev == NULL)
		return -1;

	dev_mem = dev->mem_arr[dev->mem_idx];
	if (dev_mem) {
		free_mem_region(dev_mem);
		free(dev_mem);
		dev->mem_arr[dev->mem_idx] = NULL;
	}

	dev->mem_arr[dev->mem_idx] = calloc(1,
		sizeof(struct virtio_memory) +
		sizeof(struct virtio_memory_regions) * memory.nregions +
		sizeof(struct orig_region_map) * memory.nregions);

	dev_mem = dev->mem_arr[dev->mem_idx];
	if (dev_mem == NULL) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"(%"PRIu64") Failed to allocate memory for dev->mem_arr[%d]\n",
			dev->device_fh, dev->mem_idx);
		return -1;
	}
	dev_mem->nregions = memory.nregions;

	pregion_orig = orig_region(dev_mem, memory.nregions);
	for (idx = 0; idx < memory.nregions; idx++) {
		pregion = &dev_mem->regions[idx];
		pregion->guest_phys_address =
			memory.regions[idx].guest_phys_addr;
		pregion->guest_phys_address_end =
			memory.regions[idx].guest_phys_addr +
			memory.regions[idx].memory_size;
		pregion->memory_size =
			memory.regions[idx].memory_size;
		pregion->userspace_address =
			memory.regions[idx].userspace_addr;

		/* This is ugly */
		mapped_size = memory.regions[idx].memory_size +
			memory.regions[idx].mmap_offset;
		mapped_address = (uint64_t)(uintptr_t)mmap(NULL,
			mapped_size,
			PROT_READ | PROT_WRITE, MAP_SHARED,
			pmsg->fds[idx],
			0);

		RTE_LOG(INFO, VHOST_CONFIG,
			"mapped region %d fd:%d to %p sz:0x%"PRIx64" off:0x%"PRIx64"\n",
			idx, pmsg->fds[idx], (void *)(uintptr_t)mapped_address,
			mapped_size, memory.regions[idx].mmap_offset);

		if (mapped_address == (uint64_t)(uintptr_t)MAP_FAILED) {
			RTE_LOG(ERR, VHOST_CONFIG,
				"mmap qemu guest failed.\n");
			goto err_mmap;
		}

		pregion_orig[idx].mapped_address = mapped_address;
		pregion_orig[idx].mapped_size = mapped_size;
		pregion_orig[idx].blksz = get_blk_size(pmsg->fds[idx]);
		pregion_orig[idx].fd = pmsg->fds[idx];

		mapped_address +=  memory.regions[idx].mmap_offset;

		pregion->address_offset = mapped_address -
			pregion->guest_phys_address;

		if (memory.regions[idx].guest_phys_addr == 0) {
			dev_mem->base_address =
				memory.regions[idx].userspace_addr;
			dev_mem->mapped_address =
				pregion->address_offset;
		}

		LOG_DEBUG(VHOST_CONFIG,
			"REGION: %u GPA: %p QEMU VA: %p SIZE (%"PRIu64")\n",
			idx,
			(void *)(uintptr_t)pregion->guest_phys_address,
			(void *)(uintptr_t)pregion->userspace_address,
			 pregion->memory_size);
	}

	dev->mem_idx = (dev->mem_idx + 1) % (dev->num_virt_queues * VIRTIO_QNUM);
	return 0;

err_mmap:
	while (idx--) {
		alignment = pregion_orig[idx].blksz;
		munmap((void *)(uintptr_t)RTE_ALIGN_FLOOR(
			pregion_orig[idx].mapped_address, alignment),
			RTE_ALIGN_CEIL(pregion_orig[idx].mapped_size,
					alignment));
		close(pregion_orig[idx].fd);
	}
	free(dev_mem);
	dev->mem_arr[dev->mem_idx] = NULL;
	return -1;
}

static int
virtio_is_ready(struct virtio_net *dev)
{
	struct vhost_virtqueue *rvq, *tvq;
	uint32_t q_idx;

	/* mq support in future.*/
	for (q_idx = 0; q_idx < dev->num_virt_queues; q_idx++) {
		uint32_t virt_rx_q_idx = q_idx * VIRTIO_QNUM + VIRTIO_RXQ;
		uint32_t virt_tx_q_idx = q_idx * VIRTIO_QNUM + VIRTIO_TXQ;

		rvq = dev->virtqueue[virt_rx_q_idx];
		tvq = dev->virtqueue[virt_tx_q_idx];
		if ((rvq == NULL) || (tvq == NULL) ||
			(rvq->desc == NULL) || (tvq->desc == NULL) ||
			(rvq->kickfd == (eventfd_t)-1) ||
			(rvq->callfd == (eventfd_t)-1) ||
			(tvq->kickfd == (eventfd_t)-1) ||
			(tvq->callfd == (eventfd_t)-1)) {
			RTE_LOG(INFO, VHOST_CONFIG,
				"virtio isn't ready for processing.\n");
			return 0;
		}
	}
	RTE_LOG(INFO, VHOST_CONFIG,
		"virtio is now ready for processing.\n");
	return 1;
}

void
user_set_vring_call(struct vhost_device_ctx ctx, struct VhostUserMsg *pmsg)
{
	struct vhost_vring_file file;
	struct virtio_net *dev = get_device(ctx);
	uint32_t cur_qp_idx;

	file.index = pmsg->payload.u64 & VHOST_USER_VRING_IDX_MASK;
	cur_qp_idx = (file.index & (~0x1)) >> 1;

	if (dev->num_virt_queues < cur_qp_idx + 1) {
		if (alloc_vring_queue_pair(dev, cur_qp_idx) == 0) {
			dev->num_virt_queues = cur_qp_idx + 1;
			init_vring_queue_pair(dev, cur_qp_idx);
		}
	}

	if (pmsg->payload.u64 & VHOST_USER_VRING_NOFD_MASK)
		file.fd = -1;
	else
		file.fd = pmsg->fds[0];
	RTE_LOG(INFO, VHOST_CONFIG,
		"vring call idx:%d file:%d\n", file.index, file.fd);
	ops->set_vring_call(ctx, &file);
}


/*
 *  In vhost-user, when we receive kick message, will test whether virtio
 *  device is ready for packet processing.
 */
void
user_set_vring_kick(struct vhost_device_ctx ctx, struct VhostUserMsg *pmsg)
{
	struct vhost_vring_file file;
	struct virtio_net *dev = get_device(ctx);

	file.index = pmsg->payload.u64 & VHOST_USER_VRING_IDX_MASK;
	if (pmsg->payload.u64 & VHOST_USER_VRING_NOFD_MASK)
		file.fd = -1;
	else
		file.fd = pmsg->fds[0];
	RTE_LOG(INFO, VHOST_CONFIG,
		"vring kick idx:%d file:%d\n", file.index, file.fd);
	ops->set_vring_kick(ctx, &file);

	if (virtio_is_ready(dev) &&
		!(dev->flags & VIRTIO_DEV_RUNNING))
			notify_ops->new_device(dev);
}

/*
 * when virtio is stopped, qemu will send us the GET_VRING_BASE message.
 */
int
user_get_vring_base(struct vhost_device_ctx ctx,
	struct vhost_vring_state *state)
{
	struct virtio_net *dev = get_device(ctx);

	/* We have to stop the queue (virtio) if it is running. */
	if (dev->flags & VIRTIO_DEV_RUNNING)
		notify_ops->destroy_device(dev);

	/* Here we are safe to get the last used index */
	ops->get_vring_base(ctx, state->index, state);

	RTE_LOG(INFO, VHOST_CONFIG,
		"vring base idx:%d file:%d\n", state->index, state->num);
	/*
	 * Based on current qemu vhost-user implementation, this message is
	 * sent and only sent in vhost_vring_stop.
	 * TODO: cleanup the vring, it isn't usable since here.
	 */
	if (((int)dev->virtqueue[state->index]->kickfd) >= 0) {
		close(dev->virtqueue[state->index]->kickfd);
		dev->virtqueue[state->index]->kickfd = (eventfd_t)-1;
	}

	return 0;
}

/*
 * when virtio is stopped, qemu will send us the RESET_OWNER message.
 */
int
user_reset_owner(struct vhost_device_ctx ctx,
	struct vhost_vring_state *state)
{
	struct virtio_net *dev = get_device(ctx);

	/* We have to stop the queue (virtio) if it is running. */
	if (dev->flags & VIRTIO_DEV_RUNNING)
		notify_ops->destroy_device(dev);

	RTE_LOG(INFO, VHOST_CONFIG,
		"reset owner --- state idx:%d state num:%d\n", state->index, state->num);
	/*
	 * Based on current qemu vhost-user implementation, this message is
	 * sent and only sent in vhost_net_stop_one.
	 * TODO: cleanup the vring, it isn't usable since here.
	 */
	if (((int)dev->virtqueue[state->index]->kickfd) >= 0) {
		close(dev->virtqueue[state->index]->kickfd);
		dev->virtqueue[state->index]->kickfd = (eventfd_t)-1;
	}

	return 0;
}

void
user_destroy_device(struct vhost_device_ctx ctx)
{
	struct virtio_net *dev = get_device(ctx);
	uint32_t i;

	if (dev && (dev->flags & VIRTIO_DEV_RUNNING))
		notify_ops->destroy_device(dev);

	for (i = 0; i < dev->num_virt_queues; i++)
		if (dev && dev->mem_arr[i]) {
			free_mem_region(dev->mem_arr[i]);
			free(dev->mem_arr[i]);
			dev->mem_arr[i] = NULL;
		}
}
