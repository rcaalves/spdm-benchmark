//#define DEBUG
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/interrupt.h>
#include <linux/virtio.h>
#include <linux/virtio_blk.h>
#include <linux/scatterlist.h>
#include <linux/string_helpers.h>
#include <scsi/scsi_cmnd.h>
#include <linux/idr.h>
#include <linux/blk-mq.h>
#include <linux/blk-mq-virtio.h>
#include <linux/numa.h>


#define SPDM_ENABLED 1
#if SPDM_ENABLED
#include "../../block/blk-mq-sched.h"

#include <libspdm_common_lib.h>
#include <libspdm_requester_lib.h>
#include <mctp.h>
#include <internal/libspdm_secured_message_lib.h>
#include <internal/libspdm_common_lib.h>
// #include <spdm_requester_lib_internal.h>

#include <spdm_sample_certs.h>
#include "spdm_default_params.h"
#include "spdm_auth.h"


#endif /* SPDM_ENABLED */

#define SPDM_CERT_FROM_KERNEL 0
#define BLK_SPDM_DEMO_PRINT 0
#define DEMO_PRINT_LIMIT 256
#define DEMO_BYTES_PER_LINE 16

#define SPDM_EXTRA_BYTES 512


#define LIBSPDM_MAX_SPDM_MSG_SIZE 0x2200 // Max size for SPDM message

#define SPDM_CTX_TO_VIRTIOBLK(spdm_context_ptr) *(struct virtio_blk**)(((char*)spdm_context_ptr) + libspdm_get_context_size())


#define PART_BITS 4
#define VQ_NAME_LEN 16

static int major;
static DEFINE_IDA(vd_index_ida);

#define BLK_SPDM_DEBUG 0

#if BLK_SPDM_DEBUG
#define BLK_SPDM_PRINT(format,  ...) printk(format, ##__VA_ARGS__)
#else
#define BLK_SPDM_PRINT(format,  ...)
#endif /*BLK_SPDM_DEBUG*/

static struct workqueue_struct *virtblk_wq;

struct virtio_blk_vq {
	struct virtqueue *vq;
	spinlock_t lock;
	char name[VQ_NAME_LEN];
} ____cacheline_aligned_in_smp;

struct virtio_blk {
	struct virtio_device *vdev;

	/* The disk structure for the kernel. */
	struct gendisk *disk;

	/* Block layer tags. */
	struct blk_mq_tag_set tag_set;

	/* Process context for config space updates */
	struct work_struct config_work;

	/* What host tells us, plus 2 for header & tailer. */
	unsigned int sg_elems;

	/* Ida index - used to track minor number allocations. */
	int index;

	/* num of vqs */
	int num_vqs;
	struct virtio_blk_vq *vqs;

#if SPDM_ENABLED
	void* spdm_context;
	spinlock_t spdm_spinlock;
	struct kobject *spdm_sysfs;
	bool ts[10];
	uint32_t session_id;
	uint64_t remaining_bits;
	uint8_t in_danger;
	uint8_t wrapped;
#endif
};

struct virtblk_req {
#ifdef CONFIG_VIRTIO_BLK_SCSI
	struct scsi_request sreq;	/* for SCSI passthrough, must be first */
	u8 sense[SCSI_SENSE_BUFFERSIZE];
	struct virtio_scsi_inhdr in_hdr;
#endif
	struct virtio_blk_outhdr out_hdr;
	u8 status;
	struct scatterlist sg[];
};

#if SPDM_ENABLED
static int virtblk_send_arbitrary_data(struct gendisk *disk, char *buf, size_t size, sector_t pos, unsigned int op, struct request* main_req);
static int virtblk_get_arbitrary_data(struct gendisk *disk, char *buf, size_t *size, sector_t pos, unsigned int op, struct request* main_req);
void* virtblk_init_spdm(void);
#endif /* SPDM_ENABLED */

#define isprint(a) ((a >=' ')&&(a <= '~'))
void demo_print_buffer(char* buffer, size_t len, const char* message) {
#if BLK_SPDM_DEMO_PRINT
    int j, k;
    unsigned char* c;
    uint32_t print_limit = min(((size_t)DEMO_PRINT_LIMIT), len);
    uint32_t line_limit;
    printk(KERN_NOTICE "%s\n", message);
    printk("%lu bytes\n", len);
    for (j = 0; j < print_limit; j+= DEMO_BYTES_PER_LINE) {
        line_limit = min(((size_t)DEMO_BYTES_PER_LINE), len - j);
        printk(KERN_CONT "0x%02X\t", j);
        // prints hexa
        for (k = 0; k < line_limit; k++) {
            c = &((unsigned  char*)buffer)[j+k];
            printk (KERN_CONT "%02X ", *c);
        }
        for (k = 0; k < DEMO_BYTES_PER_LINE - line_limit; k++) {
            printk (KERN_CONT "   ");
        }
        printk (KERN_CONT "   ");
        // prints human readable
        for (k = 0; k < line_limit; k++) {
            c = &((unsigned  char*)buffer)[j+k];
            printk (KERN_CONT "%c ", isprint(*c) ? *c : '-');
        }
        printk (KERN_CONT "\n");
    }
    if (print_limit != len)
        printk(KERN_NOTICE "Data truncated to %d bytes\n", DEMO_PRINT_LIMIT);
    printk (KERN_CONT "\n");
#endif /* BLK_SPDM_DEMO_PRINT */
}

static inline blk_status_t virtblk_result(struct virtblk_req *vbr)
{
	switch (vbr->status) {
	case VIRTIO_BLK_S_OK:
		return BLK_STS_OK;
	case VIRTIO_BLK_S_UNSUPP:
		return BLK_STS_NOTSUPP;
	default:
		return BLK_STS_IOERR;
	}
}

/*
 * If this is a packet command we need a couple of additional headers.  Behind
 * the normal outhdr we put a segment with the scsi command block, and before
 * the normal inhdr we put the sense data and the inhdr with additional status
 * information.
 */
#ifdef CONFIG_VIRTIO_BLK_SCSI
static int virtblk_add_req_scsi(struct virtqueue *vq, struct virtblk_req *vbr,
		struct scatterlist *data_sg, bool have_data)
{
	struct scatterlist hdr, status, cmd, sense, inhdr, *sgs[6];
	unsigned int num_out = 0, num_in = 0;

	sg_init_one(&hdr, &vbr->out_hdr, sizeof(vbr->out_hdr));
	sgs[num_out++] = &hdr;
	sg_init_one(&cmd, vbr->sreq.cmd, vbr->sreq.cmd_len);
	sgs[num_out++] = &cmd;

	if (have_data) {
		if (vbr->out_hdr.type & cpu_to_virtio32(vq->vdev, VIRTIO_BLK_T_OUT))
			sgs[num_out++] = data_sg;
		else
			sgs[num_out + num_in++] = data_sg;
	}

	sg_init_one(&sense, vbr->sense, SCSI_SENSE_BUFFERSIZE);
	sgs[num_out + num_in++] = &sense;
	sg_init_one(&inhdr, &vbr->in_hdr, sizeof(vbr->in_hdr));
	sgs[num_out + num_in++] = &inhdr;
	sg_init_one(&status, &vbr->status, sizeof(vbr->status));
	sgs[num_out + num_in++] = &status;

	return virtqueue_add_sgs(vq, sgs, num_out, num_in, vbr, GFP_ATOMIC);
}

static inline void virtblk_scsi_request_done(struct request *req)
{
	struct virtblk_req *vbr = blk_mq_rq_to_pdu(req);
	struct virtio_blk *vblk = req->q->queuedata;
	struct scsi_request *sreq = &vbr->sreq;

	sreq->resid_len = virtio32_to_cpu(vblk->vdev, vbr->in_hdr.residual);
	sreq->sense_len = virtio32_to_cpu(vblk->vdev, vbr->in_hdr.sense_len);
	sreq->result = virtio32_to_cpu(vblk->vdev, vbr->in_hdr.errors);
}

static int virtblk_ioctl(struct block_device *bdev, fmode_t mode,
			     unsigned int cmd, unsigned long data)
{
	struct gendisk *disk = bdev->bd_disk;
	struct virtio_blk *vblk = disk->private_data;

	/*
	 * Only allow the generic SCSI ioctls if the host can support it.
	 */
	if (!virtio_has_feature(vblk->vdev, VIRTIO_BLK_F_SCSI))
		return -ENOTTY;

	return scsi_cmd_blk_ioctl(bdev, mode, cmd,
				  (void __user *)data);
}
#else
static inline int virtblk_add_req_scsi(struct virtqueue *vq,
		struct virtblk_req *vbr, struct scatterlist *data_sg,
		bool have_data)
{
	return -EIO;
}
static inline void virtblk_scsi_request_done(struct request *req)
{
}
#define virtblk_ioctl	NULL
#endif /* CONFIG_VIRTIO_BLK_SCSI */

static int virtblk_add_req(struct virtqueue *vq, struct virtblk_req *vbr,
		struct scatterlist *data_sg, bool have_data)
{
	struct scatterlist hdr, status, *sgs[3];
	unsigned int num_out = 0, num_in = 0;

	sg_init_one(&hdr, &vbr->out_hdr, sizeof(vbr->out_hdr));
	sgs[num_out++] = &hdr;

	BLK_SPDM_PRINT (KERN_NOTICE "HPSPDM, virt_blk: virtblk_add_req (type = %X, length = %u) ", vbr->out_hdr.type, data_sg->length);
	if (have_data) {
		if (vbr->out_hdr.type & cpu_to_virtio32(vq->vdev, VIRTIO_BLK_T_OUT)) {
			sgs[num_out++] = data_sg;
			// printk (KERN_CONT "out (len %u) ", data_sg->length);
		}
		else {
			sgs[num_out + num_in++] = data_sg;
			// printk (KERN_CONT "in ");
		}
	}

	sg_init_one(&status, &vbr->status, sizeof(vbr->status));
	sgs[num_out + num_in++] = &status;

	return virtqueue_add_sgs(vq, sgs, num_out, num_in, vbr, GFP_ATOMIC);
}

#if SPDM_ENABLED
void spdm_fix_internal_seqno(libspdm_context_t *spdm_context, uint8_t *msg_buffer) {
    // hax to fix out of order sequence numbers, considering 16-bit overflows
    // the overflow issue was not obseved in the responder -> requester direction,
    // but it does not hurt to be careful
    // considering the "danger zone" += 1/4 of the whole 16-bit range
    const uint64_t WRAP_DANGER_OUT = 0x4000;
    const uint64_t WRAP_DANGER_IN  = 0xC000;

    struct virtio_blk *vblk = SPDM_CTX_TO_VIRTIOBLK(spdm_context);
    libspdm_session_info_t *session_info = NULL;
    libspdm_secured_message_context_t *secured_message_context = NULL;
    // uint8_t seqno[8];
    uint64_t seqno = 0;
    uint8_t seqno_size;
    int i;

    if (spdm_context->transport_decode_message != libspdm_transport_mctp_decode_message) {
      printk("%s: Not supported!\n", __func__);
      return;
    }

    // get seqno within the packet
    seqno_size = libspdm_mctp_get_sequence_number(0, (uint8_t*)&seqno);
    memcpy(&seqno, msg_buffer + sizeof(mctp_message_header_t) + sizeof(spdm_secured_message_a_data_header1_t), seqno_size);

    if ((seqno & 0xFFFF) == WRAP_DANGER_OUT) {
        vblk->wrapped = 0;
        vblk->in_danger = 0;
    }

    if ((seqno & 0xFFFF) >= WRAP_DANGER_IN) {
        vblk->in_danger = 1;
    }

    if ((seqno & 0xFFFF) == 0xFFFF) {
        vblk->remaining_bits += 0x10000;
        vblk->wrapped = 1;
    }

    seqno += vblk->remaining_bits;

    if (vblk->in_danger && !vblk->wrapped && ((seqno & 0xFFFF) < WRAP_DANGER_OUT)) {
        seqno += 0x10000;
    }
    if (vblk->in_danger && vblk->wrapped && ((seqno & 0xFFFF) >= WRAP_DANGER_IN)) {
        seqno -= 0x10000;
    }

    // set seqno in all active sessions
    for (i = 0; i < LIBSPDM_MAX_SESSION_COUNT; i++) {
        if (spdm_context->session_info[i].session_id != INVALID_SESSION_ID) {
            session_info = libspdm_get_session_info_via_session_id(spdm_context, spdm_context->session_info[i].session_id);
            secured_message_context = session_info->secured_message_context;
            secured_message_context->application_secret.response_data_sequence_number = seqno;
        }
    }
}
#endif /* SPDM_ENABLED */

static inline void virtblk_request_done(struct request *req)
{
	struct virtblk_req *vbr = blk_mq_rq_to_pdu(req);
#if SPDM_ENABLED
	struct virtio_blk *vblk = req->rq_disk->private_data;
#endif
	// unsigned long flags;

	switch (req_op(req)) {
	case REQ_OP_SCSI_IN:
	case REQ_OP_SCSI_OUT:
		virtblk_scsi_request_done(req);
		break;
	}

	BLK_SPDM_PRINT (KERN_NOTICE "HPSPDM virtblk_request_done: req_op(req): %X %X, len: %u, islast: %lu, %llx %px", req_op(req), vbr->out_hdr.type, vbr->sg->length, sg_is_last(vbr->sg), sg_phys(vbr->sg), sg_virt(vbr->sg));
#if BLK_SPDM_DEBUG
	if (req_op(req) == REQ_OP_READ) {
		u8 *i;
		for(i = sg_virt(vbr->sg); i < (u8*)sg_virt(vbr->sg) + vbr->sg->length; i++) {
			if (((i-((u8*)sg_virt(vbr->sg)))%16) == 0) printk (KERN_CONT "\n(%04lX) ", (i-((u8*)sg_virt(vbr->sg))));
			printk (KERN_CONT "%02X ", *i);
		}
		printk (KERN_CONT "\n");
	}
#endif
	if (req_op(req) == REQ_OP_READ || req_op(req) == REQ_OP_SPDM_APP) {
		struct scatterlist *temp_sct = vbr->sg;
		do {
			demo_print_buffer(sg_virt(temp_sct), temp_sct->length, "Kernel driver received the following data:");
			temp_sct = sg_next(temp_sct);
		} while (temp_sct != NULL);
	}

#if SPDM_ENABLED
	if (req->spdm_original_req) {
		if (req_op(req) == REQ_OP_SPDM || req_op(req) == REQ_OP_SPDM_APP) {
			// original request was a read operation
			unsigned long int index_original, index_copy, copy_len;
			unsigned long long int sector_diff_bytes;
			unsigned char *temp_buffer;
			size_t temp_buffer_size;
			uint32_t *session_id;
			bool is_app_message;

			uint8_t *scratch_buffer;
			size_t scratch_buffer_size;
			libspdm_return_t status;
			uint32_t size;

			struct virtblk_req *vbr2 = blk_mq_rq_to_pdu(req->spdm_original_req);
			struct scatterlist *original_sct = vbr2->sg;
			struct scatterlist *this_sct = vbr->sg;
			index_original = 0;
			index_copy = 0;
			BLK_SPDM_PRINT(KERN_NOTICE "Original request ptr: %px", req->spdm_original_req);
			BLK_SPDM_PRINT (KERN_NOTICE "req_op(req) == REQ_OP_SPDM, blk_rq_pos(req) %lu, blk_rq_pos(req->spdm_original_req) %lu", blk_rq_pos(req), blk_rq_pos(req->spdm_original_req));
			BLK_SPDM_PRINT (KERN_NOTICE "req_op(req) == REQ_OP_SPDM, original_sct->length %u (%lu), vbr->sg->length %u (%lu)", original_sct->length, sg_is_last(original_sct), vbr->sg->length, sg_is_last(vbr->sg));

			// checking if data is encrypted
			if (vblk->spdm_context) {
				// temp_buffer = kmalloc(LIBSPDM_MAX_SPDM_MSG_SIZE, GFP_ATOMIC /*GFP_KERNEL*/); //cant sleep here
				// if (temp_buffer == NULL) {
				// 	printk(KERN_ALERT "no mem to allocate decode buffer");
				// 	blk_mq_end_request(req, BLK_STS_IOERR);
				// 	return;
				// }
				do {
					void *temp_buffer_to_pass;

					/* always use scratch buffer to response.
					 * if it is secured message, this scratch buffer will be used.
					 */
					size_t transport_header_size = ((libspdm_context_t *)vblk->spdm_context)->local_context.capability.transport_header_size;
					libspdm_get_scratch_buffer (vblk->spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
					temp_buffer = scratch_buffer + libspdm_get_scratch_buffer_secure_message_offset(vblk->spdm_context) +
						transport_header_size;
					temp_buffer_size = libspdm_get_scratch_buffer_secure_message_capacity(vblk->spdm_context) -
						transport_header_size;
#else
					temp_buffer = scratch_buffer + transport_header_size;
					temp_buffer_size = scratch_buffer_size - transport_header_size;
#endif
					temp_buffer_to_pass = temp_buffer;
					size = *((uint32_t*)sg_virt(this_sct));
					BLK_SPDM_PRINT(KERN_NOTICE "encoded size = %u", size);
					memmove(sg_virt(this_sct), ((uint32_t*)sg_virt(this_sct)) + 1, size);

					// temp_buffer_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

					spdm_fix_internal_seqno(vblk->spdm_context, sg_virt(this_sct));
					status = ((libspdm_context_t *)vblk->spdm_context)->transport_decode_message( vblk->spdm_context, &session_id, &is_app_message,
																		false, size, sg_virt(this_sct), &temp_buffer_size, &temp_buffer_to_pass);
					if (LIBSPDM_STATUS_IS_ERROR(status) || !is_app_message) {
						printk(KERN_ALERT "%s: transport_decode_message error status - %x\n", __func__, status);
						printk(KERN_ALERT "\tsession_id: %u\n", *session_id);
					} else {
						temp_buffer = temp_buffer_to_pass;
						this_sct->length = temp_buffer_size - sizeof(mctp_message_header_t);
						memcpy(sg_virt(this_sct), temp_buffer + sizeof(mctp_message_header_t), this_sct->length);
					}

					/* test code without spdm encryption */
					// size = *((uint32_t*)sg_virt(this_sct));
					// if (size != this_sct->length)
					// 	printk(KERN_NOTICE "encoded size = %u, %u", size, this_sct->length);
					// this_sct->length = size /*- sizeof(mctp_message_header_t)*/;
					// memmove(((uint8_t*)sg_virt(this_sct)), ((uint8_t*)sg_virt(this_sct)) + sizeof(mctp_message_header_t) + sizeof(uint32_t), size);
					/* end test code without spdm encryption */
					this_sct = sg_next(this_sct);
				} while (this_sct != NULL);
				// kfree(temp_buffer);
				this_sct = vbr->sg;
			} else {
				BLK_SPDM_PRINT(KERN_ALERT "%s: spdm_context == NULL", __func__);
			}

			// spin_lock_irqsave(&myspinlock, flags); // virtblk_request_done runs atomically (AFAIK), so no locking is needed
			// seek original request copy point
			sector_diff_bytes = (blk_rq_pos(req) - blk_rq_pos(req->spdm_original_req))*SECTOR_SIZE;
			do {
				if (sector_diff_bytes - index_original > original_sct->length) {
					index_original += original_sct->length;
					original_sct = sg_next(original_sct);
				} else {
					index_original = sector_diff_bytes - index_original;
					break;
				}
			} while (original_sct != NULL);

			// copy remaining data
			while (original_sct != NULL && this_sct != NULL) {
				copy_len = LIBSPDM_MIN(original_sct->length - index_original, (this_sct->length) - index_copy);
				memcpy(((unsigned char*)sg_virt(original_sct)) + index_original, ((unsigned char*)sg_virt(this_sct)) + index_copy, copy_len);
				index_copy += copy_len;
				index_original += copy_len;
				if (index_copy == (this_sct->length)) {
					this_sct = sg_next(this_sct);
					index_copy = 0;
				}
				if (index_original == original_sct->length) {
					original_sct = sg_next(original_sct);
					index_original = 0;
				}
			}
			// spin_unlock_irqrestore(&myspinlock, flags);
		}

		// spin_lock_irqsave(&myspinlock, flags);
		((struct request *)req->spdm_original_req)->active_splits--;
		if (!((struct request *)req->spdm_original_req)->active_splits) {
			// spin_unlock_irqrestore(&myspinlock, flags);
			BLK_SPDM_PRINT(KERN_NOTICE "Ending original request     %lu %u %u %px", blk_rq_pos(req), blk_rq_bytes(req), ((struct request *)req->spdm_original_req)->active_splits, req->spdm_original_req);
			blk_mq_end_request(req->spdm_original_req, virtblk_result(vbr));
		} else {
			// spin_unlock_irqrestore(&myspinlock, flags);
			BLK_SPDM_PRINT(KERN_NOTICE "Do not end original request %lu %u %u %px", blk_rq_pos(req), blk_rq_bytes(req), ((struct request *)req->spdm_original_req)->active_splits, req->spdm_original_req);
		}

	}
#endif /* SPDM_ENABLED */
	blk_mq_end_request(req, virtblk_result(vbr));
}

static void virtblk_done(struct virtqueue *vq)
{
	struct virtio_blk *vblk = vq->vdev->priv;
	bool req_done = false;
	int qid = vq->index;
	struct virtblk_req *vbr;
	unsigned long flags;
	unsigned int len;

	spin_lock_irqsave(&vblk->vqs[qid].lock, flags);
	do {
		virtqueue_disable_cb(vq);
		while ((vbr = virtqueue_get_buf(vblk->vqs[qid].vq, &len)) != NULL) {
			struct request *req = blk_mq_rq_from_pdu(vbr);

			blk_mq_complete_request(req);
			req_done = true;
		}
		if (unlikely(virtqueue_is_broken(vq)))
			break;
	} while (!virtqueue_enable_cb(vq));

	/* In case queue is stopped waiting for more buffers. */
	if (req_done)
		blk_mq_start_stopped_hw_queues(vblk->disk->queue, true);
	spin_unlock_irqrestore(&vblk->vqs[qid].lock, flags);
}

static blk_status_t virtio_queue_rq(struct blk_mq_hw_ctx *hctx,
			   const struct blk_mq_queue_data *bd)
{
	struct virtio_blk *vblk = hctx->queue->queuedata;
	struct request *req = bd->rq;
	struct virtblk_req *vbr = blk_mq_rq_to_pdu(req);
	unsigned long flags;
	unsigned int num;
	int qid = hctx->queue_num;
	int err;
	bool notify = false;
	u32 type;

#if SPDM_ENABLED
	struct scatterlist *temp_sct;
	char * copied_data;
	size_t copied_size;
	blk_status_t blk_status;
#endif /* SPDM_ENABLED */

	BUG_ON(req->nr_phys_segments + 2 > vblk->sg_elems);

	switch (req_op(req)) {
	case REQ_OP_READ:
	case REQ_OP_WRITE:
		type = 0;
		break;
	case REQ_OP_FLUSH:
		type = VIRTIO_BLK_T_FLUSH;
		break;
	case REQ_OP_SCSI_IN:
	case REQ_OP_SCSI_OUT:
		type = VIRTIO_BLK_T_SCSI_CMD;
		break;
	case REQ_OP_SPDM | REQ_OP_WRITE:
	case REQ_OP_SPDM:
		type = VIRTIO_BLK_T_SPDM;
		break;
	case REQ_OP_SPDM_APP | REQ_OP_WRITE:
	case REQ_OP_SPDM_APP:
		type = VIRTIO_BLK_T_SPDM_APP;
		break;
	case REQ_OP_DRV_IN:
		type = VIRTIO_BLK_T_GET_ID;
		break;
	default:
		WARN_ON_ONCE(1);
		return BLK_STS_IOERR;
	}

	vbr->out_hdr.type = cpu_to_virtio32(vblk->vdev, type);
	vbr->out_hdr.sector = (type!=0 && type!=VIRTIO_BLK_T_SPDM && type!=VIRTIO_BLK_T_SPDM_APP) ?
		0 : cpu_to_virtio64(vblk->vdev, blk_rq_pos(req));
	vbr->out_hdr.ioprio = cpu_to_virtio32(vblk->vdev, req_get_ioprio(req));

	if (type != VIRTIO_BLK_T_SPDM && type != VIRTIO_BLK_T_SPDM_APP)
		req->spdm_original_req = NULL;

	blk_mq_start_request(req);

	num = blk_rq_map_sg(hctx->queue, req, vbr->sg); // num is used as a boolean argument in virtblk_add_req, but may be larger than 1
	BLK_SPDM_PRINT (KERN_NOTICE "NUM: %d, sg_is_last %lu, type %u, sector %llu (%lu), blk_rq_bytes %u, req %px", num, sg_is_last(vbr->sg), type, vbr->out_hdr.sector, (req->__sector), blk_rq_bytes(req), req);

	if (num) {
		if (rq_data_dir(req) == WRITE)
			vbr->out_hdr.type |= cpu_to_virtio32(vblk->vdev, VIRTIO_BLK_T_OUT);
		else
			vbr->out_hdr.type |= cpu_to_virtio32(vblk->vdev, VIRTIO_BLK_T_IN);
	}

#if SPDM_ENABLED
	// Assuming extra spdm headers take up to SPDM_EXTRA_BYTES bytes. Resulting payload have to be multiple of 512
	#define MAX_SPDM_PLAIN_TEXT_SIZE (LIBSPDM_MAX_SPDM_MSG_SIZE - SPDM_EXTRA_BYTES + sizeof(mctp_message_header_t))
	// re-encapsulate write requests
	if (vblk->spdm_context && num && req_op(req) == REQ_OP_WRITE) {
		// printk(KERN_ALERT "Write req: %px", req);
		if (vblk->spdm_context) {
			size_t temp_sct_copied_size;
			char * cipher_data;
			size_t cipher_size;
			size_t to_copy_size;
			size_t block_count;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;
            size_t max_copy_size;
            size_t transport_header_size;
			libspdm_return_t status;
			bool stop = 0;

			temp_sct = vbr->sg;
			temp_sct_copied_size = 0;
			block_count = 0;
			cipher_data = (char*) kmalloc(LIBSPDM_MAX_SPDM_MSG_SIZE, GFP_KERNEL);
			if (cipher_data == NULL) {
				printk(KERN_ERR "%s out of mem", __func__);
				return BLK_STS_IOERR;
			}
			// libspdm 3.2 requires input data to be the scratch buffer
			// copied_data = (char*) kmalloc(LIBSPDM_MAX_SPDM_MSG_SIZE, GFP_KERNEL);
			// if (copied_data == NULL) {
			// 	printk(KERN_ERR "%s out of mem", __func__);
			// 	kfree(cipher_data);
			// 	return BLK_STS_IOERR;
			// }

			transport_header_size = ((libspdm_context_t *)vblk->spdm_context)->local_context.capability.transport_header_size;
			libspdm_get_scratch_buffer (vblk->spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
			copied_data = scratch_buffer + libspdm_get_scratch_buffer_secure_message_offset(vblk->spdm_context) +
				transport_header_size;
			max_copy_size = libspdm_get_scratch_buffer_secure_message_capacity(vblk->spdm_context) -
				transport_header_size - ((libspdm_context_t *)vblk->spdm_context)->local_context.capability.transport_tail_size;
#else
			copied_data = scratch_buffer + transport_header_size;
			max_copy_size = scratch_buffer_size - transport_header_size -
				((libspdm_context_t *)s->spdm_context)->local_context.capability.transport_tail_size;
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */

			req->active_splits = 1;
			cipher_size = LIBSPDM_MAX_SPDM_MSG_SIZE;
			copied_size = sizeof(mctp_message_header_t);
			((mctp_message_header_t*)copied_data)->message_type = MCTP_MESSAGE_TYPE_VENDOR_DEFINED_PCI;

			do {
				do {
					if (temp_sct != NULL) {
						to_copy_size = min(temp_sct->length - temp_sct_copied_size, MAX_SPDM_PLAIN_TEXT_SIZE - copied_size); // minimum between whats left on the scatterlist and how much the buffer can still acommodate
						BLK_SPDM_PRINT("blk_rq_bytes(req) %u, temp_sct->length %u, to_copy_size %lu", blk_rq_bytes(req), temp_sct->length, to_copy_size);
						BLK_SPDM_PRINT("copied_size %lu, temp_sct_copied_size %lu (before)", copied_size, temp_sct_copied_size);
						memcpy(copied_data + copied_size, sg_virt(temp_sct) + temp_sct_copied_size, to_copy_size);
						copied_size += to_copy_size;
						temp_sct_copied_size += to_copy_size;
					}

					BLK_SPDM_PRINT("copied_size %lu, temp_sct_copied_size %lu, isnull %u", copied_size, temp_sct_copied_size, temp_sct == NULL);
					if (copied_size == MAX_SPDM_PLAIN_TEXT_SIZE || (temp_sct == NULL && copied_size != 0)) {
						void *cipher_data_ptr = cipher_data;
						BLK_SPDM_PRINT("trying to encode and send");

						spin_lock_irqsave(&vblk->spdm_spinlock, flags);
						status = ((libspdm_context_t *)vblk->spdm_context)->transport_encode_message(vblk->spdm_context, &vblk->session_id, true, true, copied_size, copied_data, &cipher_size, &cipher_data_ptr);
						spin_unlock_irqrestore(&vblk->spdm_spinlock, flags);

						if (LIBSPDM_STATUS_IS_ERROR(status)) {
							printk(KERN_ALERT "transport_encode_message status - %x\n", status);
							kfree(cipher_data);
							// kfree(copied_data);
							return BLK_STS_IOERR;
						}
						if (blk_rq_pos(req) + block_count + (copied_size-sizeof(mctp_message_header_t))/SECTOR_SIZE >= blk_rq_pos(req) + blk_rq_bytes(req)/SECTOR_SIZE) {
							stop = 1;
						}
						BLK_SPDM_PRINT("%lu + %lu = %lu (blk_rq_pos(req) + block_count)", blk_rq_pos(req), block_count, blk_rq_pos(req) + block_count);
						req->active_splits++;
						blk_status = virtblk_send_arbitrary_data(vblk->disk, cipher_data_ptr, cipher_size, blk_rq_pos(req) + block_count, REQ_OP_SPDM_APP, req);
						if (blk_status != BLK_STS_OK) {
							printk(KERN_ALERT "Error on virtblk_send_arbitrary_data()");
							kfree(cipher_data);
							// kfree(copied_data);
							return blk_status;

						}
						block_count += (copied_size-sizeof(mctp_message_header_t)) / SECTOR_SIZE;
						cipher_size = LIBSPDM_MAX_SPDM_MSG_SIZE;
						copied_size = sizeof(mctp_message_header_t);
						((mctp_message_header_t*)copied_data)->message_type = MCTP_MESSAGE_TYPE_VENDOR_DEFINED_PCI;
					}
					BLK_SPDM_PRINT("-----");
				} while (!stop && temp_sct != NULL && temp_sct_copied_size < temp_sct->length);

				temp_sct_copied_size = 0;

				/****************************** start test code *************************************/
				// virtblk_send_arbitrary_data(vblk->disk, sg_virt(temp_sct), temp_sct->length, blk_rq_pos(req) + block_count, REQ_OP_SPDM_APP, req);
				// block_count += temp_sct->length / SECTOR_SIZE;
				/******************************* end test code ************************************/

				if (!stop && temp_sct) temp_sct = sg_next(temp_sct);
			} while (!stop && (temp_sct != NULL || copied_size != 0));


			/************************** start test code *****************************************/
			// temp_sct = vbr->sg;
			// temp_size = 0;
			// copied_size = 0;

			// do {
			// 	temp_size += temp_sct->length;
			// 	temp_sct = sg_next(temp_sct);
			// } while (temp_sct != NULL);

			// copied_data = (char*) kmalloc(temp_size, GFP_KERNEL);

			// temp_sct = vbr->sg;
			// do {
			// 	memcpy(copied_data + copied_size, sg_virt(temp_sct), temp_sct->length);
			// 	copied_size += temp_sct->length;
			// 	temp_sct = sg_next(temp_sct);
			// } while (temp_sct != NULL);

			// virtblk_send_arbitrary_data(vblk->disk, copied_data, temp_size, blk_rq_pos(req), REQ_OP_SPDM_APP, req); // magic number: same as above
			/*************************** end test code ****************************************/

			req->active_splits--;
			if (!req->active_splits) {
				blk_mq_end_request(req, virtblk_result(vbr));
			}

			kfree(cipher_data);
			// kfree(copied_data);

			return BLK_STS_OK;
		} else {
			printk(KERN_ALERT "Spdm context is NULL");
			return BLK_STS_IOERR;
		}
	}

	// re-encapsulate read requests
	if (num && req_op(req) == REQ_OP_READ) {
		#define MAX_SPDM_PLAIN_TEXT_SIZE_RX (LIBSPDM_MAX_SPDM_MSG_SIZE - SPDM_EXTRA_BYTES) // Assuming extra spdm headers take up to SPDM_EXTRA_BYTES bytes
		size_t temp_sct_copied_size;
		size_t to_copy_size;
		size_t block_count;
		bool stop = 0;

		temp_sct = vbr->sg;
		temp_sct_copied_size = 0;
		block_count = 0;
		copied_size = 0;
		req->active_splits = 1;

		do {
			do {
				if (temp_sct != NULL) {
					to_copy_size = min(temp_sct->length - temp_sct_copied_size, MAX_SPDM_PLAIN_TEXT_SIZE_RX - copied_size); // minimum between whats left on the scatterlist and how much the buffer can still acommodate
					copied_size += to_copy_size;
					temp_sct_copied_size += to_copy_size;
				}

				BLK_SPDM_PRINT("copied_size %lu, temp_sct_copied_size %lu, isnull %u", copied_size, temp_sct_copied_size, temp_sct == NULL);
				if (copied_size == MAX_SPDM_PLAIN_TEXT_SIZE_RX || (temp_sct == NULL && copied_size != 0)) {
					if (blk_rq_pos(req) + block_count + copied_size/SECTOR_SIZE >= blk_rq_pos(req) + blk_rq_bytes(req)/SECTOR_SIZE) {
						stop = 1;
					}
					// copied_size += 512; // changing size here was causing problems... moved inside virtblk_get_arbitrary_data()
					// spin_lock_irqsave(&myspinlock, flags);
					req->active_splits++;
					// spin_unlock_irqrestore(&myspinlock, flags);
					blk_status = virtblk_get_arbitrary_data(vblk->disk, NULL, &copied_size, blk_rq_pos(req) + block_count, REQ_OP_SPDM_APP, req);
					if (blk_status != BLK_STS_OK) {
						printk(KERN_ALERT "Error on virtblk_get_arbitrary_data()");
						return blk_status;
					}
					// copied_size -= 512;
					block_count += copied_size / SECTOR_SIZE;
					copied_size = 0;
				}
				BLK_SPDM_PRINT("-----");
			} while (!stop && temp_sct != NULL && temp_sct_copied_size < temp_sct->length);

			temp_sct_copied_size = 0;

			if (!stop && temp_sct) temp_sct = sg_next(temp_sct);
		} while (!stop && (temp_sct != NULL || copied_size != 0));

		// spin_lock_irqsave(&myspinlock, flags);
		req->active_splits--;

		if (!req->active_splits) {
			// spin_unlock_irqrestore(&myspinlock, flags);
			// printk(KERN_NOTICE "Ending original request in     %s, %px", __func__, req);
			blk_mq_end_request(req, virtblk_result(vbr));
		} else {
			// spin_unlock_irqrestore(&myspinlock, flags);
			// printk(KERN_NOTICE "Do not end original request in %s, %px", __func__, req);
		}

		return BLK_STS_OK;
	}
#endif /* SPDM_ENABLED */

	spin_lock_irqsave(&vblk->vqs[qid].lock, flags);

	BLK_SPDM_PRINT (KERN_NOTICE "HPSPDM virt_blk: queueing for disk %s type: %X  num: %d is_scsi%d\n", vblk->disk->disk_name, vbr->out_hdr.type, num, blk_rq_is_scsi(req));

	if (blk_rq_is_scsi(req)) {
		err = virtblk_add_req_scsi(vblk->vqs[qid].vq, vbr, vbr->sg, num);
	}
	else {
		err = virtblk_add_req(vblk->vqs[qid].vq, vbr, vbr->sg, num);
	}
	if (err) {
		virtqueue_kick(vblk->vqs[qid].vq);
		blk_mq_stop_hw_queue(hctx);
		spin_unlock_irqrestore(&vblk->vqs[qid].lock, flags);
		/* Out of mem doesn't actually happen, since we fall back
		 * to direct descriptors */
		if (err == -ENOMEM || err == -ENOSPC)
			return BLK_STS_DEV_RESOURCE;
		return BLK_STS_IOERR;
	}

	if (bd->last && virtqueue_kick_prepare(vblk->vqs[qid].vq))
		notify = true;
	spin_unlock_irqrestore(&vblk->vqs[qid].lock, flags);

	if (notify)
		virtqueue_notify(vblk->vqs[qid].vq);

	return BLK_STS_OK;
}

/* return id (s/n) string for *disk to *id_str
 */
static int virtblk_get_id(struct gendisk *disk, char *id_str)
{
	struct virtio_blk *vblk = disk->private_data;
	struct request_queue *q = vblk->disk->queue;
	struct request *req;
	int err;

	req = blk_get_request(q, REQ_OP_DRV_IN, 0);
	if (IS_ERR(req))
		return PTR_ERR(req);

	err = blk_rq_map_kern(q, req, id_str, VIRTIO_BLK_ID_BYTES, GFP_KERNEL);
	if (err)
		goto out;

	blk_execute_rq(vblk->disk->queue, vblk->disk, req, false);
	err = blk_status_to_errno(virtblk_result(blk_mq_rq_to_pdu(req)));
out:
	blk_put_request(req);
	return err;
}


#if SPDM_ENABLED
// inspired by blk_end_sync_rq
static void my_blk_end_rq(struct request *rq, blk_status_t error)
{
	if (rq->end_io_data) kfree(rq->end_io_data);
	blk_put_request(rq);
}

static int virtblk_send_arbitrary_data(struct gendisk *disk, char *some_data, size_t size, sector_t pos, unsigned int op, struct request* main_req)
{
	struct virtio_blk *vblk = disk->private_data;
	struct request_queue *q = vblk->disk->queue;
	struct request *req;
	int err;

	req = blk_get_request(q, op | REQ_OP_WRITE, 0);
	if (IS_ERR(req))
		return PTR_ERR(req);

	if (vblk->disk->queue->mq_ops && main_req) {
		char *new_buffer;
		new_buffer = kmalloc(size, GFP_KERNEL);
		if (!new_buffer) {
			err = -ENOMEM;
			goto out;
		}
		memcpy(new_buffer, some_data, size);
		err = blk_rq_map_kern(q, req, new_buffer, size, GFP_KERNEL);
		if (err) {
			kfree(new_buffer);
			goto out;
		}

		req->__sector = pos;
		req->spdm_original_req = main_req;
		// some flags to make sure no one will mess with the request
		req->rq_flags |= (RQF_SOFTBARRIER | RQF_STARTED);

		// re-encapsulated messages should be added to the queue, but not executed, to avoid recursion issues
		req->rq_disk = vblk->disk;
		req->end_io = my_blk_end_rq;
		req->end_io_data = new_buffer;
		//            (struct request *rq, bool at_head, bool run_queue, bool async)
		// it is better to enqueue at head, otherwise stackoverflows were noticed
		blk_mq_sched_insert_request(req, true /*at_head*/, false /*true*/, false);
		return BLK_STS_OK;
	} else {
		err = blk_rq_map_kern(q, req, some_data, size, GFP_KERNEL);
		if (err)
			goto out;

		req->__sector = pos;
		req->spdm_original_req = main_req;
		// 'pure' SPDM messages can be executed righ away
		// printk(KERN_ALERT "blk_execute_rq params: %px %px %px", vblk->disk->queue, vblk->disk, req);
		blk_execute_rq(vblk->disk->queue, vblk->disk, req, true);
	}

	// not sure what this does
	err = blk_status_to_errno(virtblk_result(blk_mq_rq_to_pdu(req)));
out:
	blk_put_request(req);
	return err;
}

static int virtblk_get_arbitrary_data(struct gendisk *disk, char *buf, size_t *size, sector_t pos, unsigned int op, struct request* main_req)
{
	struct virtio_blk *vblk = disk->private_data;
	struct request_queue *q = vblk->disk->queue;
	struct request *req;
	size_t temp_size;
	int err;

	req = blk_get_request(q, op, 0);
	if (IS_ERR(req))
		return PTR_ERR(req);

	if (vblk->disk->queue->mq_ops && main_req) {
		char *new_buffer;
		new_buffer = kmalloc(*size + SPDM_EXTRA_BYTES, GFP_KERNEL);
		if (!new_buffer) {
			err = -ENOMEM;
			goto out;
		}
		err = blk_rq_map_kern(q, req, new_buffer, *size, GFP_KERNEL);
		if (err) {
			kfree(new_buffer);
			goto out;
		}

		req->__sector = pos;
		req->spdm_original_req = main_req;
		// some flags to make sure no one will mess with the request
		req->rq_flags |= (RQF_SOFTBARRIER | RQF_STARTED);

		// re-encapsulated messages should be added to the queue, but not executed, to avoid recursion issues
		req->rq_disk = vblk->disk;
		req->end_io = my_blk_end_rq;
		req->end_io_data = new_buffer;

		blk_mq_sched_insert_request(req, true /*at_head*/, false /*true*/, false);
		return BLK_STS_OK;
	} else {
		err = blk_rq_map_kern(q, req, buf, *size, GFP_KERNEL);
		if (err)
			goto out;

		req->__sector = pos;
		req->spdm_original_req = main_req;
		// 'pure' SPDM messages can be executed righ away
		blk_execute_rq(vblk->disk->queue, vblk->disk, req, true);
	}

#if BLK_SPDM_DEBUG
	{
	int i;
	printk (KERN_NOTICE "HPSPDM, virtblk_get_arbitrary_data got: ");
	for (i=0; i < ((*size < 64) ? *size : 64); i++) { printk (KERN_CONT " %02X", ((unsigned char*)buf)[i]); }
	printk (KERN_CONT "\n");
	}
#endif

	if (!main_req) {
		temp_size = * ((u32*) (buf+1));
		if (temp_size  > *size) {
			err = -1;
			*size = 0;
			goto out;
		}
		*size = temp_size;
		BLK_SPDM_PRINT (KERN_NOTICE "HPSPDM, changed size to %lu", *size);
		memmove (buf, buf + 5, *size); // magic number: assuming 1-byte message type and 4-byte message size
	}

#if BLK_SPDM_DEBUG
	{
	int i;
	printk (KERN_NOTICE "HPSPDM, virtblk_get_arbitrary_data got: ");
	for (i=0; i < ((*size < 64) ? *size : 64); i++) { printk (KERN_CONT " %02X", ((unsigned char*)buf)[i]); }
	printk (KERN_CONT "\n");
	}
#endif

	// not sure what this does
	err = blk_status_to_errno(virtblk_result(blk_mq_rq_to_pdu(req)));
out:
	blk_put_request(req);
	return err;
}

#define TEST_PSK_DATA_STRING "TestPskData"
#define TEST_PSK_HINT_STRING "TestPskHint"

libspdm_return_t do_authentication_via_spdm(void* spdm_context);

libspdm_return_t spdm_blk_send_message( void *spdm_context,
				        size_t request_size, const void *request,
				        uint64_t timeout)
{
	struct virtio_blk* vblk;
	struct gendisk *spdm_disk = NULL;
	vblk = SPDM_CTX_TO_VIRTIOBLK(spdm_context);
	if (vblk)
		spdm_disk = vblk->disk;
	virtblk_send_arbitrary_data(spdm_disk, (char *) request, request_size, 0, REQ_OP_SPDM, NULL);
	return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t spdm_blk_receive_message( void *spdm_context,
					    size_t *response_size,
					    void **response,
					   uint64_t timeout)
{
	struct virtio_blk* vblk;
	struct gendisk *spdm_disk = NULL;
	size_t size;
	vblk = SPDM_CTX_TO_VIRTIOBLK(spdm_context);
	if (vblk)
		spdm_disk = vblk->disk;
	size = *response_size;
	virtblk_get_arbitrary_data(spdm_disk, *response, &size, 0, REQ_OP_SPDM, NULL);
	*response_size = size;
	return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t spdm_device_acquire_sender_buffer (
  void *context, void **msg_buf_ptr);

void spdm_device_release_sender_buffer (
  void *context, const void *msg_buf_ptr);

libspdm_return_t spdm_device_acquire_receiver_buffer (
  void *context, void **msg_buf_ptr);

void spdm_device_release_receiver_buffer (
  void *context, const void *msg_buf_ptr);

void* virtblk_init_spdm(void) {
	void *spdm_context;
	libspdm_data_parameter_t parameter;
	uint8_t data8;
	uint16_t data16;
	uint32_t data32;
	// void *hash;
	// size_t hash_size;
	spdm_version_number_t spdm_version;
	size_t scratch_buffer_size;
	void *scratch_buffer;

	spdm_context = (void *)kmalloc(libspdm_get_context_size()+sizeof(void*), GFP_KERNEL);
	if (spdm_context == NULL) {
		pr_alert("Could not allocate spdm_context %s", __func__);
		return NULL;
	}

	libspdm_init_context(spdm_context);
	libspdm_register_device_io_func(
		spdm_context,
		spdm_blk_send_message,
		spdm_blk_receive_message);

	if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
		libspdm_register_transport_layer_func(
			spdm_context,
			LIBSPDM_MAX_SPDM_MSG_SIZE - LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE - LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE, //LIBSPDM_MAX_SPDM_MSG_SIZE,
			LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE,
			LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE,
			libspdm_transport_mctp_encode_message,
			libspdm_transport_mctp_decode_message);
	} else {
		pr_alert("SPDM transfer type not supported.\n");
		kfree(spdm_context);
		return NULL;
	}

	// if (m_load_state_file_name != NULL) {
	// 	spdm_load_negotiated_state(spdm_context, true);
	// }

	libspdm_register_device_buffer_func(
		spdm_context,
		LIBSPDM_MAX_SPDM_MSG_SIZE,
		LIBSPDM_MAX_SPDM_MSG_SIZE,
		spdm_device_acquire_sender_buffer,
		spdm_device_release_sender_buffer,
		spdm_device_acquire_receiver_buffer,
		spdm_device_release_receiver_buffer
	);

	scratch_buffer_size = libspdm_get_sizeof_required_scratch_buffer(spdm_context);
	scratch_buffer = (void *)kmalloc(scratch_buffer_size, GFP_KERNEL);
	if (scratch_buffer == NULL) {
		pr_alert("Could not allocate scratch_buffer.\n");
		kfree(spdm_context);
		spdm_context = NULL;
		return NULL;
	}
	libspdm_set_scratch_buffer(spdm_context, scratch_buffer, scratch_buffer_size);

	if (m_use_version != 0) {
		libspdm_zero_mem(&parameter, sizeof(parameter));
		parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
		spdm_version = m_use_version << SPDM_VERSION_NUMBER_SHIFT_BIT;
		libspdm_set_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
			&spdm_version, sizeof(spdm_version));
	}

	if (m_use_secured_message_version != 0) {
		libspdm_zero_mem(&parameter, sizeof(parameter));
		if (m_use_secured_message_version != 0) {
			parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
			spdm_version = m_use_secured_message_version << SPDM_VERSION_NUMBER_SHIFT_BIT;
			libspdm_set_data(spdm_context,
				LIBSPDM_DATA_SECURED_MESSAGE_VERSION,
				&parameter, &spdm_version,
				sizeof(spdm_version));
		} else {
			libspdm_set_data(spdm_context,
				LIBSPDM_DATA_SECURED_MESSAGE_VERSION,
				&parameter, NULL, 0);
		}
	}

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

	data8 = 0;
	libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
		&parameter, &data8, sizeof(data8));
	data32 = m_use_requester_capability_flags;
	if (m_use_capability_flags != 0) {
		data32 = m_use_capability_flags;
	}
	libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
		&data32, sizeof(data32));

	data8 = m_support_measurement_spec;
	libspdm_set_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
		&data8, sizeof(data8));
	data32 = m_support_asym_algo;
	libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
		&data32, sizeof(data32));
	data32 = m_support_hash_algo;
	libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
		&data32, sizeof(data32));
	data16 = m_support_dhe_algo;
	libspdm_set_data(spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter,
		&data16, sizeof(data16));
	data16 = m_support_aead_algo;
	libspdm_set_data(spdm_context, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
		&data16, sizeof(data16));
	data16 = m_support_req_asym_algo;
	libspdm_set_data(spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
		&data16, sizeof(data16));
	data16 = m_support_key_schedule_algo;
	libspdm_set_data(spdm_context, LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &data16,
	sizeof(data16));
	data8 = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
	libspdm_set_data(spdm_context, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter,
		&data8, sizeof(data8));
	data8 = SPDM_MEL_SPECIFICATION_DMTF;
	libspdm_set_data(spdm_context, LIBSPDM_DATA_MEL_SPEC, &parameter,
		&data8, sizeof(data8));

	return spdm_context;
}


void virtblk_init_spdm_certificates(void* spdm_context) {
	uint8_t index;
	bool res;
	void *data;
	size_t data_size;
	libspdm_data_parameter_t parameter;
	uint8_t data8;
	uint16_t data16;
	uint32_t data32;
	void *hash;
	size_t hash_size;

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;

	data_size = sizeof(data32);
	libspdm_get_data(spdm_context, LIBSPDM_DATA_CONNECTION_STATE, &parameter,
		&data32, &data_size);
	// LIBSPDM_ASSERT(data32 == LIBSPDM_CONNECTION_STATE_NEGOTIATED);

	data_size = sizeof(data32);
	libspdm_get_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
		&data32, &data_size);
	m_use_measurement_hash_algo = data32;

	data_size = sizeof(data32);
	libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
		&data32, &data_size);
	m_use_asym_algo = data32;

	data_size = sizeof(data32);
	libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
		&data32, &data_size);
	m_use_hash_algo = data32;

	data_size = sizeof(data16);
	libspdm_get_data(spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
		&data16, &data_size);
	m_use_req_asym_algo = data16;

	// printf("read_responder_public_certificate_chain\n");
	if ((m_use_slot_id == 0xFF) ||
	    ((m_use_requester_capability_flags &
	      SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP) != 0)) {
		// res = read_responder_public_certificate_chain(m_use_hash_algo,
		// 					      m_use_asym_algo,
		// 					      &data, &data_size,
		// 					      NULL, NULL);
		res = false; // We do not support this use case (public key of the Responder provisioned to the Requester previously)
		// if (!res) {
		// 	res = true;
		// 	data = responder_public_certificate_chain_data;
		// 	data_size = responder_public_certificate_chain_size;
		// }
		if (res) {
			libspdm_zero_mem(&parameter, sizeof(parameter));
			parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
			libspdm_set_data(spdm_context,
				      LIBSPDM_DATA_LOCAL_PUBLIC_KEY,
				      &parameter, data, data_size);
			// Do not free it.
		}
	} else {
#if SPDM_CERT_FROM_KERNEL
		res = read_responder_root_public_certificate_from_system_certificate_list(m_use_hash_algo,
							     // m_use_asym_algo,
							     &data, &data_size,
							     &hash, &hash_size);
#else
		res = true;
		hash = responder_public_certificate_chain_hash;
		hash_size = responder_public_certificate_chain_hash_size;
#endif
		// res = read_responder_root_public_certificate(m_use_hash_algo,
		// 					     m_use_asym_algo,
		// 					     &data, &data_size,
		// 					     &hash, &hash_size);
		// if (!res) {
		// 	res = true;
		// 	hash = responder_public_certificate_chain_hash;
		// 	hash_size = responder_public_certificate_chain_hash_size;
		// }
		if (res) {
			libspdm_zero_mem(&parameter, sizeof(parameter));
			parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
			libspdm_set_data(spdm_context,
				      LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT, //SPDM_DATA_PEER_PUBLIC_ROOT_CERT_HASH,
				      &parameter, hash, hash_size);
			// Do not free it.
		}
	}

	// res = read_requester_public_certificate_chain(m_use_hash_algo,
	// 					      m_use_req_asym_algo,
	// 					      &data, &data_size, NULL,
	// 					      NULL);
	res = false; // The requester public certifiate chain is only needed if mutual authentication is enabled

	if (!res) {
		res = true;
		data = requester_public_certificate_chain_data;
		data_size = requester_public_certificate_chain_size;
	}

	if (res) {
		libspdm_zero_mem(&parameter, sizeof(parameter));
		parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
		data8 = 0;
		for (index = 0; index < m_use_slot_count; index++) {
			data8 |= (1 << index);
		}

		libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_SUPPORTED_SLOT_MASK,
					&parameter, &data8, sizeof(data8));

		libspdm_zero_mem(&parameter, sizeof(parameter));
		parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
		data8 = m_use_slot_count;
		libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_SUPPORTED_SLOT_MASK,
			      &parameter, &data8, sizeof(data8));

		for (index = 0; index < m_use_slot_count; index++) {
			parameter.additional_data[0] = index;
			libspdm_set_data(spdm_context,
				      LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
				      &parameter, data, data_size);
		}
		// printf("read_requester_public_certificate_chain\n");
		// do not free it
	} else {
		libspdm_zero_mem(&parameter, sizeof(parameter));
		parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
		data8 = 0;
		libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_SUPPORTED_SLOT_MASK,
					&parameter, &data8, sizeof(data8));
	}

}
#endif /* SPDM_ENABLED */

/* We provide getgeo only to please some old bootloader/partitioning tools */
static int virtblk_getgeo(struct block_device *bd, struct hd_geometry *geo)
{
	struct virtio_blk *vblk = bd->bd_disk->private_data;

	/* see if the host passed in geometry config */
	if (virtio_has_feature(vblk->vdev, VIRTIO_BLK_F_GEOMETRY)) {
		virtio_cread(vblk->vdev, struct virtio_blk_config,
			     geometry.cylinders, &geo->cylinders);
		virtio_cread(vblk->vdev, struct virtio_blk_config,
			     geometry.heads, &geo->heads);
		virtio_cread(vblk->vdev, struct virtio_blk_config,
			     geometry.sectors, &geo->sectors);
	} else {
		/* some standard values, similar to sd */
		geo->heads = 1 << 6;
		geo->sectors = 1 << 5;
		geo->cylinders = get_capacity(bd->bd_disk) >> 11;
	}
	return 0;
}

static const struct block_device_operations virtblk_fops = {
	.ioctl  = virtblk_ioctl,
	.owner  = THIS_MODULE,
	.getgeo = virtblk_getgeo,
};

static int index_to_minor(int index)
{
	return index << PART_BITS;
}

static int minor_to_index(int minor)
{
	return minor >> PART_BITS;
}

static ssize_t virtblk_serial_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct gendisk *disk = dev_to_disk(dev);
	int err;

	/* sysfs gives us a PAGE_SIZE buffer */
	BUILD_BUG_ON(PAGE_SIZE < VIRTIO_BLK_ID_BYTES);

	buf[VIRTIO_BLK_ID_BYTES] = '\0';
	err = virtblk_get_id(disk, buf);
	if (!err)
		return strlen(buf);

	if (err == -EIO) /* Unsupported? Make it empty. */
		return 0;

	return err;
}

static DEVICE_ATTR(serial, 0444, virtblk_serial_show, NULL);

/* The queue's logical block size must be set before calling this */
static void virtblk_update_capacity(struct virtio_blk *vblk, bool resize)
{
	struct virtio_device *vdev = vblk->vdev;
	struct request_queue *q = vblk->disk->queue;
	char cap_str_2[10], cap_str_10[10];
	unsigned long long nblocks;
	u64 capacity;

	/* Host must always specify the capacity. */
	virtio_cread(vdev, struct virtio_blk_config, capacity, &capacity);

	/* If capacity is too big, truncate with warning. */
	if ((sector_t)capacity != capacity) {
		dev_warn(&vdev->dev, "Capacity %llu too large: truncating\n",
			 (unsigned long long)capacity);
		capacity = (sector_t)-1;
	}

	nblocks = DIV_ROUND_UP_ULL(capacity, queue_logical_block_size(q) >> 9);

	string_get_size(nblocks, queue_logical_block_size(q),
			STRING_UNITS_2, cap_str_2, sizeof(cap_str_2));
	string_get_size(nblocks, queue_logical_block_size(q),
			STRING_UNITS_10, cap_str_10, sizeof(cap_str_10));

	dev_notice(&vdev->dev,
		   "[%s] %s%llu %d-byte logical blocks (%s/%s)\n",
		   vblk->disk->disk_name,
		   resize ? "new size: " : "",
		   nblocks,
		   queue_logical_block_size(q),
		   cap_str_10,
		   cap_str_2);

	set_capacity(vblk->disk, capacity);
}

static void virtblk_config_changed_work(struct work_struct *work)
{
	struct virtio_blk *vblk =
		container_of(work, struct virtio_blk, config_work);
	char *envp[] = { "RESIZE=1", NULL };

	virtblk_update_capacity(vblk, true);
	revalidate_disk(vblk->disk);
	kobject_uevent_env(&disk_to_dev(vblk->disk)->kobj, KOBJ_CHANGE, envp);
}

static void virtblk_config_changed(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;

	queue_work(virtblk_wq, &vblk->config_work);
}

static int init_vq(struct virtio_blk *vblk)
{
	int err;
	int i;
	vq_callback_t **callbacks;
	const char **names;
	struct virtqueue **vqs;
	unsigned short num_vqs;
	struct virtio_device *vdev = vblk->vdev;
	struct irq_affinity desc = { 0, };

	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_MQ,
				   struct virtio_blk_config, num_queues,
				   &num_vqs);
	if (err)
		num_vqs = 1;

	num_vqs = min_t(unsigned int, nr_cpu_ids, num_vqs);

	vblk->vqs = kmalloc_array(num_vqs, sizeof(*vblk->vqs), GFP_KERNEL);
	if (!vblk->vqs)
		return -ENOMEM;

	names = kmalloc_array(num_vqs, sizeof(*names), GFP_KERNEL);
	callbacks = kmalloc_array(num_vqs, sizeof(*callbacks), GFP_KERNEL);
	vqs = kmalloc_array(num_vqs, sizeof(*vqs), GFP_KERNEL);
	if (!names || !callbacks || !vqs) {
		err = -ENOMEM;
		goto out;
	}

	for (i = 0; i < num_vqs; i++) {
		callbacks[i] = virtblk_done;
		snprintf(vblk->vqs[i].name, VQ_NAME_LEN, "req.%d", i);
		names[i] = vblk->vqs[i].name;
	}

	/* Discover virtqueues and write information to configuration.  */
	err = virtio_find_vqs(vdev, num_vqs, vqs, callbacks, names, &desc);
	if (err)
		goto out;

	for (i = 0; i < num_vqs; i++) {
		spin_lock_init(&vblk->vqs[i].lock);
		vblk->vqs[i].vq = vqs[i];
	}
	vblk->num_vqs = num_vqs;

out:
	kfree(vqs);
	kfree(callbacks);
	kfree(names);
	if (err)
		kfree(vblk->vqs);
	return err;
}

/*
 * Legacy naming scheme used for virtio devices.  We are stuck with it for
 * virtio blk but don't ever use it for any new driver.
 */
static int virtblk_name_format(char *prefix, int index, char *buf, int buflen)
{
	const int base = 'z' - 'a' + 1;
	char *begin = buf + strlen(prefix);
	char *end = buf + buflen;
	char *p;
	int unit;

	p = end - 1;
	*p = '\0';
	unit = base;
	do {
		if (p == begin)
			return -EINVAL;
		*--p = 'a' + (index % unit);
		index = (index / unit) - 1;
	} while (index >= 0);

	memmove(begin, p, end - p);
	memcpy(buf, prefix, strlen(prefix));

	return 0;
}

static int virtblk_get_cache_mode(struct virtio_device *vdev)
{
	u8 writeback;
	int err;

	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_CONFIG_WCE,
				   struct virtio_blk_config, wce,
				   &writeback);

	/*
	 * If WCE is not configurable and flush is not available,
	 * assume no writeback cache is in use.
	 */
	if (err)
		writeback = virtio_has_feature(vdev, VIRTIO_BLK_F_FLUSH);

	return writeback;
}

static void virtblk_update_cache_mode(struct virtio_device *vdev)
{
	u8 writeback = virtblk_get_cache_mode(vdev);
	struct virtio_blk *vblk = vdev->priv;

	blk_queue_write_cache(vblk->disk->queue, writeback, false);
	revalidate_disk(vblk->disk);
}

static const char *const virtblk_cache_types[] = {
	"write through", "write back"
};

static ssize_t
virtblk_cache_type_store(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count)
{
	struct gendisk *disk = dev_to_disk(dev);
	struct virtio_blk *vblk = disk->private_data;
	struct virtio_device *vdev = vblk->vdev;
	int i;

	BUG_ON(!virtio_has_feature(vblk->vdev, VIRTIO_BLK_F_CONFIG_WCE));
	i = sysfs_match_string(virtblk_cache_types, buf);
	if (i < 0)
		return i;

	virtio_cwrite8(vdev, offsetof(struct virtio_blk_config, wce), i);
	virtblk_update_cache_mode(vdev);
	return count;
}

static ssize_t
virtblk_cache_type_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct gendisk *disk = dev_to_disk(dev);
	struct virtio_blk *vblk = disk->private_data;
	u8 writeback = virtblk_get_cache_mode(vblk->vdev);

	BUG_ON(writeback >= ARRAY_SIZE(virtblk_cache_types));
	return snprintf(buf, 40, "%s\n", virtblk_cache_types[writeback]);
}

static const struct device_attribute dev_attr_cache_type_ro =
	__ATTR(cache_type, 0444,
	       virtblk_cache_type_show, NULL);
static const struct device_attribute dev_attr_cache_type_rw =
	__ATTR(cache_type, 0644,
	       virtblk_cache_type_show, virtblk_cache_type_store);

#if SPDM_ENABLED

size_t print_measurement(char *buf, size_t buf_size, spdm_measurement_block_dmtf_t *measurement_block_dmtf) {
	unsigned int i;
	size_t total_size = 0;
	total_size += snprintf(buf + total_size, buf_size - total_size, "measurement %u:\n", measurement_block_dmtf->measurement_block_common_header.index);
	total_size += snprintf(buf + total_size, buf_size - total_size, "0x%X 0x%X %u\n", measurement_block_dmtf->measurement_block_common_header.measurement_specification,
												measurement_block_dmtf->measurement_block_dmtf_header.dmtf_spec_measurement_value_type,
												measurement_block_dmtf->measurement_block_dmtf_header.dmtf_spec_measurement_value_size);
	for (i = 0; i < measurement_block_dmtf->measurement_block_dmtf_header.dmtf_spec_measurement_value_size; i++) {
		total_size += snprintf(buf + total_size, buf_size - total_size, "%02X ", ((uint8_t*)(measurement_block_dmtf+1))[i]);
		if ( (i+1) % 16 == 0 )
			total_size += snprintf(buf + total_size, buf_size - total_size, "\n");
	}
	return total_size;
}

static ssize_t
virtblk_spdm_measurement_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct gendisk *disk = dev_to_disk(dev);
	struct virtio_blk *vblk = disk->private_data;
	libspdm_return_t status;
	uint8_t request_attribute;
	uint8_t number_of_blocks;
	uint8_t content_changed;
	uint32_t measurement_record_length;
	uint8_t *measurement_record; //[MAX_SPDM_MEASUREMENT_RECORD_SIZE];
	spdm_measurement_block_dmtf_t *measurement_block_dmtf;
	size_t total_size = 0;
	unsigned int i;

	measurement_record = kmalloc(LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE, GFP_KERNEL);
	if (measurement_record == NULL) {
		return sprintf(buf, "Could not allocate memory");
	}

	request_attribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
	measurement_record_length = LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE;

	status = libspdm_get_measurement (
		vblk->spdm_context,
		NULL,
		request_attribute,
		SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
		m_use_slot_id & 0xF,
		&content_changed,
		&number_of_blocks,
		&measurement_record_length,
		measurement_record
		);

	if (LIBSPDM_STATUS_IS_ERROR(status)) {
		return sprintf(buf, "Could not obtain measurements Error %x", status);
	}

	measurement_block_dmtf = (spdm_measurement_block_dmtf_t *) measurement_record;
	for (i = 0; i < number_of_blocks && total_size < PAGE_SIZE; i++) {
		total_size += print_measurement(buf + total_size, PAGE_SIZE - total_size, measurement_block_dmtf);

		measurement_block_dmtf = (spdm_measurement_block_dmtf_t *) (((uint8_t*)measurement_block_dmtf) +
									measurement_block_dmtf->measurement_block_common_header.measurement_size +
									sizeof(spdm_measurement_block_common_header_t));
	}

	if (total_size == PAGE_SIZE) {
		sprintf(buf + PAGE_SIZE - (strlen("...")+1), "...");
	}

	kfree(measurement_record);
	return total_size;
}
static const struct device_attribute dev_attr_spdm_measurement =
	__ATTR(spdm_all_measurements, 0444,
	       virtblk_spdm_measurement_show, NULL);


static ssize_t
virtblk_spdm_tamper_store(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count)
{
	struct gendisk *disk = dev_to_disk(dev);
	struct virtio_blk *vblk = disk->private_data;

	int err;
	u8 measurement_index;
	libspdm_return_t status;

	uint8_t spdm_tamper_msg[10] = {MCTP_MESSAGE_TYPE_VENDOR_DEFINED_IANA, SPDM_BLK_APP_TAMPER };
	uint8_t spdm_tamper_rsp[10];
	size_t spdm_tamper_rsp_size = sizeof(spdm_tamper_rsp);

	err = kstrtou8(buf, 10, &measurement_index);
	if (err || measurement_index > 9)
		return -EINVAL;

	spdm_tamper_msg[2] = measurement_index;

	status = libspdm_send_receive_data(vblk->spdm_context, &vblk->session_id, true,
						spdm_tamper_msg,
						sizeof(spdm_tamper_msg),
						spdm_tamper_rsp,
						&spdm_tamper_rsp_size);
	if (LIBSPDM_STATUS_IS_ERROR(status)) {
		printk("%s error - %x\n", __func__, (uint32_t)status);
		return -EINVAL;
	}

	vblk->ts[measurement_index] = true;

	return count;
}
static ssize_t
virtblk_spdm_tamper_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct gendisk *disk = dev_to_disk(dev);
	struct virtio_blk *vblk = disk->private_data;
	unsigned int i;
	ssize_t print_size = 0;

	struct attribute **spdm_attrs = vblk->spdm_sysfs->ktype->default_attrs;
	i = 0;
	while (spdm_attrs[i] != NULL) {
		print_size += sprintf(buf + print_size, "Measurement %u:%s tampered\n", i, (vblk->ts[i]) ? "" : " not" );
		i++;
	}

	return print_size;
}
static const struct device_attribute dev_attr_spdm_tamper =
	__ATTR(spdm_tamper_measurement, 0644,
	       virtblk_spdm_tamper_show, virtblk_spdm_tamper_store);
#endif /* SPDM_ENABLED */

static int virtblk_init_request(struct blk_mq_tag_set *set, struct request *rq,
		unsigned int hctx_idx, unsigned int numa_node)
{
	struct virtio_blk *vblk = set->driver_data;
	struct virtblk_req *vbr = blk_mq_rq_to_pdu(rq);

#ifdef CONFIG_VIRTIO_BLK_SCSI
	vbr->sreq.sense = vbr->sense;
#endif
	sg_init_table(vbr->sg, vblk->sg_elems);
	return 0;
}

static int virtblk_map_queues(struct blk_mq_tag_set *set)
{
	struct virtio_blk *vblk = set->driver_data;

	return blk_mq_virtio_map_queues(set, vblk->vdev, 0);
}

#ifdef CONFIG_VIRTIO_BLK_SCSI
static void virtblk_initialize_rq(struct request *req)
{
	struct virtblk_req *vbr = blk_mq_rq_to_pdu(req);

	scsi_req_init(&vbr->sreq);
}
#endif

static const struct blk_mq_ops virtio_mq_ops = {
	.queue_rq	= virtio_queue_rq,
	.complete	= virtblk_request_done,
	.init_request	= virtblk_init_request,
#ifdef CONFIG_VIRTIO_BLK_SCSI
	.initialize_rq_fn = virtblk_initialize_rq,
#endif
	.map_queues	= virtblk_map_queues,
};

static unsigned int virtblk_queue_depth;
module_param_named(queue_depth, virtblk_queue_depth, uint, 0444);

#if SPDM_ENABLED

struct spdm_sysfs_entry {
		struct attribute attr;
		ssize_t (*show)(int, char *);
		ssize_t (*store)(int, const char *, size_t);
};

static ssize_t dummy_show(int index, char *buf)
{
		return 0;
}

static struct spdm_sysfs_entry meas0_attribute = __ATTR(meas0, S_IRUGO, dummy_show, NULL);
static struct spdm_sysfs_entry meas1_attribute = __ATTR(meas1, S_IRUGO, dummy_show, NULL);
static struct spdm_sysfs_entry meas2_attribute = __ATTR(meas2, S_IRUGO, dummy_show, NULL);
static struct spdm_sysfs_entry meas3_attribute = __ATTR(meas3, S_IRUGO, dummy_show, NULL);
static struct spdm_sysfs_entry meas4_attribute = __ATTR(meas4, S_IRUGO, dummy_show, NULL);
static struct spdm_sysfs_entry meas5_attribute = __ATTR(meas5, S_IRUGO, dummy_show, NULL);
static struct spdm_sysfs_entry meas6_attribute = __ATTR(meas6, S_IRUGO, dummy_show, NULL);
static struct spdm_sysfs_entry meas7_attribute = __ATTR(meas7, S_IRUGO, dummy_show, NULL);
static struct spdm_sysfs_entry meas8_attribute = __ATTR(meas8, S_IRUGO, dummy_show, NULL);
static struct spdm_sysfs_entry meas9_attribute = __ATTR(meas9, S_IRUGO, dummy_show, NULL);

static struct attribute *spdm_attrs[] = {
		&meas0_attribute.attr,
		&meas1_attribute.attr,
		&meas2_attribute.attr,
		&meas3_attribute.attr,
		&meas4_attribute.attr,
		&meas5_attribute.attr,
		&meas6_attribute.attr,
		&meas7_attribute.attr,
		&meas8_attribute.attr,
		&meas9_attribute.attr,
		NULL,   /* need to NULL terminate the list of attributes */
};

static void spdm_release(struct kobject *kobj)
{

}

static ssize_t spdm_type_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
		struct kobject *parent = kobj->parent;
		struct device *disk_dev = container_of(parent, struct device, kobj);
		struct gendisk *disk = dev_to_disk(disk_dev);
		struct virtio_blk *vblk = disk->private_data;

		struct spdm_sysfs_entry *entry;
		ssize_t return_size;

		unsigned int i;

		libspdm_return_t status;
		uint8_t content_changed;
		uint8_t number_of_blocks;
		uint32_t measurement_record_length;
		uint8_t *measurement_record;

		entry = container_of(attr, struct spdm_sysfs_entry, attr);

		if (!entry->show)
			return -EIO;

		i = 0;
		while (spdm_attrs[i] != NULL) {
			if(spdm_attrs[i] == attr) break;
			i++;
		}
		if (spdm_attrs[i] == NULL) {
			return sprintf(buf, "Measurement index not available\n");
		}

		i++; //measurements are counted starting from 1

		measurement_record = kmalloc(LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE, GFP_KERNEL);
		if (measurement_record == NULL) {
			return sprintf(buf, "Could not allocate memory\n");
		}

		status = libspdm_get_measurement (
				vblk->spdm_context,
				NULL,
				SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE,
				i,
				m_use_slot_id & 0xF,
				&content_changed,
				&number_of_blocks,
				&measurement_record_length,
				measurement_record
		     );

		if (LIBSPDM_STATUS_IS_ERROR(status)) {
			kfree(measurement_record);
			return sprintf(buf, "Could not obtain measurements Error %x\n", status);
		}

		return_size = print_measurement(buf, PAGE_SIZE, (spdm_measurement_block_dmtf_t *)measurement_record);
		kfree(measurement_record);

		return return_size;
}

static const struct sysfs_ops spdm_sysfs_ops = {
		.show = spdm_type_show,
};

// static struct kobj_type spdm_type = {
//         .release        = spdm_release,
//         .sysfs_ops      = &spdm_sysfs_ops,
//         .default_attrs  = spdm_attrs,
// };

static int virtblk_setup_spdm_sysfs(struct virtio_blk *vblk, uint8_t measurement_count) {
	struct kobj_type *spdm_type;
	struct attribute **spdm_attrs_local;
	int err;
	unsigned int i;

	for (i = 0; i < 10; i++) {
		vblk->ts[i] = false;
	}

	// create sysfs entry for measurement
	err = device_create_file(disk_to_dev(vblk->disk), &dev_attr_spdm_measurement);
	if (err)
		return -ENOMEM;
	err = device_create_file(disk_to_dev(vblk->disk), &dev_attr_spdm_tamper);
	if (err)
		return -ENOMEM;

	vblk->spdm_sysfs = kmalloc(sizeof(struct kobject), GFP_KERNEL);
	if (vblk->spdm_sysfs == NULL)
		return -ENOMEM;
	memset(vblk->spdm_sysfs, 0, sizeof(struct kobject));

	// assuming each HD could have different number of measurements,
	//  so we allocate and fill kobj type and attributes dynamically
	spdm_type = kmalloc(sizeof(struct kobj_type), GFP_KERNEL);
	if (vblk->spdm_sysfs == NULL) {
		kfree(vblk->spdm_sysfs);
		return -ENOMEM;
	}
	spdm_attrs_local = kmalloc(sizeof(struct attribute*) * measurement_count, GFP_KERNEL);
	if (vblk->spdm_sysfs == NULL) {
		kfree(vblk->spdm_sysfs);
		kfree(spdm_type);
		return -ENOMEM;
	}
	memcpy(spdm_attrs_local, spdm_attrs, measurement_count * (sizeof(struct attribute*)));
	spdm_attrs_local[measurement_count] = NULL;

	spdm_type->release        = spdm_release;
	spdm_type->sysfs_ops      = &spdm_sysfs_ops;
	spdm_type->default_attrs  = spdm_attrs_local;

	kobject_init(vblk->spdm_sysfs, spdm_type);
	err = -1;
	if (vblk->spdm_sysfs)
		err = kobject_add(vblk->spdm_sysfs, &disk_to_dev(vblk->disk)->kobj, "spdm");
	if (err) {
		printk("error %s\n", __func__);
		kobject_put(vblk->spdm_sysfs);
		kfree(vblk->spdm_sysfs);
		kfree(spdm_type);
		kfree(spdm_attrs_local);
		return err;
	}
	return 0;
}
#endif /* SPDM_ENABLED */

static int virtblk_probe(struct virtio_device *vdev)
{
	struct virtio_blk *vblk;
	struct request_queue *q;
	int err, index;

#if SPDM_ENABLED
	libspdm_return_t status;
	bool use_psk;
	uint8_t heartbeat_period;
	uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
	uint8_t content_changed;
	uint8_t number_of_blocks;
	uint8_t spdm_test_msg[] = {MCTP_MESSAGE_TYPE_VENDOR_DEFINED_IANA, SPDM_BLK_APP_MSG, 'h', 'e', 'l', 'l', 'o', '0'};
	uint8_t spdm_test_rsp[50];
	size_t spdm_test_rsp_size = sizeof(spdm_test_rsp);
#endif /* SPDM_ENABLED */
	// struct request *req;

	u32 v, blk_size, sg_elems, opt_io_size;
	u16 min_io_size;
	u8 physical_block_exp, alignment_offset;

	if (!vdev->config->get) {
		dev_err(&vdev->dev, "%s failure: config access disabled\n",
			__func__);
		return -EINVAL;
	}

	err = ida_simple_get(&vd_index_ida, 0, minor_to_index(1 << MINORBITS),
			     GFP_KERNEL);
	if (err < 0)
		goto out;
	index = err;

	/* We need to know how many segments before we allocate. */
	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_SEG_MAX,
				   struct virtio_blk_config, seg_max,
				   &sg_elems);

	/* We need at least one SG element, whatever they say. */
	if (err || !sg_elems)
		sg_elems = 1;

	/* We need an extra sg elements at head and tail. */
	sg_elems += 2;
	vdev->priv = vblk = kmalloc(sizeof(*vblk), GFP_KERNEL);
	if (!vblk) {
		err = -ENOMEM;
		goto out_free_index;
	}

	vblk->vdev = vdev;
	vblk->sg_elems = sg_elems;

#if SPDM_ENABLED
	vblk->spdm_context = NULL;
	vblk->session_id = 0;
#endif /* SPDM_ENABLED */

	INIT_WORK(&vblk->config_work, virtblk_config_changed_work);

	err = init_vq(vblk);
	if (err)
		goto out_free_vblk;

#if SPDM_ENABLED
	spin_lock_init(&vblk->spdm_spinlock);
#endif /* SPDM_ENABLED */

	/* FIXME: How many partitions?  How long is a piece of string? */
	vblk->disk = alloc_disk(1 << PART_BITS);
	if (!vblk->disk) {
		err = -ENOMEM;
		goto out_free_vq;
	}

	/* Default queue sizing is to fill the ring. */
	if (!virtblk_queue_depth) {
		virtblk_queue_depth = vblk->vqs[0].vq->num_free;
		/* ... but without indirect descs, we use 2 descs per req */
		if (!virtio_has_feature(vdev, VIRTIO_RING_F_INDIRECT_DESC))
			virtblk_queue_depth /= 2;
	}

	memset(&vblk->tag_set, 0, sizeof(vblk->tag_set));
	vblk->tag_set.ops = &virtio_mq_ops;
	vblk->tag_set.queue_depth = BLK_MQ_MAX_DEPTH; //virtblk_queue_depth;
	vblk->tag_set.numa_node = NUMA_NO_NODE;
	vblk->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	vblk->tag_set.cmd_size =
		sizeof(struct virtblk_req) +
		sizeof(struct scatterlist) * sg_elems;
	vblk->tag_set.driver_data = vblk;
	vblk->tag_set.nr_hw_queues = vblk->num_vqs;

	err = blk_mq_alloc_tag_set(&vblk->tag_set);
	if (err)
		goto out_put_disk;

	q = blk_mq_init_queue(&vblk->tag_set);
	if (IS_ERR(q)) {
		err = -ENOMEM;
		goto out_free_tags;
	}
	vblk->disk->queue = q;

	q->queuedata = vblk;

	virtblk_name_format("vd", index, vblk->disk->disk_name, DISK_NAME_LEN);
	BLK_SPDM_PRINT (KERN_NOTICE "HPSPDM virt_blk: creating disk %s\n", vblk->disk->disk_name);

	vblk->disk->major = major;
	vblk->disk->first_minor = index_to_minor(index);
	vblk->disk->private_data = vblk;
	vblk->disk->fops = &virtblk_fops;
	vblk->disk->flags |= GENHD_FL_EXT_DEVT;
	vblk->index = index;

	/* configure queue flush support */
	virtblk_update_cache_mode(vdev);

	/* If disk is read-only in the host, the guest should obey */
	if (virtio_has_feature(vdev, VIRTIO_BLK_F_RO))
		set_disk_ro(vblk->disk, 1);

	/* We can handle whatever the host told us to handle. */
	blk_queue_max_segments(q, vblk->sg_elems-2);

	/* No real sector limit. */
	blk_queue_max_hw_sectors(q, -1U);

	/* Host can optionally specify maximum segment size and number of
	 * segments. */
	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_SIZE_MAX,
				   struct virtio_blk_config, size_max, &v);
	if (!err)
		blk_queue_max_segment_size(q, v);
	else
		blk_queue_max_segment_size(q, -1U);

	/* Host can optionally specify the block size of the device */
	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_BLK_SIZE,
				   struct virtio_blk_config, blk_size,
				   &blk_size);
	if (!err)
		blk_queue_logical_block_size(q, blk_size);
	else
		blk_size = queue_logical_block_size(q);

	/* Use topology information if available */
	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_TOPOLOGY,
				   struct virtio_blk_config, physical_block_exp,
				   &physical_block_exp);
	if (!err && physical_block_exp)
		blk_queue_physical_block_size(q,
				blk_size * (1 << physical_block_exp));

	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_TOPOLOGY,
				   struct virtio_blk_config, alignment_offset,
				   &alignment_offset);
	if (!err && alignment_offset)
		blk_queue_alignment_offset(q, blk_size * alignment_offset);

	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_TOPOLOGY,
				   struct virtio_blk_config, min_io_size,
				   &min_io_size);
	if (!err && min_io_size)
		blk_queue_io_min(q, blk_size * min_io_size);

	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_TOPOLOGY,
				   struct virtio_blk_config, opt_io_size,
				   &opt_io_size);
	if (!err && opt_io_size)
		blk_queue_io_opt(q, blk_size * opt_io_size);

	virtblk_update_capacity(vblk, false);
	virtio_device_ready(vdev);

	device_add_disk(&vdev->dev, vblk->disk);
	err = device_create_file(disk_to_dev(vblk->disk), &dev_attr_serial);

	if (err)
		goto out_del_disk;

	if (virtio_has_feature(vdev, VIRTIO_BLK_F_CONFIG_WCE))
		err = device_create_file(disk_to_dev(vblk->disk),
					 &dev_attr_cache_type_rw);
	else
		err = device_create_file(disk_to_dev(vblk->disk),
					 &dev_attr_cache_type_ro);
	if (err)
		goto out_del_disk;

#if SPDM_ENABLED

	// uint8_t getversion[] = {0x05, 0x10, 0x84, 0x00, 0x00};
	// spdm_blk_send_message(NULL, 5, getversion, 0);

	vblk->spdm_context = virtblk_init_spdm();

	if (vblk->spdm_context == NULL)
		goto out_del_disk;

	vblk->remaining_bits = 0;
	vblk->in_danger = 0;
	vblk->wrapped = 0;

	// hack to be able to access vblk if we only have the context
	SPDM_CTX_TO_VIRTIOBLK(vblk->spdm_context) = vblk;

	// get_version, get_capabilities, and negotiate_algorithms
	status = libspdm_init_connection(
			vblk->spdm_context, false);
	if (LIBSPDM_STATUS_IS_ERROR(status)) {
		printk(KERN_ALERT "Error on spdm_init_connection.");
		goto out_free_spdm;
	} else {
		BLK_SPDM_PRINT(KERN_ALERT "SpdmContext initialized.");
	}

	virtblk_init_spdm_certificates(vblk->spdm_context);

	// other messages
	status = do_authentication_via_spdm(vblk->spdm_context);
	if (LIBSPDM_STATUS_IS_ERROR(status)) {
		printk("do_authentication_via_spdm - %x\n", (uint32_t)status);
		goto out_free_spdm;
	} else {
		BLK_SPDM_PRINT("do_authentication_via_spdm - done");
	}

	use_psk = false;
	heartbeat_period = 0;
	status = libspdm_start_session(vblk->spdm_context, use_psk,
					TEST_PSK_HINT_STRING,
					sizeof(TEST_PSK_HINT_STRING),
				    m_use_measurement_summary_hash_type,
				    m_use_slot_id, m_session_policy, &vblk->session_id,
				    &heartbeat_period, measurement_hash);
	if (LIBSPDM_STATUS_IS_ERROR(status)) {
		printk("spdm_start_session - %x\n", (uint32_t)status);
		goto out_free_spdm;
	}

	// query the total number of measurements available
	status = libspdm_get_measurement (
		vblk->spdm_context,
		NULL,
		0,
		SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
		m_use_slot_id & 0xF,
		&content_changed,
		&number_of_blocks,
		NULL,
		NULL);

	if (LIBSPDM_STATUS_IS_ERROR(status)) {
		goto out_free_spdm;
	}

	for (; spdm_test_msg[sizeof(spdm_test_msg)-1] < '1'; spdm_test_msg[sizeof(spdm_test_msg)-1]++) {
		// send an arbitraty message, so last_spdm_request_session_id is set at the responder
		status = libspdm_send_receive_data(vblk->spdm_context, &vblk->session_id, true,
							spdm_test_msg,
							sizeof(spdm_test_msg),
							spdm_test_rsp,
							&spdm_test_rsp_size);
		if (LIBSPDM_STATUS_IS_ERROR(status)) {
			printk("spdm_send_receive_data error - %x\n", (uint32_t)status);
			goto out_free_spdm;
		}
	#if BLK_SPDM_DEBUG
		printk("response: %lu\n", spdm_test_rsp_size);
		for (index = 0; index < spdm_test_rsp_size; index++)
			printk(KERN_CONT "%c", spdm_test_rsp[index]);
		printk("\n");
	#endif
	}

	err = virtblk_setup_spdm_sysfs(vblk, number_of_blocks);
	if (err)
		goto out_free_spdm;

#endif /* SPDM_ENABLED */
	return 0;

#if SPDM_ENABLED
out_free_spdm:
	kfree(vblk->spdm_context);
#endif /* SPDM_ENABLED */
out_del_disk:
	del_gendisk(vblk->disk);
	blk_cleanup_queue(vblk->disk->queue);
out_free_tags:
	blk_mq_free_tag_set(&vblk->tag_set);
out_put_disk:
	put_disk(vblk->disk);
out_free_vq:
	vdev->config->del_vqs(vdev);
out_free_vblk:
	kfree(vblk);
out_free_index:
	ida_simple_remove(&vd_index_ida, index);
out:
	return err;
}

static void virtblk_remove(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;
	int index = vblk->index;
	int refc;

#if SPDM_ENABLED
	libspdm_send_receive_end_session(vblk->spdm_context, vblk->session_id, 1);
#endif

	/* Make sure no work handler is accessing the device. */
	flush_work(&vblk->config_work);

#if SPDM_ENABLED
	kfree(vblk->spdm_sysfs->ktype->default_attrs);
	kfree(vblk->spdm_sysfs->ktype);
	kobject_put(vblk->spdm_sysfs);
	kfree(vblk->spdm_sysfs);
	kfree(vblk->spdm_context);
#endif /* SPDM_ENABLED */

	del_gendisk(vblk->disk);
	blk_cleanup_queue(vblk->disk->queue);

	blk_mq_free_tag_set(&vblk->tag_set);

	/* Stop all the virtqueues. */
	vdev->config->reset(vdev);

	refc = kref_read(&disk_to_dev(vblk->disk)->kobj.kref);
	put_disk(vblk->disk);
	vdev->config->del_vqs(vdev);
	kfree(vblk->vqs);
	kfree(vblk);

	/* Only free device id if we don't have any users */
	if (refc == 1)
		ida_simple_remove(&vd_index_ida, index);
}

#ifdef CONFIG_PM_SLEEP
static int virtblk_freeze(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;

	/* Ensure we don't receive any more interrupts */
	vdev->config->reset(vdev);

	/* Make sure no work handler is accessing the device. */
	flush_work(&vblk->config_work);

	blk_mq_quiesce_queue(vblk->disk->queue);

	vdev->config->del_vqs(vdev);
	return 0;
}

static int virtblk_restore(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;
	int ret;

	ret = init_vq(vdev->priv);
	if (ret)
		return ret;

	virtio_device_ready(vdev);

	blk_mq_unquiesce_queue(vblk->disk->queue);
	return 0;
}
#endif

static const struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_BLOCK, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features_legacy[] = {
	VIRTIO_BLK_F_SEG_MAX, VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_GEOMETRY,
	VIRTIO_BLK_F_RO, VIRTIO_BLK_F_BLK_SIZE,
#ifdef CONFIG_VIRTIO_BLK_SCSI
	VIRTIO_BLK_F_SCSI,
#endif
	VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_CONFIG_WCE,
	VIRTIO_BLK_F_MQ,
}
;
static unsigned int features[] = {
	VIRTIO_BLK_F_SEG_MAX, VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_GEOMETRY,
	VIRTIO_BLK_F_RO, VIRTIO_BLK_F_BLK_SIZE,
	VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_CONFIG_WCE,
	VIRTIO_BLK_F_MQ,
};

static struct virtio_driver virtio_blk = {
	.feature_table			= features,
	.feature_table_size		= ARRAY_SIZE(features),
	.feature_table_legacy		= features_legacy,
	.feature_table_size_legacy	= ARRAY_SIZE(features_legacy),
	.driver.name			= KBUILD_MODNAME,
	.driver.owner			= THIS_MODULE,
	.id_table			= id_table,
	.probe				= virtblk_probe,
	.remove				= virtblk_remove,
	.config_changed			= virtblk_config_changed,
#ifdef CONFIG_PM_SLEEP
	.freeze				= virtblk_freeze,
	.restore			= virtblk_restore,
#endif
};

static int __init init(void)
{
	int error;

	printk(KERN_INFO "%s: SPDM_ENABLED: %u", __FILE__, SPDM_ENABLED);

	virtblk_wq = alloc_workqueue("virtio-blk", 0, 0);
	if (!virtblk_wq)
		return -ENOMEM;

	major = register_blkdev(0, "virtblk");
	if (major < 0) {
		error = major;
		goto out_destroy_workqueue;
	}

	error = register_virtio_driver(&virtio_blk);
	if (error)
		goto out_unregister_blkdev;
	return 0;

out_unregister_blkdev:
	unregister_blkdev(major, "virtblk");
out_destroy_workqueue:
	destroy_workqueue(virtblk_wq);
	return error;
}

static void __exit fini(void)
{
	unregister_virtio_driver(&virtio_blk);
	unregister_blkdev(major, "virtblk");
	destroy_workqueue(virtblk_wq);
}

// delaying module init so it runs after system keyring has initialized
// module_init(init);
// late_initcall_sync(init); // this one for keyring
core_initcall(init); // change to this one to measure boot time
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio block driver");
MODULE_LICENSE("GPL");
