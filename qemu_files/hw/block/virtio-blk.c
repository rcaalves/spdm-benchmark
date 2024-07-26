/*
 * Virtio Block Device
 *
 * Copyright IBM, Corp. 2007
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/iov.h"
#include "qemu/module.h"
#include "qemu/error-report.h"
#include "trace.h"
#include "hw/block/block.h"
#include "sysemu/blockdev.h"
#include "hw/virtio/virtio-blk.h"
#include "dataplane/virtio-blk.h"
#include "scsi/constants.h"
#ifdef __linux__
# include <scsi/sg.h>
#endif
#include "hw/virtio/virtio-bus.h"
#include "hw/virtio/virtio-access.h"


#define ENABLE_SPDM 1

#if ENABLE_SPDM
// avoiding some annoying redefine warnings

// #pragma GCC diagnostic ignored "-Wredundant-decls"
// #pragma GCC diagnostic pop

// libspdm includes
#pragma GCC diagnostic ignored "-Wundef"
#pragma GCC diagnostic ignored "-Wredundant-decls"
#include <hal/base.h>
#include <hal/library/memlib.h>
#include <library/spdm_common_lib.h>
#include <library/spdm_responder_lib.h>
#include <library/spdm_transport_mctp_lib.h>
#include <internal/libspdm_common_lib.h>
#include <internal/libspdm_secured_message_lib.h>
#include <spdm_device_secret_lib_internal.h>
#include "mctp.h"
#pragma GCC diagnostic pop
#pragma GCC diagnostic pop


#endif // ENABLE_SPDM
#include "spdm_emu_blk.c"

#define MAX_SPDM_MESSAGE_BUFFER_SIZE 0x2200
#define BLK_SPDM_DEBUG 0
#define BLK_SPDM_DEMO_PRINT 0
#define DEMO_PRINT_LIMIT 256
#define DEMO_BYTES_PER_LINE 16

#if BLK_SPDM_DEBUG
#define BLK_SPDM_PRINT(format,  ...) printf(format, ##__VA_ARGS__)
#else
#define BLK_SPDM_PRINT(format,  ...)
#endif /*BLK_SPDM_DEBUG*/

#define SPDM_CTX_TO_VIRTIOBLOCK(spdm_context_ptr) *(VirtIOBlock**)((char*)(spdm_context_ptr) + libspdm_get_context_size())

/* Config size before the discard support (hide associated config fields) */
#define VIRTIO_BLK_CFG_SIZE offsetof(struct virtio_blk_config, \
                                     max_discard_sectors)
/*
 * Starting from the discard feature, we can use this array to properly
 * set the config size depending on the features enabled.
 */
static VirtIOFeature feature_sizes[] = {
    {.flags = 1ULL << VIRTIO_BLK_F_DISCARD,
     .end = virtio_endof(struct virtio_blk_config, discard_sector_alignment)},
    {.flags = 1ULL << VIRTIO_BLK_F_WRITE_ZEROES,
     .end = virtio_endof(struct virtio_blk_config, write_zeroes_may_unmap)},
    {}
};

static void virtio_blk_set_config_size(VirtIOBlock *s, uint64_t host_features)
{
    s->config_size = MAX(VIRTIO_BLK_CFG_SIZE,
        virtio_feature_get_config_size(feature_sizes, host_features));

    assert(s->config_size <= sizeof(struct virtio_blk_config));
}

void demo_print_buffer(char* buffer, size_t len, const char* message);

void demo_print_buffer(char* buffer, size_t len, const char* message) {
#if BLK_SPDM_DEMO_PRINT
    int j, k;
    unsigned char* c;
    uint32_t print_limit = MIN(DEMO_PRINT_LIMIT, len);
    uint32_t line_limit;
    printf("%s\n", message);
    printf("%lu bytes\n", len);
    for (j = 0; j < print_limit; j+= DEMO_BYTES_PER_LINE) {
        line_limit = MIN(DEMO_BYTES_PER_LINE, len - j);
        printf("0x%02X\t", j);
        // prints hexa
        for (k = 0; k < line_limit; k++) {
            c = &((unsigned  char*)buffer)[j+k];
            printf ("%02X ", *c);
        }
        for (k = 0; k < DEMO_BYTES_PER_LINE - line_limit; k++) {
            printf ("   ");
        }
        printf ("   ");
        // prints human readable
        for (k = 0; k < line_limit; k++) {
            c = &((unsigned  char*)buffer)[j+k];
            printf ("%c ", isprint(*c) ? *c : '-');
        }
        printf ("\n");
    }
    if (print_limit != len)
        printf("Data truncated to %d bytes\n", DEMO_PRINT_LIMIT);
    printf ("\n");
#endif /* BLK_SPDM_DEMO_PRINT */
}

#if ENABLE_SPDM

void
virtio_blk_spdm_server_callback (
   void                         *spdm_context
  );

void
virtio_blk_spdm_server_callback (
   void                         *spdm_context
  )
{
    static bool AlgoProvisioned = false;
    bool res;
    // libspdm_return_t status;
    libspdm_data_parameter_t parameter;
    uint8_t Index;
    uint8_t data8;
    uint16_t data16;
    uint32_t data32;
    uint8_t m_use_slot_count = 3;
    uint8_t m_use_slot_id = 0;
    // uint32_t m_use_measurement_hash_algo;
    uint32_t m_use_asym_algo;
    uint32_t m_use_hash_algo;
    uint16_t m_use_req_asym_algo;
    size_t data_size;
    size_t hash_size;
    void *hash;
    void *data;

    if (AlgoProvisioned) {
        return;
    }

    libspdm_zero_mem (&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;

    data_size = sizeof(data32);
    libspdm_get_data (spdm_context, LIBSPDM_DATA_CONNECTION_STATE, &parameter, &data32, &data_size);
    if (data32 != LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        // printf ("data32 != SPDM_CONNECTION_STATE_NEGOTIATED: %u\n", data32);
        return;
    }

    // AlgoProvisioned = true;
    atomic_set(&AlgoProvisioned, true);

    // data_size = sizeof(data32);
    // libspdm_get_data (spdm_context, SPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter, &data32, &data_size);
    // m_use_measurement_hash_algo = data32;
    data_size = sizeof(data32);
    libspdm_get_data (spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter, &data32, &data_size);
    m_use_asym_algo = data32;
    data_size = sizeof(data32);
    libspdm_get_data (spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter, &data32, &data_size);
    m_use_hash_algo = data32;
    data_size = sizeof(data16);
    libspdm_get_data (spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter, &data16, &data_size);
    m_use_req_asym_algo = data16;

    res = libspdm_read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, NULL, NULL);
    if (res) {
        libspdm_zero_mem (&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        data8 = m_use_slot_count;
        libspdm_set_data (spdm_context, LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN, &parameter, &data8, sizeof(data8));

        for (Index = 0; Index < m_use_slot_count; Index++) {
            parameter.additional_data[0] = Index;
            libspdm_set_data (spdm_context, LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN, &parameter, data, data_size);
        }
        // do not free it
    }

    if (m_use_slot_id == 0xFF) {
        res = libspdm_read_requester_public_certificate_chain (m_use_hash_algo, m_use_req_asym_algo, &data, &data_size, NULL, NULL);
        if (res) {
            libspdm_zero_mem (&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
            libspdm_set_data (spdm_context, LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN, &parameter, data, data_size);
            // Do not free it.
        }
    } else {
        res = libspdm_read_requester_root_public_certificate (m_use_hash_algo, m_use_req_asym_algo, &data, &data_size, &hash, &hash_size);
        if (res) {
            libspdm_zero_mem (&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
            libspdm_set_data (spdm_context, LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT, &parameter, hash, hash_size);
            // Do not free it.
        }
    }

    if (res) {
        data8 = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST;
        if (data8 != 0) {
            data8 |= SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
        }
        parameter.additional_data[0] = m_use_slot_id; // ReqSlotNum;
        parameter.additional_data[1] = SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH; // MeasurementHashType;
        libspdm_set_data (spdm_context, LIBSPDM_DATA_MUT_AUTH_REQUESTED, &parameter, &data8, sizeof(data8));

        data8 = (SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST & 0x1);
        libspdm_set_data (spdm_context, LIBSPDM_DATA_BASIC_MUT_AUTH_REQUESTED, &parameter, &data8, sizeof(data8));
    }

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    data8 = 0x3F;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_SUPPORTED_SLOT_MASK, &parameter,
                        &data8, sizeof(data8));
  return;
}
#endif // ENABLE_SPDM

static void virtio_blk_init_request(VirtIOBlock *s, VirtQueue *vq,
                                    VirtIOBlockReq *req)
{
    req->dev = s;
    req->vq = vq;
    req->qiov.size = 0;
    req->in_len = 0;
    req->next = NULL;
    req->mr_next = NULL;
}

static void virtio_blk_free_request(VirtIOBlockReq *req)
{
    g_free(req);
}

static void virtio_blk_req_complete(VirtIOBlockReq *req, unsigned char status)
{
    VirtIOBlock *s = req->dev;
    VirtIODevice *vdev = VIRTIO_DEVICE(s);

    trace_virtio_blk_req_complete(vdev, req, status);

    stb_p(&req->in->status, status);
    virtqueue_push(req->vq, &req->elem, req->in_len);
    if (s->dataplane_started && !s->dataplane_disabled) {
        virtio_blk_data_plane_notify(s->dataplane, req->vq);
    } else {
        virtio_notify(vdev, req->vq);
    }
}

static int virtio_blk_handle_rw_error(VirtIOBlockReq *req, int error,
    bool is_read, bool acct_failed)
{
    VirtIOBlock *s = req->dev;
    BlockErrorAction action = blk_get_error_action(s->blk, is_read, error);

    if (action == BLOCK_ERROR_ACTION_STOP) {
        /* Break the link as the next request is going to be parsed from the
         * ring again. Otherwise we may end up doing a double completion! */
        req->mr_next = NULL;
        req->next = s->rq;
        s->rq = req;
    } else if (action == BLOCK_ERROR_ACTION_REPORT) {
        virtio_blk_req_complete(req, VIRTIO_BLK_S_IOERR);
        if (acct_failed) {
            block_acct_failed(blk_get_stats(s->blk), &req->acct);
        }
        virtio_blk_free_request(req);
    }

    blk_error_action(s->blk, action, is_read, error);
    return action != BLOCK_ERROR_ACTION_IGNORE;
}

static void virtio_blk_rw_complete(void *opaque, int ret)
{
    VirtIOBlockReq *next = opaque;
    VirtIOBlock *s = next->dev;
    VirtIODevice *vdev = VIRTIO_DEVICE(s);

    aio_context_acquire(blk_get_aio_context(s->conf.conf.blk));
    while (next) {
        VirtIOBlockReq *req = next;
        next = req->mr_next;
        trace_virtio_blk_rw_complete(vdev, req, ret);
#if ENABLE_SPDM
        int reqtype = virtio_ldl_p(VIRTIO_DEVICE(s), &req->out.type);
        BLK_SPDM_PRINT("HPSPDM complete req type %d, niov %d, iov[0].iov_len %lu\n", reqtype, req->qiov.niov, req->qiov.iov[0].iov_len);
        if (reqtype == VIRTIO_BLK_T_SPDM_APP /*!(reqtype & VIRTIO_BLK_T_OUT)*/) {
            struct iovec *in_iov = req->qiov.iov; //req->elem.in_sg;
            unsigned in_num = req->qiov.niov; //req->elem.in_num;

            uint8_t cipher_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
            void *cipher_data_ptr = cipher_data;
            size_t cipher_size = MAX_SPDM_MESSAGE_BUFFER_SIZE;

            uint8_t *my_response;
            size_t my_response_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            libspdm_return_t status;

#if BLK_SPDM_DEBUG
            for (int j = 0; j < MIN(64, req->qiov.iov[0].iov_len); j++) {
                unsigned char* c = &((unsigned char*)req->qiov.iov[0].iov_base)[j];
                if ((j%16) == 0) printf ("\n(%04X) ", j);
                printf ("%02X ", *c);
            }
            printf ("\n");
#endif

            // for (int i = 0; i < in_num; i ++) {
                // demo_print_buffer(in_iov[i].iov_base, in_iov[i].iov_len, "Hard drive is about to send the following data (clear text):");
            // }

            for (int i = 0; i < in_num; i ++) {
                // at least extra 512 bytes has been allocated on kernel side
                cipher_size = in_iov[i].iov_len + 512;
                BLK_SPDM_PRINT("trying to encode in_iov[%d] len: %lu\n", i, in_iov[i].iov_len);
                if (((libspdm_context_t *)s->spdm_context)->last_spdm_request_session_id_valid) {
                  size_t transport_header_size = ((libspdm_context_t *)s->spdm_context)->local_context.capability.transport_header_size;

                  libspdm_get_scratch_buffer (s->spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
                  my_response = scratch_buffer + libspdm_get_scratch_buffer_secure_message_offset(s->spdm_context) +
                        transport_header_size;
                  my_response_size = libspdm_get_scratch_buffer_secure_message_capacity(s->spdm_context) -
                        transport_header_size - ((libspdm_context_t *)s->spdm_context)->local_context.capability.transport_tail_size;
#else
                  my_response = scratch_buffer + transport_header_size;
                  my_response_size = scratch_buffer_size - transport_header_size -
                        ((libspdm_context_t *)s->spdm_context)->local_context.capability.transport_tail_size;
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */

                  if (my_response_size < in_iov[i].iov_len + sizeof(mctp_message_header_t)) {
                    printf("Scratch buffer too small!\n");
                  } else {
                    my_response_size = in_iov[i].iov_len + sizeof(mctp_message_header_t);
                  }
                  ((mctp_message_header_t*)my_response)->message_type = MCTP_MESSAGE_TYPE_VENDOR_DEFINED_PCI;
                  memcpy(my_response + sizeof(mctp_message_header_t), ((uint8_t *)in_iov[i].iov_base), in_iov[i].iov_len);

                  // making room for the mctp header
                  // memmove( ((uint8_t *)in_iov[i].iov_base) + sizeof(mctp_message_header_t), in_iov[i].iov_base, in_iov[i].iov_len );
                  // ((mctp_message_header_t*)in_iov[i].iov_base)->message_type = MCTP_MESSAGE_TYPE_VENDOR_DEFINED_PCI;

                  // ToDo: not sure if we are running atomicaly in this function or not...
                  // qemu_mutex_lock(&spdm_encdec_mutex);

                  status = ((libspdm_context_t *)s->spdm_context)->transport_encode_message(s->spdm_context, &(((libspdm_context_t *)s->spdm_context)->last_spdm_request_session_id), true, false,
                                                                                         // in_iov[i].iov_len + sizeof(mctp_message_header_t), in_iov[i].iov_base,
                                                                                         my_response_size, my_response,
                                                                                         &cipher_size, &cipher_data_ptr);
                  // qemu_mutex_unlock(&spdm_encdec_mutex);
                  if (LIBSPDM_STATUS_IS_ERROR(status)) {
                      printf("%s: transport_encode_message status - %x\n", __func__, status);
                      return;
                  }
                  BLK_SPDM_PRINT("\tsize after encoding %lu\n", cipher_size);
                  memcpy(((uint8_t*) in_iov[i].iov_base) + sizeof(uint32_t), cipher_data_ptr, cipher_size);

                  // changing iov_len does not reflect on the kernel side and may cause problems on qemu
                  // in_iov[i].iov_len = cipher_size + sizeof(uint32_t);
                  // so the message size is encoded in the first 4 bytes
                  * ((uint32_t*) ((uint8_t*) in_iov[i].iov_base)) = cipher_size;
                  // demo_print_buffer(in_iov[i].iov_base, in_iov[i].iov_len, "Hard drive is about to send the following data (encrypted):");

                  /* test code without spdm encryption */
                  // uint32_t temp_iov_len = in_iov[i].iov_len /*- 512*/;
                  // memmove( ((uint8_t *)in_iov[i].iov_base) + sizeof(mctp_message_header_t) + sizeof(uint32_t), in_iov[i].iov_base, temp_iov_len /*in_iov[i].iov_len*/ );
                  // * ((uint32_t*) ((uint8_t*) in_iov[i].iov_base)) = temp_iov_len; // in_iov[i].iov_len + sizeof(mctp_message_header_t);
                  /* end test code without spdm encryption */
                } else {
                    static bool first = true;
                    if (first) {
                        first = false;
                    } else {
                        printf("Invalid last_spdm_request_session_id_valid\n");
                    }
                }
            }
        }
#endif //ENABLE_SPDM
        if (req->qiov.nalloc != -1) {
            /* If nalloc is != -1 req->qiov is a local copy of the original
             * external iovec. It was allocated in submit_requests to be
             * able to merge requests. */
            qemu_iovec_destroy(&req->qiov);
        }

        if (ret) {
            int p = virtio_ldl_p(VIRTIO_DEVICE(s), &req->out.type);
            bool is_read = !(p & VIRTIO_BLK_T_OUT);
            /* Note that memory may be dirtied on read failure.  If the
             * virtio request is not completed here, as is the case for
             * BLOCK_ERROR_ACTION_STOP, the memory may not be copied
             * correctly during live migration.  While this is ugly,
             * it is acceptable because the device is free to write to
             * the memory until the request is completed (which will
             * happen on the other side of the migration).
             */
            if (virtio_blk_handle_rw_error(req, -ret, is_read, true)) {
                continue;
            }
        }

        virtio_blk_req_complete(req, VIRTIO_BLK_S_OK);
        block_acct_done(blk_get_stats(s->blk), &req->acct);
        virtio_blk_free_request(req);
    }
    aio_context_release(blk_get_aio_context(s->conf.conf.blk));
}

static void virtio_blk_flush_complete(void *opaque, int ret)
{
    VirtIOBlockReq *req = opaque;
    VirtIOBlock *s = req->dev;

    aio_context_acquire(blk_get_aio_context(s->conf.conf.blk));
    if (ret) {
        if (virtio_blk_handle_rw_error(req, -ret, 0, true)) {
            goto out;
        }
    }

    virtio_blk_req_complete(req, VIRTIO_BLK_S_OK);
    block_acct_done(blk_get_stats(s->blk), &req->acct);
    virtio_blk_free_request(req);

out:
    aio_context_release(blk_get_aio_context(s->conf.conf.blk));
}

static void virtio_blk_discard_write_zeroes_complete(void *opaque, int ret)
{
    VirtIOBlockReq *req = opaque;
    VirtIOBlock *s = req->dev;
    bool is_write_zeroes = (virtio_ldl_p(VIRTIO_DEVICE(s), &req->out.type) &
                            ~VIRTIO_BLK_T_BARRIER) == VIRTIO_BLK_T_WRITE_ZEROES;

    aio_context_acquire(blk_get_aio_context(s->conf.conf.blk));
    if (ret) {
        if (virtio_blk_handle_rw_error(req, -ret, false, is_write_zeroes)) {
            goto out;
        }
    }

    virtio_blk_req_complete(req, VIRTIO_BLK_S_OK);
    if (is_write_zeroes) {
        block_acct_done(blk_get_stats(s->blk), &req->acct);
    }
    virtio_blk_free_request(req);

out:
    aio_context_release(blk_get_aio_context(s->conf.conf.blk));
}

#ifdef __linux__

typedef struct {
    VirtIOBlockReq *req;
    struct sg_io_hdr hdr;
} VirtIOBlockIoctlReq;

static void virtio_blk_ioctl_complete(void *opaque, int status)
{
    VirtIOBlockIoctlReq *ioctl_req = opaque;
    VirtIOBlockReq *req = ioctl_req->req;
    VirtIOBlock *s = req->dev;
    VirtIODevice *vdev = VIRTIO_DEVICE(s);
    struct virtio_scsi_inhdr *scsi;
    struct sg_io_hdr *hdr;

    scsi = (void *)req->elem.in_sg[req->elem.in_num - 2].iov_base;

    if (status) {
        status = VIRTIO_BLK_S_UNSUPP;
        virtio_stl_p(vdev, &scsi->errors, 255);
        goto out;
    }

    hdr = &ioctl_req->hdr;
    /*
     * From SCSI-Generic-HOWTO: "Some lower level drivers (e.g. ide-scsi)
     * clear the masked_status field [hence status gets cleared too, see
     * block/scsi_ioctl.c] even when a CHECK_CONDITION or COMMAND_TERMINATED
     * status has occurred.  However they do set DRIVER_SENSE in driver_status
     * field. Also a (sb_len_wr > 0) indicates there is a sense buffer.
     */
    if (hdr->status == 0 && hdr->sb_len_wr > 0) {
        hdr->status = CHECK_CONDITION;
    }

    virtio_stl_p(vdev, &scsi->errors,
                 hdr->status | (hdr->msg_status << 8) |
                 (hdr->host_status << 16) | (hdr->driver_status << 24));
    virtio_stl_p(vdev, &scsi->residual, hdr->resid);
    virtio_stl_p(vdev, &scsi->sense_len, hdr->sb_len_wr);
    virtio_stl_p(vdev, &scsi->data_len, hdr->dxfer_len);

out:
    aio_context_acquire(blk_get_aio_context(s->conf.conf.blk));
    virtio_blk_req_complete(req, status);
    virtio_blk_free_request(req);
    aio_context_release(blk_get_aio_context(s->conf.conf.blk));
    g_free(ioctl_req);
}

#endif

static VirtIOBlockReq *virtio_blk_get_request(VirtIOBlock *s, VirtQueue *vq)
{
    VirtIOBlockReq *req = virtqueue_pop(vq, sizeof(VirtIOBlockReq));

    if (req) {
        virtio_blk_init_request(s, vq, req);
    }
    return req;
}

static int virtio_blk_handle_scsi_req(VirtIOBlockReq *req)
{
    int status = VIRTIO_BLK_S_OK;
    struct virtio_scsi_inhdr *scsi = NULL;
    VirtIOBlock *blk = req->dev;
    VirtIODevice *vdev = VIRTIO_DEVICE(blk);
    VirtQueueElement *elem = &req->elem;

#ifdef __linux__
    int i;
    VirtIOBlockIoctlReq *ioctl_req;
    BlockAIOCB *acb;
#endif

    /*
     * We require at least one output segment each for the virtio_blk_outhdr
     * and the SCSI command block.
     *
     * We also at least require the virtio_blk_inhdr, the virtio_scsi_inhdr
     * and the sense buffer pointer in the input segments.
     */
    if (elem->out_num < 2 || elem->in_num < 3) {
        status = VIRTIO_BLK_S_IOERR;
        goto fail;
    }

    /*
     * The scsi inhdr is placed in the second-to-last input segment, just
     * before the regular inhdr.
     */
    scsi = (void *)elem->in_sg[elem->in_num - 2].iov_base;

    if (!virtio_has_feature(blk->host_features, VIRTIO_BLK_F_SCSI)) {
        status = VIRTIO_BLK_S_UNSUPP;
        goto fail;
    }

    /*
     * No support for bidirection commands yet.
     */
    if (elem->out_num > 2 && elem->in_num > 3) {
        status = VIRTIO_BLK_S_UNSUPP;
        goto fail;
    }

#ifdef __linux__
    ioctl_req = g_new0(VirtIOBlockIoctlReq, 1);
    ioctl_req->req = req;
    ioctl_req->hdr.interface_id = 'S';
    ioctl_req->hdr.cmd_len = elem->out_sg[1].iov_len;
    ioctl_req->hdr.cmdp = elem->out_sg[1].iov_base;
    ioctl_req->hdr.dxfer_len = 0;

    if (elem->out_num > 2) {
        /*
         * If there are more than the minimally required 2 output segments
         * there is write payload starting from the third iovec.
         */
        ioctl_req->hdr.dxfer_direction = SG_DXFER_TO_DEV;
        ioctl_req->hdr.iovec_count = elem->out_num - 2;

        for (i = 0; i < ioctl_req->hdr.iovec_count; i++) {
            ioctl_req->hdr.dxfer_len += elem->out_sg[i + 2].iov_len;
        }

        ioctl_req->hdr.dxferp = elem->out_sg + 2;

    } else if (elem->in_num > 3) {
        /*
         * If we have more than 3 input segments the guest wants to actually
         * read data.
         */
        ioctl_req->hdr.dxfer_direction = SG_DXFER_FROM_DEV;
        ioctl_req->hdr.iovec_count = elem->in_num - 3;
        for (i = 0; i < ioctl_req->hdr.iovec_count; i++) {
            ioctl_req->hdr.dxfer_len += elem->in_sg[i].iov_len;
        }

        ioctl_req->hdr.dxferp = elem->in_sg;
    } else {
        /*
         * Some SCSI commands don't actually transfer any data.
         */
        ioctl_req->hdr.dxfer_direction = SG_DXFER_NONE;
    }

    ioctl_req->hdr.sbp = elem->in_sg[elem->in_num - 3].iov_base;
    ioctl_req->hdr.mx_sb_len = elem->in_sg[elem->in_num - 3].iov_len;

    acb = blk_aio_ioctl(blk->blk, SG_IO, &ioctl_req->hdr,
                        virtio_blk_ioctl_complete, ioctl_req);
    if (!acb) {
        g_free(ioctl_req);
        status = VIRTIO_BLK_S_UNSUPP;
        goto fail;
    }
    return -EINPROGRESS;
#else
    abort();
#endif

fail:
    /* Just put anything nonzero so that the ioctl fails in the guest.  */
    if (scsi) {
        virtio_stl_p(vdev, &scsi->errors, 255);
    }
    return status;
}

static void virtio_blk_handle_scsi(VirtIOBlockReq *req)
{
    int status;

    status = virtio_blk_handle_scsi_req(req);
    if (status != -EINPROGRESS) {
        virtio_blk_req_complete(req, status);
        virtio_blk_free_request(req);
    }
}

static inline void submit_requests(BlockBackend *blk, MultiReqBuffer *mrb,
                                   int start, int num_reqs, int niov)
{
    QEMUIOVector *qiov = &mrb->reqs[start]->qiov;
    int64_t sector_num = mrb->reqs[start]->sector_num;
    bool is_write = mrb->is_write;

    BLK_SPDM_PRINT("HPSPDM submit_requests to %s num_reqs(%d), is_write %u\n", blk_name(blk), num_reqs, is_write);

    if (num_reqs > 1) {
        int i;
        struct iovec *tmp_iov = qiov->iov;
        int tmp_niov = qiov->niov;

        /* mrb->reqs[start]->qiov was initialized from external so we can't
         * modify it here. We need to initialize it locally and then add the
         * external iovecs. */
        qemu_iovec_init(qiov, niov);

        for (i = 0; i < tmp_niov; i++) {
            qemu_iovec_add(qiov, tmp_iov[i].iov_base, tmp_iov[i].iov_len);
        }

        for (i = start + 1; i < start + num_reqs; i++) {
            qemu_iovec_concat(qiov, &mrb->reqs[i]->qiov, 0,
                              mrb->reqs[i]->qiov.size);
            mrb->reqs[i - 1]->mr_next = mrb->reqs[i];
        }

        trace_virtio_blk_submit_multireq(VIRTIO_DEVICE(mrb->reqs[start]->dev),
                                         mrb, start, num_reqs,
                                         sector_num << BDRV_SECTOR_BITS,
                                         qiov->size, is_write);
        block_acct_merge_done(blk_get_stats(blk),
                              is_write ? BLOCK_ACCT_WRITE : BLOCK_ACCT_READ,
                              num_reqs - 1);
    }
    else {
#if BLK_SPDM_DEBUG
        printf("qiov->iov->iov_len: %lu, niov %d\n", qiov->iov->iov_len, qiov->niov);
        if (is_write) {
            for (int j = 0; j < qiov->iov->iov_len; j++) {
                unsigned char* c = &((unsigned  char*)qiov->iov->iov_base)[j];
                if (j < 64)
                    printf ("%02X ", *c);
            }
            printf ("\n");
        }
#endif

        // if (is_write) {
            // demo_print_buffer(qiov->iov->iov_base, qiov->iov->iov_len, "Hard drive received the following data (clear text):");
        // }
    }

    if (is_write) {
        blk_aio_pwritev(blk, sector_num << BDRV_SECTOR_BITS, qiov, 0,
                        virtio_blk_rw_complete, mrb->reqs[start]);
    } else {
        blk_aio_preadv(blk, sector_num << BDRV_SECTOR_BITS, qiov, 0,
                       virtio_blk_rw_complete, mrb->reqs[start]);
    }
}

static int multireq_compare(const void *a, const void *b)
{
    const VirtIOBlockReq *req1 = *(VirtIOBlockReq **)a,
                         *req2 = *(VirtIOBlockReq **)b;

    /*
     * Note that we can't simply subtract sector_num1 from sector_num2
     * here as that could overflow the return value.
     */
    if (req1->sector_num > req2->sector_num) {
        return 1;
    } else if (req1->sector_num < req2->sector_num) {
        return -1;
    } else {
        return 0;
    }
}

static void virtio_blk_submit_multireq(BlockBackend *blk, MultiReqBuffer *mrb)
{
    int i = 0, start = 0, num_reqs = 0, niov = 0, nb_sectors = 0;
    uint32_t max_transfer;
    int64_t sector_num = 0;

    if (mrb->num_reqs == 1) {
        submit_requests(blk, mrb, 0, 1, -1);
        mrb->num_reqs = 0;
        return;
    }

    max_transfer = blk_get_max_transfer(mrb->reqs[0]->dev->blk);

    qsort(mrb->reqs, mrb->num_reqs, sizeof(*mrb->reqs),
          &multireq_compare);

    for (i = 0; i < mrb->num_reqs; i++) {
        VirtIOBlockReq *req = mrb->reqs[i];
        if (num_reqs > 0) {
            /*
             * NOTE: We cannot merge the requests in below situations:
             * 1. requests are not sequential
             * 2. merge would exceed maximum number of IOVs
             * 3. merge would exceed maximum transfer length of backend device
             */
            if (sector_num + nb_sectors != req->sector_num ||
                niov > blk_get_max_iov(blk) - req->qiov.niov ||
                req->qiov.size > max_transfer ||
                nb_sectors > (max_transfer -
                              req->qiov.size) / BDRV_SECTOR_SIZE) {
                submit_requests(blk, mrb, start, num_reqs, niov);
                num_reqs = 0;
            }
        }

        if (num_reqs == 0) {
            sector_num = req->sector_num;
            nb_sectors = niov = 0;
            start = i;
        }

        nb_sectors += req->qiov.size / BDRV_SECTOR_SIZE;
        niov += req->qiov.niov;
        num_reqs++;
    }

    submit_requests(blk, mrb, start, num_reqs, niov);
    mrb->num_reqs = 0;
}

static void virtio_blk_handle_flush(VirtIOBlockReq *req, MultiReqBuffer *mrb)
{
    VirtIOBlock *s = req->dev;

    block_acct_start(blk_get_stats(s->blk), &req->acct, 0,
                     BLOCK_ACCT_FLUSH);

    /*
     * Make sure all outstanding writes are posted to the backing device.
     */
    if (mrb->is_write && mrb->num_reqs > 0) {
        virtio_blk_submit_multireq(s->blk, mrb);
    }
    blk_aio_flush(s->blk, virtio_blk_flush_complete, req);
}

static bool virtio_blk_sect_range_ok(VirtIOBlock *dev,
                                     uint64_t sector, size_t size)
{
    uint64_t nb_sectors = size >> BDRV_SECTOR_BITS;
    uint64_t total_sectors;

    if (nb_sectors > BDRV_REQUEST_MAX_SECTORS) {
        return false;
    }
    if (sector & dev->sector_mask) {
        return false;
    }
    if (size % dev->conf.conf.logical_block_size) {
        return false;
    }
    blk_get_geometry(dev->blk, &total_sectors);
    if (sector > total_sectors || nb_sectors > total_sectors - sector) {
        return false;
    }
    return true;
}

static uint8_t virtio_blk_handle_discard_write_zeroes(VirtIOBlockReq *req,
    struct virtio_blk_discard_write_zeroes *dwz_hdr, bool is_write_zeroes)
{
    VirtIOBlock *s = req->dev;
    VirtIODevice *vdev = VIRTIO_DEVICE(s);
    uint64_t sector;
    uint32_t num_sectors, flags, max_sectors;
    uint8_t err_status;
    int bytes;

    sector = virtio_ldq_p(vdev, &dwz_hdr->sector);
    num_sectors = virtio_ldl_p(vdev, &dwz_hdr->num_sectors);
    flags = virtio_ldl_p(vdev, &dwz_hdr->flags);
    max_sectors = is_write_zeroes ? s->conf.max_write_zeroes_sectors :
                  s->conf.max_discard_sectors;

    /*
     * max_sectors is at most BDRV_REQUEST_MAX_SECTORS, this check
     * make us sure that "num_sectors << BDRV_SECTOR_BITS" can fit in
     * the integer variable.
     */
    if (unlikely(num_sectors > max_sectors)) {
        err_status = VIRTIO_BLK_S_IOERR;
        goto err;
    }

    bytes = num_sectors << BDRV_SECTOR_BITS;

    if (unlikely(!virtio_blk_sect_range_ok(s, sector, bytes))) {
        err_status = VIRTIO_BLK_S_IOERR;
        goto err;
    }

    /*
     * The device MUST set the status byte to VIRTIO_BLK_S_UNSUPP for discard
     * and write zeroes commands if any unknown flag is set.
     */
    if (unlikely(flags & ~VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP)) {
        err_status = VIRTIO_BLK_S_UNSUPP;
        goto err;
    }

    if (is_write_zeroes) { /* VIRTIO_BLK_T_WRITE_ZEROES */
        int blk_aio_flags = 0;

        if (flags & VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP) {
            blk_aio_flags |= BDRV_REQ_MAY_UNMAP;
        }

        block_acct_start(blk_get_stats(s->blk), &req->acct, bytes,
                         BLOCK_ACCT_WRITE);

        blk_aio_pwrite_zeroes(s->blk, sector << BDRV_SECTOR_BITS,
                              bytes, blk_aio_flags,
                              virtio_blk_discard_write_zeroes_complete, req);
    } else { /* VIRTIO_BLK_T_DISCARD */
        /*
         * The device MUST set the status byte to VIRTIO_BLK_S_UNSUPP for
         * discard commands if the unmap flag is set.
         */
        if (unlikely(flags & VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP)) {
            err_status = VIRTIO_BLK_S_UNSUPP;
            goto err;
        }

        blk_aio_pdiscard(s->blk, sector << BDRV_SECTOR_BITS, bytes,
                         virtio_blk_discard_write_zeroes_complete, req);
    }

    return VIRTIO_BLK_S_OK;

err:
    if (is_write_zeroes) {
        block_acct_invalid(blk_get_stats(s->blk), BLOCK_ACCT_WRITE);
    }
    return err_status;
}

#if ENABLE_SPDM
void spdm_fix_internal_seqno(libspdm_context_t *spdm_context, uint8_t *msg_buffer);

void spdm_fix_internal_seqno(libspdm_context_t *spdm_context, uint8_t *msg_buffer) {
    // hax to fix out of order sequence numbers, considering 16-bit overflows
    // considering the "danger zone" += 1/4 of the whole range
    const uint64_t WRAP_DANGER_OUT = 0x4000;
    const uint64_t WRAP_DANGER_IN  = 0xC000;

    VirtIOBlock *s = SPDM_CTX_TO_VIRTIOBLOCK(spdm_context);
    libspdm_session_info_t *session_info = NULL;
    libspdm_secured_message_context_t *secured_message_context = NULL;
    if (spdm_context->transport_decode_message != libspdm_transport_mctp_decode_message) {
      printf("%s: Not supported!\n", __func__);
      return;
    }
    // get seqno within the packet
    uint64_t seqno = 0;
    uint8_t seqno_size = libspdm_mctp_get_sequence_number(0, (uint8_t*)&seqno);

    // ToDo: maybe we should worry about endianess...
    memcpy(&seqno, msg_buffer + sizeof(mctp_message_header_t) + sizeof(spdm_secured_message_a_data_header1_t), seqno_size);

    if ((seqno & 0xFFFF) == WRAP_DANGER_OUT) {
        s->wrapped = 0;
        s->in_danger = 0;
        BLK_SPDM_PRINT("out of danger! %lX \n", seqno);
    }

    if ((seqno & 0xFFFF) >= WRAP_DANGER_IN) {
        s->in_danger = 1;
        // printf("in the danger zone! %llX \n", seqno);
    }

    if ((seqno & 0xFFFF) == 0xFFFF) {
        s->remaining_bits += 0x10000;
        s->wrapped = 1;
        BLK_SPDM_PRINT("wrapped! %lX \n", seqno);
    }

    // printf("%06llX", seqno);

    seqno += s->remaining_bits;

    if (s->in_danger && !s->wrapped && ((seqno & 0xFFFF) < WRAP_DANGER_OUT)) {
        seqno += 0x10000;
    }
    if (s->in_danger && s->wrapped && ((seqno & 0xFFFF) >= WRAP_DANGER_IN)) {
        seqno -= 0x10000;
    }

    // printf(" => %06llX \n", seqno);

    // set seqno in all active sessions
    for (int i = 0; i <= LIBSPDM_MAX_SESSION_COUNT; i++) {
        if (spdm_context->session_info[i].session_id != INVALID_SESSION_ID) {
            session_info = libspdm_get_session_info_via_session_id(spdm_context, spdm_context->session_info[i].session_id);
            if (session_info) {
                secured_message_context = session_info->secured_message_context;
                secured_message_context->application_secret.request_data_sequence_number = seqno;
                // memcpy(&secured_message_context->application_secret.request_data_sequence_number, seqno, seqno_size);
                // or response_data_sequence_number, depending on the source.
            } else {
                // printf("session info %d is null\n", i);
            }
        }
    }
}
#endif // ENABLE_SPDM

static int virtio_blk_handle_request(VirtIOBlockReq *req, MultiReqBuffer *mrb)
{
    uint32_t type;
    struct iovec *in_iov = req->elem.in_sg;
    struct iovec *out_iov = req->elem.out_sg;
    unsigned in_num = req->elem.in_num;
    unsigned out_num = req->elem.out_num;
    VirtIOBlock *s = req->dev;
    VirtIODevice *vdev = VIRTIO_DEVICE(s);

    if (req->elem.out_num < 1 || req->elem.in_num < 1) {
        virtio_error(vdev, "virtio-blk missing headers");
        return -1;
    }

    if (unlikely(iov_to_buf(out_iov, out_num, 0, &req->out,
                            sizeof(req->out)) != sizeof(req->out))) {
        virtio_error(vdev, "virtio-blk request outhdr too short");
        return -1;
    }

    iov_discard_front(&out_iov, &out_num, sizeof(req->out));

    if (in_iov[in_num - 1].iov_len < sizeof(struct virtio_blk_inhdr)) {
        virtio_error(vdev, "virtio-blk request inhdr too short");
        return -1;
    }

    /* We always touch the last byte, so just see how big in_iov is.  */
    req->in_len = iov_size(in_iov, in_num);
    req->in = (void *)in_iov[in_num - 1].iov_base
              + in_iov[in_num - 1].iov_len
              - sizeof(struct virtio_blk_inhdr);
    iov_discard_back(in_iov, &in_num, sizeof(struct virtio_blk_inhdr));

    type = virtio_ldl_p(vdev, &req->out.type);

    BLK_SPDM_PRINT("virtio_blk_handle_request type: %u sector: %lu\n", type, req->sector_num);


    if (type == (VIRTIO_BLK_T_SPDM_APP | VIRTIO_BLK_T_OUT) || type == (VIRTIO_BLK_T_IN | VIRTIO_BLK_T_OUT)) {
        for (int i = 0; i < out_num && (&out_iov[i])->iov_len != 0; i ++) {
            demo_print_buffer((&out_iov[i])->iov_base, (&out_iov[i])->iov_len, "Hard drive received the following data:");
        }
    }

    /* VIRTIO_BLK_T_OUT defines the command direction. VIRTIO_BLK_T_BARRIER
     * is an optional flag. Although a guest should not send this flag if
     * not negotiated we ignored it in the past. So keep ignoring it. */
    switch (type & ~(VIRTIO_BLK_T_OUT | VIRTIO_BLK_T_BARRIER)) {
    case VIRTIO_BLK_T_IN:
    {
HANDLE_RW_L:
        BLK_SPDM_PRINT("label, req->sector_num %lu\n",req->sector_num);
        bool is_write = type & VIRTIO_BLK_T_OUT;
        req->sector_num = virtio_ldq_p(vdev, &req->out.sector);

        if (is_write) {
            qemu_iovec_init_external(&req->qiov, out_iov, out_num);
            trace_virtio_blk_handle_write(vdev, req, req->sector_num,
                                          req->qiov.size / BDRV_SECTOR_SIZE);
        } else {
            qemu_iovec_init_external(&req->qiov, in_iov, in_num);
            trace_virtio_blk_handle_read(vdev, req, req->sector_num,
                                         req->qiov.size / BDRV_SECTOR_SIZE);
        }

        if (!virtio_blk_sect_range_ok(s, req->sector_num, req->qiov.size)) {
            virtio_blk_req_complete(req, VIRTIO_BLK_S_IOERR);
            block_acct_invalid(blk_get_stats(s->blk),
                               is_write ? BLOCK_ACCT_WRITE : BLOCK_ACCT_READ);
            virtio_blk_free_request(req);
            return 0;
        }

        block_acct_start(blk_get_stats(s->blk), &req->acct, req->qiov.size,
                         is_write ? BLOCK_ACCT_WRITE : BLOCK_ACCT_READ);

        /* merge would exceed maximum number of requests or IO direction
         * changes */
        if (mrb->num_reqs > 0 && (mrb->num_reqs == VIRTIO_BLK_MAX_MERGE_REQS ||
                                  is_write != mrb->is_write ||
                                  !s->conf.request_merging)) {
            virtio_blk_submit_multireq(s->blk, mrb);
        }

        assert(mrb->num_reqs < VIRTIO_BLK_MAX_MERGE_REQS);
        mrb->reqs[mrb->num_reqs++] = req;
        mrb->is_write = is_write;
        break;
    }
    case VIRTIO_BLK_T_FLUSH:
        virtio_blk_handle_flush(req, mrb);
        break;
    case VIRTIO_BLK_T_SCSI_CMD:
        virtio_blk_handle_scsi(req);
        break;
    case VIRTIO_BLK_T_GET_ID:
    {
        /*
         * NB: per existing s/n string convention the string is
         * terminated by '\0' only when shorter than buffer.
         */
        const char *serial = s->conf.serial ? s->conf.serial : "";
        size_t size = MIN(strlen(serial) + 1,
                          MIN(iov_size(in_iov, in_num),
                              VIRTIO_BLK_ID_BYTES));
        iov_from_buf(in_iov, in_num, 0, serial, size);
        virtio_blk_req_complete(req, VIRTIO_BLK_S_OK);
        virtio_blk_free_request(req);
        break;
    }
    /*
     * VIRTIO_BLK_T_DISCARD and VIRTIO_BLK_T_WRITE_ZEROES are defined with
     * VIRTIO_BLK_T_OUT flag set. We masked this flag in the switch statement,
     * so we must mask it for these requests, then we will check if it is set.
     */
    case VIRTIO_BLK_T_DISCARD & ~VIRTIO_BLK_T_OUT:
    case VIRTIO_BLK_T_WRITE_ZEROES & ~VIRTIO_BLK_T_OUT:
    {
        struct virtio_blk_discard_write_zeroes dwz_hdr;
        size_t out_len = iov_size(out_iov, out_num);
        bool is_write_zeroes = (type & ~VIRTIO_BLK_T_BARRIER) ==
                               VIRTIO_BLK_T_WRITE_ZEROES;
        uint8_t err_status;

        /*
         * Unsupported if VIRTIO_BLK_T_OUT is not set or the request contains
         * more than one segment.
         */
        if (unlikely(!(type & VIRTIO_BLK_T_OUT) ||
                     out_len > sizeof(dwz_hdr))) {
            virtio_blk_req_complete(req, VIRTIO_BLK_S_UNSUPP);
            virtio_blk_free_request(req);
            return 0;
        }

        if (unlikely(iov_to_buf(out_iov, out_num, 0, &dwz_hdr,
                                sizeof(dwz_hdr)) != sizeof(dwz_hdr))) {
            virtio_error(vdev, "virtio-blk discard/write_zeroes header"
                         " too short");
            return -1;
        }

        err_status = virtio_blk_handle_discard_write_zeroes(req, &dwz_hdr,
                                                            is_write_zeroes);
        if (err_status != VIRTIO_BLK_S_OK) {
            virtio_blk_req_complete(req, err_status);
            virtio_blk_free_request(req);
        }

        break;
    }
#if ENABLE_SPDM
    case VIRTIO_BLK_T_SPDM:
    {
        bool is_write = type & VIRTIO_BLK_T_OUT;

        if (is_write) {
            BLK_SPDM_PRINT("VIRTIO_BLK_T_SPDM (write) %lu %p %p %d \n",out_iov->iov_len, req, out_iov, out_num);
            qemu_mutex_lock(&s->spdm_io_mutex);

            s->spdm_buf_size = 0;
            for (int i = 0; i < out_num; i ++) {
              memcpy(s->spdm_buf + s->spdm_buf_size, (&out_iov[i])->iov_base, (&out_iov[i])->iov_len);
              s->spdm_buf_size += (&out_iov[i])->iov_len;
            }

            s->spdm_receive_is_ready = 1;
            qemu_cond_signal(&s->spdm_io_cond);
            qemu_mutex_unlock(&s->spdm_io_mutex);
        } else {
            BLK_SPDM_PRINT("VIRTIO_BLK_T_SPDM (read) %lu, byte 0: %02X \n",in_iov->iov_len, ((unsigned  char*)in_iov->iov_base)[0]);

            memset(in_iov->iov_base, 0, in_iov->iov_len);
            qemu_mutex_lock(&s->spdm_io_mutex);
            if (!s->spdm_send_is_ready) {
                qemu_cond_wait(&s->spdm_io_cond, &s->spdm_io_mutex);
            }
            s->spdm_send_is_ready = 0;
            if (in_iov->iov_len < s->spdm_buf_size + 1 + sizeof(s->spdm_buf_size)) {
                // TODO: how to inform SpdmSend there is a problem?
                BLK_SPDM_PRINT("Buffer too small\n");
                virtio_blk_req_complete(req, VIRTIO_BLK_S_IOERR);
                virtio_blk_free_request(req);
                break;
            }
            in_iov->iov_len = s->spdm_buf_size + sizeof(s->spdm_buf_size);
            * ((uint8_t*) in_iov->iov_base) = MCTP_MESSAGE_TYPE_SPDM;

            * ((uint32_t*) (((uint8_t*) in_iov->iov_base) + 1)) = s->spdm_buf_size;
            BLK_SPDM_PRINT("response size %u %X\n", s->spdm_buf_size, s->spdm_buf_size);
            memcpy(in_iov->iov_base + 1 + sizeof(s->spdm_buf_size), s->spdm_buf, s->spdm_buf_size); // magic number: 1 header byte

            qemu_mutex_unlock(&s->spdm_io_mutex);
        }

        virtio_blk_req_complete(req, VIRTIO_BLK_S_OK);
        virtio_blk_free_request(req);
        break;
    }
    case VIRTIO_BLK_T_SPDM_APP:
    {
        bool is_write = type & VIRTIO_BLK_T_OUT;

        uint32_t *message_session_id;
        unsigned char *temp_buffer = NULL;
        size_t temp_buffer_size;
        libspdm_return_t status;
        bool is_app_message;
        libspdm_context_t *spdm_context = s->spdm_context;
        size_t copied_len;
        int i;

        if (is_write) {

            BLK_SPDM_PRINT("VIRTIO_BLK_T_SPDM_APP (write) %lu %p %p %d \n",out_iov->iov_len, req, out_iov, out_num);

            temp_buffer_size = 0;
            for (int i = 0; i < out_num; i ++) {
                // internal_dump_hex((unsigned  char*) (&out_iov[i])->iov_base, (&out_iov[i])->iov_len);
                // printf(" out_iov[%d].iov_len %lu \n",i, out_iov[i].iov_len);
                // demo_print_buffer((&out_iov[i])->iov_base, (&out_iov[i])->iov_len, "Hard drive received the following data (encrypted):");
                temp_buffer = (unsigned char*) realloc(temp_buffer, temp_buffer_size + (&out_iov[i])->iov_len);
                memcpy(temp_buffer + temp_buffer_size, (&out_iov[i])->iov_base, (&out_iov[i])->iov_len);
                temp_buffer_size += (&out_iov[i])->iov_len;
            }

            // Do we need to enforce spdm_context mutually exclusive access?
            // qemu_mutex_lock(&spdm_encdec_mutex);
            // force seqno
            spdm_fix_internal_seqno(s->spdm_context, temp_buffer);
            status = libspdm_process_request((libspdm_context_t*)(s->spdm_context), &message_session_id, &is_app_message,
                                          temp_buffer_size, temp_buffer);
            // qemu_mutex_unlock(&spdm_encdec_mutex);
            if (LIBSPDM_STATUS_IS_ERROR(status) || !is_app_message) {
                printf ("oops: ");
                for (int i = 0; i < 16; i++) {
                    printf ("%02X ", temp_buffer[i]);
                }
                printf ("\n");
            }
            free(temp_buffer);
            // printf("spdm_context->last_spdm_request_size %lu - %X\n", spdm_context->last_spdm_request_size, status);

            // internal_dump_hex((unsigned  char*) spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);

            if (LIBSPDM_STATUS_IS_ERROR(status) || !is_app_message) {
                printf("%s: transport_decode_message error status - %x (is app %u)\n", __func__, status, is_app_message);
                printf("temp_buffer_size %lu\n", temp_buffer_size);
                virtio_blk_req_complete(req, VIRTIO_BLK_S_IOERR);
                virtio_blk_free_request(req);
                return 0;
            } else {
                copied_len = sizeof(mctp_message_header_t); // skip MCTP header
                i=0;
                // printf("spdm_context->last_spdm_request_size %lu\n", spdm_context->last_spdm_request_size);
                while (copied_len < spdm_context->last_spdm_request_size) {
                    if (i > out_num) break;
                    // printf(" out_iov[%d].iov_len %lu, spdm_context->last_spdm_request_size - copied_len %lu\n",i, out_iov[i].iov_len, spdm_context->last_spdm_request_size - copied_len);
                    out_iov[i].iov_len = MIN(out_iov[i].iov_len, spdm_context->last_spdm_request_size - copied_len);
                    memcpy(out_iov[i].iov_base, spdm_context->last_spdm_request + copied_len, out_iov[i].iov_len);
                    copied_len += out_iov[i].iov_len;
                    i++;
                }
                while (i < out_num) {
                    BLK_SPDM_PRINT("zeroing remaining iov lengths %lu\n", out_iov[i].iov_len);
                    out_iov[i].iov_len = 0;
                    i++;
                }

                BLK_SPDM_PRINT("this is a converted request\n");
                goto HANDLE_RW_L;
            }
        } else {
            BLK_SPDM_PRINT("VIRTIO_BLK_T_SPDM_APP (read) %lu, in_num %u; byte 0: %02X \n",in_iov->iov_len, in_num, ((unsigned  char*)in_iov->iov_base)[0]);

            // changing the iov_len was causing problems...
            // for (int i = 0; i < in_num; i++) {
            //     in_iov[i].iov_len -= 512; // magic number: assuming the driver is allocating 512 extra bytes
            // }
            BLK_SPDM_PRINT("this is a converted read request\n");
            goto HANDLE_RW_L;

        }
        virtio_blk_req_complete(req, VIRTIO_BLK_S_OK);
        virtio_blk_free_request(req);

      break;
    }
#endif // ENABLE_SPDM
    default:
        virtio_blk_req_complete(req, VIRTIO_BLK_S_UNSUPP);
        virtio_blk_free_request(req);
    }
    return 0;
}

bool virtio_blk_handle_vq(VirtIOBlock *s, VirtQueue *vq)
{
    VirtIOBlockReq *req;
    MultiReqBuffer mrb = {};
    bool progress = false;

    aio_context_acquire(blk_get_aio_context(s->blk));
    blk_io_plug(s->blk);

    do {
        virtio_queue_set_notification(vq, 0);

        while ((req = virtio_blk_get_request(s, vq))) {
            progress = true;
            if (virtio_blk_handle_request(req, &mrb)) {
                virtqueue_detach_element(req->vq, &req->elem, 0);
                virtio_blk_free_request(req);
                break;
            }
        }

        virtio_queue_set_notification(vq, 1);
    } while (!virtio_queue_empty(vq));

    if (mrb.num_reqs) {
        virtio_blk_submit_multireq(s->blk, &mrb);
    }

    blk_io_unplug(s->blk);
    aio_context_release(blk_get_aio_context(s->blk));
    return progress;
}

static void virtio_blk_handle_output_do(VirtIOBlock *s, VirtQueue *vq)
{
    virtio_blk_handle_vq(s, vq);
}

static void virtio_blk_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOBlock *s = (VirtIOBlock *)vdev;

    if (s->dataplane) {
        /* Some guests kick before setting VIRTIO_CONFIG_S_DRIVER_OK so start
         * dataplane here instead of waiting for .set_status().
         */
        virtio_device_start_ioeventfd(vdev);
        if (!s->dataplane_disabled) {
            return;
        }
    }
    virtio_blk_handle_output_do(s, vq);
}

static void virtio_blk_dma_restart_bh(void *opaque)
{
    VirtIOBlock *s = opaque;
    VirtIOBlockReq *req = s->rq;
    MultiReqBuffer mrb = {};

    qemu_bh_delete(s->bh);
    s->bh = NULL;

    s->rq = NULL;

    aio_context_acquire(blk_get_aio_context(s->conf.conf.blk));
    while (req) {
        VirtIOBlockReq *next = req->next;
        if (virtio_blk_handle_request(req, &mrb)) {
            /* Device is now broken and won't do any processing until it gets
             * reset. Already queued requests will be lost: let's purge them.
             */
            while (req) {
                next = req->next;
                virtqueue_detach_element(req->vq, &req->elem, 0);
                virtio_blk_free_request(req);
                req = next;
            }
            break;
        }
        req = next;
    }

    if (mrb.num_reqs) {
        virtio_blk_submit_multireq(s->blk, &mrb);
    }
    blk_dec_in_flight(s->conf.conf.blk);
    aio_context_release(blk_get_aio_context(s->conf.conf.blk));
}

static void virtio_blk_dma_restart_cb(void *opaque, int running,
                                      RunState state)
{
    VirtIOBlock *s = opaque;

    if (!running) {
        return;
    }

    if (!s->bh) {
        /* FIXME The data plane is not started yet, so these requests are
         * processed in the main thread. */
        s->bh = aio_bh_new(blk_get_aio_context(s->conf.conf.blk),
                           virtio_blk_dma_restart_bh, s);
        blk_inc_in_flight(s->conf.conf.blk);
        qemu_bh_schedule(s->bh);
    }
}

static void virtio_blk_reset(VirtIODevice *vdev)
{
    VirtIOBlock *s = VIRTIO_BLK(vdev);
    AioContext *ctx;
    VirtIOBlockReq *req;

    ctx = blk_get_aio_context(s->blk);
    aio_context_acquire(ctx);
    blk_drain(s->blk);

    /* We drop queued requests after blk_drain() because blk_drain() itself can
     * produce them. */
    while (s->rq) {
        req = s->rq;
        s->rq = req->next;
        virtqueue_detach_element(req->vq, &req->elem, 0);
        virtio_blk_free_request(req);
    }

    aio_context_release(ctx);

    assert(!s->dataplane_started);
    blk_set_enable_write_cache(s->blk, s->original_wce);
}

/* coalesce internal state, copy to pci i/o region 0
 */
static void virtio_blk_update_config(VirtIODevice *vdev, uint8_t *config)
{
    VirtIOBlock *s = VIRTIO_BLK(vdev);
    BlockConf *conf = &s->conf.conf;
    struct virtio_blk_config blkcfg;
    uint64_t capacity;
    int64_t length;
    int blk_size = conf->logical_block_size;

    blk_get_geometry(s->blk, &capacity);
    memset(&blkcfg, 0, sizeof(blkcfg));
    virtio_stq_p(vdev, &blkcfg.capacity, capacity);
    virtio_stl_p(vdev, &blkcfg.seg_max, 128 - 2);
    virtio_stw_p(vdev, &blkcfg.geometry.cylinders, conf->cyls);
    virtio_stl_p(vdev, &blkcfg.blk_size, blk_size);
    virtio_stw_p(vdev, &blkcfg.min_io_size, conf->min_io_size / blk_size);
    virtio_stw_p(vdev, &blkcfg.opt_io_size, conf->opt_io_size / blk_size);
    blkcfg.geometry.heads = conf->heads;
    /*
     * We must ensure that the block device capacity is a multiple of
     * the logical block size. If that is not the case, let's use
     * sector_mask to adopt the geometry to have a correct picture.
     * For those devices where the capacity is ok for the given geometry
     * we don't touch the sector value of the geometry, since some devices
     * (like s390 dasd) need a specific value. Here the capacity is already
     * cyls*heads*secs*blk_size and the sector value is not block size
     * divided by 512 - instead it is the amount of blk_size blocks
     * per track (cylinder).
     */
    length = blk_getlength(s->blk);
    if (length > 0 && length / conf->heads / conf->secs % blk_size) {
        blkcfg.geometry.sectors = conf->secs & ~s->sector_mask;
    } else {
        blkcfg.geometry.sectors = conf->secs;
    }
    blkcfg.size_max = 0;
    blkcfg.physical_block_exp = get_physical_block_exp(conf);
    blkcfg.alignment_offset = 0;
    blkcfg.wce = blk_enable_write_cache(s->blk);
    virtio_stw_p(vdev, &blkcfg.num_queues, s->conf.num_queues);
    if (virtio_has_feature(s->host_features, VIRTIO_BLK_F_DISCARD)) {
        virtio_stl_p(vdev, &blkcfg.max_discard_sectors,
                     s->conf.max_discard_sectors);
        virtio_stl_p(vdev, &blkcfg.discard_sector_alignment,
                     blk_size >> BDRV_SECTOR_BITS);
        /*
         * We support only one segment per request since multiple segments
         * are not widely used and there are no userspace APIs that allow
         * applications to submit multiple segments in a single call.
         */
        virtio_stl_p(vdev, &blkcfg.max_discard_seg, 1);
    }
    if (virtio_has_feature(s->host_features, VIRTIO_BLK_F_WRITE_ZEROES)) {
        virtio_stl_p(vdev, &blkcfg.max_write_zeroes_sectors,
                     s->conf.max_write_zeroes_sectors);
        blkcfg.write_zeroes_may_unmap = 1;
        virtio_stl_p(vdev, &blkcfg.max_write_zeroes_seg, 1);
    }
    memcpy(config, &blkcfg, s->config_size);
}

static void virtio_blk_set_config(VirtIODevice *vdev, const uint8_t *config)
{
    VirtIOBlock *s = VIRTIO_BLK(vdev);
    struct virtio_blk_config blkcfg;

    memcpy(&blkcfg, config, s->config_size);

    aio_context_acquire(blk_get_aio_context(s->blk));
    blk_set_enable_write_cache(s->blk, blkcfg.wce != 0);
    aio_context_release(blk_get_aio_context(s->blk));
}

static uint64_t virtio_blk_get_features(VirtIODevice *vdev, uint64_t features,
                                        Error **errp)
{
    VirtIOBlock *s = VIRTIO_BLK(vdev);

    /* Firstly sync all virtio-blk possible supported features */
    features |= s->host_features;

    virtio_add_feature(&features, VIRTIO_BLK_F_SEG_MAX);
    virtio_add_feature(&features, VIRTIO_BLK_F_GEOMETRY);
    virtio_add_feature(&features, VIRTIO_BLK_F_TOPOLOGY);
    virtio_add_feature(&features, VIRTIO_BLK_F_BLK_SIZE);
    if (virtio_has_feature(features, VIRTIO_F_VERSION_1)) {
        if (virtio_has_feature(s->host_features, VIRTIO_BLK_F_SCSI)) {
            error_setg(errp, "Please set scsi=off for virtio-blk devices in order to use virtio 1.0");
            return 0;
        }
    } else {
        virtio_clear_feature(&features, VIRTIO_F_ANY_LAYOUT);
        virtio_add_feature(&features, VIRTIO_BLK_F_SCSI);
    }

    if (blk_enable_write_cache(s->blk)) {
        virtio_add_feature(&features, VIRTIO_BLK_F_WCE);
    }
    if (blk_is_read_only(s->blk)) {
        virtio_add_feature(&features, VIRTIO_BLK_F_RO);
    }
    if (s->conf.num_queues > 1) {
        virtio_add_feature(&features, VIRTIO_BLK_F_MQ);
    }

    return features;
}

static void virtio_blk_set_status(VirtIODevice *vdev, uint8_t status)
{
    VirtIOBlock *s = VIRTIO_BLK(vdev);

    if (!(status & (VIRTIO_CONFIG_S_DRIVER | VIRTIO_CONFIG_S_DRIVER_OK))) {
        assert(!s->dataplane_started);
    }

    if (!(status & VIRTIO_CONFIG_S_DRIVER_OK)) {
        return;
    }

    /* A guest that supports VIRTIO_BLK_F_CONFIG_WCE must be able to send
     * cache flushes.  Thus, the "auto writethrough" behavior is never
     * necessary for guests that support the VIRTIO_BLK_F_CONFIG_WCE feature.
     * Leaving it enabled would break the following sequence:
     *
     *     Guest started with "-drive cache=writethrough"
     *     Guest sets status to 0
     *     Guest sets DRIVER bit in status field
     *     Guest reads host features (WCE=0, CONFIG_WCE=1)
     *     Guest writes guest features (WCE=0, CONFIG_WCE=1)
     *     Guest writes 1 to the WCE configuration field (writeback mode)
     *     Guest sets DRIVER_OK bit in status field
     *
     * s->blk would erroneously be placed in writethrough mode.
     */
    if (!virtio_vdev_has_feature(vdev, VIRTIO_BLK_F_CONFIG_WCE)) {
        aio_context_acquire(blk_get_aio_context(s->blk));
        blk_set_enable_write_cache(s->blk,
                                   virtio_vdev_has_feature(vdev,
                                                           VIRTIO_BLK_F_WCE));
        aio_context_release(blk_get_aio_context(s->blk));
    }
}

static void virtio_blk_save_device(VirtIODevice *vdev, QEMUFile *f)
{
    VirtIOBlock *s = VIRTIO_BLK(vdev);
    VirtIOBlockReq *req = s->rq;

    while (req) {
        qemu_put_sbyte(f, 1);

        if (s->conf.num_queues > 1) {
            qemu_put_be32(f, virtio_get_queue_index(req->vq));
        }

        qemu_put_virtqueue_element(f, &req->elem);
        req = req->next;
    }
    qemu_put_sbyte(f, 0);
}

static int virtio_blk_load_device(VirtIODevice *vdev, QEMUFile *f,
                                  int version_id)
{
    VirtIOBlock *s = VIRTIO_BLK(vdev);

    while (qemu_get_sbyte(f)) {
        unsigned nvqs = s->conf.num_queues;
        unsigned vq_idx = 0;
        VirtIOBlockReq *req;

        if (nvqs > 1) {
            vq_idx = qemu_get_be32(f);

            if (vq_idx >= nvqs) {
                error_report("Invalid virtqueue index in request list: %#x",
                             vq_idx);
                return -EINVAL;
            }
        }

        req = qemu_get_virtqueue_element(vdev, f, sizeof(VirtIOBlockReq));
        virtio_blk_init_request(s, virtio_get_queue(vdev, vq_idx), req);
        req->next = s->rq;
        s->rq = req;
    }

    return 0;
}

static void virtio_blk_resize(void *opaque)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(opaque);

    virtio_notify_config(vdev);
}

static const BlockDevOps virtio_block_ops = {
    .resize_cb = virtio_blk_resize,
};

#if ENABLE_SPDM
// Functions to be used with spdm_register_device_io_func
libspdm_return_t virtio_blk_spdm_send (
       void                    *spdm_context,
       size_t                   request_size,
       const void              *request,
       uint64_t                  timeout
  );

libspdm_return_t virtio_blk_spdm_receive (
    void                    *spdm_context,
    size_t                   *response_size,
    void                    **response,
    uint64_t                  timeout
  );

libspdm_return_t virtio_blk_spdm_send (
       void                    *spdm_context,
       size_t                   request_size,
       const void              *request,
       uint64_t                 timeout
  )
{
    VirtIOBlock *s = SPDM_CTX_TO_VIRTIOBLOCK(spdm_context);
    BLK_SPDM_PRINT("virtio_blk_spdm_send\n");

    if (request_size > sizeof(s->spdm_buf)) {
        printf("request_size too large %lu\n", request_size);
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }

    qemu_mutex_lock(&s->spdm_io_mutex);
    s->spdm_buf_size = request_size;
    memcpy(s->spdm_buf, request, request_size);
#if BLK_SPDM_DEBUG
    for (int i = 0; i < s->spdm_buf_size; i++) {
      printf("%02X ", ((uint8_t*)s->spdm_buf)[i]);
    }
    printf("\n");
#endif
    s->spdm_send_is_ready = 1;
    qemu_cond_signal(&s->spdm_io_cond);
    qemu_mutex_unlock(&s->spdm_io_mutex);
    return LIBSPDM_STATUS_SUCCESS;
}


static void spdm_clearall_session_id(libspdm_context_t *spdm_context)
{
    libspdm_session_info_t *session_info;
    size_t index;

    session_info = spdm_context->session_info;
    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++) {
        session_info[index].session_id = (INVALID_SESSION_ID & 0xFFFF);
    }
}

libspdm_return_t virtio_blk_spdm_receive (
    void                     *spdm_context,
    size_t                   *response_size,
    void                    **response,
    uint64_t                  timeout
  )
{
    VirtIOBlock *s = SPDM_CTX_TO_VIRTIOBLOCK(spdm_context);
    const uint8_t GET_VERSION[] = {0x05, 0x10, 0x84, 0x00, 0x00};
    BLK_SPDM_PRINT("virtio_blk_spdm_receive\n");
    if (*response_size < atomic_read(&s->spdm_buf_size)) {
        printf("*response_size too small %lu\n", *response_size);
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }
#if BLK_SPDM_DEBUG
    for (int i = 0; i < s->spdm_buf_size; i++) {
      printf("%02X ", ((uint8_t*)s->spdm_buf)[i]);
    }
    printf("\n");
#endif
    // Hax to for all sessions to be cleared
    // not clearing cases problems after MAX_SPDM_SESSION_COUNT VM reboots due to session vector overflow
    // could not find a more appropriate location to do it (does not work on virtio_blk_reset)
    qemu_mutex_lock(&s->spdm_io_mutex);
    if (!memcmp(GET_VERSION, s->spdm_buf, sizeof(GET_VERSION))) {
        BLK_SPDM_PRINT("Got get_version: clearing all sessions...\n");
        spdm_clearall_session_id(spdm_context);
        s->remaining_bits = 0;
        s->in_danger = 0;
        s->wrapped = 0;
    }
    *response_size = s->spdm_buf_size;
    memcpy(*response, s->spdm_buf, *response_size);
    qemu_mutex_unlock(&s->spdm_io_mutex);
    return LIBSPDM_STATUS_SUCCESS;
}

static void *virtio_blk_spdm_io_thread(void *opaque)
{
    VirtIOBlock *s = opaque;
    libspdm_return_t status;

    while (1) {
        BLK_SPDM_PRINT("virtio_blk_spdm_io_thread() loop\n");
        qemu_mutex_lock(&s->spdm_io_mutex);
        if (!s->spdm_receive_is_ready) {
            qemu_cond_wait(&s->spdm_io_cond, &s->spdm_io_mutex);
        }
        s->spdm_receive_is_ready = 0;

        qemu_mutex_unlock(&s->spdm_io_mutex);

        // ToDo: whats the stopping condition?
        // if (spdmst->stopping) {
        //     break;
        // }

        status = libspdm_responder_dispatch_message (s->spdm_context);

        if (status == LIBSPDM_STATUS_SUCCESS) {
            // load certificates and stuff
            virtio_blk_spdm_server_callback (s->spdm_context);
        } else {
            printf("SpdmResponderDispatchMessage error: %X\n", status);
        }

    }

    return NULL;
}

libspdm_return_t spdm_get_response_vendor_defined_request(
   void *spdm_context, const uint32_t *session_id,  bool is_app_message,
   size_t request_size, const void *request,   size_t *response_size,
   void *response);

libspdm_return_t spdm_get_response_vendor_defined_request(
   void *spdm_context, const uint32_t *session_id,  bool is_app_message,
   size_t request_size, const void *request,   size_t *response_size,
   void *response)
{
  const uint8_t *request_bytes = request;
  if (request_bytes[1] == SPDM_BLK_APP_TAMPER) {
    uint8_t index = request_bytes[2];
    ts[index] = MAX(ts[index], ts[index] + 1);
    printf("Triggering tamper of measurement %u\n", index);
  }
  memcpy(response, request, request_size);
  *response_size = request_size;
  return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t virtioblk_spdm_acquire_buffer (void *context, void **msg_buf_ptr);
void virtioblk_spdm_release_buffer(void *context, const void *msg_buf_ptr);

libspdm_return_t virtioblk_spdm_acquire_buffer (
    void *context, void **msg_buf_ptr)
{
    VirtIOBlock *s = SPDM_CTX_TO_VIRTIOBLOCK(context);
    qemu_mutex_lock(&s->spdm_io_mutex);
    *msg_buf_ptr = (void *)malloc(SPDMDEV_MAX_BUF);
    if (*msg_buf_ptr == NULL)
        return LIBSPDM_STATUS_ACQUIRE_FAIL;
    qemu_mutex_unlock(&s->spdm_io_mutex);

    return LIBSPDM_STATUS_SUCCESS;
}

void virtioblk_spdm_release_buffer(
    void *context, const void *msg_buf_ptr)
{
    VirtIOBlock *s = SPDM_CTX_TO_VIRTIOBLOCK(context);
    qemu_mutex_lock(&s->spdm_io_mutex);
    if (msg_buf_ptr != NULL)
        free((void *)msg_buf_ptr);
    qemu_mutex_unlock(&s->spdm_io_mutex);

    return;
}

static int virtio_blk_spdm_init(VirtIOBlock *s) {
    uint8_t data8;
    uint16_t data16;
    uint32_t data32;
    uint8_t m_use_version = SPDM_MESSAGE_VERSION_13; //SPDM_MESSAGE_VERSION_11;
    uint8_t m_use_secured_message_version = SECURED_SPDM_VERSION_11;
    libspdm_data_parameter_t parameter;
    spdm_version_number_t spdm_version;
    size_t scratch_buffer_size;
    void *requester_cert_chain_buffer;

    BLK_SPDM_PRINT("init_spdm\n");
    s->spdm_context = (void *)malloc(libspdm_get_context_size() + sizeof(VirtIOBlock*));
    if (s->spdm_context == NULL) {
        printf("Failed to initialize SPDM context.\n");
        return -1;
    }

    // Initialize context variable
    libspdm_init_context(s->spdm_context);

    SPDM_CTX_TO_VIRTIOBLOCK(s->spdm_context) = s;

    // Set functions for setting and receiving SPDM messages
    libspdm_register_device_io_func(
            s->spdm_context,
            virtio_blk_spdm_send,
            virtio_blk_spdm_receive);

    libspdm_register_transport_layer_func(
            s->spdm_context,
            (SPDMDEV_MAX_BUF - LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE - LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE),
            LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE,
            LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE,
            libspdm_transport_mctp_encode_message,
            libspdm_transport_mctp_decode_message);

    libspdm_register_device_buffer_func(
        s->spdm_context,
        SPDMDEV_MAX_BUF,
        SPDMDEV_MAX_BUF,
        virtioblk_spdm_acquire_buffer,
        virtioblk_spdm_release_buffer,
        virtioblk_spdm_acquire_buffer,
        virtioblk_spdm_release_buffer);

    scratch_buffer_size = libspdm_get_sizeof_required_scratch_buffer(s->spdm_context);
    s->scratch_buffer = (void *)malloc(scratch_buffer_size);
    if (s->scratch_buffer == NULL) {
        printf("Failed to allocate scratch buffer.\n");
        free(s->spdm_context);
        return -1;
    }
    libspdm_set_scratch_buffer(s->spdm_context, s->scratch_buffer, scratch_buffer_size);

    requester_cert_chain_buffer = (void *)malloc(SPDM_MAX_CERTIFICATE_CHAIN_SIZE);
    if (requester_cert_chain_buffer == NULL) {
        printf("Failed to allocate requester_cert_chain_buffer.\n");
        return -1;
    }
    libspdm_register_cert_chain_buffer(s->spdm_context, requester_cert_chain_buffer, SPDM_MAX_CERTIFICATE_CHAIN_SIZE);

    if (!libspdm_check_context(s->spdm_context)) {
        printf("Failed SPDM context check.\n");
        return -1;
    }

    if (m_use_version != 0) {
        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        spdm_version = m_use_version << SPDM_VERSION_NUMBER_SHIFT_BIT;
        libspdm_set_data(s->spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                  &spdm_version, sizeof(spdm_version));
    }

    if (m_use_secured_message_version != 0) {
        libspdm_zero_mem(&parameter, sizeof(parameter));
        if (m_use_secured_message_version != 0) {
            parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
            spdm_version = m_use_secured_message_version << SPDM_VERSION_NUMBER_SHIFT_BIT;
            libspdm_set_data(s->spdm_context,
                      LIBSPDM_DATA_SECURED_MESSAGE_VERSION,
                      &parameter, &spdm_version,
                      sizeof(spdm_version));
        } else {
            libspdm_set_data(s->spdm_context,
                      LIBSPDM_DATA_SECURED_MESSAGE_VERSION,
                      &parameter, NULL, 0);
        }
    }

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

    data8 = 0;
    libspdm_set_data(s->spdm_context, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
              &parameter, &data8, sizeof(data8));
    data32 = m_use_responder_capability_flags;
    libspdm_set_data(s->spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
              &data32, sizeof(data32));

    data8 = m_support_measurement_spec;
    libspdm_set_data(s->spdm_context, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
              &data8, sizeof(data8));
    data32 = m_support_measurement_hash_algo;
    libspdm_set_data(s->spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
              &data32, sizeof(data32));
    data32 = m_support_asym_algo;
    libspdm_set_data(s->spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
              &data32, sizeof(data32));
    data32 = m_support_hash_algo;
    libspdm_set_data(s->spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
              &data32, sizeof(data32));
    data16 = m_support_dhe_algo;
    libspdm_set_data(s->spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter,
              &data16, sizeof(data16));
    data16 = m_support_aead_algo;
    libspdm_set_data(s->spdm_context, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
              &data16, sizeof(data16));
    data16 = m_support_req_asym_algo;
    libspdm_set_data(s->spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
              &data16, sizeof(data16));
    data16 = m_support_key_schedule_algo;
    libspdm_set_data(s->spdm_context, LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &data16,
              sizeof(data16));
    data8 = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    libspdm_set_data(s->spdm_context, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter,
                     &data8, sizeof(data8));
    data8 = SPDM_MEL_SPECIFICATION_DMTF;
    libspdm_set_data(s->spdm_context, LIBSPDM_DATA_MEL_SPEC, &parameter,
                     &data8, sizeof(data8));

    data8 = 0xF0;
    libspdm_set_data(s->spdm_context, LIBSPDM_DATA_HEARTBEAT_PERIOD, &parameter,
                     &data8, sizeof(data8));

    qemu_mutex_init(&s->spdm_io_mutex);
    // qemu_mutex_init(&spdm_encdec_mutex);
    qemu_cond_init(&s->spdm_io_cond);
    s->spdm_buf_size = 0;
    s->spdm_send_is_ready = 0;
    s->spdm_receive_is_ready = 0;

    s->remaining_bits = 0;
    s->in_danger = 0;
    s->wrapped = 0;

    libspdm_register_get_response_func(s->spdm_context, spdm_get_response_vendor_defined_request);

    qemu_thread_create(&s->spdm_io_thread, "spdm_io_virtio_blk", virtio_blk_spdm_io_thread,
                       s, QEMU_THREAD_JOINABLE);
    return 0;
}
#endif // ENABLE_SPDM

static void virtio_blk_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOBlock *s = VIRTIO_BLK(dev);
    VirtIOBlkConf *conf = &s->conf;
    Error *err = NULL;
    unsigned i;

    if (!conf->conf.blk) {
        error_setg(errp, "drive property not set");
        return;
    }
    if (!blk_is_inserted(conf->conf.blk)) {
        error_setg(errp, "Device needs media, but drive is empty");
        return;
    }
    if (!conf->num_queues) {
        error_setg(errp, "num-queues property must be larger than 0");
        return;
    }
    if (!is_power_of_2(conf->queue_size) ||
        conf->queue_size > VIRTQUEUE_MAX_SIZE) {
        error_setg(errp, "invalid queue-size property (%" PRIu16 "), "
                   "must be a power of 2 (max %d)",
                   conf->queue_size, VIRTQUEUE_MAX_SIZE);
        return;
    }

    if (!blkconf_apply_backend_options(&conf->conf,
                                       blk_is_read_only(conf->conf.blk), true,
                                       errp)) {
        return;
    }
    s->original_wce = blk_enable_write_cache(conf->conf.blk);
    if (!blkconf_geometry(&conf->conf, NULL, 65535, 255, 255, errp)) {
        return;
    }

    blkconf_blocksizes(&conf->conf);

    if (conf->conf.logical_block_size >
        conf->conf.physical_block_size) {
        error_setg(errp,
                   "logical_block_size > physical_block_size not supported");
        return;
    }

    if (virtio_has_feature(s->host_features, VIRTIO_BLK_F_DISCARD) &&
        (!conf->max_discard_sectors ||
         conf->max_discard_sectors > BDRV_REQUEST_MAX_SECTORS)) {
        error_setg(errp, "invalid max-discard-sectors property (%" PRIu32 ")"
                   ", must be between 1 and %d",
                   conf->max_discard_sectors, (int)BDRV_REQUEST_MAX_SECTORS);
        return;
    }

    if (virtio_has_feature(s->host_features, VIRTIO_BLK_F_WRITE_ZEROES) &&
        (!conf->max_write_zeroes_sectors ||
         conf->max_write_zeroes_sectors > BDRV_REQUEST_MAX_SECTORS)) {
        error_setg(errp, "invalid max-write-zeroes-sectors property (%" PRIu32
                   "), must be between 1 and %d",
                   conf->max_write_zeroes_sectors,
                   (int)BDRV_REQUEST_MAX_SECTORS);
        return;
    }

    virtio_blk_set_config_size(s, s->host_features);

    virtio_init(vdev, "virtio-blk", VIRTIO_ID_BLOCK, s->config_size);

    s->blk = conf->conf.blk;
    s->rq = NULL;
    s->sector_mask = (s->conf.conf.logical_block_size / BDRV_SECTOR_SIZE) - 1;

    for (i = 0; i < conf->num_queues; i++) {
        virtio_add_queue(vdev, conf->queue_size, virtio_blk_handle_output);
    }
    virtio_blk_data_plane_create(vdev, conf, &s->dataplane, &err);
    if (err != NULL) {
        error_propagate(errp, err);
        virtio_cleanup(vdev);
        return;
    }

    s->change = qemu_add_vm_change_state_handler(virtio_blk_dma_restart_cb, s);
    blk_set_dev_ops(s->blk, &virtio_block_ops, s);
    blk_set_guest_block_size(s->blk, s->conf.conf.logical_block_size);
#if ENABLE_SPDM
    virtio_blk_spdm_init(s);
#endif

    blk_iostatus_enable(s->blk);
}

static void virtio_blk_device_unrealize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOBlock *s = VIRTIO_BLK(dev);

    virtio_blk_data_plane_destroy(s->dataplane);
    s->dataplane = NULL;
    qemu_del_vm_change_state_handler(s->change);
    blockdev_mark_auto_del(s->blk);
    virtio_cleanup(vdev);
}

static void virtio_blk_instance_init(Object *obj)
{
    VirtIOBlock *s = VIRTIO_BLK(obj);

    device_add_bootindex_property(obj, &s->conf.conf.bootindex,
                                  "bootindex", "/disk@0,0",
                                  DEVICE(obj), NULL);
}

static const VMStateDescription vmstate_virtio_blk = {
    .name = "virtio-blk",
    .minimum_version_id = 2,
    .version_id = 2,
    .fields = (VMStateField[]) {
        VMSTATE_VIRTIO_DEVICE,
        VMSTATE_END_OF_LIST()
    },
};

static Property virtio_blk_properties[] = {
    DEFINE_BLOCK_PROPERTIES(VirtIOBlock, conf.conf),
    DEFINE_BLOCK_ERROR_PROPERTIES(VirtIOBlock, conf.conf),
    DEFINE_BLOCK_CHS_PROPERTIES(VirtIOBlock, conf.conf),
    DEFINE_PROP_STRING("serial", VirtIOBlock, conf.serial),
    DEFINE_PROP_BIT64("config-wce", VirtIOBlock, host_features,
                      VIRTIO_BLK_F_CONFIG_WCE, true),
#ifdef __linux__
    DEFINE_PROP_BIT64("scsi", VirtIOBlock, host_features,
                      VIRTIO_BLK_F_SCSI, false),
#endif
    // set to false, since merging was causing issues with SPDM encryption from responder to requester
    DEFINE_PROP_BIT("request-merging", VirtIOBlock, conf.request_merging, 0,
                    false),
    DEFINE_PROP_UINT16("num-queues", VirtIOBlock, conf.num_queues, 1),
    DEFINE_PROP_UINT16("queue-size", VirtIOBlock, conf.queue_size, 128),
    DEFINE_PROP_LINK("iothread", VirtIOBlock, conf.iothread, TYPE_IOTHREAD,
                     IOThread *),
    DEFINE_PROP_BIT64("discard", VirtIOBlock, host_features,
                      VIRTIO_BLK_F_DISCARD, true),
    DEFINE_PROP_BIT64("write-zeroes", VirtIOBlock, host_features,
                      VIRTIO_BLK_F_WRITE_ZEROES, true),
    DEFINE_PROP_UINT32("max-discard-sectors", VirtIOBlock,
                       conf.max_discard_sectors, BDRV_REQUEST_MAX_SECTORS),
    DEFINE_PROP_UINT32("max-write-zeroes-sectors", VirtIOBlock,
                       conf.max_write_zeroes_sectors, BDRV_REQUEST_MAX_SECTORS),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_blk_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    dc->props = virtio_blk_properties;
    dc->vmsd = &vmstate_virtio_blk;
    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    vdc->realize = virtio_blk_device_realize;
    vdc->unrealize = virtio_blk_device_unrealize;
    vdc->get_config = virtio_blk_update_config;
    vdc->set_config = virtio_blk_set_config;
    vdc->get_features = virtio_blk_get_features;
    vdc->set_status = virtio_blk_set_status;
    vdc->reset = virtio_blk_reset;
    vdc->save = virtio_blk_save_device;
    vdc->load = virtio_blk_load_device;
    vdc->start_ioeventfd = virtio_blk_data_plane_start;
    vdc->stop_ioeventfd = virtio_blk_data_plane_stop;
}

static const TypeInfo virtio_blk_info = {
    .name = TYPE_VIRTIO_BLK,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtIOBlock),
    .instance_init = virtio_blk_instance_init,
    .class_init = virtio_blk_class_init,
};

static void virtio_register_types(void)
{
    type_register_static(&virtio_blk_info);
}

type_init(virtio_register_types)
