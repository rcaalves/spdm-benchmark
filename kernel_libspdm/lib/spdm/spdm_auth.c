/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
**/


#include <linux/slab.h>
#include <base.h>
#include <library/memlib.h>
#include <library/spdm_requester_lib.h>
#include <library/spdm_transport_mctp_lib.h>
#include <library/spdm_transport_pcidoe_lib.h>
#include <spdm_default_params.h>

/**
  This function sends GET_DIGEST, GET_CERTIFICATE, CHALLENGE
  to authenticate the device.

  This function is combination of libspdm_get_digest, libspdm_get_certificate, libspdm_challenge.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  slot_mask                     The slots which deploy the CertificateChain.
  @param  total_digest_buffer            A pointer to a destination buffer to store the digest buffer.
  @param  slot_id                      The number of slot for the certificate chain.
  @param  cert_chain_size                On input, indicate the size in bytes of the destination buffer to store the digest buffer.
                                       On output, indicate the size in bytes of the certificate chain.
  @param  cert_chain                    A pointer to a destination buffer to store the certificate chain.
  @param  measurement_hash_type          The type of the measurement hash.
  @param  measurement_hash              A pointer to a destination buffer to store the measurement hash.

  @retval LIBSPDM_STATUS_SUCCESS               The authentication is got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
libspdm_return_t
spdm_authentication(void *context, uint8_t *slot_mask,
		    void *total_digest_buffer, uint8_t slot_id,
		    size_t *cert_chain_size, void *cert_chain,
		    uint8_t measurement_hash_type, void *measurement_hash)
{
	libspdm_return_t status;

	status = libspdm_get_digest(context, NULL, slot_mask,
				 total_digest_buffer);
	if (LIBSPDM_STATUS_IS_ERROR(status)) {
		return status;
	}


	if (slot_id != 0xFF) {
		status = libspdm_get_certificate(
			context, NULL, slot_id, cert_chain_size, cert_chain);
		if (LIBSPDM_STATUS_IS_ERROR(status)) {
			printk(KERN_WARNING "libspdm_get_certificate failed %X", status);
			return status;
		}
	}

	status = libspdm_challenge(context, NULL, slot_id, measurement_hash_type,
				measurement_hash, slot_mask);
	if (LIBSPDM_STATUS_IS_ERROR(status)) {
		printk(KERN_WARNING "libspdm_challenge failed %X", status);
		return status;
	}

	return LIBSPDM_STATUS_SUCCESS;
}

/**
  This function executes SPDM authentication.

  @param[in]  spdm_context            The SPDM context for the device.
**/
libspdm_return_t do_authentication_via_spdm(void* spdm_context)
{
	libspdm_return_t status = LIBSPDM_STATUS_SUCCESS;
	uint8_t slot_mask;
	size_t cert_chain_size;
	uint8_t *cert_chain;
	uint8_t *total_digest_buffer;
	uint8_t *measurement_hash;

	cert_chain = kmalloc(LIBSPDM_MAX_CERT_CHAIN_SIZE, GFP_KERNEL);
	if (cert_chain == NULL) {
		printk("Out of mem\n");
		status = LIBSPDM_STATUS_ACQUIRE_FAIL;
		goto out_auth_ret;
	}

	total_digest_buffer = kmalloc(LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT, GFP_KERNEL);
	if (total_digest_buffer == NULL) {
		printk("Out of mem\n");
		status = LIBSPDM_STATUS_ACQUIRE_FAIL;
		goto out_auth_free_cc;
	}

	measurement_hash = kmalloc(LIBSPDM_MAX_HASH_SIZE, GFP_KERNEL);
	if (measurement_hash == NULL) {
		printk("Out of mem\n");
		status = LIBSPDM_STATUS_ACQUIRE_FAIL;
		goto out_auth_free_db;
	}

	libspdm_zero_mem(total_digest_buffer, LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT);
	cert_chain_size = LIBSPDM_MAX_CERT_CHAIN_SIZE;
	libspdm_zero_mem(cert_chain, LIBSPDM_MAX_CERT_CHAIN_SIZE);
	libspdm_zero_mem(measurement_hash, LIBSPDM_MAX_HASH_SIZE);
	status = spdm_authentication(spdm_context, &slot_mask,
				     total_digest_buffer, m_use_slot_id,
				     &cert_chain_size, cert_chain,
				     m_use_measurement_summary_hash_type,
				     measurement_hash);

	kfree(measurement_hash);
out_auth_free_db:
	kfree(total_digest_buffer);
out_auth_free_cc:
	kfree(cert_chain);
out_auth_ret:
	return status;
}
