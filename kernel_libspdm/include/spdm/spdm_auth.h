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
		    uint8_t measurement_hash_type, void *measurement_hash);

/**
  This function executes SPDM authentication.

  @param[in]  spdm_context            The SPDM context for the device.
**/
libspdm_return_t do_authentication_via_spdm(void* spdm_context);