// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 1999 - 2006 Intel Corporation. */

#include "e1000.h"
#include <net/ip6_checksum.h>
#include <linux/io.h>
#include <linux/prefetch.h>
#include <linux/bitops.h>
#include <linux/if_vlan.h>

// #define SPDM_ENABLED 1

#include <spdm_common_lib.h>
#include <library/spdm_requester_lib.h>
#include <library/spdm_transport_mctp_lib.h>
#include <industry_standard/mctp.h>
#include <internal/libspdm_secured_message_lib.h>

#include <spdm_auth.h>
#include <spdm_sample_certs.h>
#include <spdm_default_params.h>

#define LIBSPDM_MAX_SPDM_MSG_SIZE 0x2200 // Max size for SPDM message
#define SPDM_CERT_FROM_KERNEL 0

// global variables
void* global_spdm_context;
uint32_t global_session_id;


#define E1000_SPDM_DEBUG 0

#if E1000_SPDM_DEBUG
#define E1000_SPDM_PRINT(format,  ...) printk(format, ##__VA_ARGS__)
#else /*E1000_SPDM_DEBUG*/
#define E1000_SPDM_PRINT(format,  ...)
#endif /*E1000_SPDM_DEBUG*/

#define isprint(a) ((a >=' ')&&(a <= '~'))
void demo_e1000_print_buffer(char* buffer, size_t len, const char* message) {
#if E1000_SPDM_DEMO_PRINT
#define DEMO_PRINT_LIMIT 256
#define DEMO_BYTES_PER_LINE 16
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


char e1000_driver_name[] = "e1000";
static char e1000_driver_string[] = "Intel(R) PRO/1000 Network Driver";
#define DRV_VERSION "7.3.21-k8-NAPI"
const char e1000_driver_version[] = DRV_VERSION;
static const char e1000_copyright[] = "Copyright (c) 1999-2006 Intel Corporation.";

/* e1000_pci_tbl - PCI Device ID Table
 *
 * Last entry must be all 0s
 *
 * Macro expands to...
 *   {PCI_DEVICE(PCI_VENDOR_ID_INTEL, device_id)}
 */
static const struct pci_device_id e1000_pci_tbl[] = {
	INTEL_E1000_ETHERNET_DEVICE(0x1000),
	INTEL_E1000_ETHERNET_DEVICE(0x1001),
	INTEL_E1000_ETHERNET_DEVICE(0x1004),
	INTEL_E1000_ETHERNET_DEVICE(0x1008),
	INTEL_E1000_ETHERNET_DEVICE(0x1009),
	INTEL_E1000_ETHERNET_DEVICE(0x100C),
	INTEL_E1000_ETHERNET_DEVICE(0x100D),
	INTEL_E1000_ETHERNET_DEVICE(0x100E),
	INTEL_E1000_ETHERNET_DEVICE(0x100F),
	INTEL_E1000_ETHERNET_DEVICE(0x1010),
	INTEL_E1000_ETHERNET_DEVICE(0x1011),
	INTEL_E1000_ETHERNET_DEVICE(0x1012),
	INTEL_E1000_ETHERNET_DEVICE(0x1013),
	INTEL_E1000_ETHERNET_DEVICE(0x1014),
	INTEL_E1000_ETHERNET_DEVICE(0x1015),
	INTEL_E1000_ETHERNET_DEVICE(0x1016),
	INTEL_E1000_ETHERNET_DEVICE(0x1017),
	INTEL_E1000_ETHERNET_DEVICE(0x1018),
	INTEL_E1000_ETHERNET_DEVICE(0x1019),
	INTEL_E1000_ETHERNET_DEVICE(0x101A),
	INTEL_E1000_ETHERNET_DEVICE(0x101D),
	INTEL_E1000_ETHERNET_DEVICE(0x101E),
	INTEL_E1000_ETHERNET_DEVICE(0x1026),
	INTEL_E1000_ETHERNET_DEVICE(0x1027),
	INTEL_E1000_ETHERNET_DEVICE(0x1028),
	INTEL_E1000_ETHERNET_DEVICE(0x1075),
	INTEL_E1000_ETHERNET_DEVICE(0x1076),
	INTEL_E1000_ETHERNET_DEVICE(0x1077),
	INTEL_E1000_ETHERNET_DEVICE(0x1078),
	INTEL_E1000_ETHERNET_DEVICE(0x1079),
	INTEL_E1000_ETHERNET_DEVICE(0x107A),
	INTEL_E1000_ETHERNET_DEVICE(0x107B),
	INTEL_E1000_ETHERNET_DEVICE(0x107C),
	INTEL_E1000_ETHERNET_DEVICE(0x108A),
	INTEL_E1000_ETHERNET_DEVICE(0x1099),
	INTEL_E1000_ETHERNET_DEVICE(0x10B5),
	INTEL_E1000_ETHERNET_DEVICE(0x2E6E),
	/* required last entry */
	{0,}
};

MODULE_DEVICE_TABLE(pci, e1000_pci_tbl);

int e1000_up(struct e1000_adapter *adapter);
void e1000_down(struct e1000_adapter *adapter);
void e1000_reinit_locked(struct e1000_adapter *adapter);
void e1000_reset(struct e1000_adapter *adapter);
int e1000_setup_all_tx_resources(struct e1000_adapter *adapter);
int e1000_setup_all_rx_resources(struct e1000_adapter *adapter);
void e1000_free_all_tx_resources(struct e1000_adapter *adapter);
void e1000_free_all_rx_resources(struct e1000_adapter *adapter);
static int e1000_setup_tx_resources(struct e1000_adapter *adapter,
				    struct e1000_tx_ring *txdr);
static int e1000_setup_rx_resources(struct e1000_adapter *adapter,
				    struct e1000_rx_ring *rxdr);
static void e1000_free_tx_resources(struct e1000_adapter *adapter,
				    struct e1000_tx_ring *tx_ring);
static void e1000_free_rx_resources(struct e1000_adapter *adapter,
				    struct e1000_rx_ring *rx_ring);
void e1000_update_stats(struct e1000_adapter *adapter);

static int e1000_init_module(void);
static void e1000_exit_module(void);
static int e1000_probe(struct pci_dev *pdev, const struct pci_device_id *ent);
static void e1000_remove(struct pci_dev *pdev);
static int e1000_alloc_queues(struct e1000_adapter *adapter);
static int e1000_sw_init(struct e1000_adapter *adapter);
int e1000_open(struct net_device *netdev);
int e1000_close(struct net_device *netdev);
static void e1000_configure_tx(struct e1000_adapter *adapter);
static void e1000_configure_rx(struct e1000_adapter *adapter);
static void e1000_setup_rctl(struct e1000_adapter *adapter);
static void e1000_clean_all_tx_rings(struct e1000_adapter *adapter);
static void e1000_clean_all_rx_rings(struct e1000_adapter *adapter);
static void e1000_clean_tx_ring(struct e1000_adapter *adapter,
				struct e1000_tx_ring *tx_ring);
static void e1000_clean_rx_ring(struct e1000_adapter *adapter,
				struct e1000_rx_ring *rx_ring);
static void e1000_set_rx_mode(struct net_device *netdev);
static void e1000_update_phy_info_task(struct work_struct *work);
static void e1000_watchdog(struct work_struct *work);
static void e1000_82547_tx_fifo_stall_task(struct work_struct *work);
static netdev_tx_t e1000_xmit_frame(struct sk_buff *skb,
				    struct net_device *netdev);
static netdev_tx_t e1000_spdm_xmit_frame(struct sk_buff *skb,
				    struct net_device *netdev, uint8_t spdm_msg_type);
static int e1000_change_mtu(struct net_device *netdev, int new_mtu);
static int e1000_set_mac(struct net_device *netdev, void *p);
static irqreturn_t e1000_intr(int irq, void *data);
static bool e1000_clean_tx_irq(struct e1000_adapter *adapter,
			       struct e1000_tx_ring *tx_ring);
static int e1000_clean(struct napi_struct *napi, int budget);
static bool e1000_clean_rx_irq(struct e1000_adapter *adapter,
			       struct e1000_rx_ring *rx_ring,
			       int *work_done, int work_to_do);
static bool e1000_clean_jumbo_rx_irq(struct e1000_adapter *adapter,
				     struct e1000_rx_ring *rx_ring,
				     int *work_done, int work_to_do);
static void e1000_alloc_dummy_rx_buffers(struct e1000_adapter *adapter,
					 struct e1000_rx_ring *rx_ring,
					 int cleaned_count)
{
}
static void e1000_alloc_rx_buffers(struct e1000_adapter *adapter,
				   struct e1000_rx_ring *rx_ring,
				   int cleaned_count);
static void e1000_alloc_jumbo_rx_buffers(struct e1000_adapter *adapter,
					 struct e1000_rx_ring *rx_ring,
					 int cleaned_count);
static int e1000_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd);
static int e1000_mii_ioctl(struct net_device *netdev, struct ifreq *ifr,
			   int cmd);
static void e1000_enter_82542_rst(struct e1000_adapter *adapter);
static void e1000_leave_82542_rst(struct e1000_adapter *adapter);
static void e1000_tx_timeout(struct net_device *dev);
static void e1000_reset_task(struct work_struct *work);
static void e1000_smartspeed(struct e1000_adapter *adapter);
static int e1000_82547_fifo_workaround(struct e1000_adapter *adapter,
				       struct sk_buff *skb);

static bool e1000_vlan_used(struct e1000_adapter *adapter);
static void e1000_vlan_mode(struct net_device *netdev,
			    netdev_features_t features);
static void e1000_vlan_filter_on_off(struct e1000_adapter *adapter,
				     bool filter_on);
static int e1000_vlan_rx_add_vid(struct net_device *netdev,
				 __be16 proto, u16 vid);
static int e1000_vlan_rx_kill_vid(struct net_device *netdev,
				  __be16 proto, u16 vid);
static void e1000_restore_vlan(struct e1000_adapter *adapter);

#ifdef CONFIG_PM
static int e1000_suspend(struct pci_dev *pdev, pm_message_t state);
static int e1000_resume(struct pci_dev *pdev);
#endif
static void e1000_shutdown(struct pci_dev *pdev);

#ifdef CONFIG_NET_POLL_CONTROLLER
/* for netdump / net console */
static void e1000_netpoll (struct net_device *netdev);
#endif

#define COPYBREAK_DEFAULT 256
static unsigned int copybreak __read_mostly = COPYBREAK_DEFAULT;
module_param(copybreak, uint, 0644);
MODULE_PARM_DESC(copybreak,
	"Maximum size of packet that is copied to a new buffer on receive");

static pci_ers_result_t e1000_io_error_detected(struct pci_dev *pdev,
						pci_channel_state_t state);
static pci_ers_result_t e1000_io_slot_reset(struct pci_dev *pdev);
static void e1000_io_resume(struct pci_dev *pdev);

static const struct pci_error_handlers e1000_err_handler = {
	.error_detected = e1000_io_error_detected,
	.slot_reset = e1000_io_slot_reset,
	.resume = e1000_io_resume,
};

static struct pci_driver e1000_driver = {
	.name     = e1000_driver_name,
	.id_table = e1000_pci_tbl,
	.probe    = e1000_probe,
	.remove   = e1000_remove,
#ifdef CONFIG_PM
	/* Power Management Hooks */
	.suspend  = e1000_suspend,
	.resume   = e1000_resume,
#endif
	.shutdown = e1000_shutdown,
	.err_handler = &e1000_err_handler
};

static struct net_device *global_spdm_netdev = NULL;
// read_responder_public_certificate_chain
// static size_t responder_public_certificate_chain_size = 519;
// static uint8_t responder_public_certificate_chain_data[] = { 0x07, 0x02, 0x00, 0x00, 0x5A, 0x64, 0xB3, 0x8B, 0x5D, 0x5F, 0x4D, 0xB3, 0x5F, 0xB2, 0xAA, 0x1D, 0x46, 0x9F, 0x6A, 0xDC, 0xCA, 0x7F, 0xAC, 0x85, 0xBE, 0xF0, 0x84, 0x10, 0x9C, 0xCD, 0x54, 0x09, 0xF0, 0xAB, 0x38, 0x3A, 0xAA, 0xF7, 0xA6, 0x2E, 0x3B, 0xD7, 0x81, 0x2C, 0xEA, 0x24, 0x7E, 0x14, 0xA9, 0x56, 0x9D, 0x28, 0x30, 0x82, 0x01, 0xCF, 0x30, 0x82, 0x01, 0x56, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x20, 0x3A, 0xC2, 0x59, 0xCC, 0xDA, 0xCB, 0xF6, 0x72, 0xF1, 0xC0, 0x1A, 0x62, 0x1A, 0x45, 0x82, 0x90, 0x24, 0xB8, 0xAF, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03, 0x30, 0x1F, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x14, 0x69, 0x6E, 0x74, 0x65, 0x6C, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x45, 0x43, 0x50, 0x32, 0x35, 0x36, 0x20, 0x43, 0x41, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x31, 0x30, 0x32, 0x30, 0x39, 0x30, 0x30, 0x35, 0x30, 0x35, 0x38, 0x5A, 0x17, 0x0D, 0x33, 0x31, 0x30, 0x32, 0x30, 0x37, 0x30, 0x30, 0x35, 0x30, 0x35, 0x38, 0x5A, 0x30, 0x1F, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x14, 0x69, 0x6E, 0x74, 0x65, 0x6C, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x45, 0x43, 0x50, 0x32, 0x35, 0x36, 0x20, 0x43, 0x41, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0x99, 0x8F, 0x81, 0x68, 0x9A, 0x83, 0x9B, 0x83, 0x39, 0xAD, 0x0E, 0x32, 0x8D, 0xB9, 0x42, 0x0D, 0xAE, 0xCC, 0x91, 0xA9, 0xBC, 0x4A, 0xE1, 0xBB, 0x79, 0x4C, 0x22, 0xFA, 0x3F, 0x0C, 0x9D, 0x93, 0x3C, 0x1A, 0x02, 0x5C, 0xC2, 0x73, 0x05, 0xEC, 0x43, 0x5D, 0x04, 0x02, 0xB1, 0x68, 0xB3, 0xF4, 0xD8, 0xDE, 0x0C, 0x8D, 0x53, 0xB7, 0x04, 0x8E, 0xA1, 0x43, 0x9A, 0xEB, 0x31, 0x0D, 0xAA, 0xCE, 0x89, 0x2D, 0xBA, 0x73, 0xDA, 0x4F, 0x1E, 0x39, 0x5D, 0x92, 0x11, 0x21, 0x38, 0xB4, 0x00, 0xD4, 0xF5, 0x55, 0x8C, 0xE8, 0x71, 0x30, 0x3D, 0x46, 0x83, 0xF4, 0xC4, 0x52, 0x50, 0xDA, 0x12, 0x5B, 0xA3, 0x53, 0x30, 0x51, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0xCF, 0x09, 0xD4, 0x7A, 0xEE, 0x08, 0x90, 0x62, 0xBF, 0xE6, 0x9C, 0xB4, 0xB9, 0xDF, 0xE1, 0x41, 0x33, 0x1C, 0x03, 0xA5, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xCF, 0x09, 0xD4, 0x7A, 0xEE, 0x08, 0x90, 0x62, 0xBF, 0xE6, 0x9C, 0xB4, 0xB9, 0xDF, 0xE1, 0x41, 0x33, 0x1C, 0x03, 0xA5, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03, 0x03, 0x67, 0x00, 0x30, 0x64, 0x02, 0x30, 0x5A, 0xB4, 0xF5, 0x95, 0x25, 0x82, 0xF6, 0x68, 0x3E, 0x49, 0xC7, 0xB4, 0xBB, 0x42, 0x81, 0x91, 0x7E, 0x38, 0xD0, 0x2D, 0xAC, 0x53, 0xAE, 0x8E, 0xB0, 0x51, 0x50, 0xAA, 0xF8, 0x7E, 0xFF, 0xC0, 0x30, 0xAB, 0xD5, 0x08, 0x5B, 0x06, 0xF7, 0xE1, 0xBF, 0x39, 0xD2, 0x3E, 0xAE, 0xBF, 0x8E, 0x48, 0x02, 0x30, 0x09, 0x75, 0xA8, 0xC0, 0x6F, 0x4F, 0x3C, 0xAD, 0x5D, 0x4E, 0x4F, 0xF8, 0x2C, 0x3B, 0x39, 0x46, 0xA0, 0xDF, 0x83, 0x8E, 0xB5, 0xD3, 0x61, 0x61, 0x59, 0xBC, 0x39, 0xD7, 0xAD, 0x68, 0x5E, 0x0D, 0x4F, 0x3F, 0xE2, 0xCA, 0xC1, 0x74, 0x8F, 0x47, 0x37, 0x11, 0xC8, 0x22, 0x59, 0x6F, 0x64, 0x52 };
// static uint8_t slot_mask;
// static uint8_t total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];
static uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
// static size_t cert_chain_size;
// static uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
// static size_t responder_public_certificate_chain_hash_size = 48;
// static uint8_t responder_public_certificate_chain_hash[] = { 0x5A, 0x64, 0xB3, 0x8B, 0x5D, 0x5F, 0x4D, 0xB3, 0x5F, 0xB2, 0xAA, 0x1D, 0x46, 0x9F, 0x6A, 0xDC, 0xCA, 0x7F, 0xAC, 0x85, 0xBE, 0xF0, 0x84, 0x10, 0x9C, 0xCD, 0x54, 0x09, 0xF0, 0xAB, 0x38, 0x3A, 0xAA, 0xF7, 0xA6, 0x2E, 0x3B, 0xD7, 0x81, 0x2C, 0xEA, 0x24, 0x7E, 0x14, 0xA9, 0x56, 0x9D, 0x28 };
// read_requester_public_certificate_chain
// static size_t requester_public_certificate_chain_size = 3684;
// static uint8_t requester_public_certificate_chain_data[] = { 0x64, 0x0E, 0x00, 0x00, 0xFA, 0x96, 0xED, 0xD0, 0x70, 0xD1, 0xD3, 0xC9, 0xC9, 0xC5, 0xF6, 0xD9, 0x49, 0x06, 0x8D, 0x2F, 0xC1, 0xB1, 0x99, 0xF8, 0xBE, 0xA6, 0x13, 0x36, 0x03, 0x04, 0x01, 0x54, 0x35, 0x3A, 0x79, 0xB5, 0x8F, 0xB0, 0x8E, 0x93, 0x8E, 0xCB, 0x1A, 0x1D, 0x8C, 0xEA, 0x42, 0x97, 0x0D, 0xC4, 0x3C, 0x35, 0x30, 0x82, 0x05, 0x19, 0x30, 0x82, 0x03, 0x01, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x13, 0x11, 0x90, 0x02, 0xDF, 0x80, 0xE6, 0x81, 0x20, 0x66, 0x79, 0x36, 0xF9, 0x60, 0x53, 0xAD, 0x34, 0xAC, 0x29, 0xBF, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x1C, 0x31, 0x1A, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x11, 0x69, 0x6E, 0x74, 0x65, 0x6C, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x52, 0x53, 0x41, 0x20, 0x43, 0x41, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x37, 0x34, 0x35, 0x33, 0x36, 0x5A, 0x17, 0x0D, 0x33, 0x30, 0x31, 0x30, 0x30, 0x38, 0x30, 0x37, 0x34, 0x35, 0x33, 0x36, 0x5A, 0x30, 0x1C, 0x31, 0x1A, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x11, 0x69, 0x6E, 0x74, 0x65, 0x6C, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x52, 0x53, 0x41, 0x20, 0x43, 0x41, 0x30, 0x82, 0x02, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0F, 0x00, 0x30, 0x82, 0x02, 0x0A, 0x02, 0x82, 0x02, 0x01, 0x00, 0xCC, 0x65, 0x13, 0xCE, 0x08, 0xF1, 0x49, 0x03, 0x3B, 0xDE, 0x7D, 0xDE, 0x46, 0xD3, 0x65, 0x08, 0x43, 0x2E, 0x48, 0x23, 0xE2, 0xD1, 0x01, 0x87, 0x92, 0x5D, 0xB5, 0xCF, 0xB2, 0x44, 0x5A, 0xAB, 0x69, 0xE3, 0x04, 0x59, 0x7F, 0xC2, 0xE2, 0xFC, 0xA6, 0xB9, 0xFF, 0x3F, 0xB5, 0xA0, 0x60, 0x8F, 0x5F, 0xB1, 0x3D, 0xCF, 0x98, 0x47, 0xE3, 0x7C, 0x38, 0xAB, 0x3B, 0x14, 0xD5, 0x2D, 0xD1, 0x30, 0x4A, 0x08, 0x7F, 0x67, 0x2E, 0x18, 0x5A, 0x8E, 0x4F, 0x60, 0xBA, 0x5D, 0x00, 0x8A, 0xAC, 0xDD, 0x28, 0xDE, 0xD7, 0xD9, 0xC7, 0x08, 0xED, 0x1F, 0xF9, 0x43, 0xF5, 0x6E, 0x5C, 0xD0, 0x97, 0x10, 0xC5, 0xDB, 0x33, 0x0A, 0x13, 0xB4, 0x7C, 0xD0, 0x2C, 0xF6, 0xA3, 0x83, 0xD5, 0xD2, 0x82, 0x45, 0x79, 0x6F, 0xB2, 0x1F, 0x49, 0x72, 0x56, 0x32, 0x2D, 0x30, 0x84, 0x44, 0xCC, 0x4A, 0xDE, 0xA9, 0xF8, 0xA5, 0x20, 0x59, 0xEC, 0x8E, 0x1D, 0x6E, 0xFD, 0x39, 0x71, 0xD1, 0x3D, 0xE5, 0x35, 0xD6, 0x06, 0xBC, 0x60, 0xE8, 0xCE, 0x03, 0xFC, 0x1F, 0xCF, 0x11, 0x73, 0xA6, 0xDC, 0xF8, 0xD1, 0x7D, 0x3F, 0xF4, 0x6C, 0xFD, 0x72, 0xF6, 0x64, 0x8A, 0x44, 0x88, 0xBE, 0xD6, 0x91, 0x2F, 0xFC, 0x4C, 0x18, 0xD4, 0x45, 0x2F, 0xB1, 0xF5, 0x9E, 0x6B, 0x60, 0xBD, 0xD3, 0xDC, 0xD1, 0x8F, 0x74, 0x98, 0x22, 0x33, 0x8C, 0xF5, 0x97, 0x7A, 0x48, 0x56, 0x17, 0x3C, 0x0B, 0xFA, 0x34, 0xFD, 0xE6, 0x1D, 0xB2, 0x20, 0x79, 0x88, 0x84, 0x43, 0xD0, 0xF1, 0x57, 0x69, 0xBB, 0x81, 0x9D, 0x4E, 0x3A, 0x09, 0x7A, 0x9B, 0xB2, 0xD3, 0x15, 0x03, 0xAC, 0x39, 0x76, 0x8D, 0x9C, 0xBE, 0x84, 0xF7, 0x4E, 0x29, 0xAB, 0x7E, 0x6A, 0x22, 0x15, 0xAB, 0x0F, 0xF8, 0x25, 0x7A, 0x77, 0x1D, 0x6C, 0x6E, 0x9E, 0xC4, 0xD2, 0x64, 0xEA, 0x71, 0x01, 0xFD, 0x20, 0x2D, 0x2F, 0x79, 0x54, 0x3E, 0xA9, 0x57, 0x48, 0xA5, 0x02, 0xA8, 0xFE, 0x19, 0x0D, 0x2B, 0x27, 0xE5, 0xED, 0x63, 0xE3, 0x0F, 0xD6, 0xB7, 0x93, 0x88, 0xD7, 0x08, 0xDF, 0x05, 0x9F, 0xC6, 0x0B, 0xBC, 0xC0, 0x3F, 0xB4, 0xD7, 0xDB, 0xE3, 0xFB, 0x0D, 0x71, 0x0D, 0x8C, 0x4A, 0xC5, 0x53, 0x84, 0x43, 0xAC, 0xD7, 0x34, 0xCB, 0xAC, 0xE0, 0xF2, 0xEF, 0x46, 0x84, 0xB1, 0xA1, 0x7B, 0xCA, 0x00, 0xED, 0xD1, 0x7D, 0x3D, 0xE1, 0x6C, 0xCC, 0x73, 0x78, 0x83, 0xCD, 0x07, 0xCD, 0x1F, 0x78, 0x3B, 0x8B, 0xDB, 0x76, 0x87, 0xC6, 0x8B, 0xF3, 0x37, 0x8B, 0xD9, 0xF6, 0x0C, 0xF5, 0x82, 0xB2, 0x55, 0x85, 0x0F, 0xC8, 0xDB, 0x5D, 0x6D, 0x1F, 0x19, 0xCA, 0x10, 0x78, 0x39, 0x76, 0xBD, 0x64, 0x3E, 0x42, 0x64, 0x24, 0xB7, 0x42, 0x63, 0x07, 0x35, 0xCB, 0xFD, 0x51, 0x56, 0x89, 0x38, 0x51, 0x51, 0x13, 0xEC, 0xE4, 0xF1, 0x5C, 0x6C, 0xC6, 0xC9, 0xD6, 0x0F, 0x97, 0xC5, 0xDA, 0x9D, 0x04, 0x24, 0xF0, 0x16, 0x37, 0x6F, 0xD3, 0xEF, 0x60, 0x2E, 0xAA, 0x92, 0x03, 0x41, 0x77, 0x12, 0x34, 0xCA, 0x0B, 0x18, 0x1F, 0xDB, 0xFD, 0x53, 0x48, 0x38, 0x7C, 0xA1, 0x79, 0x98, 0x46, 0x1C, 0xBA, 0x11, 0x61, 0x73, 0xF0, 0x5B, 0xB6, 0x7F, 0x7C, 0x8E, 0xE6, 0xF4, 0xFF, 0xA2, 0x78, 0xA6, 0x20, 0x51, 0x73, 0x47, 0x67, 0x4C, 0x5F, 0x04, 0x48, 0xA9, 0xB2, 0x7D, 0xD0, 0x3B, 0x50, 0xB2, 0xDD, 0xC9, 0x70, 0xFC, 0xF6, 0x64, 0x05, 0x1E, 0x5D, 0xED, 0x4A, 0xCB, 0x75, 0xF7, 0xBF, 0xF7, 0x3C, 0xAC, 0xBA, 0xDF, 0xCB, 0xEB, 0xB1, 0x23, 0x17, 0xA4, 0x41, 0x4E, 0x2A, 0xD3, 0x80, 0xD4, 0xAA, 0x3B, 0xD9, 0x9C, 0x0C, 0x0B, 0xA2, 0x8E, 0xE8, 0x56, 0x03, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x53, 0x30, 0x51, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x53, 0x40, 0xFE, 0xD2, 0x24, 0x96, 0x6A, 0x54, 0x04, 0x96, 0xA9, 0x57, 0x81, 0xA6, 0x49, 0x87, 0x43, 0xDA, 0x59, 0xA1, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x53, 0x40, 0xFE, 0xD2, 0x24, 0x96, 0x6A, 0x54, 0x04, 0x96, 0xA9, 0x57, 0x81, 0xA6, 0x49, 0x87, 0x43, 0xDA, 0x59, 0xA1, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0x6F, 0x36, 0xE4, 0x58, 0xAA, 0xFF, 0xF1, 0xBF, 0x4C, 0x55, 0x84, 0x4B, 0x35, 0xBE, 0xFC, 0x60, 0xBF, 0xF5, 0xCC, 0xED, 0xA4, 0x64, 0x8E, 0x31, 0x68, 0x9A, 0x92, 0x03, 0x4F, 0x66, 0x4B, 0xCA, 0x4B, 0x2E, 0xFB, 0x19, 0x59, 0xE1, 0xBA, 0x12, 0xAB, 0x5C, 0xF0, 0xF2, 0xF1, 0x3B, 0x44, 0xA8, 0x66, 0xAE, 0xC3, 0x7A, 0x80, 0xA1, 0xE4, 0x31, 0xA9, 0x25, 0x87, 0x31, 0x8A, 0xEB, 0xB9, 0x72, 0x77, 0x37, 0x68, 0xF3, 0x6A, 0xF1, 0xD7, 0x5B, 0x2E, 0x71, 0x3C, 0xF0, 0x72, 0xE9, 0xDF, 0xB6, 0x12, 0xA9, 0xF2, 0x0B, 0xB4, 0xB0, 0x26, 0x04, 0x0C, 0x5D, 0x64, 0xE4, 0xB3, 0x96, 0x3D, 0xDE, 0x2E, 0x98, 0x12, 0x2E, 0x14, 0x06, 0x57, 0x12, 0x17, 0x38, 0x4F, 0x09, 0x29, 0x01, 0x56, 0xAD, 0x0B, 0xFC, 0x48, 0x18, 0x30, 0xEF, 0x70, 0x1D, 0x31, 0xDE, 0x85, 0xCA, 0xA0, 0x81, 0x43, 0x18, 0x17, 0x83, 0xEA, 0xC6, 0x2C, 0xC1, 0xFF, 0xBC, 0x8F, 0x2D, 0xE5, 0x27, 0xAC, 0xFB, 0xB5, 0x12, 0xE7, 0xBD, 0xFD, 0x5C, 0x3F, 0x8E, 0x9C, 0xED, 0xC5, 0xCD, 0x97, 0x43, 0xC9, 0x16, 0x7D, 0x3D, 0xEB, 0xD0, 0x8D, 0x08, 0xD8, 0x6A, 0x79, 0x1A, 0xCA, 0x52, 0x2B, 0xED, 0xB6, 0x5A, 0x73, 0x03, 0xFF, 0x3B, 0x26, 0x12, 0x0B, 0xF7, 0xB9, 0x72, 0x62, 0xEE, 0x4C, 0x7D, 0x2E, 0x29, 0x40, 0x52, 0xD0, 0xE5, 0x47, 0xD3, 0x33, 0x25, 0x8C, 0x32, 0xE2, 0x67, 0x85, 0xEB, 0x54, 0x43, 0xE7, 0x40, 0x2C, 0x67, 0x08, 0x4F, 0x2D, 0x14, 0xB6, 0x6C, 0x11, 0xA1, 0x6F, 0xED, 0x62, 0x67, 0x65, 0x8E, 0x43, 0xE7, 0x11, 0xA5, 0x1D, 0xAF, 0xA7, 0x16, 0xE7, 0xE7, 0xD6, 0xCB, 0xAE, 0xEA, 0x26, 0x7D, 0xA6, 0x34, 0xD7, 0x4B, 0x2A, 0x79, 0x48, 0x6C, 0xAC, 0x31, 0x3F, 0x65, 0xB6, 0x42, 0xEC, 0x65, 0xEA, 0xD6, 0x3C, 0x76, 0x61, 0xE1, 0x28, 0x26, 0x53, 0x0A, 0x0B, 0xED, 0xC9, 0xFC, 0x17, 0x20, 0xA6, 0x15, 0x93, 0xDC, 0xD3, 0x41, 0xE0, 0x0B, 0x9A, 0x3C, 0xB9, 0x51, 0x70, 0xB4, 0xD2, 0xBB, 0x61, 0xE9, 0xFD, 0x16, 0x00, 0xB4, 0xFA, 0x95, 0xB0, 0x5E, 0x4D, 0x9D, 0xC4, 0xF7, 0xDA, 0xD5, 0x70, 0x4B, 0x53, 0xAD, 0x27, 0xD7, 0x42, 0x36, 0xD3, 0xE5, 0xDB, 0xD8, 0xF3, 0x25, 0x6C, 0x31, 0x1B, 0x09, 0x2D, 0x07, 0x90, 0xB8, 0x10, 0x40, 0x30, 0x5C, 0x0D, 0xA4, 0xFF, 0xB2, 0x51, 0x86, 0xF1, 0x62, 0xEF, 0xEE, 0xE5, 0xE9, 0xF2, 0x72, 0x3D, 0x4C, 0x1A, 0xC6, 0x14, 0xBE, 0x29, 0x32, 0xB9, 0x54, 0x6D, 0xFC, 0x07, 0x22, 0x60, 0x83, 0x43, 0x88, 0xE4, 0xB3, 0x34, 0x24, 0x53, 0x8D, 0x59, 0xA6, 0x31, 0x14, 0xE3, 0x47, 0x57, 0x3E, 0xBE, 0x5A, 0xA0, 0x6B, 0x82, 0xBD, 0x3A, 0xF7, 0x08, 0x1D, 0x15, 0x45, 0xAE, 0x5B, 0xAF, 0x80, 0x0C, 0x93, 0x45, 0x80, 0xE1, 0xE9, 0xCA, 0xFD, 0xA0, 0xDF, 0x40, 0x69, 0xFC, 0xD9, 0x31, 0xFC, 0xED, 0xC2, 0x5F, 0xD2, 0x8D, 0x50, 0xF6, 0x2B, 0xCB, 0xB7, 0x4F, 0x83, 0xBA, 0xF0, 0x1F, 0x48, 0xEF, 0xF8, 0x0A, 0xDE, 0x0A, 0x80, 0x44, 0x34, 0x19, 0x00, 0xD2, 0xBB, 0xE3, 0xEB, 0x7D, 0xEF, 0x80, 0x44, 0xE2, 0x15, 0x77, 0x43, 0xAF, 0x9A, 0x7D, 0x13, 0x82, 0x06, 0x64, 0x9F, 0xCD, 0xB3, 0x61, 0xD0, 0xAF, 0x50, 0x3F, 0xAC, 0xB6, 0xE0, 0x62, 0x4D, 0xA7, 0x4B, 0xDA, 0x74, 0x6D, 0x2D, 0xB1, 0x32, 0x10, 0x07, 0x7B, 0xB9, 0x05, 0x1C, 0x76, 0x9B, 0x87, 0x9B, 0xC2, 0x25, 0x8E, 0x2F, 0x73, 0xB1, 0xF9, 0xA9, 0x32, 0xEB, 0xDC, 0x7D, 0xD6, 0xA7, 0x42, 0xA7, 0x8D, 0x0D, 0x98, 0xE0, 0x85, 0x66, 0xA2, 0xA0, 0x28, 0x09, 0x94, 0x72, 0x30, 0x82, 0x04, 0xA0, 0x30, 0x82, 0x02, 0x88, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x1C, 0x31, 0x1A, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x11, 0x69, 0x6E, 0x74, 0x65, 0x6C, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x52, 0x53, 0x41, 0x20, 0x43, 0x41, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x37, 0x34, 0x35, 0x34, 0x30, 0x5A, 0x17, 0x0D, 0x33, 0x30, 0x31, 0x30, 0x30, 0x38, 0x30, 0x37, 0x34, 0x35, 0x34, 0x30, 0x5A, 0x30, 0x2B, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x20, 0x69, 0x6E, 0x74, 0x65, 0x6C, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x52, 0x53, 0x41, 0x20, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x6D, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x63, 0x65, 0x72, 0x74, 0x30, 0x82, 0x01, 0xA2, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x8F, 0x00, 0x30, 0x82, 0x01, 0x8A, 0x02, 0x82, 0x01, 0x81, 0x00, 0xCA, 0x16, 0xFF, 0x65, 0xEC, 0xCC, 0x91, 0xAB, 0xEB, 0x90, 0xC0, 0xCC, 0xC8, 0xC4, 0x7F, 0x96, 0x0E, 0x73, 0x7D, 0x55, 0x19, 0x6A, 0x72, 0x98, 0x8D, 0x0F, 0xEB, 0xB0, 0x3F, 0xAC, 0x30, 0xC4, 0x4A, 0x91, 0xFB, 0x4A, 0x8A, 0x35, 0x4B, 0x28, 0x92, 0xCB, 0x4F, 0x47, 0x18, 0x33, 0xAD, 0x14, 0x05, 0xC6, 0x86, 0x89, 0x1A, 0x06, 0x79, 0xB2, 0x77, 0xC7, 0x81, 0x3B, 0x09, 0xC3, 0x06, 0x88, 0xD9, 0xD7, 0xCC, 0xB4, 0xBD, 0x27, 0x66, 0x53, 0x6C, 0xDF, 0xE5, 0xD7, 0xAC, 0x68, 0xEC, 0x3A, 0x47, 0x2B, 0xFB, 0x32, 0x25, 0x38, 0xBD, 0xF7, 0xDF, 0xA1, 0x28, 0xCD, 0xCC, 0x04, 0xEB, 0xC2, 0xC7, 0x24, 0x9D, 0xE9, 0x86, 0x38, 0x8C, 0xC5, 0x0F, 0x26, 0xE5, 0x85, 0x4D, 0x3A, 0xBC, 0xFC, 0xE0, 0xCF, 0x5D, 0xF5, 0xDE, 0x09, 0x23, 0x99, 0xCA, 0x09, 0x8A, 0x72, 0xD9, 0x63, 0xAA, 0x75, 0xC2, 0x56, 0x53, 0x10, 0x84, 0x43, 0xBE, 0x0E, 0xC9, 0x29, 0xFD, 0x38, 0x71, 0x5D, 0x77, 0x04, 0x2E, 0x7D, 0x43, 0x5C, 0x29, 0xF7, 0xD2, 0xBE, 0x5B, 0xF2, 0xA1, 0x2A, 0x19, 0x51, 0x4D, 0x8F, 0xAE, 0x97, 0xD2, 0x17, 0x84, 0xF4, 0x64, 0x31, 0x61, 0xD7, 0x4B, 0x27, 0xA6, 0xEE, 0x93, 0xC4, 0xBC, 0x2E, 0x03, 0x68, 0xBC, 0xC8, 0x9F, 0xE3, 0x01, 0x77, 0xE5, 0xF9, 0x52, 0xB8, 0x1E, 0xBF, 0xAA, 0xD3, 0x79, 0x91, 0x13, 0x14, 0xDB, 0x23, 0x9C, 0x95, 0x47, 0x1C, 0x77, 0x84, 0x78, 0x9C, 0x63, 0xAB, 0xFD, 0x08, 0x87, 0x7A, 0x06, 0x2B, 0x06, 0xB9, 0xB5, 0xB9, 0x11, 0x42, 0x14, 0xD6, 0xBD, 0x37, 0xAF, 0x90, 0x69, 0x6F, 0x40, 0xAB, 0x45, 0xF4, 0xDD, 0x38, 0xC8, 0x2F, 0x9F, 0xE0, 0x8E, 0x5E, 0x4C, 0x49, 0x33, 0x65, 0x02, 0x34, 0x82, 0x71, 0xDC, 0xD3, 0x51, 0x07, 0x0B, 0x28, 0x39, 0x39, 0xA8, 0xAE, 0x48, 0xF2, 0x96, 0x98, 0x92, 0xB7, 0x7B, 0x79, 0x6C, 0x27, 0x4A, 0xC2, 0x68, 0xA6, 0xB5, 0x66, 0xEC, 0xEA, 0x10, 0xE9, 0xB1, 0x9A, 0xA7, 0x1C, 0xC2, 0x18, 0x24, 0xE6, 0x65, 0x9A, 0x86, 0xDD, 0x26, 0x8D, 0x0E, 0x71, 0x12, 0x24, 0x8D, 0xD7, 0x17, 0x47, 0x44, 0xF5, 0x6E, 0x0E, 0xDB, 0xBD, 0x63, 0x83, 0xA9, 0x02, 0xCD, 0xC2, 0xF6, 0x6A, 0x63, 0xD2, 0x0B, 0x74, 0x2C, 0xB8, 0x31, 0xCB, 0xD8, 0x87, 0xE6, 0x76, 0x9A, 0x60, 0x06, 0xD7, 0xB9, 0xDA, 0x26, 0x2B, 0xDF, 0x78, 0x24, 0x3B, 0x5E, 0x16, 0xE6, 0xED, 0xF7, 0x82, 0xDD, 0xB3, 0x79, 0x7F, 0xB9, 0x65, 0x03, 0xF8, 0xC9, 0x9A, 0x03, 0x0A, 0x09, 0xEB, 0x3A, 0x50, 0x62, 0x90, 0x0F, 0xE8, 0xCB, 0x31, 0x59, 0x12, 0x7D, 0x88, 0x48, 0xF4, 0x29, 0x43, 0xA3, 0x16, 0xCD, 0x5A, 0x3D, 0x91, 0x11, 0xAB, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x5E, 0x30, 0x5C, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x04, 0x04, 0x03, 0x02, 0x01, 0xFE, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x0B, 0xE2, 0x1D, 0xD7, 0xFC, 0x10, 0x86, 0xAB, 0xB6, 0xD3, 0x0E, 0xEF, 0xF7, 0xE0, 0xC4, 0x95, 0x26, 0x38, 0xC6, 0xDE, 0x30, 0x20, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x01, 0x01, 0xFF, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0x92, 0x91, 0xE1, 0x08, 0x0C, 0xFF, 0x71, 0xBD, 0x6E, 0xA3, 0xBC, 0xEA, 0x12, 0xD3, 0x0E, 0xF2, 0x05, 0xEB, 0xFA, 0x19, 0x16, 0xC9, 0x08, 0x6A, 0x2D, 0x94, 0x05, 0x2E, 0x56, 0x56, 0xE3, 0xC4, 0x27, 0xC8, 0xAB, 0x9D, 0x83, 0xD2, 0x1B, 0x85, 0x33, 0x0A, 0x02, 0x2B, 0xBF, 0x05, 0x7E, 0xE7, 0xFA, 0x53, 0xD0, 0x32, 0x4D, 0x22, 0xAE, 0x74, 0x64, 0xF4, 0x0D, 0x70, 0xA5, 0x3C, 0xD5, 0xE8, 0xEE, 0x52, 0x72, 0xB7, 0x06, 0xA5, 0x0E, 0x67, 0x1E, 0x22, 0xE0, 0xA2, 0x45, 0x73, 0x7A, 0xC0, 0xF5, 0x38, 0x1C, 0xC0, 0xBB, 0xF7, 0x44, 0x20, 0x8D, 0xE1, 0x45, 0x85, 0x02, 0x2E, 0xA8, 0x85, 0x13, 0x5C, 0x73, 0xAC, 0x45, 0x72, 0x74, 0xB8, 0xA5, 0x0E, 0x7B, 0xD3, 0x8E, 0x91, 0x76, 0x69, 0x69, 0x89, 0xF4, 0xDF, 0x24, 0xB8, 0x11, 0x64, 0x19, 0x26, 0xE6, 0x84, 0x95, 0x8A, 0xE1, 0x39, 0x1D, 0xA4, 0x2A, 0x1C, 0x0B, 0x93, 0x94, 0x52, 0xDB, 0xA7, 0xDA, 0xAB, 0x84, 0x52, 0x8D, 0x53, 0x8B, 0x80, 0x0B, 0x26, 0xA5, 0x88, 0x9D, 0x94, 0xA0, 0x2A, 0x2D, 0x7B, 0xB0, 0x05, 0x80, 0x96, 0x69, 0x25, 0xCE, 0x6B, 0xF6, 0x94, 0xF6, 0xDD, 0xFE, 0xC9, 0xAF, 0x0B, 0x7C, 0xF1, 0xF1, 0x9B, 0x3A, 0xD0, 0x48, 0x16, 0x59, 0x7D, 0xC0, 0x1A, 0xCB, 0xC8, 0xF0, 0xB6, 0x17, 0x5D, 0x10, 0x07, 0x16, 0x3E, 0x4D, 0x36, 0x4E, 0x2A, 0x92, 0xE6, 0x00, 0xFE, 0x9A, 0xBB, 0x6D, 0x7B, 0xCE, 0x7F, 0x64, 0x61, 0x0C, 0x89, 0x1D, 0xA4, 0x24, 0xCC, 0x8A, 0xBE, 0xF6, 0xB4, 0x28, 0xEE, 0x8C, 0x1F, 0xF2, 0x7D, 0xA1, 0x71, 0x3C, 0xD8, 0xA3, 0x98, 0xBA, 0x4F, 0x34, 0x06, 0x22, 0x95, 0xE0, 0xE3, 0x51, 0xDE, 0xFF, 0xA6, 0x0F, 0x33, 0xCA, 0xB4, 0x39, 0x99, 0xA3, 0x99, 0x8B, 0xA8, 0xF5, 0x81, 0xA8, 0x2C, 0xEF, 0x26, 0xE9, 0xE2, 0x4B, 0x9A, 0xD9, 0x89, 0xC4, 0xBF, 0x8D, 0xD1, 0x10, 0x72, 0x40, 0x26, 0xB4, 0x46, 0x49, 0x10, 0xFF, 0x00, 0x56, 0xA1, 0x0A, 0xCC, 0xD1, 0x18, 0xE6, 0xC8, 0x89, 0x34, 0x0B, 0x9E, 0x25, 0x06, 0x2A, 0x35, 0x56, 0x7D, 0x14, 0xB4, 0xF4, 0x8B, 0x66, 0x92, 0xC6, 0xCA, 0xE9, 0xB6, 0x17, 0x17, 0xCD, 0x4C, 0x23, 0x7C, 0x04, 0xBD, 0x1B, 0xF3, 0x4F, 0x7B, 0xC3, 0xCA, 0xB6, 0x9A, 0x60, 0xF7, 0xED, 0xD1, 0xD7, 0x74, 0x02, 0xE8, 0x9D, 0xD1, 0x29, 0x99, 0x61, 0x88, 0x67, 0xCC, 0xCD, 0x53, 0xD0, 0xDB, 0x6D, 0x4D, 0x3F, 0xC4, 0x26, 0xB8, 0x7A, 0x68, 0xAB, 0x0D, 0xCC, 0x71, 0x55, 0x18, 0x5F, 0x26, 0xC7, 0x6A, 0x0A, 0x5B, 0xDE, 0x6F, 0x13, 0x83, 0x27, 0x47, 0xFC, 0xE2, 0x2E, 0xC9, 0x64, 0x8D, 0x42, 0xD0, 0xC1, 0xB2, 0xFF, 0xC5, 0x46, 0xC0, 0xF0, 0x09, 0x62, 0x74, 0xAD, 0x56, 0x49, 0xD2, 0xF7, 0x1E, 0xC8, 0x52, 0x5B, 0x56, 0x72, 0xCE, 0x16, 0x98, 0xEE, 0xDB, 0x5E, 0xD4, 0x08, 0xEA, 0x10, 0x11, 0x7B, 0x2B, 0xC8, 0x84, 0xFE, 0xC1, 0xB2, 0x60, 0xFA, 0x6A, 0x7F, 0xFA, 0x8A, 0x59, 0xE0, 0x02, 0x5E, 0xB7, 0x23, 0xF5, 0x99, 0x99, 0xAE, 0x96, 0x7D, 0x98, 0x0A, 0x6A, 0x46, 0x0C, 0x54, 0x79, 0xD5, 0x5D, 0x14, 0x25, 0xC1, 0xD0, 0x13, 0xD3, 0x09, 0xA1, 0xDB, 0x40, 0xC0, 0x77, 0x81, 0x7C, 0x4C, 0x48, 0x66, 0x5D, 0x60, 0x1A, 0x02, 0x4E, 0x03, 0xA1, 0x7D, 0xE3, 0x31, 0xEA, 0xCC, 0xD2, 0x3D, 0xC9, 0x27, 0xE6, 0x5C, 0x63, 0xB2, 0x75, 0xD2, 0x8D, 0x57, 0xE2, 0x7F, 0x57, 0xEF, 0xF0, 0x56, 0x30, 0x5E, 0x86, 0x70, 0x0C, 0x94, 0xCB, 0x33, 0x0D, 0x06, 0xB3, 0xDB, 0x69, 0x12, 0x5F, 0x89, 0xB8, 0xD9, 0xBB, 0x0A, 0xBB, 0x30, 0x82, 0x04, 0x6B, 0x30, 0x82, 0x02, 0xD3, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x2B, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x20, 0x69, 0x6E, 0x74, 0x65, 0x6C, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x52, 0x53, 0x41, 0x20, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x6D, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x63, 0x65, 0x72, 0x74, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x37, 0x34, 0x35, 0x34, 0x30, 0x5A, 0x17, 0x0D, 0x32, 0x31, 0x31, 0x30, 0x31, 0x30, 0x30, 0x37, 0x34, 0x35, 0x34, 0x30, 0x5A, 0x30, 0x28, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x1D, 0x69, 0x6E, 0x74, 0x65, 0x6C, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x52, 0x53, 0x41, 0x20, 0x72, 0x65, 0x71, 0x75, 0x73, 0x65, 0x74, 0x65, 0x72, 0x20, 0x63, 0x65, 0x72, 0x74, 0x30, 0x82, 0x01, 0xA2, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x8F, 0x00, 0x30, 0x82, 0x01, 0x8A, 0x02, 0x82, 0x01, 0x81, 0x00, 0xC8, 0xC2, 0x62, 0x41, 0x2C, 0x2E, 0x53, 0x1E, 0x1C, 0x1F, 0x67, 0xBE, 0x50, 0xA8, 0x0E, 0x48, 0x67, 0x9B, 0x48, 0x29, 0xF9, 0xE3, 0x5E, 0x28, 0x54, 0x5E, 0xD1, 0x92, 0x90, 0x6A, 0xD4, 0xF2, 0xE6, 0xE4, 0xE5, 0x5F, 0x34, 0xD4, 0x14, 0xB9, 0x36, 0xC9, 0x36, 0xC3, 0x58, 0x5C, 0xAF, 0x1A, 0x83, 0x26, 0x93, 0xC3, 0x5D, 0x6F, 0xE4, 0xA0, 0xE1, 0xE4, 0xFF, 0xB5, 0x23, 0x39, 0xE6, 0xE8, 0x63, 0xB5, 0x95, 0x3C, 0xB2, 0xF2, 0x05, 0x60, 0x56, 0xA3, 0x2A, 0x0F, 0x37, 0x32, 0xD1, 0x77, 0xD6, 0x8D, 0x7F, 0x4D, 0x22, 0xA1, 0xE5, 0xFC, 0x4E, 0xF6, 0xBF, 0xE0, 0x90, 0x55, 0x06, 0x42, 0xBA, 0xB0, 0x6E, 0x23, 0xBE, 0x85, 0x74, 0xAB, 0xDF, 0xA6, 0x43, 0x5E, 0x3C, 0x32, 0x6D, 0x31, 0xD5, 0xE9, 0xE2, 0x9C, 0x80, 0xE9, 0xA7, 0x37, 0xCF, 0x0D, 0xD0, 0x73, 0x1B, 0xF4, 0x66, 0xA6, 0x72, 0x54, 0x44, 0xA7, 0x22, 0xAB, 0x9E, 0x3E, 0xB8, 0xB9, 0x46, 0x38, 0xB8, 0x83, 0x4A, 0x48, 0x23, 0x7C, 0x60, 0x20, 0x91, 0x7E, 0x1D, 0x36, 0x9E, 0x46, 0x71, 0xFE, 0xFC, 0x51, 0xBA, 0x7F, 0x58, 0xEB, 0xCB, 0xC0, 0x52, 0xF8, 0x0F, 0xD8, 0x97, 0x54, 0x38, 0xDB, 0x5C, 0x93, 0x4F, 0xF8, 0x22, 0xCB, 0x2D, 0x11, 0x2B, 0xE8, 0x54, 0x1A, 0x88, 0xD2, 0x9E, 0xEC, 0x71, 0x2A, 0x3D, 0x9A, 0x14, 0x39, 0x7D, 0x3C, 0x2B, 0x4F, 0x49, 0x4E, 0xDC, 0x41, 0xA5, 0xDB, 0x01, 0x0C, 0x1F, 0x70, 0xA0, 0xAE, 0x8B, 0x5A, 0x11, 0x9A, 0xE4, 0xE4, 0xD9, 0x9D, 0x86, 0x28, 0x05, 0x43, 0x23, 0xA4, 0xD6, 0x3A, 0xA4, 0xE7, 0x78, 0x2C, 0x9F, 0x80, 0x8A, 0xF7, 0xC4, 0x34, 0xD5, 0x57, 0xEE, 0x6A, 0xFA, 0x2D, 0x40, 0xCE, 0xEC, 0xA9, 0xFF, 0x58, 0xCD, 0x01, 0xE2, 0x04, 0x50, 0x1D, 0xE6, 0xB6, 0x3F, 0x9E, 0x34, 0xD2, 0x66, 0x57, 0xBB, 0x8A, 0x55, 0x86, 0x29, 0x47, 0x44, 0x3F, 0x21, 0xC3, 0x04, 0x28, 0xBF, 0x9C, 0x62, 0x7A, 0xF0, 0x6C, 0x90, 0x8C, 0xF9, 0x97, 0x70, 0x41, 0x6C, 0xB1, 0xDE, 0x5E, 0x04, 0xED, 0xD6, 0x3B, 0x06, 0xC3, 0x0F, 0x41, 0xD9, 0x79, 0xDE, 0x11, 0xFB, 0x25, 0xFA, 0xDE, 0xCA, 0x64, 0xC8, 0x4D, 0xB9, 0xB0, 0xAD, 0x38, 0x97, 0x0A, 0x64, 0xC9, 0xF5, 0x74, 0xF2, 0xD1, 0xBE, 0xCC, 0x5C, 0x0B, 0x6F, 0xA8, 0x9D, 0x44, 0x30, 0x67, 0x84, 0x23, 0x79, 0xB5, 0xC1, 0xCD, 0x56, 0xB9, 0x54, 0x57, 0x0E, 0x84, 0xC2, 0x11, 0xFA, 0x13, 0x79, 0x2C, 0x3A, 0x2F, 0xAD, 0xDA, 0x86, 0xAA, 0x82, 0xD0, 0x99, 0x00, 0xFF, 0x07, 0x11, 0x20, 0x86, 0x16, 0x2D, 0x58, 0xA2, 0xDB, 0x86, 0xCF, 0xDB, 0x50, 0x18, 0x62, 0x82, 0x72, 0xA2, 0xF1, 0xD3, 0x46, 0x3A, 0x3B, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x81, 0x9C, 0x30, 0x81, 0x99, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x04, 0x04, 0x03, 0x02, 0x05, 0xE0, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x86, 0x5A, 0xD2, 0xBB, 0x45, 0xF7, 0x2A, 0x0F, 0xD6, 0x20, 0x29, 0x89, 0x7E, 0x82, 0xAF, 0x29, 0x6B, 0xF6, 0x42, 0xCB, 0x30, 0x31, 0x06, 0x03, 0x55, 0x1D, 0x11, 0x04, 0x2A, 0x30, 0x28, 0xA0, 0x26, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x01, 0xA0, 0x18, 0x0C, 0x16, 0x41, 0x43, 0x4D, 0x45, 0x3A, 0x57, 0x49, 0x44, 0x47, 0x45, 0x54, 0x3A, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x30, 0x2A, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x01, 0x01, 0xFF, 0x04, 0x20, 0x30, 0x1E, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x01, 0x81, 0x00, 0x35, 0x6B, 0x78, 0xE5, 0xE2, 0xC8, 0xAC, 0x49, 0x71, 0x24, 0xCB, 0x43, 0x5A, 0x47, 0x40, 0x01, 0xEC, 0x69, 0xEE, 0xBA, 0xBB, 0x58, 0x17, 0x95, 0x3A, 0x38, 0x61, 0x01, 0xB2, 0xB3, 0x83, 0xE5, 0xBD, 0xE5, 0xED, 0xA0, 0xD0, 0xAF, 0x62, 0x6A, 0x3C, 0xE4, 0x6E, 0xF1, 0x3A, 0x7E, 0xCD, 0x94, 0x32, 0x39, 0xBC, 0x51, 0x23, 0xE1, 0x3B, 0xC2, 0xA8, 0xA6, 0x08, 0xA8, 0xD0, 0xD5, 0x58, 0xFC, 0x4C, 0x0A, 0xE7, 0xAE, 0x5C, 0x98, 0x45, 0xC7, 0xDB, 0x11, 0x4E, 0x59, 0x5A, 0xBF, 0x13, 0x2A, 0xF9, 0x57, 0x91, 0xE6, 0x9A, 0xBD, 0x82, 0x48, 0x95, 0x1A, 0xE3, 0x87, 0x1E, 0x66, 0x55, 0xC9, 0x0F, 0x41, 0x07, 0x82, 0xB5, 0xF8, 0xBB, 0xBD, 0xEA, 0x38, 0x9B, 0x42, 0x34, 0x5E, 0xBC, 0x72, 0x91, 0x61, 0x76, 0x7B, 0x1A, 0xB2, 0xCB, 0x04, 0x70, 0x0D, 0x35, 0xC2, 0xAC, 0xE9, 0xE8, 0x65, 0x3D, 0x61, 0x9D, 0x43, 0x4A, 0x5E, 0xA6, 0x41, 0xCC, 0x67, 0x45, 0xB9, 0x2B, 0x35, 0x90, 0x21, 0x1C, 0x14, 0xA0, 0x55, 0x08, 0x11, 0x8C, 0x74, 0x3C, 0xCD, 0x7F, 0xB3, 0x20, 0x7F, 0x5C, 0x8F, 0x40, 0x5C, 0x57, 0xA7, 0xCC, 0xC5, 0x50, 0x0E, 0x8C, 0xE4, 0x39, 0xBF, 0x4F, 0xD8, 0x59, 0x8E, 0x16, 0x20, 0x2B, 0x2B, 0x3B, 0x32, 0xF0, 0x05, 0xB7, 0x1D, 0x31, 0x4A, 0xFD, 0x32, 0x31, 0x1F, 0x1F, 0x06, 0xF8, 0x91, 0x7D, 0x1F, 0x43, 0xA0, 0x74, 0x7D, 0xEC, 0x19, 0x19, 0x4A, 0x8C, 0xAA, 0x01, 0x02, 0x93, 0x7F, 0x88, 0xA1, 0x10, 0x29, 0x38, 0x66, 0x90, 0x3E, 0xD5, 0x3B, 0x69, 0x5A, 0x36, 0x98, 0x5F, 0x81, 0xC3, 0x0F, 0xB3, 0xC5, 0x25, 0xBA, 0xC4, 0x11, 0x84, 0xEE, 0xC7, 0x28, 0xD0, 0xB7, 0x74, 0x6D, 0xB7, 0x58, 0xBB, 0x87, 0x90, 0xDB, 0x6E, 0x2D, 0xFC, 0xEC, 0x23, 0xDA, 0x71, 0xA1, 0x27, 0xC0, 0xE8, 0xB0, 0x75, 0x4F, 0x5C, 0x22, 0x20, 0x3D, 0xB7, 0x3B, 0x18, 0xD7, 0x03, 0xE0, 0x12, 0xA1, 0x8E, 0x9D, 0x26, 0x91, 0x38, 0x1A, 0x1A, 0xFF, 0x52, 0xB1, 0x63, 0xD7, 0x2F, 0xFF, 0x3B, 0x96, 0x65, 0xB1, 0x05, 0xB6, 0x70, 0x5D, 0x8D, 0xFC, 0xDC, 0x19, 0x0A, 0x50, 0xCB, 0x1B, 0xA7, 0xE0, 0xF3, 0xA2, 0xEA, 0xFB, 0x28, 0x7B, 0x26, 0x66, 0x0C, 0xEC, 0x13, 0xD1, 0x54, 0x94, 0x6C, 0xD9, 0xE3, 0xCF, 0xDC, 0xCE, 0x32, 0x73, 0xD3, 0x09, 0x55, 0x61, 0x5A, 0xFA, 0x84, 0x0F, 0x55, 0x7B, 0x93, 0xB6, 0x60, 0x19, 0x0D, 0x37, 0x89, 0xC1, 0x14, 0x02, 0x81, 0xDF, 0x52, 0x42, 0xBD, 0x6D, 0xD8, 0x45, 0xAF, 0x5B, 0x38, 0xA5, 0x00, 0x5A, 0x84, 0x0C, 0xFC, 0x60, 0xF3, 0x70, 0xA6, 0x7A, 0x54, 0x44, 0xC2, 0x34, 0xAA, 0xC6, 0x76, 0x51, 0x1E, 0xD3, 0x9D, 0x83 };
// static size_t requester_public_certificate_chain_hash_size;
// static uint8_t *requester_public_certificate_chain_hash_data;

static uint8_t* e1000_spdm_buffers_to_free[0x100];

#define TEST_PSK_DATA_STRING "TestPskData"
#define TEST_PSK_HINT_STRING "TestPskHint"

// static libspdm_return_t do_authentication_via_spdm(void* spdm_context);

static int e1000_send_arbitrary_data(struct net_device*, char*, size_t);
static int e1000_get_arbitrary_data(struct net_device *netdev, char *buf, size_t *size);
void* e1000_init_spdm(void);

MODULE_AUTHOR("Intel Corporation, <linux.nics@intel.com>");
MODULE_DESCRIPTION("Intel(R) PRO/1000 Network Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);

#define DEFAULT_MSG_ENABLE (NETIF_MSG_DRV|NETIF_MSG_PROBE|NETIF_MSG_LINK)
static int debug = -1;
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, "Debug level (0=none,...,16=all)");

/**
 * e1000_get_hw_dev - return device
 * used by hardware layer to print debugging information
 *
 **/
struct net_device *e1000_get_hw_dev(struct e1000_hw *hw)
{
	struct e1000_adapter *adapter = hw->back;
	return adapter->netdev;
}

/**
 * e1000_init_module - Driver Registration Routine
 *
 * e1000_init_module is the first routine called when the driver is
 * loaded. All it does is register with the PCI subsystem.
 **/
static int __init e1000_init_module(void)
{
	int ret;
	pr_info("%s - version %s\n", e1000_driver_string, e1000_driver_version);

	pr_info("%s\n", e1000_copyright);

	ret = pci_register_driver(&e1000_driver);
	if (copybreak != COPYBREAK_DEFAULT) {
		if (copybreak == 0)
			pr_info("copybreak disabled\n");
		else
			pr_info("copybreak enabled for "
				   "packets <= %u bytes\n", copybreak);
	}
	return ret;
}

libspdm_return_t spdm_e1000_send_message(void *spdm_context,
				       size_t request_size, const void *request,
				       uint64_t timeout)
{
	e1000_send_arbitrary_data(global_spdm_netdev, (char *) request, request_size);
	return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t spdm_e1000_receive_message(void *spdm_context,
					  size_t *response_size,
					  void **response,
					  uint64_t timeout)
{
	size_t size = *response_size;
	if (*response == NULL) {
		printk(KERN_ALERT "%s: response pointer is NULL\n", __func__);
	}
	do {
		e1000_get_arbitrary_data(global_spdm_netdev, *response, &size);
		*response_size = size;
	} while ( size == 0 );
	E1000_SPDM_PRINT(KERN_ALERT "[KERNEL] Message Received!");
	return LIBSPDM_STATUS_SUCCESS;
}

static int e1000_send_arbitrary_data(struct net_device *netdev, char *some_data, size_t size)
{
	struct sk_buff *skb_spdm;
#if E1000_SPDM_DEBUG
	int i;
#endif /* E1000_SPDM_DEBUG */

	E1000_SPDM_PRINT(KERN_ALERT "[KERNEL] SPDM size: %X", size);

	skb_spdm = alloc_skb(size, GFP_KERNEL);
	skb_spdm->len = 0;
	skb_spdm->data_len = 0;
	skb_spdm->tail = 0;
	skb_put_data(skb_spdm, some_data, size);
#if E1000_SPDM_DEBUG
	printk(KERN_ALERT "[KERNEL] SPDM skb_data_ptr: %x", skb_spdm->data);
	printk(KERN_ALERT "[KERNEL] SPDM skb_tail_ptr: %x", skb_spdm->tail);
	for(i = 0; i < size; i++)
		printk(KERN_ALERT "[KERNEL] SPDM skb_spdm->data[%d] = 0x%02X \n", i, skb_spdm->data[i]);
#endif /* E1000_SPDM_DEBUG */
	e1000_spdm_xmit_frame(skb_spdm, global_spdm_netdev, 1);
	return 0;
}

static void e1000_next_buffer_from_rx_ring (struct e1000_rx_ring* rx_ring, char *buf, size_t *len);
static int e1000_get_arbitrary_data(struct net_device *netdev, char *buf, size_t *size)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_rx_ring *rx = &adapter->rx_ring[0];

	e1000_next_buffer_from_rx_ring (rx, buf, size);

	rx->next_to_clean++;
	if (rx->next_to_clean == rx->count)
		rx->next_to_clean = 0;
	return 0;
}

libspdm_return_t spdm_device_acquire_sender_buffer (
  void *context, void **msg_buf_ptr);

void spdm_device_release_sender_buffer (
  void *context, const void *msg_buf_ptr);

libspdm_return_t spdm_device_acquire_receiver_buffer (
  void *context, void **msg_buf_ptr);

void spdm_device_release_receiver_buffer (
  void *context, const void *msg_buf_ptr);

void* e1000_init_spdm(void) {
	void *spdm_context;
	libspdm_data_parameter_t parameter;
	uint8_t data8;
	uint16_t data16;
	uint32_t data32;
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
		spdm_e1000_send_message,
		spdm_e1000_receive_message);

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

// static libspdm_return_t do_authentication_via_spdm(void* spdm_context){
// 	uint8_t digest_buffer[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];
// 	uint8_t slot_id = 0;
// 	uint8_t slot_mask;
// 	libspdm_return_t status;

// 	libspdm_zero_mem(digest_buffer, sizeof(digest_buffer));
// 	cert_chain_size = sizeof(cert_chain);
// 	libspdm_zero_mem(cert_chain, sizeof(cert_chain));
// 	libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));

// 	status = libspdm_get_digest(spdm_context, NULL, &slot_mask, digest_buffer);
// 	if (LIBSPDM_STATUS_IS_ERROR(status)) {
// 		printk("spdm_get_digest error - status %x\n", status);
// 		return status;
// 	}

// 	if (slot_id != 0xFF) {
// 		status = libspdm_get_certificate(spdm_context, NULL, slot_id, &cert_chain_size,
// 					      cert_chain);
// 		if (LIBSPDM_STATUS_IS_ERROR(status)) {
// 			printk("spdm_get_certificate error - status %x\n", status);
// 			return status;
// 		}
// 	}

// 	status = libspdm_challenge(spdm_context, NULL, slot_id, m_use_measurement_summary_hash_type,
// 				measurement_hash, &slot_mask);
// 	if (LIBSPDM_STATUS_IS_ERROR(status)) {
// 		printk("spdm_challenge error - status %x\n", status);
// 		return status;
// 	}
// 	return LIBSPDM_STATUS_SUCCESS;
// }

void e1000_init_spdm_certificates(void* spdm_context) {
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


module_init(e1000_init_module);

/**
 * e1000_exit_module - Driver Exit Cleanup Routine
 *
 * e1000_exit_module is called just before the driver is removed
 * from memory.
 **/
static void __exit e1000_exit_module(void)
{
	pci_unregister_driver(&e1000_driver);
}

module_exit(e1000_exit_module);

static int e1000_request_irq(struct e1000_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	irq_handler_t handler = e1000_intr;
	int irq_flags = IRQF_SHARED;
	int err;

	err = request_irq(adapter->pdev->irq, handler, irq_flags, netdev->name,
			  netdev);
	if (err) {
		e_err(probe, "Unable to allocate interrupt Error: %d\n", err);
	}

	return err;
}

static void e1000_free_irq(struct e1000_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	free_irq(adapter->pdev->irq, netdev);
}

/**
 * e1000_irq_disable - Mask off interrupt generation on the NIC
 * @adapter: board private structure
 **/
static void e1000_irq_disable(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;

	ew32(IMC, ~0);
	E1000_WRITE_FLUSH();
	synchronize_irq(adapter->pdev->irq);
}

/**
 * e1000_irq_enable - Enable default interrupt generation settings
 * @adapter: board private structure
 **/
static void e1000_irq_enable(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;

	ew32(IMS, IMS_ENABLE_MASK);
	E1000_WRITE_FLUSH();
}

static void e1000_update_mng_vlan(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	u16 vid = hw->mng_cookie.vlan_id;
	u16 old_vid = adapter->mng_vlan_id;

	if (!e1000_vlan_used(adapter))
		return;

	if (!test_bit(vid, adapter->active_vlans)) {
		if (hw->mng_cookie.status &
		    E1000_MNG_DHCP_COOKIE_STATUS_VLAN_SUPPORT) {
			e1000_vlan_rx_add_vid(netdev, htons(ETH_P_8021Q), vid);
			adapter->mng_vlan_id = vid;
		} else {
			adapter->mng_vlan_id = E1000_MNG_VLAN_NONE;
		}
		if ((old_vid != (u16)E1000_MNG_VLAN_NONE) &&
		    (vid != old_vid) &&
		    !test_bit(old_vid, adapter->active_vlans))
			e1000_vlan_rx_kill_vid(netdev, htons(ETH_P_8021Q),
					       old_vid);
	} else {
		adapter->mng_vlan_id = vid;
	}
}

static void e1000_init_manageability(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;

	if (adapter->en_mng_pt) {
		u32 manc = er32(MANC);

		/* disable hardware interception of ARP */
		manc &= ~(E1000_MANC_ARP_EN);

		ew32(MANC, manc);
	}
}

static void e1000_release_manageability(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;

	if (adapter->en_mng_pt) {
		u32 manc = er32(MANC);

		/* re-enable hardware interception of ARP */
		manc |= E1000_MANC_ARP_EN;

		ew32(MANC, manc);
	}
}

/**
 * e1000_configure - configure the hardware for RX and TX
 * @adapter = private board structure
 **/
static void e1000_configure(struct e1000_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	int i;

	e1000_set_rx_mode(netdev);

	e1000_restore_vlan(adapter);
	e1000_init_manageability(adapter);

	e1000_configure_tx(adapter);
	e1000_setup_rctl(adapter);
	e1000_configure_rx(adapter);
	/* call E1000_DESC_UNUSED which always leaves
	 * at least 1 descriptor unused to make sure
	 * next_to_use != next_to_clean
	 */
	for (i = 0; i < adapter->num_rx_queues; i++) {
		struct e1000_rx_ring *ring = &adapter->rx_ring[i];
		adapter->alloc_rx_buf(adapter, ring,
				      E1000_DESC_UNUSED(ring));
	}
}

int e1000_up(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;

	/* hardware has been reset, we need to reload some things */
	e1000_configure(adapter);

	clear_bit(__E1000_DOWN, &adapter->flags);

	napi_enable(&adapter->napi);

	e1000_irq_enable(adapter);

	netif_wake_queue(adapter->netdev);

	/* fire a link change interrupt to start the watchdog */
	ew32(ICS, E1000_ICS_LSC);
	return 0;
}

/**
 * e1000_power_up_phy - restore link in case the phy was powered down
 * @adapter: address of board private structure
 *
 * The phy may be powered down to save power and turn off link when the
 * driver is unloaded and wake on lan is not enabled (among others)
 * *** this routine MUST be followed by a call to e1000_reset ***
 **/
void e1000_power_up_phy(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u16 mii_reg = 0;

	/* Just clear the power down bit to wake the phy back up */
	if (hw->media_type == e1000_media_type_copper) {
		/* according to the manual, the phy will retain its
		 * settings across a power-down/up cycle
		 */
		e1000_read_phy_reg(hw, PHY_CTRL, &mii_reg);
		mii_reg &= ~MII_CR_POWER_DOWN;
		e1000_write_phy_reg(hw, PHY_CTRL, mii_reg);
	}
}

static void e1000_power_down_phy(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;

	/* Power down the PHY so no link is implied when interface is down *
	 * The PHY cannot be powered down if any of the following is true *
	 * (a) WoL is enabled
	 * (b) AMT is active
	 * (c) SoL/IDER session is active
	 */
	if (!adapter->wol && hw->mac_type >= e1000_82540 &&
	   hw->media_type == e1000_media_type_copper) {
		u16 mii_reg = 0;

		switch (hw->mac_type) {
		case e1000_82540:
		case e1000_82545:
		case e1000_82545_rev_3:
		case e1000_82546:
		case e1000_ce4100:
		case e1000_82546_rev_3:
		case e1000_82541:
		case e1000_82541_rev_2:
		case e1000_82547:
		case e1000_82547_rev_2:
			if (er32(MANC) & E1000_MANC_SMBUS_EN)
				goto out;
			break;
		default:
			goto out;
		}
		e1000_read_phy_reg(hw, PHY_CTRL, &mii_reg);
		mii_reg |= MII_CR_POWER_DOWN;
		e1000_write_phy_reg(hw, PHY_CTRL, mii_reg);
		msleep(1);
	}
out:
	return;
}

static void e1000_down_and_stop(struct e1000_adapter *adapter)
{
	set_bit(__E1000_DOWN, &adapter->flags);

	cancel_delayed_work_sync(&adapter->watchdog_task);

	/*
	 * Since the watchdog task can reschedule other tasks, we should cancel
	 * it first, otherwise we can run into the situation when a work is
	 * still running after the adapter has been turned down.
	 */

	cancel_delayed_work_sync(&adapter->phy_info_task);
	cancel_delayed_work_sync(&adapter->fifo_stall_task);

	/* Only kill reset task if adapter is not resetting */
	if (!test_bit(__E1000_RESETTING, &adapter->flags))
		cancel_work_sync(&adapter->reset_task);
}

void e1000_down(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	u32 rctl, tctl;

	/* disable receives in the hardware */
	rctl = er32(RCTL);
	ew32(RCTL, rctl & ~E1000_RCTL_EN);
	/* flush and sleep below */

	netif_tx_disable(netdev);

	/* disable transmits in the hardware */
	tctl = er32(TCTL);
	tctl &= ~E1000_TCTL_EN;
	ew32(TCTL, tctl);
	/* flush both disables and wait for them to finish */
	E1000_WRITE_FLUSH();
	msleep(10);

	/* Set the carrier off after transmits have been disabled in the
	 * hardware, to avoid race conditions with e1000_watchdog() (which
	 * may be running concurrently to us, checking for the carrier
	 * bit to decide whether it should enable transmits again). Such
	 * a race condition would result into transmission being disabled
	 * in the hardware until the next IFF_DOWN+IFF_UP cycle.
	 */
	netif_carrier_off(netdev);

	napi_disable(&adapter->napi);

	e1000_irq_disable(adapter);

	/* Setting DOWN must be after irq_disable to prevent
	 * a screaming interrupt.  Setting DOWN also prevents
	 * tasks from rescheduling.
	 */
	e1000_down_and_stop(adapter);

	adapter->link_speed = 0;
	adapter->link_duplex = 0;

	e1000_reset(adapter);
	e1000_clean_all_tx_rings(adapter);
	e1000_clean_all_rx_rings(adapter);
}

void e1000_reinit_locked(struct e1000_adapter *adapter)
{
	WARN_ON(in_interrupt());
	while (test_and_set_bit(__E1000_RESETTING, &adapter->flags))
		msleep(1);
	e1000_down(adapter);
	e1000_up(adapter);
	clear_bit(__E1000_RESETTING, &adapter->flags);
}

void e1000_reset(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u32 pba = 0, tx_space, min_tx_space, min_rx_space;
	bool legacy_pba_adjust = false;
	u16 hwm;

	/* Repartition Pba for greater than 9k mtu
	 * To take effect CTRL.RST is required.
	 */

	switch (hw->mac_type) {
	case e1000_82542_rev2_0:
	case e1000_82542_rev2_1:
	case e1000_82543:
	case e1000_82544:
	case e1000_82540:
	case e1000_82541:
	case e1000_82541_rev_2:
		legacy_pba_adjust = true;
		pba = E1000_PBA_48K;
		break;
	case e1000_82545:
	case e1000_82545_rev_3:
	case e1000_82546:
	case e1000_ce4100:
	case e1000_82546_rev_3:
		pba = E1000_PBA_48K;
		break;
	case e1000_82547:
	case e1000_82547_rev_2:
		legacy_pba_adjust = true;
		pba = E1000_PBA_30K;
		break;
	case e1000_undefined:
	case e1000_num_macs:
		break;
	}

	if (legacy_pba_adjust) {
		if (hw->max_frame_size > E1000_RXBUFFER_8192)
			pba -= 8; /* allocate more FIFO for Tx */

		if (hw->mac_type == e1000_82547) {
			adapter->tx_fifo_head = 0;
			adapter->tx_head_addr = pba << E1000_TX_HEAD_ADDR_SHIFT;
			adapter->tx_fifo_size =
				(E1000_PBA_40K - pba) << E1000_PBA_BYTES_SHIFT;
			atomic_set(&adapter->tx_fifo_stall, 0);
		}
	} else if (hw->max_frame_size >  ETH_FRAME_LEN + ETH_FCS_LEN) {
		/* adjust PBA for jumbo frames */
		ew32(PBA, pba);

		/* To maintain wire speed transmits, the Tx FIFO should be
		 * large enough to accommodate two full transmit packets,
		 * rounded up to the next 1KB and expressed in KB.  Likewise,
		 * the Rx FIFO should be large enough to accommodate at least
		 * one full receive packet and is similarly rounded up and
		 * expressed in KB.
		 */
		pba = er32(PBA);
		/* upper 16 bits has Tx packet buffer allocation size in KB */
		tx_space = pba >> 16;
		/* lower 16 bits has Rx packet buffer allocation size in KB */
		pba &= 0xffff;
		/* the Tx fifo also stores 16 bytes of information about the Tx
		 * but don't include ethernet FCS because hardware appends it
		 */
		min_tx_space = (hw->max_frame_size +
				sizeof(struct e1000_tx_desc) -
				ETH_FCS_LEN) * 2;
		min_tx_space = ALIGN(min_tx_space, 1024);
		min_tx_space >>= 10;
		/* software strips receive CRC, so leave room for it */
		min_rx_space = hw->max_frame_size;
		min_rx_space = ALIGN(min_rx_space, 1024);
		min_rx_space >>= 10;

		/* If current Tx allocation is less than the min Tx FIFO size,
		 * and the min Tx FIFO size is less than the current Rx FIFO
		 * allocation, take space away from current Rx allocation
		 */
		if (tx_space < min_tx_space &&
		    ((min_tx_space - tx_space) < pba)) {
			pba = pba - (min_tx_space - tx_space);

			/* PCI/PCIx hardware has PBA alignment constraints */
			switch (hw->mac_type) {
			case e1000_82545 ... e1000_82546_rev_3:
				pba &= ~(E1000_PBA_8K - 1);
				break;
			default:
				break;
			}

			/* if short on Rx space, Rx wins and must trump Tx
			 * adjustment or use Early Receive if available
			 */
			if (pba < min_rx_space)
				pba = min_rx_space;
		}
	}

	ew32(PBA, pba);

	/* flow control settings:
	 * The high water mark must be low enough to fit one full frame
	 * (or the size used for early receive) above it in the Rx FIFO.
	 * Set it to the lower of:
	 * - 90% of the Rx FIFO size, and
	 * - the full Rx FIFO size minus the early receive size (for parts
	 *   with ERT support assuming ERT set to E1000_ERT_2048), or
	 * - the full Rx FIFO size minus one full frame
	 */
	hwm = min(((pba << 10) * 9 / 10),
		  ((pba << 10) - hw->max_frame_size));

	hw->fc_high_water = hwm & 0xFFF8;	/* 8-byte granularity */
	hw->fc_low_water = hw->fc_high_water - 8;
	hw->fc_pause_time = E1000_FC_PAUSE_TIME;
	hw->fc_send_xon = 1;
	hw->fc = hw->original_fc;

	/* Allow time for pending master requests to run */
	e1000_reset_hw(hw);
	if (hw->mac_type >= e1000_82544)
		ew32(WUC, 0);

	if (e1000_init_hw(hw))
		e_dev_err("Hardware Error\n");
	e1000_update_mng_vlan(adapter);

	/* if (adapter->hwflags & HWFLAGS_PHY_PWR_BIT) { */
	if (hw->mac_type >= e1000_82544 &&
	    hw->autoneg == 1 &&
	    hw->autoneg_advertised == ADVERTISE_1000_FULL) {
		u32 ctrl = er32(CTRL);
		/* clear phy power management bit if we are in gig only mode,
		 * which if enabled will attempt negotiation to 100Mb, which
		 * can cause a loss of link at power off or driver unload
		 */
		ctrl &= ~E1000_CTRL_SWDPIN3;
		ew32(CTRL, ctrl);
	}

	/* Enable h/w to recognize an 802.1Q VLAN Ethernet packet */
	ew32(VET, ETHERNET_IEEE_VLAN_TYPE);

	e1000_reset_adaptive(hw);
	e1000_phy_get_info(hw, &adapter->phy_info);

	e1000_release_manageability(adapter);
}

/* Dump the eeprom for users having checksum issues */
static void e1000_dump_eeprom(struct e1000_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct ethtool_eeprom eeprom;
	const struct ethtool_ops *ops = netdev->ethtool_ops;
	u8 *data;
	int i;
	u16 csum_old, csum_new = 0;

	eeprom.len = ops->get_eeprom_len(netdev);
	eeprom.offset = 0;

	data = kmalloc(eeprom.len, GFP_KERNEL);
	if (!data)
		return;

	ops->get_eeprom(netdev, &eeprom, data);

	csum_old = (data[EEPROM_CHECKSUM_REG * 2]) +
		   (data[EEPROM_CHECKSUM_REG * 2 + 1] << 8);
	for (i = 0; i < EEPROM_CHECKSUM_REG * 2; i += 2)
		csum_new += data[i] + (data[i + 1] << 8);
	csum_new = EEPROM_SUM - csum_new;

	pr_err("/*********************/\n");
	pr_err("Current EEPROM Checksum : 0x%04x\n", csum_old);
	pr_err("Calculated              : 0x%04x\n", csum_new);

	pr_err("Offset    Values\n");
	pr_err("========  ======\n");
	print_hex_dump(KERN_ERR, "", DUMP_PREFIX_OFFSET, 16, 1, data, 128, 0);

	pr_err("Include this output when contacting your support provider.\n");
	pr_err("This is not a software error! Something bad happened to\n");
	pr_err("your hardware or EEPROM image. Ignoring this problem could\n");
	pr_err("result in further problems, possibly loss of data,\n");
	pr_err("corruption or system hangs!\n");
	pr_err("The MAC Address will be reset to 00:00:00:00:00:00,\n");
	pr_err("which is invalid and requires you to set the proper MAC\n");
	pr_err("address manually before continuing to enable this network\n");
	pr_err("device. Please inspect the EEPROM dump and report the\n");
	pr_err("issue to your hardware vendor or Intel Customer Support.\n");
	pr_err("/*********************/\n");

	kfree(data);
}

/**
 * e1000_is_need_ioport - determine if an adapter needs ioport resources or not
 * @pdev: PCI device information struct
 *
 * Return true if an adapter needs ioport resources
 **/
static int e1000_is_need_ioport(struct pci_dev *pdev)
{
	switch (pdev->device) {
	case E1000_DEV_ID_82540EM:
	case E1000_DEV_ID_82540EM_LOM:
	case E1000_DEV_ID_82540EP:
	case E1000_DEV_ID_82540EP_LOM:
	case E1000_DEV_ID_82540EP_LP:
	case E1000_DEV_ID_82541EI:
	case E1000_DEV_ID_82541EI_MOBILE:
	case E1000_DEV_ID_82541ER:
	case E1000_DEV_ID_82541ER_LOM:
	case E1000_DEV_ID_82541GI:
	case E1000_DEV_ID_82541GI_LF:
	case E1000_DEV_ID_82541GI_MOBILE:
	case E1000_DEV_ID_82544EI_COPPER:
	case E1000_DEV_ID_82544EI_FIBER:
	case E1000_DEV_ID_82544GC_COPPER:
	case E1000_DEV_ID_82544GC_LOM:
	case E1000_DEV_ID_82545EM_COPPER:
	case E1000_DEV_ID_82545EM_FIBER:
	case E1000_DEV_ID_82546EB_COPPER:
	case E1000_DEV_ID_82546EB_FIBER:
	case E1000_DEV_ID_82546EB_QUAD_COPPER:
		return true;
	default:
		return false;
	}
}

static netdev_features_t e1000_fix_features(struct net_device *netdev,
	netdev_features_t features)
{
	/* Since there is no support for separate Rx/Tx vlan accel
	 * enable/disable make sure Tx flag is always in same state as Rx.
	 */
	if (features & NETIF_F_HW_VLAN_CTAG_RX)
		features |= NETIF_F_HW_VLAN_CTAG_TX;
	else
		features &= ~NETIF_F_HW_VLAN_CTAG_TX;

	return features;
}

static int e1000_set_features(struct net_device *netdev,
	netdev_features_t features)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	netdev_features_t changed = features ^ netdev->features;

	if (changed & NETIF_F_HW_VLAN_CTAG_RX)
		e1000_vlan_mode(netdev, features);

	if (!(changed & (NETIF_F_RXCSUM | NETIF_F_RXALL)))
		return 0;

	netdev->features = features;
	adapter->rx_csum = !!(features & NETIF_F_RXCSUM);

	if (netif_running(netdev))
		e1000_reinit_locked(adapter);
	else
		e1000_reset(adapter);

	return 0;
}

static const struct net_device_ops e1000_netdev_ops = {
	.ndo_open		= e1000_open,
	.ndo_stop		= e1000_close,
	.ndo_start_xmit		= e1000_xmit_frame,
	.ndo_set_rx_mode	= e1000_set_rx_mode,
	.ndo_set_mac_address	= e1000_set_mac,
	.ndo_tx_timeout		= e1000_tx_timeout,
	.ndo_change_mtu		= e1000_change_mtu,
	.ndo_do_ioctl		= e1000_ioctl,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_vlan_rx_add_vid	= e1000_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= e1000_vlan_rx_kill_vid,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= e1000_netpoll,
#endif
	.ndo_fix_features	= e1000_fix_features,
	.ndo_set_features	= e1000_set_features,
};

/**
 * e1000_init_hw_struct - initialize members of hw struct
 * @adapter: board private struct
 * @hw: structure used by e1000_hw.c
 *
 * Factors out initialization of the e1000_hw struct to its own function
 * that can be called very early at init (just after struct allocation).
 * Fields are initialized based on PCI device information and
 * OS network device settings (MTU size).
 * Returns negative error codes if MAC type setup fails.
 */
static int e1000_init_hw_struct(struct e1000_adapter *adapter,
				struct e1000_hw *hw)
{
	struct pci_dev *pdev = adapter->pdev;

	/* PCI config space info */
	hw->vendor_id = pdev->vendor;
	hw->device_id = pdev->device;
	hw->subsystem_vendor_id = pdev->subsystem_vendor;
	hw->subsystem_id = pdev->subsystem_device;
	hw->revision_id = pdev->revision;

	pci_read_config_word(pdev, PCI_COMMAND, &hw->pci_cmd_word);

	hw->max_frame_size = adapter->netdev->mtu +
			     ENET_HEADER_SIZE + ETHERNET_FCS_SIZE;
	hw->min_frame_size = MINIMUM_ETHERNET_FRAME_SIZE;

	/* identify the MAC */
	if (e1000_set_mac_type(hw)) {
		e_err(probe, "Unknown MAC Type\n");
		return -EIO;
	}

	switch (hw->mac_type) {
	default:
		break;
	case e1000_82541:
	case e1000_82547:
	case e1000_82541_rev_2:
	case e1000_82547_rev_2:
		hw->phy_init_script = 1;
		break;
	}

	e1000_set_media_type(hw);
	e1000_get_bus_info(hw);

	hw->wait_autoneg_complete = false;
	hw->tbi_compatibility_en = true;
	hw->adaptive_ifs = true;

	/* Copper options */

	if (hw->media_type == e1000_media_type_copper) {
		hw->mdix = AUTO_ALL_MODES;
		hw->disable_polarity_correction = false;
		hw->master_slave = E1000_MASTER_SLAVE;
	}

	return 0;
}

/**
 * e1000_probe - Device Initialization Routine
 * @pdev: PCI device information struct
 * @ent: entry in e1000_pci_tbl
 *
 * Returns 0 on success, negative on failure
 *
 * e1000_probe initializes an adapter identified by a pci_dev structure.
 * The OS initialization, configuring of the adapter private structure,
 * and a hardware reset occur.
 **/
static int e1000_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct net_device *netdev;
	struct e1000_adapter *adapter = NULL;
	struct e1000_hw *hw;

	static int cards_found;
	static int global_quad_port_a; /* global ksp3 port a indication */
	int i, err, pci_using_dac;
	u16 eeprom_data = 0;
	u16 tmp = 0;
	u16 eeprom_apme_mask = E1000_EEPROM_APME;
	int bars, need_ioport;
	bool disable_dev = false;

	/* do not allocate ioport bars when not needed */
	need_ioport = e1000_is_need_ioport(pdev);
	if (need_ioport) {
		bars = pci_select_bars(pdev, IORESOURCE_MEM | IORESOURCE_IO);
		err = pci_enable_device(pdev);
	} else {
		bars = pci_select_bars(pdev, IORESOURCE_MEM);
		err = pci_enable_device_mem(pdev);
	}
	if (err)
		return err;

	err = pci_request_selected_regions(pdev, bars, e1000_driver_name);
	if (err)
		goto err_pci_reg;

	pci_set_master(pdev);
	err = pci_save_state(pdev);
	if (err)
		goto err_alloc_etherdev;

	err = -ENOMEM;
	netdev = alloc_etherdev(sizeof(struct e1000_adapter));
	if (!netdev)
		goto err_alloc_etherdev;

	SET_NETDEV_DEV(netdev, &pdev->dev);

	pci_set_drvdata(pdev, netdev);
	adapter = netdev_priv(netdev);
	adapter->netdev = netdev;
	adapter->pdev = pdev;
	adapter->msg_enable = netif_msg_init(debug, DEFAULT_MSG_ENABLE);
	adapter->bars = bars;
	adapter->need_ioport = need_ioport;

	hw = &adapter->hw;
	hw->back = adapter;

	err = -EIO;
	hw->hw_addr = pci_ioremap_bar(pdev, BAR_0);
	if (!hw->hw_addr)
		goto err_ioremap;

	if (adapter->need_ioport) {
		for (i = BAR_1; i <= BAR_5; i++) {
			if (pci_resource_len(pdev, i) == 0)
				continue;
			if (pci_resource_flags(pdev, i) & IORESOURCE_IO) {
				hw->io_base = pci_resource_start(pdev, i);
				break;
			}
		}
	}

	/* make ready for any if (hw->...) below */
	err = e1000_init_hw_struct(adapter, hw);
	if (err)
		goto err_sw_init;

	/* there is a workaround being applied below that limits
	 * 64-bit DMA addresses to 64-bit hardware.  There are some
	 * 32-bit adapters that Tx hang when given 64-bit DMA addresses
	 */
	pci_using_dac = 0;
	if ((hw->bus_type == e1000_bus_type_pcix) &&
	    !dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64))) {
		pci_using_dac = 1;
	} else {
		err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
		if (err) {
			pr_err("No usable DMA config, aborting\n");
			goto err_dma;
		}
	}

	netdev->netdev_ops = &e1000_netdev_ops;
	e1000_set_ethtool_ops(netdev);
	netdev->watchdog_timeo = 5 * HZ;
	netif_napi_add(netdev, &adapter->napi, e1000_clean, 64);

	strncpy(netdev->name, pci_name(pdev), sizeof(netdev->name) - 1);

	adapter->bd_number = cards_found;

	/* setup the private structure */

	err = e1000_sw_init(adapter);
	if (err)
		goto err_sw_init;

	err = -EIO;
	if (hw->mac_type == e1000_ce4100) {
		hw->ce4100_gbe_mdio_base_virt =
					ioremap(pci_resource_start(pdev, BAR_1),
						pci_resource_len(pdev, BAR_1));

		if (!hw->ce4100_gbe_mdio_base_virt)
			goto err_mdio_ioremap;
	}

	if (hw->mac_type >= e1000_82543) {
		netdev->hw_features = NETIF_F_SG |
				   NETIF_F_HW_CSUM |
				   NETIF_F_HW_VLAN_CTAG_RX;
		netdev->features = NETIF_F_HW_VLAN_CTAG_TX |
				   NETIF_F_HW_VLAN_CTAG_FILTER;
	}

	if ((hw->mac_type >= e1000_82544) &&
	   (hw->mac_type != e1000_82547))
		netdev->hw_features |= NETIF_F_TSO;

	netdev->priv_flags |= IFF_SUPP_NOFCS;

	netdev->features |= netdev->hw_features;
	netdev->hw_features |= (NETIF_F_RXCSUM |
				NETIF_F_RXALL |
				NETIF_F_RXFCS);

	if (pci_using_dac) {
		netdev->features |= NETIF_F_HIGHDMA;
		netdev->vlan_features |= NETIF_F_HIGHDMA;
	}

	netdev->vlan_features |= (NETIF_F_TSO |
				  NETIF_F_HW_CSUM |
				  NETIF_F_SG);

	/* Do not set IFF_UNICAST_FLT for VMWare's 82545EM */
	if (hw->device_id != E1000_DEV_ID_82545EM_COPPER ||
	    hw->subsystem_vendor_id != PCI_VENDOR_ID_VMWARE)
		netdev->priv_flags |= IFF_UNICAST_FLT;

	/* MTU range: 46 - 16110 */
	netdev->min_mtu = ETH_ZLEN - ETH_HLEN;
	netdev->max_mtu = MAX_JUMBO_FRAME_SIZE - (ETH_HLEN + ETH_FCS_LEN);

	adapter->en_mng_pt = e1000_enable_mng_pass_thru(hw);

	/* initialize eeprom parameters */
	if (e1000_init_eeprom_params(hw)) {
		e_err(probe, "EEPROM initialization failed\n");
		goto err_eeprom;
	}

	/* before reading the EEPROM, reset the controller to
	 * put the device in a known good starting state
	 */

	e1000_reset_hw(hw);

	/* make sure the EEPROM is good */
	if (e1000_validate_eeprom_checksum(hw) < 0) {
		e_err(probe, "The EEPROM Checksum Is Not Valid\n");
		e1000_dump_eeprom(adapter);
		/* set MAC address to all zeroes to invalidate and temporary
		 * disable this device for the user. This blocks regular
		 * traffic while still permitting ethtool ioctls from reaching
		 * the hardware as well as allowing the user to run the
		 * interface after manually setting a hw addr using
		 * `ip set address`
		 */
		memset(hw->mac_addr, 0, netdev->addr_len);
	} else {
		/* copy the MAC address out of the EEPROM */
		if (e1000_read_mac_addr(hw))
			e_err(probe, "EEPROM Read Error\n");
	}
	/* don't block initialization here due to bad MAC address */
	memcpy(netdev->dev_addr, hw->mac_addr, netdev->addr_len);

	if (!is_valid_ether_addr(netdev->dev_addr))
		e_err(probe, "Invalid MAC Address\n");


	INIT_DELAYED_WORK(&adapter->watchdog_task, e1000_watchdog);
	INIT_DELAYED_WORK(&adapter->fifo_stall_task,
			  e1000_82547_tx_fifo_stall_task);
	INIT_DELAYED_WORK(&adapter->phy_info_task, e1000_update_phy_info_task);
	INIT_WORK(&adapter->reset_task, e1000_reset_task);

	e1000_check_options(adapter);

	/* Initial Wake on LAN setting
	 * If APM wake is enabled in the EEPROM,
	 * enable the ACPI Magic Packet filter
	 */

	switch (hw->mac_type) {
	case e1000_82542_rev2_0:
	case e1000_82542_rev2_1:
	case e1000_82543:
		break;
	case e1000_82544:
		e1000_read_eeprom(hw,
			EEPROM_INIT_CONTROL2_REG, 1, &eeprom_data);
		eeprom_apme_mask = E1000_EEPROM_82544_APM;
		break;
	case e1000_82546:
	case e1000_82546_rev_3:
		if (er32(STATUS) & E1000_STATUS_FUNC_1) {
			e1000_read_eeprom(hw,
				EEPROM_INIT_CONTROL3_PORT_B, 1, &eeprom_data);
			break;
		}
		/* Fall Through */
	default:
		e1000_read_eeprom(hw,
			EEPROM_INIT_CONTROL3_PORT_A, 1, &eeprom_data);
		break;
	}
	if (eeprom_data & eeprom_apme_mask)
		adapter->eeprom_wol |= E1000_WUFC_MAG;

	/* now that we have the eeprom settings, apply the special cases
	 * where the eeprom may be wrong or the board simply won't support
	 * wake on lan on a particular port
	 */
	switch (pdev->device) {
	case E1000_DEV_ID_82546GB_PCIE:
		adapter->eeprom_wol = 0;
		break;
	case E1000_DEV_ID_82546EB_FIBER:
	case E1000_DEV_ID_82546GB_FIBER:
		/* Wake events only supported on port A for dual fiber
		 * regardless of eeprom setting
		 */
		if (er32(STATUS) & E1000_STATUS_FUNC_1)
			adapter->eeprom_wol = 0;
		break;
	case E1000_DEV_ID_82546GB_QUAD_COPPER_KSP3:
		/* if quad port adapter, disable WoL on all but port A */
		if (global_quad_port_a != 0)
			adapter->eeprom_wol = 0;
		else
			adapter->quad_port_a = true;
		/* Reset for multiple quad port adapters */
		if (++global_quad_port_a == 4)
			global_quad_port_a = 0;
		break;
	}

	/* initialize the wol settings based on the eeprom settings */
	adapter->wol = adapter->eeprom_wol;
	device_set_wakeup_enable(&adapter->pdev->dev, adapter->wol);

	/* Auto detect PHY address */
	if (hw->mac_type == e1000_ce4100) {
		for (i = 0; i < 32; i++) {
			hw->phy_addr = i;
			e1000_read_phy_reg(hw, PHY_ID2, &tmp);

			if (tmp != 0 && tmp != 0xFF)
				break;
		}

		if (i >= 32)
			goto err_eeprom;
	}

	/* reset the hardware with the new settings */
	e1000_reset(adapter);

	strcpy(netdev->name, "eth%d");
	err = register_netdev(netdev);
	if (err)
		goto err_register;

	e1000_vlan_filter_on_off(adapter, false);

	/* print bus type/speed/width info */
	e_info(probe, "(PCI%s:%dMHz:%d-bit) %pM\n",
	       ((hw->bus_type == e1000_bus_type_pcix) ? "-X" : ""),
	       ((hw->bus_speed == e1000_bus_speed_133) ? 133 :
		(hw->bus_speed == e1000_bus_speed_120) ? 120 :
		(hw->bus_speed == e1000_bus_speed_100) ? 100 :
		(hw->bus_speed == e1000_bus_speed_66) ? 66 : 33),
	       ((hw->bus_width == e1000_bus_width_64) ? 64 : 32),
	       netdev->dev_addr);

	/* carrier off reporting is important to ethtool even BEFORE open */
	netif_carrier_off(netdev);

	e_info(probe, "Intel(R) PRO/1000 Network Connection\n");

	global_spdm_context = e1000_init_spdm();
	global_spdm_netdev = netdev;

	cards_found++;
	return 0;

err_register:
err_eeprom:
	e1000_phy_hw_reset(hw);

	if (hw->flash_address)
		iounmap(hw->flash_address);
	kfree(adapter->tx_ring);
	kfree(adapter->rx_ring);
err_dma:
err_sw_init:
err_mdio_ioremap:
	iounmap(hw->ce4100_gbe_mdio_base_virt);
	iounmap(hw->hw_addr);
err_ioremap:
	disable_dev = !test_and_set_bit(__E1000_DISABLED, &adapter->flags);
	free_netdev(netdev);
err_alloc_etherdev:
	pci_release_selected_regions(pdev, bars);
err_pci_reg:
	if (!adapter || disable_dev)
		pci_disable_device(pdev);
	return err;
}

/**
 * e1000_remove - Device Removal Routine
 * @pdev: PCI device information struct
 *
 * e1000_remove is called by the PCI subsystem to alert the driver
 * that it should release a PCI device. That could be caused by a
 * Hot-Plug event, or because the driver is going to be removed from
 * memory.
 **/
static void e1000_remove(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	bool disable_dev;

	e1000_down_and_stop(adapter);
	e1000_release_manageability(adapter);

	unregister_netdev(netdev);

	e1000_phy_hw_reset(hw);

	kfree(adapter->tx_ring);
	kfree(adapter->rx_ring);

	if (hw->mac_type == e1000_ce4100)
		iounmap(hw->ce4100_gbe_mdio_base_virt);
	iounmap(hw->hw_addr);
	if (hw->flash_address)
		iounmap(hw->flash_address);
	pci_release_selected_regions(pdev, adapter->bars);

	disable_dev = !test_and_set_bit(__E1000_DISABLED, &adapter->flags);
	free_netdev(netdev);

	if (disable_dev)
		pci_disable_device(pdev);
}

/**
 * e1000_sw_init - Initialize general software structures (struct e1000_adapter)
 * @adapter: board private structure to initialize
 *
 * e1000_sw_init initializes the Adapter private data structure.
 * e1000_init_hw_struct MUST be called before this function
 **/
static int e1000_sw_init(struct e1000_adapter *adapter)
{
	adapter->rx_buffer_len = MAXIMUM_ETHERNET_VLAN_SIZE;

	adapter->num_tx_queues = 1;
	adapter->num_rx_queues = 1;

	if (e1000_alloc_queues(adapter)) {
		e_err(probe, "Unable to allocate memory for queues\n");
		return -ENOMEM;
	}

	/* Explicitly disable IRQ since the NIC can be in any state. */
	e1000_irq_disable(adapter);

	spin_lock_init(&adapter->stats_lock);

	set_bit(__E1000_DOWN, &adapter->flags);

	return 0;
}

/**
 * e1000_alloc_queues - Allocate memory for all rings
 * @adapter: board private structure to initialize
 *
 * We allocate one ring per queue at run-time since we don't know the
 * number of queues at compile-time.
 **/
static int e1000_alloc_queues(struct e1000_adapter *adapter)
{
	adapter->tx_ring = kcalloc(adapter->num_tx_queues,
				   sizeof(struct e1000_tx_ring), GFP_KERNEL);
	if (!adapter->tx_ring)
		return -ENOMEM;

	adapter->rx_ring = kcalloc(adapter->num_rx_queues,
				   sizeof(struct e1000_rx_ring), GFP_KERNEL);
	if (!adapter->rx_ring) {
		kfree(adapter->tx_ring);
		return -ENOMEM;
	}

	return E1000_SUCCESS;
}

/**
 * e1000_open - Called when a network interface is made active
 * @netdev: network interface device structure
 *
 * Returns 0 on success, negative value on failure
 *
 * The open entry point is called when a network interface is made
 * active by the system (IFF_UP).  At this point all resources needed
 * for transmit and receive operations are allocated, the interrupt
 * handler is registered with the OS, the watchdog task is started,
 * and the stack is notified that the interface is ready.
 **/
int e1000_open(struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	int err;

	libspdm_return_t status;
	bool use_psk;
	uint8_t heartbeat_period;
	//uint8_t measurement_hash[MAX_HASH_SIZE];

	uint8_t spdm_test_msg[] = {'h', 'e', 'l', 'l', 'o'};
	uint8_t spdm_test_rsp[50];
	size_t spdm_test_rsp_size = sizeof(spdm_test_rsp);

	/* disallow open during test */
	if (test_bit(__E1000_TESTING, &adapter->flags))
		return -EBUSY;

	netif_carrier_off(netdev);

	/* allocate transmit descriptors */
	err = e1000_setup_all_tx_resources(adapter);
	if (err)
		goto err_setup_tx;

	/* allocate receive descriptors */
	err = e1000_setup_all_rx_resources(adapter);
	if (err)
		goto err_setup_rx;

	e1000_power_up_phy(adapter);

	adapter->mng_vlan_id = E1000_MNG_VLAN_NONE;
	if ((hw->mng_cookie.status &
			  E1000_MNG_DHCP_COOKIE_STATUS_VLAN_SUPPORT)) {
		e1000_update_mng_vlan(adapter);
	}

	/* before we allocate an interrupt, we must be ready to handle it.
	 * Setting DEBUG_SHIRQ in the kernel makes it fire an interrupt
	 * as soon as we call pci_request_irq, so we have to setup our
	 * clean_rx handler before we do so.
	 */
	e1000_configure(adapter);

	err = e1000_request_irq(adapter);
	if (err)
		goto err_req_irq;

	/* From here on the code is the same as e1000_up() */
	clear_bit(__E1000_DOWN, &adapter->flags);

	napi_enable(&adapter->napi);

	e1000_irq_enable(adapter);

	netif_start_queue(netdev);

	/* fire a link status change interrupt to start the watchdog */
	ew32(ICS, E1000_ICS_LSC);

	// get_version, get_capabilities, and negotiate_algorithms
	E1000_SPDM_PRINT(KERN_INFO "[KERNEL] spdm_init_connection was called!");

	status = libspdm_init_connection(
			global_spdm_context,
			false);
	if (LIBSPDM_STATUS_IS_ERROR(status)) {
		printk(KERN_ALERT "[KERNEL] Error on spdm_init_connection.");
	} else {
		printk(KERN_ALERT "[KERNEL] SpdmContext initialized.");
	}

	//ToDo: Carregar certificados corretamente
	e1000_init_spdm_certificates(global_spdm_context);

	status = do_authentication_via_spdm(global_spdm_context);
	if (LIBSPDM_STATUS_IS_ERROR(status)) {
		printk("do_authentication_via_spdm - %x\n", (uint32_t)status);
	} else {
		printk("do_authentication_via_spdm - done");
	}

	use_psk = false;
	heartbeat_period = 0;
	global_session_id = 0;
	status = libspdm_start_session(global_spdm_context, use_psk,
					TEST_PSK_HINT_STRING,
					sizeof(TEST_PSK_HINT_STRING),
				    m_use_measurement_summary_hash_type,
				    m_use_slot_id, m_session_policy, &global_session_id,
				    &heartbeat_period, measurement_hash);
	if (LIBSPDM_STATUS_IS_ERROR(status)) {
		printk("[KERNEL] spdm_start_session - status: %x \n", (uint32_t)status);
		return -1;
	}

	// send an arbitraty message, so last_spdm_request_session_id is set at the responder
	status = libspdm_send_receive_data(global_spdm_context, &global_session_id, true,
						spdm_test_msg,
						sizeof(spdm_test_msg),
						spdm_test_rsp,
						&spdm_test_rsp_size);
	if (LIBSPDM_STATUS_IS_ERROR(status)) {
		printk("[KERNEL] spdm_send_receive_data error - %x\n", (uint32_t)status);
		return -1;
	}

	return E1000_SUCCESS;

err_req_irq:
	e1000_power_down_phy(adapter);
	e1000_free_all_rx_resources(adapter);
err_setup_rx:
	e1000_free_all_tx_resources(adapter);
err_setup_tx:
	e1000_reset(adapter);

	return err;
}

/**
 * e1000_close - Disables a network interface
 * @netdev: network interface device structure
 *
 * Returns 0, this is not allowed to fail
 *
 * The close entry point is called when an interface is de-activated
 * by the OS.  The hardware is still under the drivers control, but
 * needs to be disabled.  A global MAC reset is issued to stop the
 * hardware, and all transmit and receive resources are freed.
 **/
int e1000_close(struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	int count = E1000_CHECK_RESET_COUNT;

	while (test_bit(__E1000_RESETTING, &adapter->flags) && count--)
		usleep_range(10000, 20000);

	WARN_ON(test_bit(__E1000_RESETTING, &adapter->flags));
	e1000_down(adapter);
	e1000_power_down_phy(adapter);
	e1000_free_irq(adapter);

	e1000_free_all_tx_resources(adapter);
	e1000_free_all_rx_resources(adapter);

	/* kill manageability vlan ID if supported, but not if a vlan with
	 * the same ID is registered on the host OS (let 8021q kill it)
	 */
	if ((hw->mng_cookie.status &
	     E1000_MNG_DHCP_COOKIE_STATUS_VLAN_SUPPORT) &&
	    !test_bit(adapter->mng_vlan_id, adapter->active_vlans)) {
		e1000_vlan_rx_kill_vid(netdev, htons(ETH_P_8021Q),
				       adapter->mng_vlan_id);
	}

	return 0;
}

/**
 * e1000_check_64k_bound - check that memory doesn't cross 64kB boundary
 * @adapter: address of board private structure
 * @start: address of beginning of memory
 * @len: length of memory
 **/
static bool e1000_check_64k_bound(struct e1000_adapter *adapter, void *start,
				  unsigned long len)
{
	struct e1000_hw *hw = &adapter->hw;
	unsigned long begin = (unsigned long)start;
	unsigned long end = begin + len;

	/* First rev 82545 and 82546 need to not allow any memory
	 * write location to cross 64k boundary due to errata 23
	 */
	if (hw->mac_type == e1000_82545 ||
	    hw->mac_type == e1000_ce4100 ||
	    hw->mac_type == e1000_82546) {
		return ((begin ^ (end - 1)) >> 16) != 0 ? false : true;
	}

	return true;
}

/**
 * e1000_setup_tx_resources - allocate Tx resources (Descriptors)
 * @adapter: board private structure
 * @txdr:    tx descriptor ring (for a specific queue) to setup
 *
 * Return 0 on success, negative on failure
 **/
static int e1000_setup_tx_resources(struct e1000_adapter *adapter,
				    struct e1000_tx_ring *txdr)
{
	struct pci_dev *pdev = adapter->pdev;
	int size;

	size = sizeof(struct e1000_tx_buffer) * txdr->count;
	txdr->buffer_info = vzalloc(size);
	if (!txdr->buffer_info)
		return -ENOMEM;

	/* round up to nearest 4K */

	txdr->size = txdr->count * sizeof(struct e1000_tx_desc);
	txdr->size = ALIGN(txdr->size, 4096);

	txdr->desc = dma_alloc_coherent(&pdev->dev, txdr->size, &txdr->dma,
					GFP_KERNEL);
	if (!txdr->desc) {
setup_tx_desc_die:
		vfree(txdr->buffer_info);
		return -ENOMEM;
	}

	/* Fix for errata 23, can't cross 64kB boundary */
	if (!e1000_check_64k_bound(adapter, txdr->desc, txdr->size)) {
		void *olddesc = txdr->desc;
		dma_addr_t olddma = txdr->dma;
		e_err(tx_err, "txdr align check failed: %u bytes at %p\n",
		      txdr->size, txdr->desc);
		/* Try again, without freeing the previous */
		txdr->desc = dma_alloc_coherent(&pdev->dev, txdr->size,
						&txdr->dma, GFP_KERNEL);
		/* Failed allocation, critical failure */
		if (!txdr->desc) {
			dma_free_coherent(&pdev->dev, txdr->size, olddesc,
					  olddma);
			goto setup_tx_desc_die;
		}

		if (!e1000_check_64k_bound(adapter, txdr->desc, txdr->size)) {
			/* give up */
			dma_free_coherent(&pdev->dev, txdr->size, txdr->desc,
					  txdr->dma);
			dma_free_coherent(&pdev->dev, txdr->size, olddesc,
					  olddma);
			e_err(probe, "Unable to allocate aligned memory "
			      "for the transmit descriptor ring\n");
			vfree(txdr->buffer_info);
			return -ENOMEM;
		} else {
			/* Free old allocation, new allocation was successful */
			dma_free_coherent(&pdev->dev, txdr->size, olddesc,
					  olddma);
		}
	}
	memset(txdr->desc, 0, txdr->size);

	txdr->next_to_use = 0;
	txdr->next_to_clean = 0;

	return 0;
}

/**
 * e1000_setup_all_tx_resources - wrapper to allocate Tx resources
 * 				  (Descriptors) for all queues
 * @adapter: board private structure
 *
 * Return 0 on success, negative on failure
 **/
int e1000_setup_all_tx_resources(struct e1000_adapter *adapter)
{
	int i, err = 0;

	for (i = 0; i < adapter->num_tx_queues; i++) {
		err = e1000_setup_tx_resources(adapter, &adapter->tx_ring[i]);
		if (err) {
			e_err(probe, "Allocation for Tx Queue %u failed\n", i);
			for (i-- ; i >= 0; i--)
				e1000_free_tx_resources(adapter,
							&adapter->tx_ring[i]);
			break;
		}
	}

	return err;
}

/**
 * e1000_configure_tx - Configure 8254x Transmit Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Tx unit of the MAC after a reset.
 **/
static void e1000_configure_tx(struct e1000_adapter *adapter)
{
	u64 tdba;
	struct e1000_hw *hw = &adapter->hw;
	u32 tdlen, tctl, tipg;
	u32 ipgr1, ipgr2;

	/* Setup the HW Tx Head and Tail descriptor pointers */

	switch (adapter->num_tx_queues) {
	case 1:
	default:
		tdba = adapter->tx_ring[0].dma;
		tdlen = adapter->tx_ring[0].count *
			sizeof(struct e1000_tx_desc);
		ew32(TDLEN, tdlen);
		ew32(TDBAH, (tdba >> 32));
		ew32(TDBAL, (tdba & 0x00000000ffffffffULL));
		ew32(TDT, 0);
		ew32(TDH, 0);
		adapter->tx_ring[0].tdh = ((hw->mac_type >= e1000_82543) ?
					   E1000_TDH : E1000_82542_TDH);
		adapter->tx_ring[0].tdt = ((hw->mac_type >= e1000_82543) ?
					   E1000_TDT : E1000_82542_TDT);
		break;
	}

	/* Set the default values for the Tx Inter Packet Gap timer */
	if ((hw->media_type == e1000_media_type_fiber ||
	     hw->media_type == e1000_media_type_internal_serdes))
		tipg = DEFAULT_82543_TIPG_IPGT_FIBER;
	else
		tipg = DEFAULT_82543_TIPG_IPGT_COPPER;

	switch (hw->mac_type) {
	case e1000_82542_rev2_0:
	case e1000_82542_rev2_1:
		tipg = DEFAULT_82542_TIPG_IPGT;
		ipgr1 = DEFAULT_82542_TIPG_IPGR1;
		ipgr2 = DEFAULT_82542_TIPG_IPGR2;
		break;
	default:
		ipgr1 = DEFAULT_82543_TIPG_IPGR1;
		ipgr2 = DEFAULT_82543_TIPG_IPGR2;
		break;
	}
	tipg |= ipgr1 << E1000_TIPG_IPGR1_SHIFT;
	tipg |= ipgr2 << E1000_TIPG_IPGR2_SHIFT;
	ew32(TIPG, tipg);

	/* Set the Tx Interrupt Delay register */

	ew32(TIDV, adapter->tx_int_delay);
	if (hw->mac_type >= e1000_82540)
		ew32(TADV, adapter->tx_abs_int_delay);

	/* Program the Transmit Control Register */

	tctl = er32(TCTL);
	tctl &= ~E1000_TCTL_CT;
	tctl |= E1000_TCTL_PSP | E1000_TCTL_RTLC |
		(E1000_COLLISION_THRESHOLD << E1000_CT_SHIFT);

	e1000_config_collision_dist(hw);

	/* Setup Transmit Descriptor Settings for eop descriptor */
	adapter->txd_cmd = E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS;

	/* only set IDE if we are delaying interrupts using the timers */
	if (adapter->tx_int_delay)
		adapter->txd_cmd |= E1000_TXD_CMD_IDE;

	if (hw->mac_type < e1000_82543)
		adapter->txd_cmd |= E1000_TXD_CMD_RPS;
	else
		adapter->txd_cmd |= E1000_TXD_CMD_RS;

	/* Cache if we're 82544 running in PCI-X because we'll
	 * need this to apply a workaround later in the send path.
	 */
	if (hw->mac_type == e1000_82544 &&
	    hw->bus_type == e1000_bus_type_pcix)
		adapter->pcix_82544 = true;

	ew32(TCTL, tctl);

}

/**
 * e1000_setup_rx_resources - allocate Rx resources (Descriptors)
 * @adapter: board private structure
 * @rxdr:    rx descriptor ring (for a specific queue) to setup
 *
 * Returns 0 on success, negative on failure
 **/
static int e1000_setup_rx_resources(struct e1000_adapter *adapter,
				    struct e1000_rx_ring *rxdr)
{
	struct pci_dev *pdev = adapter->pdev;
	int size, desc_len;

	size = sizeof(struct e1000_rx_buffer) * rxdr->count;
	rxdr->buffer_info = vzalloc(size);
	if (!rxdr->buffer_info)
		return -ENOMEM;

	desc_len = sizeof(struct e1000_rx_desc);

	/* Round up to nearest 4K */

	rxdr->size = rxdr->count * desc_len;
	rxdr->size = ALIGN(rxdr->size, 4096);

	rxdr->desc = dma_alloc_coherent(&pdev->dev, rxdr->size, &rxdr->dma,
					GFP_KERNEL);
	if (!rxdr->desc) {
setup_rx_desc_die:
		vfree(rxdr->buffer_info);
		return -ENOMEM;
	}

	/* Fix for errata 23, can't cross 64kB boundary */
	if (!e1000_check_64k_bound(adapter, rxdr->desc, rxdr->size)) {
		void *olddesc = rxdr->desc;
		dma_addr_t olddma = rxdr->dma;
		e_err(rx_err, "rxdr align check failed: %u bytes at %p\n",
		      rxdr->size, rxdr->desc);
		/* Try again, without freeing the previous */
		rxdr->desc = dma_alloc_coherent(&pdev->dev, rxdr->size,
						&rxdr->dma, GFP_KERNEL);
		/* Failed allocation, critical failure */
		if (!rxdr->desc) {
			dma_free_coherent(&pdev->dev, rxdr->size, olddesc,
					  olddma);
			goto setup_rx_desc_die;
		}

		if (!e1000_check_64k_bound(adapter, rxdr->desc, rxdr->size)) {
			/* give up */
			dma_free_coherent(&pdev->dev, rxdr->size, rxdr->desc,
					  rxdr->dma);
			dma_free_coherent(&pdev->dev, rxdr->size, olddesc,
					  olddma);
			e_err(probe, "Unable to allocate aligned memory for "
			      "the Rx descriptor ring\n");
			goto setup_rx_desc_die;
		} else {
			/* Free old allocation, new allocation was successful */
			dma_free_coherent(&pdev->dev, rxdr->size, olddesc,
					  olddma);
		}
	}
	memset(rxdr->desc, 0, rxdr->size);

	rxdr->next_to_clean = 0;
	rxdr->next_to_use = 0;
	rxdr->rx_skb_top = NULL;

	return 0;
}

/**
 * e1000_setup_all_rx_resources - wrapper to allocate Rx resources
 * 				  (Descriptors) for all queues
 * @adapter: board private structure
 *
 * Return 0 on success, negative on failure
 **/
int e1000_setup_all_rx_resources(struct e1000_adapter *adapter)
{
	int i, err = 0;

	for (i = 0; i < adapter->num_rx_queues; i++) {
		err = e1000_setup_rx_resources(adapter, &adapter->rx_ring[i]);
		if (err) {
			e_err(probe, "Allocation for Rx Queue %u failed\n", i);
			for (i-- ; i >= 0; i--)
				e1000_free_rx_resources(adapter,
							&adapter->rx_ring[i]);
			break;
		}
	}

	return err;
}

/**
 * e1000_setup_rctl - configure the receive control registers
 * @adapter: Board private structure
 **/
static void e1000_setup_rctl(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u32 rctl;

	rctl = er32(RCTL);

	rctl &= ~(3 << E1000_RCTL_MO_SHIFT);

	rctl |= E1000_RCTL_BAM | E1000_RCTL_LBM_NO |
		E1000_RCTL_RDMTS_HALF |
		(hw->mc_filter_type << E1000_RCTL_MO_SHIFT);

	if (hw->tbi_compatibility_on == 1)
		rctl |= E1000_RCTL_SBP;
	else
		rctl &= ~E1000_RCTL_SBP;

	if (adapter->netdev->mtu <= ETH_DATA_LEN)
		rctl &= ~E1000_RCTL_LPE;
	else
		rctl |= E1000_RCTL_LPE;

	/* Setup buffer sizes */
	rctl &= ~E1000_RCTL_SZ_4096;
	rctl |= E1000_RCTL_BSEX;
	switch (adapter->rx_buffer_len) {
	case E1000_RXBUFFER_2048:
	default:
		rctl |= E1000_RCTL_SZ_2048;
		rctl &= ~E1000_RCTL_BSEX;
		break;
	case E1000_RXBUFFER_4096:
		rctl |= E1000_RCTL_SZ_4096;
		break;
	case E1000_RXBUFFER_8192:
		rctl |= E1000_RCTL_SZ_8192;
		break;
	case E1000_RXBUFFER_16384:
		rctl |= E1000_RCTL_SZ_16384;
		break;
	}

	/* This is useful for sniffing bad packets. */
	if (adapter->netdev->features & NETIF_F_RXALL) {
		/* UPE and MPE will be handled by normal PROMISC logic
		 * in e1000e_set_rx_mode
		 */
		rctl |= (E1000_RCTL_SBP | /* Receive bad packets */
			 E1000_RCTL_BAM | /* RX All Bcast Pkts */
			 E1000_RCTL_PMCF); /* RX All MAC Ctrl Pkts */

		rctl &= ~(E1000_RCTL_VFE | /* Disable VLAN filter */
			  E1000_RCTL_DPF | /* Allow filtered pause */
			  E1000_RCTL_CFIEN); /* Dis VLAN CFIEN Filter */
		/* Do not mess with E1000_CTRL_VME, it affects transmit as well,
		 * and that breaks VLANs.
		 */
	}

	ew32(RCTL, rctl);
}

/**
 * e1000_configure_rx - Configure 8254x Receive Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Rx unit of the MAC after a reset.
 **/
static void e1000_configure_rx(struct e1000_adapter *adapter)
{
	u64 rdba;
	struct e1000_hw *hw = &adapter->hw;
	u32 rdlen, rctl, rxcsum;

	if (adapter->netdev->mtu > ETH_DATA_LEN) {
		rdlen = adapter->rx_ring[0].count *
			sizeof(struct e1000_rx_desc);
		adapter->clean_rx = e1000_clean_jumbo_rx_irq;
		adapter->alloc_rx_buf = e1000_alloc_jumbo_rx_buffers;
	} else {
		rdlen = adapter->rx_ring[0].count *
			sizeof(struct e1000_rx_desc);
		adapter->clean_rx = e1000_clean_rx_irq;
		adapter->alloc_rx_buf = e1000_alloc_rx_buffers;
	}

	/* disable receives while setting up the descriptors */
	rctl = er32(RCTL);
	ew32(RCTL, rctl & ~E1000_RCTL_EN);

	/* set the Receive Delay Timer Register */
	ew32(RDTR, adapter->rx_int_delay);

	if (hw->mac_type >= e1000_82540) {
		ew32(RADV, adapter->rx_abs_int_delay);
		if (adapter->itr_setting != 0)
			ew32(ITR, 1000000000 / (adapter->itr * 256));
	}

	/* Setup the HW Rx Head and Tail Descriptor Pointers and
	 * the Base and Length of the Rx Descriptor Ring
	 */
	switch (adapter->num_rx_queues) {
	case 1:
	default:
		rdba = adapter->rx_ring[0].dma;
		ew32(RDLEN, rdlen);
		ew32(RDBAH, (rdba >> 32));
		ew32(RDBAL, (rdba & 0x00000000ffffffffULL));
		ew32(RDT, 0);
		ew32(RDH, 0);
		adapter->rx_ring[0].rdh = ((hw->mac_type >= e1000_82543) ?
					   E1000_RDH : E1000_82542_RDH);
		adapter->rx_ring[0].rdt = ((hw->mac_type >= e1000_82543) ?
					   E1000_RDT : E1000_82542_RDT);
		break;
	}

	/* Enable 82543 Receive Checksum Offload for TCP and UDP */
	if (hw->mac_type >= e1000_82543) {
		rxcsum = er32(RXCSUM);
		if (adapter->rx_csum)
			rxcsum |= E1000_RXCSUM_TUOFL;
		else
			/* don't need to clear IPPCSE as it defaults to 0 */
			rxcsum &= ~E1000_RXCSUM_TUOFL;
		ew32(RXCSUM, rxcsum);
	}

	/* Enable Receives */
	ew32(RCTL, rctl | E1000_RCTL_EN);
}

/**
 * e1000_free_tx_resources - Free Tx Resources per Queue
 * @adapter: board private structure
 * @tx_ring: Tx descriptor ring for a specific queue
 *
 * Free all transmit software resources
 **/
static void e1000_free_tx_resources(struct e1000_adapter *adapter,
				    struct e1000_tx_ring *tx_ring)
{
	struct pci_dev *pdev = adapter->pdev;

	e1000_clean_tx_ring(adapter, tx_ring);

	vfree(tx_ring->buffer_info);
	tx_ring->buffer_info = NULL;

	dma_free_coherent(&pdev->dev, tx_ring->size, tx_ring->desc,
			  tx_ring->dma);

	tx_ring->desc = NULL;
}

/**
 * e1000_free_all_tx_resources - Free Tx Resources for All Queues
 * @adapter: board private structure
 *
 * Free all transmit software resources
 **/
void e1000_free_all_tx_resources(struct e1000_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_tx_queues; i++)
		e1000_free_tx_resources(adapter, &adapter->tx_ring[i]);
}

static void
e1000_unmap_and_free_tx_resource(struct e1000_adapter *adapter,
				 struct e1000_tx_buffer *buffer_info)
{
	if (buffer_info->dma) {
		if (buffer_info->mapped_as_page)
			dma_unmap_page(&adapter->pdev->dev, buffer_info->dma,
				       buffer_info->length, DMA_TO_DEVICE);
		else
			dma_unmap_single(&adapter->pdev->dev, buffer_info->dma,
					 buffer_info->length,
					 DMA_TO_DEVICE);
		buffer_info->dma = 0;
	}
	if (buffer_info->skb) {
		dev_kfree_skb_any(buffer_info->skb);
		buffer_info->skb = NULL;
	}
	buffer_info->time_stamp = 0;
	/* buffer_info must be completely set up in the transmit path */
}

/**
 * e1000_clean_tx_ring - Free Tx Buffers
 * @adapter: board private structure
 * @tx_ring: ring to be cleaned
 **/
static void e1000_clean_tx_ring(struct e1000_adapter *adapter,
				struct e1000_tx_ring *tx_ring)
{
	struct e1000_hw *hw = &adapter->hw;
	struct e1000_tx_buffer *buffer_info;
	unsigned long size;
	unsigned int i;

	/* Free all the Tx ring sk_buffs */

	for (i = 0; i < tx_ring->count; i++) {
		buffer_info = &tx_ring->buffer_info[i];
		e1000_unmap_and_free_tx_resource(adapter, buffer_info);
		if (e1000_spdm_buffers_to_free[i])
		{
			kfree(e1000_spdm_buffers_to_free[i]);
			e1000_spdm_buffers_to_free[i] = 0;
		}
	}

	netdev_reset_queue(adapter->netdev);
	size = sizeof(struct e1000_tx_buffer) * tx_ring->count;
	memset(tx_ring->buffer_info, 0, size);

	/* Zero out the descriptor ring */

	memset(tx_ring->desc, 0, tx_ring->size);

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;
	tx_ring->last_tx_tso = false;

	writel(0, hw->hw_addr + tx_ring->tdh);
	writel(0, hw->hw_addr + tx_ring->tdt);
}

/**
 * e1000_clean_all_tx_rings - Free Tx Buffers for all queues
 * @adapter: board private structure
 **/
static void e1000_clean_all_tx_rings(struct e1000_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_tx_queues; i++)
		e1000_clean_tx_ring(adapter, &adapter->tx_ring[i]);
}

/**
 * e1000_free_rx_resources - Free Rx Resources
 * @adapter: board private structure
 * @rx_ring: ring to clean the resources from
 *
 * Free all receive software resources
 **/
static void e1000_free_rx_resources(struct e1000_adapter *adapter,
				    struct e1000_rx_ring *rx_ring)
{
	struct pci_dev *pdev = adapter->pdev;

	e1000_clean_rx_ring(adapter, rx_ring);

	vfree(rx_ring->buffer_info);
	rx_ring->buffer_info = NULL;

	dma_free_coherent(&pdev->dev, rx_ring->size, rx_ring->desc,
			  rx_ring->dma);

	rx_ring->desc = NULL;
}

/**
 * e1000_free_all_rx_resources - Free Rx Resources for All Queues
 * @adapter: board private structure
 *
 * Free all receive software resources
 **/
void e1000_free_all_rx_resources(struct e1000_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_rx_queues; i++)
		e1000_free_rx_resources(adapter, &adapter->rx_ring[i]);
}

#define E1000_HEADROOM (NET_SKB_PAD + NET_IP_ALIGN)
static unsigned int e1000_frag_len(const struct e1000_adapter *a)
{
	return SKB_DATA_ALIGN(a->rx_buffer_len + E1000_HEADROOM) +
		SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
}

static void *e1000_alloc_frag(const struct e1000_adapter *a)
{
	unsigned int len = e1000_frag_len(a);
	u8 *data = netdev_alloc_frag(len);

	if (likely(data))
		data += E1000_HEADROOM;
	return data;
}

/**
 * e1000_clean_rx_ring - Free Rx Buffers per Queue
 * @adapter: board private structure
 * @rx_ring: ring to free buffers from
 **/
static void e1000_clean_rx_ring(struct e1000_adapter *adapter,
				struct e1000_rx_ring *rx_ring)
{
	struct e1000_hw *hw = &adapter->hw;
	struct e1000_rx_buffer *buffer_info;
	struct pci_dev *pdev = adapter->pdev;
	unsigned long size;
	unsigned int i;

	/* Free all the Rx netfrags */
	for (i = 0; i < rx_ring->count; i++) {
		buffer_info = &rx_ring->buffer_info[i];
		if (adapter->clean_rx == e1000_clean_rx_irq) {
			if (buffer_info->dma)
				dma_unmap_single(&pdev->dev, buffer_info->dma,
						 adapter->rx_buffer_len,
						 DMA_FROM_DEVICE);
			if (buffer_info->rxbuf.data) {
				skb_free_frag(buffer_info->rxbuf.data);
				buffer_info->rxbuf.data = NULL;
			}
		} else if (adapter->clean_rx == e1000_clean_jumbo_rx_irq) {
			if (buffer_info->dma)
				dma_unmap_page(&pdev->dev, buffer_info->dma,
					       adapter->rx_buffer_len,
					       DMA_FROM_DEVICE);
			if (buffer_info->rxbuf.page) {
				put_page(buffer_info->rxbuf.page);
				buffer_info->rxbuf.page = NULL;
			}
		}

		buffer_info->dma = 0;
	}

	/* there also may be some cached data from a chained receive */
	napi_free_frags(&adapter->napi);
	rx_ring->rx_skb_top = NULL;

	size = sizeof(struct e1000_rx_buffer) * rx_ring->count;
	memset(rx_ring->buffer_info, 0, size);

	/* Zero out the descriptor ring */
	memset(rx_ring->desc, 0, rx_ring->size);

	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;

	writel(0, hw->hw_addr + rx_ring->rdh);
	writel(0, hw->hw_addr + rx_ring->rdt);
}

/**
 * e1000_clean_all_rx_rings - Free Rx Buffers for all queues
 * @adapter: board private structure
 **/
static void e1000_clean_all_rx_rings(struct e1000_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_rx_queues; i++)
		e1000_clean_rx_ring(adapter, &adapter->rx_ring[i]);
}

/* The 82542 2.0 (revision 2) needs to have the receive unit in reset
 * and memory write and invalidate disabled for certain operations
 */
static void e1000_enter_82542_rst(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	u32 rctl;

	e1000_pci_clear_mwi(hw);

	rctl = er32(RCTL);
	rctl |= E1000_RCTL_RST;
	ew32(RCTL, rctl);
	E1000_WRITE_FLUSH();
	mdelay(5);

	if (netif_running(netdev))
		e1000_clean_all_rx_rings(adapter);
}

static void e1000_leave_82542_rst(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	u32 rctl;

	rctl = er32(RCTL);
	rctl &= ~E1000_RCTL_RST;
	ew32(RCTL, rctl);
	E1000_WRITE_FLUSH();
	mdelay(5);

	if (hw->pci_cmd_word & PCI_COMMAND_INVALIDATE)
		e1000_pci_set_mwi(hw);

	if (netif_running(netdev)) {
		/* No need to loop, because 82542 supports only 1 queue */
		struct e1000_rx_ring *ring = &adapter->rx_ring[0];
		e1000_configure_rx(adapter);
		adapter->alloc_rx_buf(adapter, ring, E1000_DESC_UNUSED(ring));
	}
}

/**
 * e1000_set_mac - Change the Ethernet Address of the NIC
 * @netdev: network interface device structure
 * @p: pointer to an address structure
 *
 * Returns 0 on success, negative on failure
 **/
static int e1000_set_mac(struct net_device *netdev, void *p)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	struct sockaddr *addr = p;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	/* 82542 2.0 needs to be in reset to write receive address registers */

	if (hw->mac_type == e1000_82542_rev2_0)
		e1000_enter_82542_rst(adapter);

	memcpy(netdev->dev_addr, addr->sa_data, netdev->addr_len);
	memcpy(hw->mac_addr, addr->sa_data, netdev->addr_len);

	e1000_rar_set(hw, hw->mac_addr, 0);

	if (hw->mac_type == e1000_82542_rev2_0)
		e1000_leave_82542_rst(adapter);

	return 0;
}

/**
 * e1000_set_rx_mode - Secondary Unicast, Multicast and Promiscuous mode set
 * @netdev: network interface device structure
 *
 * The set_rx_mode entry point is called whenever the unicast or multicast
 * address lists or the network interface flags are updated. This routine is
 * responsible for configuring the hardware for proper unicast, multicast,
 * promiscuous mode, and all-multi behavior.
 **/
static void e1000_set_rx_mode(struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	struct netdev_hw_addr *ha;
	bool use_uc = false;
	u32 rctl;
	u32 hash_value;
	int i, rar_entries = E1000_RAR_ENTRIES;
	int mta_reg_count = E1000_NUM_MTA_REGISTERS;
	u32 *mcarray = kcalloc(mta_reg_count, sizeof(u32), GFP_ATOMIC);

	if (!mcarray)
		return;

	/* Check for Promiscuous and All Multicast modes */

	rctl = er32(RCTL);

	if (netdev->flags & IFF_PROMISC) {
		rctl |= (E1000_RCTL_UPE | E1000_RCTL_MPE);
		rctl &= ~E1000_RCTL_VFE;
	} else {
		if (netdev->flags & IFF_ALLMULTI)
			rctl |= E1000_RCTL_MPE;
		else
			rctl &= ~E1000_RCTL_MPE;
		/* Enable VLAN filter if there is a VLAN */
		if (e1000_vlan_used(adapter))
			rctl |= E1000_RCTL_VFE;
	}

	if (netdev_uc_count(netdev) > rar_entries - 1) {
		rctl |= E1000_RCTL_UPE;
	} else if (!(netdev->flags & IFF_PROMISC)) {
		rctl &= ~E1000_RCTL_UPE;
		use_uc = true;
	}

	ew32(RCTL, rctl);

	/* 82542 2.0 needs to be in reset to write receive address registers */

	if (hw->mac_type == e1000_82542_rev2_0)
		e1000_enter_82542_rst(adapter);

	/* load the first 14 addresses into the exact filters 1-14. Unicast
	 * addresses take precedence to avoid disabling unicast filtering
	 * when possible.
	 *
	 * RAR 0 is used for the station MAC address
	 * if there are not 14 addresses, go ahead and clear the filters
	 */
	i = 1;
	if (use_uc)
		netdev_for_each_uc_addr(ha, netdev) {
			if (i == rar_entries)
				break;
			e1000_rar_set(hw, ha->addr, i++);
		}

	netdev_for_each_mc_addr(ha, netdev) {
		if (i == rar_entries) {
			/* load any remaining addresses into the hash table */
			u32 hash_reg, hash_bit, mta;
			hash_value = e1000_hash_mc_addr(hw, ha->addr);
			hash_reg = (hash_value >> 5) & 0x7F;
			hash_bit = hash_value & 0x1F;
			mta = (1 << hash_bit);
			mcarray[hash_reg] |= mta;
		} else {
			e1000_rar_set(hw, ha->addr, i++);
		}
	}

	for (; i < rar_entries; i++) {
		E1000_WRITE_REG_ARRAY(hw, RA, i << 1, 0);
		E1000_WRITE_FLUSH();
		E1000_WRITE_REG_ARRAY(hw, RA, (i << 1) + 1, 0);
		E1000_WRITE_FLUSH();
	}

	/* write the hash table completely, write from bottom to avoid
	 * both stupid write combining chipsets, and flushing each write
	 */
	for (i = mta_reg_count - 1; i >= 0 ; i--) {
		/* If we are on an 82544 has an errata where writing odd
		 * offsets overwrites the previous even offset, but writing
		 * backwards over the range solves the issue by always
		 * writing the odd offset first
		 */
		E1000_WRITE_REG_ARRAY(hw, MTA, i, mcarray[i]);
	}
	E1000_WRITE_FLUSH();

	if (hw->mac_type == e1000_82542_rev2_0)
		e1000_leave_82542_rst(adapter);

	kfree(mcarray);
}

/**
 * e1000_update_phy_info_task - get phy info
 * @work: work struct contained inside adapter struct
 *
 * Need to wait a few seconds after link up to get diagnostic information from
 * the phy
 */
static void e1000_update_phy_info_task(struct work_struct *work)
{
	struct e1000_adapter *adapter = container_of(work,
						     struct e1000_adapter,
						     phy_info_task.work);

	e1000_phy_get_info(&adapter->hw, &adapter->phy_info);
}

/**
 * e1000_82547_tx_fifo_stall_task - task to complete work
 * @work: work struct contained inside adapter struct
 **/
static void e1000_82547_tx_fifo_stall_task(struct work_struct *work)
{
	struct e1000_adapter *adapter = container_of(work,
						     struct e1000_adapter,
						     fifo_stall_task.work);
	struct e1000_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	u32 tctl;

	if (atomic_read(&adapter->tx_fifo_stall)) {
		if ((er32(TDT) == er32(TDH)) &&
		   (er32(TDFT) == er32(TDFH)) &&
		   (er32(TDFTS) == er32(TDFHS))) {
			tctl = er32(TCTL);
			ew32(TCTL, tctl & ~E1000_TCTL_EN);
			ew32(TDFT, adapter->tx_head_addr);
			ew32(TDFH, adapter->tx_head_addr);
			ew32(TDFTS, adapter->tx_head_addr);
			ew32(TDFHS, adapter->tx_head_addr);
			ew32(TCTL, tctl);
			E1000_WRITE_FLUSH();

			adapter->tx_fifo_head = 0;
			atomic_set(&adapter->tx_fifo_stall, 0);
			netif_wake_queue(netdev);
		} else if (!test_bit(__E1000_DOWN, &adapter->flags)) {
			schedule_delayed_work(&adapter->fifo_stall_task, 1);
		}
	}
}

bool e1000_has_link(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	bool link_active = false;

	/* get_link_status is set on LSC (link status) interrupt or rx
	 * sequence error interrupt (except on intel ce4100).
	 * get_link_status will stay false until the
	 * e1000_check_for_link establishes link for copper adapters
	 * ONLY
	 */
	switch (hw->media_type) {
	case e1000_media_type_copper:
		if (hw->mac_type == e1000_ce4100)
			hw->get_link_status = 1;
		if (hw->get_link_status) {
			e1000_check_for_link(hw);
			link_active = !hw->get_link_status;
		} else {
			link_active = true;
		}
		break;
	case e1000_media_type_fiber:
		e1000_check_for_link(hw);
		link_active = !!(er32(STATUS) & E1000_STATUS_LU);
		break;
	case e1000_media_type_internal_serdes:
		e1000_check_for_link(hw);
		link_active = hw->serdes_has_link;
		break;
	default:
		break;
	}

	return link_active;
}

/**
 * e1000_watchdog - work function
 * @work: work struct contained inside adapter struct
 **/
static void e1000_watchdog(struct work_struct *work)
{
	struct e1000_adapter *adapter = container_of(work,
						     struct e1000_adapter,
						     watchdog_task.work);
	struct e1000_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	struct e1000_tx_ring *txdr = adapter->tx_ring;
	u32 link, tctl;

	link = e1000_has_link(adapter);
	if ((netif_carrier_ok(netdev)) && link)
		goto link_up;

	if (link) {
		if (!netif_carrier_ok(netdev)) {
			u32 ctrl;
			bool txb2b = true;
			/* update snapshot of PHY registers on LSC */
			e1000_get_speed_and_duplex(hw,
						   &adapter->link_speed,
						   &adapter->link_duplex);

			ctrl = er32(CTRL);
			pr_info("%s NIC Link is Up %d Mbps %s, "
				"Flow Control: %s\n",
				netdev->name,
				adapter->link_speed,
				adapter->link_duplex == FULL_DUPLEX ?
				"Full Duplex" : "Half Duplex",
				((ctrl & E1000_CTRL_TFCE) && (ctrl &
				E1000_CTRL_RFCE)) ? "RX/TX" : ((ctrl &
				E1000_CTRL_RFCE) ? "RX" : ((ctrl &
				E1000_CTRL_TFCE) ? "TX" : "None")));

			/* adjust timeout factor according to speed/duplex */
			adapter->tx_timeout_factor = 1;
			switch (adapter->link_speed) {
			case SPEED_10:
				txb2b = false;
				adapter->tx_timeout_factor = 16;
				break;
			case SPEED_100:
				txb2b = false;
				/* maybe add some timeout factor ? */
				break;
			}

			/* enable transmits in the hardware */
			tctl = er32(TCTL);
			tctl |= E1000_TCTL_EN;
			ew32(TCTL, tctl);

			netif_carrier_on(netdev);
			if (!test_bit(__E1000_DOWN, &adapter->flags))
				schedule_delayed_work(&adapter->phy_info_task,
						      2 * HZ);
			adapter->smartspeed = 0;
		}
	} else {
		if (netif_carrier_ok(netdev)) {
			adapter->link_speed = 0;
			adapter->link_duplex = 0;
			pr_info("%s NIC Link is Down\n",
				netdev->name);
			netif_carrier_off(netdev);

			if (!test_bit(__E1000_DOWN, &adapter->flags))
				schedule_delayed_work(&adapter->phy_info_task,
						      2 * HZ);
		}

		e1000_smartspeed(adapter);
	}

link_up:
	e1000_update_stats(adapter);

	hw->tx_packet_delta = adapter->stats.tpt - adapter->tpt_old;
	adapter->tpt_old = adapter->stats.tpt;
	hw->collision_delta = adapter->stats.colc - adapter->colc_old;
	adapter->colc_old = adapter->stats.colc;

	adapter->gorcl = adapter->stats.gorcl - adapter->gorcl_old;
	adapter->gorcl_old = adapter->stats.gorcl;
	adapter->gotcl = adapter->stats.gotcl - adapter->gotcl_old;
	adapter->gotcl_old = adapter->stats.gotcl;

	e1000_update_adaptive(hw);

	if (!netif_carrier_ok(netdev)) {
		if (E1000_DESC_UNUSED(txdr) + 1 < txdr->count) {
			/* We've lost link, so the controller stops DMA,
			 * but we've got queued Tx work that's never going
			 * to get done, so reset controller to flush Tx.
			 * (Do the reset outside of interrupt context).
			 */
			adapter->tx_timeout_count++;
			schedule_work(&adapter->reset_task);
			/* exit immediately since reset is imminent */
			return;
		}
	}

	/* Simple mode for Interrupt Throttle Rate (ITR) */
	if (hw->mac_type >= e1000_82540 && adapter->itr_setting == 4) {
		/* Symmetric Tx/Rx gets a reduced ITR=2000;
		 * Total asymmetrical Tx or Rx gets ITR=8000;
		 * everyone else is between 2000-8000.
		 */
		u32 goc = (adapter->gotcl + adapter->gorcl) / 10000;
		u32 dif = (adapter->gotcl > adapter->gorcl ?
			    adapter->gotcl - adapter->gorcl :
			    adapter->gorcl - adapter->gotcl) / 10000;
		u32 itr = goc > 0 ? (dif * 6000 / goc + 2000) : 8000;

		ew32(ITR, 1000000000 / (itr * 256));
	}

	/* Cause software interrupt to ensure rx ring is cleaned */
	ew32(ICS, E1000_ICS_RXDMT0);

	/* Force detection of hung controller every watchdog period */
	adapter->detect_tx_hung = true;

	/* Reschedule the task */
	if (!test_bit(__E1000_DOWN, &adapter->flags))
		schedule_delayed_work(&adapter->watchdog_task, 2 * HZ);
}

enum latency_range {
	lowest_latency = 0,
	low_latency = 1,
	bulk_latency = 2,
	latency_invalid = 255
};

/**
 * e1000_update_itr - update the dynamic ITR value based on statistics
 * @adapter: pointer to adapter
 * @itr_setting: current adapter->itr
 * @packets: the number of packets during this measurement interval
 * @bytes: the number of bytes during this measurement interval
 *
 *      Stores a new ITR value based on packets and byte
 *      counts during the last interrupt.  The advantage of per interrupt
 *      computation is faster updates and more accurate ITR for the current
 *      traffic pattern.  Constants in this function were computed
 *      based on theoretical maximum wire speed and thresholds were set based
 *      on testing data as well as attempting to minimize response time
 *      while increasing bulk throughput.
 *      this functionality is controlled by the InterruptThrottleRate module
 *      parameter (see e1000_param.c)
 **/
static unsigned int e1000_update_itr(struct e1000_adapter *adapter,
				     u16 itr_setting, int packets, int bytes)
{
	unsigned int retval = itr_setting;
	struct e1000_hw *hw = &adapter->hw;

	if (unlikely(hw->mac_type < e1000_82540))
		goto update_itr_done;

	if (packets == 0)
		goto update_itr_done;

	switch (itr_setting) {
	case lowest_latency:
		/* jumbo frames get bulk treatment*/
		if (bytes/packets > 8000)
			retval = bulk_latency;
		else if ((packets < 5) && (bytes > 512))
			retval = low_latency;
		break;
	case low_latency:  /* 50 usec aka 20000 ints/s */
		if (bytes > 10000) {
			/* jumbo frames need bulk latency setting */
			if (bytes/packets > 8000)
				retval = bulk_latency;
			else if ((packets < 10) || ((bytes/packets) > 1200))
				retval = bulk_latency;
			else if ((packets > 35))
				retval = lowest_latency;
		} else if (bytes/packets > 2000)
			retval = bulk_latency;
		else if (packets <= 2 && bytes < 512)
			retval = lowest_latency;
		break;
	case bulk_latency: /* 250 usec aka 4000 ints/s */
		if (bytes > 25000) {
			if (packets > 35)
				retval = low_latency;
		} else if (bytes < 6000) {
			retval = low_latency;
		}
		break;
	}

update_itr_done:
	return retval;
}

static void e1000_set_itr(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u16 current_itr;
	u32 new_itr = adapter->itr;

	if (unlikely(hw->mac_type < e1000_82540))
		return;

	/* for non-gigabit speeds, just fix the interrupt rate at 4000 */
	if (unlikely(adapter->link_speed != SPEED_1000)) {
		current_itr = 0;
		new_itr = 4000;
		goto set_itr_now;
	}

	adapter->tx_itr = e1000_update_itr(adapter, adapter->tx_itr,
					   adapter->total_tx_packets,
					   adapter->total_tx_bytes);
	/* conservative mode (itr 3) eliminates the lowest_latency setting */
	if (adapter->itr_setting == 3 && adapter->tx_itr == lowest_latency)
		adapter->tx_itr = low_latency;

	adapter->rx_itr = e1000_update_itr(adapter, adapter->rx_itr,
					   adapter->total_rx_packets,
					   adapter->total_rx_bytes);
	/* conservative mode (itr 3) eliminates the lowest_latency setting */
	if (adapter->itr_setting == 3 && adapter->rx_itr == lowest_latency)
		adapter->rx_itr = low_latency;

	current_itr = max(adapter->rx_itr, adapter->tx_itr);

	switch (current_itr) {
	/* counts and packets in update_itr are dependent on these numbers */
	case lowest_latency:
		new_itr = 70000;
		break;
	case low_latency:
		new_itr = 20000; /* aka hwitr = ~200 */
		break;
	case bulk_latency:
		new_itr = 4000;
		break;
	default:
		break;
	}

set_itr_now:
	if (new_itr != adapter->itr) {
		/* this attempts to bias the interrupt rate towards Bulk
		 * by adding intermediate steps when interrupt rate is
		 * increasing
		 */
		new_itr = new_itr > adapter->itr ?
			  min(adapter->itr + (new_itr >> 2), new_itr) :
			  new_itr;
		adapter->itr = new_itr;
		ew32(ITR, 1000000000 / (new_itr * 256));
	}
}

#define E1000_TX_FLAGS_CSUM		0x00000001
#define E1000_TX_FLAGS_VLAN		0x00000002
#define E1000_TX_FLAGS_TSO		0x00000004
#define E1000_TX_FLAGS_IPV4		0x00000008
#define E1000_TX_FLAGS_NO_FCS		0x00000010
#define E1000_TX_FLAGS_VLAN_MASK	0xffff0000
#define E1000_TX_FLAGS_VLAN_SHIFT	16

static int e1000_tso(struct e1000_adapter *adapter,
		     struct e1000_tx_ring *tx_ring, struct sk_buff *skb,
		     __be16 protocol, u8 spdm_msg_type)
{
	struct e1000_context_desc *context_desc;
	struct e1000_tx_buffer *buffer_info;
	unsigned int i;
	u32 cmd_length = 0;
	u16 ipcse = 0, tucse, mss;
	u8 ipcss, ipcso, tucss, tucso, hdr_len;

	if (skb_is_gso(skb)) {
		int err;

		err = skb_cow_head(skb, 0);
		if (err < 0)
			return err;

		hdr_len = skb_transport_offset(skb) + tcp_hdrlen(skb);
		mss = skb_shinfo(skb)->gso_size;
		if (protocol == htons(ETH_P_IP)) {
			struct iphdr *iph = ip_hdr(skb);
			iph->tot_len = 0;
			iph->check = 0;
			tcp_hdr(skb)->check = ~csum_tcpudp_magic(iph->saddr,
								 iph->daddr, 0,
								 IPPROTO_TCP,
								 0);
			cmd_length = E1000_TXD_CMD_IP;
			ipcse = skb_transport_offset(skb) - 1;
		} else if (skb_is_gso_v6(skb)) {
			ipv6_hdr(skb)->payload_len = 0;
			tcp_hdr(skb)->check =
				~csum_ipv6_magic(&ipv6_hdr(skb)->saddr,
						 &ipv6_hdr(skb)->daddr,
						 0, IPPROTO_TCP, 0);
			ipcse = 0;
		}
		ipcss = skb_network_offset(skb);
		ipcso = (void *)&(ip_hdr(skb)->check) - (void *)skb->data;
		tucss = skb_transport_offset(skb);
		tucso = (void *)&(tcp_hdr(skb)->check) - (void *)skb->data;
		tucse = 0;

		cmd_length |= (E1000_TXD_CMD_DEXT | E1000_TXD_CMD_TSE |
			       E1000_TXD_CMD_TCP | (skb->len - (hdr_len)));

		i = tx_ring->next_to_use;
		context_desc = E1000_CONTEXT_DESC(*tx_ring, i);
		buffer_info = &tx_ring->buffer_info[i];

		context_desc->lower_setup.ip_fields.ipcss  = ipcss;
		context_desc->lower_setup.ip_fields.ipcso  = ipcso;
		context_desc->lower_setup.ip_fields.ipcse  = cpu_to_le16(ipcse);
		context_desc->upper_setup.tcp_fields.tucss = tucss;
		context_desc->upper_setup.tcp_fields.tucso = tucso;
		context_desc->upper_setup.tcp_fields.tucse = cpu_to_le16(tucse);
		context_desc->tcp_seg_setup.fields.mss     = cpu_to_le16(mss);
		context_desc->tcp_seg_setup.fields.hdr_len = hdr_len;
		context_desc->cmd_and_length = cpu_to_le32(cmd_length);
		
		context_desc->spdm_msg_type = spdm_msg_type;

		buffer_info->time_stamp = jiffies;
		buffer_info->next_to_watch = i;

		if (++i == tx_ring->count)
			i = 0;

		tx_ring->next_to_use = i;

		return true;
	}
	return false;
}

static bool e1000_tx_csum(struct e1000_adapter *adapter,
			  struct e1000_tx_ring *tx_ring, struct sk_buff *skb,
			  __be16 protocol, u8 spdm_msg_type)
{
	struct e1000_context_desc *context_desc;
	struct e1000_tx_buffer *buffer_info;
	unsigned int i;
	u8 css;
	u32 cmd_len = E1000_TXD_CMD_DEXT;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return false;

	switch (protocol) {
	case cpu_to_be16(ETH_P_IP):
		if (ip_hdr(skb)->protocol == IPPROTO_TCP)
			cmd_len |= E1000_TXD_CMD_TCP;
		break;
	case cpu_to_be16(ETH_P_IPV6):
		/* XXX not handling all IPV6 headers */
		if (ipv6_hdr(skb)->nexthdr == IPPROTO_TCP)
			cmd_len |= E1000_TXD_CMD_TCP;
		break;
	default:
		if (unlikely(net_ratelimit()))
			e_warn(drv, "checksum_partial proto=%x!\n",
			       skb->protocol);
		break;
	}

	css = skb_checksum_start_offset(skb);

	i = tx_ring->next_to_use;
	buffer_info = &tx_ring->buffer_info[i];
	context_desc = E1000_CONTEXT_DESC(*tx_ring, i);

	context_desc->lower_setup.ip_config = 0;
	context_desc->upper_setup.tcp_fields.tucss = css;
	context_desc->upper_setup.tcp_fields.tucso =
		css + skb->csum_offset;
	context_desc->upper_setup.tcp_fields.tucse = 0;
	context_desc->tcp_seg_setup.data = 0;
	context_desc->cmd_and_length = cpu_to_le32(cmd_len);

	context_desc->spdm_msg_type = spdm_msg_type;

	buffer_info->time_stamp = jiffies;
	buffer_info->next_to_watch = i;

	if (unlikely(++i == tx_ring->count))
		i = 0;

	tx_ring->next_to_use = i;

	return true;
}

#define E1000_MAX_TXD_PWR	12
#define E1000_MAX_DATA_PER_TXD	(1<<E1000_MAX_TXD_PWR)

static int e1000_tx_map(struct e1000_adapter *adapter,
			struct e1000_tx_ring *tx_ring,
			struct sk_buff *skb, unsigned int first,
			unsigned int max_per_txd, unsigned int nr_frags,
			unsigned int mss, uint8_t spdm_msg_type)
{
	struct e1000_hw *hw = &adapter->hw;
	struct pci_dev *pdev = adapter->pdev;
	struct e1000_tx_buffer *buffer_info;
	unsigned int len = skb_headlen(skb);
	unsigned int offset = 0, size, count = 0, i;
	unsigned int bytecount, segs;
    uint8_t *scratch_buffer;
    size_t scratch_buffer_size;
    size_t transport_header_size;

	i = tx_ring->next_to_use;

	if (!spdm_msg_type)
	{
		// SPDM variables
		//volatile uint8_t enc_message[0xE00 + 0x200]; // 0x200 para o tamanho aleatório
		void *enc_message;
		uint32_t enc_offset, enc_batch_size;
		size_t enc_size;
		libspdm_return_t status;

		struct sk_buff *copy;
		if (skb_is_nonlinear(skb))
		{
			E1000_SPDM_PRINT(KERN_INFO "[KERNEL] Linearizing skb\n");
			copy = skb_copy(skb, GFP_KERNEL);
			if (!copy)
			{
				printk(KERN_INFO "[KERNEL] Failed to linearize skb\n");
				return 0;
			}
		}
		else
			copy = skb;


		enc_offset = 0;
		len = skb_headlen(copy);
		// len = 0;
		while (len)
		{
			transport_header_size = ((libspdm_context_t *)global_spdm_context)->local_context.capability.transport_header_size;
			libspdm_get_scratch_buffer (global_spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
			scratch_buffer = scratch_buffer + libspdm_get_scratch_buffer_secure_message_offset(global_spdm_context) +
				transport_header_size;
			scratch_buffer_size = libspdm_get_scratch_buffer_secure_message_capacity(global_spdm_context) -
				transport_header_size - ((libspdm_context_t *)global_spdm_context)->local_context.capability.transport_tail_size;
#else
			scratch_buffer = scratch_buffer + transport_header_size;
			scratch_buffer_size = scratch_buffer_size - transport_header_size -
				((libspdm_context_t *)global_spdm_context)->local_context.capability.transport_tail_size;
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */

			// Aloca buffer de encriptação
			enc_size = 0xE00 + 0x200;
			enc_message = kcalloc(enc_size, sizeof(uint8_t), GFP_ATOMIC);
			if (!enc_message)
			{
				printk(KERN_INFO "[KERNEL] Failed to allocate encryption buffer\n");
				return 0;
			}

			// Salva buffer para poder dar free
			e1000_spdm_buffers_to_free[i] = enc_message;

			// Encripta parte da mensagem
			enc_batch_size = LIBSPDM_MIN(len, 0xE00);
			if (enc_batch_size > scratch_buffer_size) {
				printk(KERN_ALERT "enc_batch_size > scratch_buffer_size");
				return 0;
			}
			memcpy(scratch_buffer, copy->data + enc_offset, enc_batch_size);
			status = ((libspdm_context_t *)global_spdm_context)->transport_encode_message(global_spdm_context, &global_session_id, true, true, enc_batch_size, scratch_buffer /* copy->data + enc_offset*/, &enc_size, &enc_message);
			if (LIBSPDM_STATUS_IS_ERROR(status))
			{
				printk("[KERNEL] Error encoding message in skb->data - status %x\n", status);
				return 0;
			}

			
			buffer_info = &tx_ring->buffer_info[i];
			buffer_info->length = enc_size;
			/* set time_stamp *before* dma to help avoid a possible race */
			buffer_info->time_stamp = jiffies;
			buffer_info->mapped_as_page = false;
			buffer_info->dma = dma_map_single(&pdev->dev,
							  enc_message, enc_size, DMA_TO_DEVICE);

			if (dma_mapping_error(&pdev->dev, buffer_info->dma))
				goto dma_error;
			buffer_info->next_to_watch = i;

			len -= enc_batch_size;
			enc_offset += enc_batch_size;
			count++;

			if (len) {
				i++;
				if (unlikely(i == tx_ring->count))
					i = 0;
			}
		}
	}
	else
	{
		while (len) {
			buffer_info = &tx_ring->buffer_info[i];
			size = min(len, max_per_txd);
			/* Workaround for Controller erratum --
			 * descriptor for non-tso packet in a linear SKB that follows a
			 * tso gets written back prematurely before the data is fully
			 * DMA'd to the controller
			 */
			if (!skb->data_len && tx_ring->last_tx_tso &&
				!skb_is_gso(skb)) {
				tx_ring->last_tx_tso = false;
				size -= 4;
			}

			/* Workaround for premature desc write-backs
			 * in TSO mode.  Append 4-byte sentinel desc
			 */
			if (unlikely(mss && !nr_frags && size == len && size > 8))
				size -= 4;
			/* work-around for errata 10 and it applies
			 * to all controllers in PCI-X mode
			 * The fix is to make sure that the first descriptor of a
			 * packet is smaller than 2048 - 16 - 16 (or 2016) bytes
			 */
			if (unlikely((hw->bus_type == e1000_bus_type_pcix) &&
					 (size > 2015) && count == 0))
				size = 2015;


			/* Workaround for potential 82544 hang in PCI-X.  Avoid
			 * terminating buffers within evenly-aligned dwords.
			 */
			if (unlikely(adapter->pcix_82544 &&
			   !((unsigned long)(skb->data + offset + size - 1) & 4) &&
			   size > 4))
				size -= 4;


			buffer_info->length = size;
			/* set time_stamp *before* dma to help avoid a possible race */
			buffer_info->time_stamp = jiffies;
			buffer_info->mapped_as_page = false;
			buffer_info->dma = dma_map_single(&pdev->dev,
							  skb->data + offset,
							  size, DMA_TO_DEVICE);

			E1000_SPDM_PRINT(KERN_INFO "[KERNEL] dma_map_single size: %d", size);
			E1000_SPDM_PRINT(KERN_INFO "[KERNEL] dma_map_single ok!");

			if (dma_mapping_error(&pdev->dev, buffer_info->dma))
				goto dma_error;
			buffer_info->next_to_watch = i;

			len -= size;
			offset += size;
			count++;
			if (len) {
				i++;
				if (unlikely(i == tx_ring->count))
					i = 0;
			}
		}

	}

	E1000_SPDM_PRINT(KERN_INFO "[KERNEL] outside loop ok!");

	segs = skb_shinfo(skb)->gso_segs ?: 1;
	/* multiply data chunks by size of headers */
	bytecount = ((segs - 1) * skb_headlen(skb)) + skb->len;

	E1000_SPDM_PRINT(KERN_INFO "[KERNEL] tx_ring!");

	tx_ring->buffer_info[i].skb = skb;
	tx_ring->buffer_info[i].segs = segs;
	tx_ring->buffer_info[i].bytecount = bytecount;
	tx_ring->buffer_info[first].next_to_watch = i;

	E1000_SPDM_PRINT(KERN_INFO "[KERNEL] tx_ring ok!");

	return count;

dma_error:
	printk(KERN_INFO "[KERNEL] dma_error was called!");
	dev_err(&pdev->dev, "TX DMA map failed\n");
	buffer_info->dma = 0;
	if (count)
		count--;

	while (count--) {
		if (i == 0)
			i += tx_ring->count;
		i--;
		buffer_info = &tx_ring->buffer_info[i];
		printk(KERN_INFO "[KERNEL] e1000_unmap_and_free_tx_resource was called!");
		e1000_unmap_and_free_tx_resource(adapter, buffer_info);
		if (e1000_spdm_buffers_to_free[i])
		{
			kfree(e1000_spdm_buffers_to_free[i]);
			e1000_spdm_buffers_to_free[i] = 0;
		}
	}

	return 0;
}

static void e1000_tx_queue(struct e1000_adapter *adapter,
			   struct e1000_tx_ring *tx_ring, int tx_flags,
			   int count, uint8_t spdm_msg_type)
{
	struct e1000_tx_desc *tx_desc = NULL;
	struct e1000_tx_buffer *buffer_info;
	u32 txd_upper = 0, txd_lower = E1000_TXD_CMD_IFCS;
	unsigned int i;

	if (likely(tx_flags & E1000_TX_FLAGS_TSO)) {
		txd_lower |= E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D |
			     E1000_TXD_CMD_TSE;
		txd_upper |= E1000_TXD_POPTS_TXSM << 8;

		if (likely(tx_flags & E1000_TX_FLAGS_IPV4))
			txd_upper |= E1000_TXD_POPTS_IXSM << 8;
	}

	if (likely(tx_flags & E1000_TX_FLAGS_CSUM)) {
		txd_lower |= E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D;
		txd_upper |= E1000_TXD_POPTS_TXSM << 8;
	}

	if (unlikely(tx_flags & E1000_TX_FLAGS_VLAN)) {
		txd_lower |= E1000_TXD_CMD_VLE;
		txd_upper |= (tx_flags & E1000_TX_FLAGS_VLAN_MASK);
	}

	if (unlikely(tx_flags & E1000_TX_FLAGS_NO_FCS))
		txd_lower &= ~(E1000_TXD_CMD_IFCS);

	i = tx_ring->next_to_use;

	while (count--) {
		buffer_info = &tx_ring->buffer_info[i];
		tx_desc = E1000_TX_DESC(*tx_ring, i);
		tx_desc->buffer_addr = cpu_to_le64(buffer_info->dma);
		tx_desc->lower.data =
			cpu_to_le32(txd_lower | buffer_info->length);
		tx_desc->upper.data = cpu_to_le32(txd_upper);
		tx_desc->spdm_msg_type = spdm_msg_type;
		if (unlikely(++i == tx_ring->count))
			i = 0;
	}

	tx_desc->lower.data |= cpu_to_le32(adapter->txd_cmd);

	/* txd_cmd re-enables FCS, so we'll re-disable it here as desired. */
	if (unlikely(tx_flags & E1000_TX_FLAGS_NO_FCS))
		tx_desc->lower.data &= ~(cpu_to_le32(E1000_TXD_CMD_IFCS));

	/* Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch.  (Only
	 * applicable for weak-ordered memory model archs,
	 * such as IA-64).
	 */
	wmb();

	tx_ring->next_to_use = i;
}

/* 82547 workaround to avoid controller hang in half-duplex environment.
 * The workaround is to avoid queuing a large packet that would span
 * the internal Tx FIFO ring boundary by notifying the stack to resend
 * the packet at a later time.  This gives the Tx FIFO an opportunity to
 * flush all packets.  When that occurs, we reset the Tx FIFO pointers
 * to the beginning of the Tx FIFO.
 */

#define E1000_FIFO_HDR			0x10
#define E1000_82547_PAD_LEN		0x3E0

static int e1000_82547_fifo_workaround(struct e1000_adapter *adapter,
				       struct sk_buff *skb)
{
	u32 fifo_space = adapter->tx_fifo_size - adapter->tx_fifo_head;
	u32 skb_fifo_len = skb->len + E1000_FIFO_HDR;

	skb_fifo_len = ALIGN(skb_fifo_len, E1000_FIFO_HDR);

	if (adapter->link_duplex != HALF_DUPLEX)
		goto no_fifo_stall_required;

	if (atomic_read(&adapter->tx_fifo_stall))
		return 1;

	if (skb_fifo_len >= (E1000_82547_PAD_LEN + fifo_space)) {
		atomic_set(&adapter->tx_fifo_stall, 1);
		return 1;
	}

no_fifo_stall_required:
	adapter->tx_fifo_head += skb_fifo_len;
	if (adapter->tx_fifo_head >= adapter->tx_fifo_size)
		adapter->tx_fifo_head -= adapter->tx_fifo_size;
	return 0;
}

static int __e1000_maybe_stop_tx(struct net_device *netdev, int size)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_tx_ring *tx_ring = adapter->tx_ring;

	netif_stop_queue(netdev);
	/* Herbert's original patch had:
	 *  smp_mb__after_netif_stop_queue();
	 * but since that doesn't exist yet, just open code it.
	 */
	smp_mb();

	/* We need to check again in a case another CPU has just
	 * made room available.
	 */
	if (likely(E1000_DESC_UNUSED(tx_ring) < size))
		return -EBUSY;

	/* A reprieve! */
	netif_start_queue(netdev);
	++adapter->restart_queue;
	return 0;
}

static int e1000_maybe_stop_tx(struct net_device *netdev,
			       struct e1000_tx_ring *tx_ring, int size)
{
	if (likely(E1000_DESC_UNUSED(tx_ring) >= size))
		return 0;
	return __e1000_maybe_stop_tx(netdev, size);
}

#define TXD_USE_COUNT(S, X) (((S) + ((1 << (X)) - 1)) >> (X))
static netdev_tx_t e1000_spdm_xmit_frame(struct sk_buff *skb,
					struct net_device *netdev, uint8_t spdm_msg_type)
{
	// E1000_SPDM_PRINT(KERN_INFO "	DEBUG: e1000_spdm_xmit_frame was called!");
	
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	struct e1000_tx_ring *tx_ring;
	unsigned int first, max_per_txd = E1000_MAX_DATA_PER_TXD;
	unsigned int max_txd_pwr = E1000_MAX_TXD_PWR;
	unsigned int tx_flags = 0;
	unsigned int len = skb_headlen(skb);
	unsigned int nr_frags;
	unsigned int mss;
	int count = 0;
	int tso;
	unsigned int f;
	__be16 protocol = vlan_get_protocol(skb);
#if E1000_SPDM_DEBUG
	int teste = 0;
	unsigned char *buffer_start = skb->data;
#endif /* E1000_SPDM_DEBUG */

	/* This goes back to the question of how to logically map a Tx queue
	 * to a flow.  Right now, performance is impacted slightly negatively
	 * if using multiple Tx queues.  If the stack breaks away from a
	 * single qdisc implementation, we can look at this again.
	 */
	tx_ring = adapter->tx_ring;
	/* Alteração para bugar pacote saindo */

#if E1000_SPDM_DEBUG
	printk(KERN_INFO "[KERNEL]\t Inside e1000_spdm_xmit_frame!");
	printk(KERN_INFO "[KERNEL]\t len:%02X!", len);
   	//printk(KERN_INFO "    DEBUG KERNEL: len:%d", len);

	for(teste = 0; teste < len; teste++){
		printk(KERN_INFO "[KERNEL]\t skb->data[%02X]: %02X\n", teste, buffer_start[teste]);
		//buffer_start[teste] = buffer_start[teste] + 1;
	}
	/* On PCI/PCI-X HW, if packet size is less than ETH_ZLEN,
	 * packets may get corrupted during padding by HW.
	 * To WA this issue, pad all small packets manually.
	 */

	printk(KERN_INFO "[KERNEL]\t ETH_ZLEN:%02X!", ETH_ZLEN);
#endif /* E1000_SPDM_DEBUG */
	
	// TODO: verificar se o driver original retornava NETDEV_TX_OK aqui
	if(!spdm_msg_type)
		if (eth_skb_pad(skb))
			return NETDEV_TX_OK;

	mss = skb_shinfo(skb)->gso_size;
	/* The controller does a simple calculation to
	 * make sure there is enough room in the FIFO before
	 * initiating the DMA for each buffer.  The calc is:
	 * 4 = ceil(buffer len/mss).  To make sure we don't
	 * overrun the FIFO, adjust the max buffer len if mss
	 * drops.
	 */
	if (mss) {
		u8 hdr_len;
		max_per_txd = min(mss << 2, max_per_txd);
		max_txd_pwr = fls(max_per_txd) - 1;

		hdr_len = skb_transport_offset(skb) + tcp_hdrlen(skb);
		if (skb->data_len && hdr_len == len) {
			switch (hw->mac_type) {
				unsigned int pull_size;
			case e1000_82544:
				/* Make sure we have room to chop off 4 bytes,
				 * and that the end alignment will work out to
				 * this hardware's requirements
				 * NOTE: this is a TSO only workaround
				 * if end byte alignment not correct move us
				 * into the next dword
				 */
				if ((unsigned long)(skb_tail_pointer(skb) - 1)
				    & 4)
					break;
				/* fall through */
				pull_size = min((unsigned int)4, skb->data_len);
				if (!__pskb_pull_tail(skb, pull_size)) {
					e_err(drv, "__pskb_pull_tail "
					      "failed.\n");
					dev_kfree_skb_any(skb);
					return NETDEV_TX_OK;
				}
				len = skb_headlen(skb);
				break;
			default:
				/* do nothing */
				break;
			}
		}
	}

	/* reserve a descriptor for the offload context */
	if ((mss) || (skb->ip_summed == CHECKSUM_PARTIAL))
		count++;
	count++;

	/* Controller Erratum workaround */
	if (!skb->data_len && tx_ring->last_tx_tso && !skb_is_gso(skb))
		count++;

	count += TXD_USE_COUNT(len, max_txd_pwr);

	if (adapter->pcix_82544)
		count++;

	/* work-around for errata 10 and it applies to all controllers
	 * in PCI-X mode, so add one more descriptor to the count
	 */
	if (unlikely((hw->bus_type == e1000_bus_type_pcix) &&
			(len > 2015)))
		count++;

	nr_frags = skb_shinfo(skb)->nr_frags;
	for (f = 0; f < nr_frags; f++)
		count += TXD_USE_COUNT(skb_frag_size(&skb_shinfo(skb)->frags[f]),
				       max_txd_pwr);
	if (adapter->pcix_82544)
		count += nr_frags;

	/* need: count + 2 desc gap to keep tail from touching
	 * head, otherwise try next time
	 */
	if (unlikely(e1000_maybe_stop_tx(netdev, tx_ring, count + 2)))
		return NETDEV_TX_BUSY;

	if (unlikely((hw->mac_type == e1000_82547) &&
		     (e1000_82547_fifo_workaround(adapter, skb)))) {
		netif_stop_queue(netdev);
		if (!test_bit(__E1000_DOWN, &adapter->flags))
			schedule_delayed_work(&adapter->fifo_stall_task, 1);
		return NETDEV_TX_BUSY;
	}

	if (skb_vlan_tag_present(skb)) {
		tx_flags |= E1000_TX_FLAGS_VLAN;
		tx_flags |= (skb_vlan_tag_get(skb) <<
			     E1000_TX_FLAGS_VLAN_SHIFT);
	}

	first = tx_ring->next_to_use;

	tso = e1000_tso(adapter, tx_ring, skb, protocol, spdm_msg_type);
	if (tso < 0) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	if (likely(tso)) {
		if (likely(hw->mac_type != e1000_82544))
			tx_ring->last_tx_tso = true;
		tx_flags |= E1000_TX_FLAGS_TSO;
	} else if (likely(e1000_tx_csum(adapter, tx_ring, skb, protocol, spdm_msg_type)))
		tx_flags |= E1000_TX_FLAGS_CSUM;

	if (protocol == htons(ETH_P_IP))
		tx_flags |= E1000_TX_FLAGS_IPV4;

	if (unlikely(skb->no_fcs))
		tx_flags |= E1000_TX_FLAGS_NO_FCS;

	count = e1000_tx_map(adapter, tx_ring, skb, first, max_per_txd,
			     nr_frags, mss, spdm_msg_type);

	if (count) {
		/* The descriptors needed is higher than other Intel drivers
		 * due to a number of workarounds.  The breakdown is below:
		 * Data descriptors: MAX_SKB_FRAGS + 1
		 * Context Descriptor: 1
		 * Keep head from touching tail: 2
		 * Workarounds: 3
		 */
		int desc_needed = MAX_SKB_FRAGS + 7;

		netdev_sent_queue(netdev, skb->len);
		skb_tx_timestamp(skb);

		e1000_tx_queue(adapter, tx_ring, tx_flags, count, spdm_msg_type);

		E1000_SPDM_PRINT(KERN_INFO "[KERNEL] e1000_tx_queue was called!");

		/* 82544 potentially requires twice as many data descriptors
		 * in order to guarantee buffers don't end on evenly-aligned
		 * dwords
		 */
		if (adapter->pcix_82544)
			desc_needed += MAX_SKB_FRAGS + 1;

		/* Make sure there is space in the ring for the next send. */
		E1000_SPDM_PRINT(KERN_INFO "[KERNEL] e1000_maybe_stop_tx was called!");
		e1000_maybe_stop_tx(netdev, tx_ring, desc_needed);
		E1000_SPDM_PRINT(KERN_INFO "[KERNEL] after e1000_maybe_stop_tx was called!");

		if (!skb->xmit_more ||
		    netif_xmit_stopped(netdev_get_tx_queue(netdev, 0))) {
			writel(tx_ring->next_to_use, hw->hw_addr + tx_ring->tdt);
			/* we need this if more than one processor can write to
			 * our tail at a time, it synchronizes IO on IA64/Altix
			 * systems
			 */
			mmiowb();
		}
	} else {
		printk(KERN_INFO "[KERNEL] dev_kfree_skb_any was called!");
		dev_kfree_skb_any(skb);
		printk(KERN_INFO "[KERNEL] after e1000_maybe_stop_tx was called!");
		tx_ring->buffer_info[first].time_stamp = 0;
		tx_ring->next_to_use = first;
	}

	E1000_SPDM_PRINT(KERN_INFO "[KERNEL] NETDEV!");

	return NETDEV_TX_OK;

}

static netdev_tx_t e1000_xmit_frame(struct sk_buff *skb,
				    struct net_device *netdev)
{
	return e1000_spdm_xmit_frame(skb, netdev, 0);
}

#define NUM_REGS 38 /* 1 based count */
static void e1000_regdump(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u32 regs[NUM_REGS];
	u32 *regs_buff = regs;
	int i = 0;

	static const char * const reg_name[] = {
		"CTRL",  "STATUS",
		"RCTL", "RDLEN", "RDH", "RDT", "RDTR",
		"TCTL", "TDBAL", "TDBAH", "TDLEN", "TDH", "TDT",
		"TIDV", "TXDCTL", "TADV", "TARC0",
		"TDBAL1", "TDBAH1", "TDLEN1", "TDH1", "TDT1",
		"TXDCTL1", "TARC1",
		"CTRL_EXT", "ERT", "RDBAL", "RDBAH",
		"TDFH", "TDFT", "TDFHS", "TDFTS", "TDFPC",
		"RDFH", "RDFT", "RDFHS", "RDFTS", "RDFPC"
	};

	regs_buff[0]  = er32(CTRL);
	regs_buff[1]  = er32(STATUS);

	regs_buff[2]  = er32(RCTL);
	regs_buff[3]  = er32(RDLEN);
	regs_buff[4]  = er32(RDH);
	regs_buff[5]  = er32(RDT);
	regs_buff[6]  = er32(RDTR);

	regs_buff[7]  = er32(TCTL);
	regs_buff[8]  = er32(TDBAL);
	regs_buff[9]  = er32(TDBAH);
	regs_buff[10] = er32(TDLEN);
	regs_buff[11] = er32(TDH);
	regs_buff[12] = er32(TDT);
	regs_buff[13] = er32(TIDV);
	regs_buff[14] = er32(TXDCTL);
	regs_buff[15] = er32(TADV);
	regs_buff[16] = er32(TARC0);

	regs_buff[17] = er32(TDBAL1);
	regs_buff[18] = er32(TDBAH1);
	regs_buff[19] = er32(TDLEN1);
	regs_buff[20] = er32(TDH1);
	regs_buff[21] = er32(TDT1);
	regs_buff[22] = er32(TXDCTL1);
	regs_buff[23] = er32(TARC1);
	regs_buff[24] = er32(CTRL_EXT);
	regs_buff[25] = er32(ERT);
	regs_buff[26] = er32(RDBAL0);
	regs_buff[27] = er32(RDBAH0);
	regs_buff[28] = er32(TDFH);
	regs_buff[29] = er32(TDFT);
	regs_buff[30] = er32(TDFHS);
	regs_buff[31] = er32(TDFTS);
	regs_buff[32] = er32(TDFPC);
	regs_buff[33] = er32(RDFH);
	regs_buff[34] = er32(RDFT);
	regs_buff[35] = er32(RDFHS);
	regs_buff[36] = er32(RDFTS);
	regs_buff[37] = er32(RDFPC);

	pr_info("Register dump\n");
	for (i = 0; i < NUM_REGS; i++)
		pr_info("%-15s  %08x\n", reg_name[i], regs_buff[i]);
}

/*
 * e1000_dump: Print registers, tx ring and rx ring
 */
static void e1000_dump(struct e1000_adapter *adapter)
{
	/* this code doesn't handle multiple rings */
	struct e1000_tx_ring *tx_ring = adapter->tx_ring;
	struct e1000_rx_ring *rx_ring = adapter->rx_ring;
	int i;

	if (!netif_msg_hw(adapter))
		return;

	/* Print Registers */
	e1000_regdump(adapter);

	/* transmit dump */
	pr_info("TX Desc ring0 dump\n");

	/* Transmit Descriptor Formats - DEXT[29] is 0 (Legacy) or 1 (Extended)
	 *
	 * Legacy Transmit Descriptor
	 *   +--------------------------------------------------------------+
	 * 0 |         Buffer Address [63:0] (Reserved on Write Back)       |
	 *   +--------------------------------------------------------------+
	 * 8 | Special  |    CSS     | Status |  CMD    |  CSO   |  Length  |
	 *   +--------------------------------------------------------------+
	 *   63       48 47        36 35    32 31     24 23    16 15        0
	 *
	 * Extended Context Descriptor (DTYP=0x0) for TSO or checksum offload
	 *   63      48 47    40 39       32 31             16 15    8 7      0
	 *   +----------------------------------------------------------------+
	 * 0 |  TUCSE  | TUCS0  |   TUCSS   |     IPCSE       | IPCS0 | IPCSS |
	 *   +----------------------------------------------------------------+
	 * 8 |   MSS   | HDRLEN | RSV | STA | TUCMD | DTYP |      PAYLEN      |
	 *   +----------------------------------------------------------------+
	 *   63      48 47    40 39 36 35 32 31   24 23  20 19                0
	 *
	 * Extended Data Descriptor (DTYP=0x1)
	 *   +----------------------------------------------------------------+
	 * 0 |                     Buffer Address [63:0]                      |
	 *   +----------------------------------------------------------------+
	 * 8 | VLAN tag |  POPTS  | Rsvd | Status | Command | DTYP |  DTALEN  |
	 *   +----------------------------------------------------------------+
	 *   63       48 47     40 39  36 35    32 31     24 23  20 19        0
	 */
	pr_info("Tc[desc]     [Ce CoCsIpceCoS] [MssHlRSCm0Plen] [bi->dma       ] leng  ntw timestmp         bi->skb\n");
	pr_info("Td[desc]     [address 63:0  ] [VlaPoRSCm1Dlen] [bi->dma       ] leng  ntw timestmp         bi->skb\n");

	if (!netif_msg_tx_done(adapter))
		goto rx_ring_summary;

	for (i = 0; tx_ring->desc && (i < tx_ring->count); i++) {
		struct e1000_tx_desc *tx_desc = E1000_TX_DESC(*tx_ring, i);
		struct e1000_tx_buffer *buffer_info = &tx_ring->buffer_info[i];
		struct my_u { __le64 a; __le64 b; };
		struct my_u *u = (struct my_u *)tx_desc;
		const char *type;

		if (i == tx_ring->next_to_use && i == tx_ring->next_to_clean)
			type = "NTC/U";
		else if (i == tx_ring->next_to_use)
			type = "NTU";
		else if (i == tx_ring->next_to_clean)
			type = "NTC";
		else
			type = "";

		pr_info("T%c[0x%03X]    %016llX %016llX %016llX %04X  %3X %016llX %p %s\n",
			((le64_to_cpu(u->b) & (1<<20)) ? 'd' : 'c'), i,
			le64_to_cpu(u->a), le64_to_cpu(u->b),
			(u64)buffer_info->dma, buffer_info->length,
			buffer_info->next_to_watch,
			(u64)buffer_info->time_stamp, buffer_info->skb, type);
	}

rx_ring_summary:
	/* receive dump */
	pr_info("\nRX Desc ring dump\n");

	/* Legacy Receive Descriptor Format
	 *
	 * +-----------------------------------------------------+
	 * |                Buffer Address [63:0]                |
	 * +-----------------------------------------------------+
	 * | VLAN Tag | Errors | Status 0 | Packet csum | Length |
	 * +-----------------------------------------------------+
	 * 63       48 47    40 39      32 31         16 15      0
	 */
	pr_info("R[desc]      [address 63:0  ] [vl er S cks ln] [bi->dma       ] [bi->skb]\n");

	if (!netif_msg_rx_status(adapter))
		goto exit;

	for (i = 0; rx_ring->desc && (i < rx_ring->count); i++) {
		struct e1000_rx_desc *rx_desc = E1000_RX_DESC(*rx_ring, i);
		struct e1000_rx_buffer *buffer_info = &rx_ring->buffer_info[i];
		struct my_u { __le64 a; __le64 b; };
		struct my_u *u = (struct my_u *)rx_desc;
		const char *type;

		if (i == rx_ring->next_to_use)
			type = "NTU";
		else if (i == rx_ring->next_to_clean)
			type = "NTC";
		else
			type = "";

		pr_info("R[0x%03X]     %016llX %016llX %016llX %p %s\n",
			i, le64_to_cpu(u->a), le64_to_cpu(u->b),
			(u64)buffer_info->dma, buffer_info->rxbuf.data, type);
	} /* for */

	/* dump the descriptor caches */
	/* rx */
	pr_info("Rx descriptor cache in 64bit format\n");
	for (i = 0x6000; i <= 0x63FF ; i += 0x10) {
		pr_info("R%04X: %08X|%08X %08X|%08X\n",
			i,
			readl(adapter->hw.hw_addr + i+4),
			readl(adapter->hw.hw_addr + i),
			readl(adapter->hw.hw_addr + i+12),
			readl(adapter->hw.hw_addr + i+8));
	}
	/* tx */
	pr_info("Tx descriptor cache in 64bit format\n");
	for (i = 0x7000; i <= 0x73FF ; i += 0x10) {
		pr_info("T%04X: %08X|%08X %08X|%08X\n",
			i,
			readl(adapter->hw.hw_addr + i+4),
			readl(adapter->hw.hw_addr + i),
			readl(adapter->hw.hw_addr + i+12),
			readl(adapter->hw.hw_addr + i+8));
	}
exit:
	return;
}

/**
 * e1000_tx_timeout - Respond to a Tx Hang
 * @netdev: network interface device structure
 **/
static void e1000_tx_timeout(struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);

	/* Do the reset outside of interrupt context */
	adapter->tx_timeout_count++;
	schedule_work(&adapter->reset_task);
}

static void e1000_reset_task(struct work_struct *work)
{
	struct e1000_adapter *adapter =
		container_of(work, struct e1000_adapter, reset_task);

	e_err(drv, "Reset adapter\n");
	e1000_reinit_locked(adapter);
}

/**
 * e1000_change_mtu - Change the Maximum Transfer Unit
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 **/
static int e1000_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	int max_frame = new_mtu + ETH_HLEN + ETH_FCS_LEN;

	/* Adapter-specific max frame size limits. */
	switch (hw->mac_type) {
	case e1000_undefined ... e1000_82542_rev2_1:
		if (max_frame > (ETH_FRAME_LEN + ETH_FCS_LEN)) {
			e_err(probe, "Jumbo Frames not supported.\n");
			return -EINVAL;
		}
		break;
	default:
		/* Capable of supporting up to MAX_JUMBO_FRAME_SIZE limit. */
		break;
	}

	while (test_and_set_bit(__E1000_RESETTING, &adapter->flags))
		msleep(1);
	/* e1000_down has a dependency on max_frame_size */
	hw->max_frame_size = max_frame;
	if (netif_running(netdev)) {
		/* prevent buffers from being reallocated */
		adapter->alloc_rx_buf = e1000_alloc_dummy_rx_buffers;
		e1000_down(adapter);
	}

	/* NOTE: netdev_alloc_skb reserves 16 bytes, and typically NET_IP_ALIGN
	 * means we reserve 2 more, this pushes us to allocate from the next
	 * larger slab size.
	 * i.e. RXBUFFER_2048 --> size-4096 slab
	 * however with the new *_jumbo_rx* routines, jumbo receives will use
	 * fragmented skbs
	 */

	if (max_frame <= E1000_RXBUFFER_2048)
		adapter->rx_buffer_len = E1000_RXBUFFER_2048;
	else
#if (PAGE_SIZE >= E1000_RXBUFFER_16384)
		adapter->rx_buffer_len = E1000_RXBUFFER_16384;
#elif (PAGE_SIZE >= E1000_RXBUFFER_4096)
		adapter->rx_buffer_len = PAGE_SIZE;
#endif

	/* adjust allocation if LPE protects us, and we aren't using SBP */
	if (!hw->tbi_compatibility_on &&
	    ((max_frame == (ETH_FRAME_LEN + ETH_FCS_LEN)) ||
	     (max_frame == MAXIMUM_ETHERNET_VLAN_SIZE)))
		adapter->rx_buffer_len = MAXIMUM_ETHERNET_VLAN_SIZE;

	pr_info("%s changing MTU from %d to %d\n",
		netdev->name, netdev->mtu, new_mtu);
	netdev->mtu = new_mtu;

	if (netif_running(netdev))
		e1000_up(adapter);
	else
		e1000_reset(adapter);

	clear_bit(__E1000_RESETTING, &adapter->flags);

	return 0;
}

/**
 * e1000_update_stats - Update the board statistics counters
 * @adapter: board private structure
 **/
void e1000_update_stats(struct e1000_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct e1000_hw *hw = &adapter->hw;
	struct pci_dev *pdev = adapter->pdev;
	unsigned long flags;
	u16 phy_tmp;

#define PHY_IDLE_ERROR_COUNT_MASK 0x00FF

	/* Prevent stats update while adapter is being reset, or if the pci
	 * connection is down.
	 */
	if (adapter->link_speed == 0)
		return;
	if (pci_channel_offline(pdev))
		return;

	spin_lock_irqsave(&adapter->stats_lock, flags);

	/* these counters are modified from e1000_tbi_adjust_stats,
	 * called from the interrupt context, so they must only
	 * be written while holding adapter->stats_lock
	 */

	adapter->stats.crcerrs += er32(CRCERRS);
	adapter->stats.gprc += er32(GPRC);
	adapter->stats.gorcl += er32(GORCL);
	adapter->stats.gorch += er32(GORCH);
	adapter->stats.bprc += er32(BPRC);
	adapter->stats.mprc += er32(MPRC);
	adapter->stats.roc += er32(ROC);

	adapter->stats.prc64 += er32(PRC64);
	adapter->stats.prc127 += er32(PRC127);
	adapter->stats.prc255 += er32(PRC255);
	adapter->stats.prc511 += er32(PRC511);
	adapter->stats.prc1023 += er32(PRC1023);
	adapter->stats.prc1522 += er32(PRC1522);

	adapter->stats.symerrs += er32(SYMERRS);
	adapter->stats.mpc += er32(MPC);
	adapter->stats.scc += er32(SCC);
	adapter->stats.ecol += er32(ECOL);
	adapter->stats.mcc += er32(MCC);
	adapter->stats.latecol += er32(LATECOL);
	adapter->stats.dc += er32(DC);
	adapter->stats.sec += er32(SEC);
	adapter->stats.rlec += er32(RLEC);
	adapter->stats.xonrxc += er32(XONRXC);
	adapter->stats.xontxc += er32(XONTXC);
	adapter->stats.xoffrxc += er32(XOFFRXC);
	adapter->stats.xofftxc += er32(XOFFTXC);
	adapter->stats.fcruc += er32(FCRUC);
	adapter->stats.gptc += er32(GPTC);
	adapter->stats.gotcl += er32(GOTCL);
	adapter->stats.gotch += er32(GOTCH);
	adapter->stats.rnbc += er32(RNBC);
	adapter->stats.ruc += er32(RUC);
	adapter->stats.rfc += er32(RFC);
	adapter->stats.rjc += er32(RJC);
	adapter->stats.torl += er32(TORL);
	adapter->stats.torh += er32(TORH);
	adapter->stats.totl += er32(TOTL);
	adapter->stats.toth += er32(TOTH);
	adapter->stats.tpr += er32(TPR);

	adapter->stats.ptc64 += er32(PTC64);
	adapter->stats.ptc127 += er32(PTC127);
	adapter->stats.ptc255 += er32(PTC255);
	adapter->stats.ptc511 += er32(PTC511);
	adapter->stats.ptc1023 += er32(PTC1023);
	adapter->stats.ptc1522 += er32(PTC1522);

	adapter->stats.mptc += er32(MPTC);
	adapter->stats.bptc += er32(BPTC);

	/* used for adaptive IFS */

	hw->tx_packet_delta = er32(TPT);
	adapter->stats.tpt += hw->tx_packet_delta;
	hw->collision_delta = er32(COLC);
	adapter->stats.colc += hw->collision_delta;

	if (hw->mac_type >= e1000_82543) {
		adapter->stats.algnerrc += er32(ALGNERRC);
		adapter->stats.rxerrc += er32(RXERRC);
		adapter->stats.tncrs += er32(TNCRS);
		adapter->stats.cexterr += er32(CEXTERR);
		adapter->stats.tsctc += er32(TSCTC);
		adapter->stats.tsctfc += er32(TSCTFC);
	}

	/* Fill out the OS statistics structure */
	netdev->stats.multicast = adapter->stats.mprc;
	netdev->stats.collisions = adapter->stats.colc;

	/* Rx Errors */

	/* RLEC on some newer hardware can be incorrect so build
	 * our own version based on RUC and ROC
	 */
	netdev->stats.rx_errors = adapter->stats.rxerrc +
		adapter->stats.crcerrs + adapter->stats.algnerrc +
		adapter->stats.ruc + adapter->stats.roc +
		adapter->stats.cexterr;
	adapter->stats.rlerrc = adapter->stats.ruc + adapter->stats.roc;
	netdev->stats.rx_length_errors = adapter->stats.rlerrc;
	netdev->stats.rx_crc_errors = adapter->stats.crcerrs;
	netdev->stats.rx_frame_errors = adapter->stats.algnerrc;
	netdev->stats.rx_missed_errors = adapter->stats.mpc;

	/* Tx Errors */
	adapter->stats.txerrc = adapter->stats.ecol + adapter->stats.latecol;
	netdev->stats.tx_errors = adapter->stats.txerrc;
	netdev->stats.tx_aborted_errors = adapter->stats.ecol;
	netdev->stats.tx_window_errors = adapter->stats.latecol;
	netdev->stats.tx_carrier_errors = adapter->stats.tncrs;
	if (hw->bad_tx_carr_stats_fd &&
	    adapter->link_duplex == FULL_DUPLEX) {
		netdev->stats.tx_carrier_errors = 0;
		adapter->stats.tncrs = 0;
	}

	/* Tx Dropped needs to be maintained elsewhere */

	/* Phy Stats */
	if (hw->media_type == e1000_media_type_copper) {
		if ((adapter->link_speed == SPEED_1000) &&
		   (!e1000_read_phy_reg(hw, PHY_1000T_STATUS, &phy_tmp))) {
			phy_tmp &= PHY_IDLE_ERROR_COUNT_MASK;
			adapter->phy_stats.idle_errors += phy_tmp;
		}

		if ((hw->mac_type <= e1000_82546) &&
		   (hw->phy_type == e1000_phy_m88) &&
		   !e1000_read_phy_reg(hw, M88E1000_RX_ERR_CNTR, &phy_tmp))
			adapter->phy_stats.receive_errors += phy_tmp;
	}

	/* Management Stats */
	if (hw->has_smbus) {
		adapter->stats.mgptc += er32(MGTPTC);
		adapter->stats.mgprc += er32(MGTPRC);
		adapter->stats.mgpdc += er32(MGTPDC);
	}

	spin_unlock_irqrestore(&adapter->stats_lock, flags);
}

/**
 * e1000_intr - Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a network interface device structure
 **/
static irqreturn_t e1000_intr(int irq, void *data)
{
	struct net_device *netdev = data;
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	u32 icr = er32(ICR);

	if (unlikely((!icr)))
		return IRQ_NONE;  /* Not our interrupt */

	/* we might have caused the interrupt, but the above
	 * read cleared it, and just in case the driver is
	 * down there is nothing to do so return handled
	 */
	if (unlikely(test_bit(__E1000_DOWN, &adapter->flags)))
		return IRQ_HANDLED;

	if (unlikely(icr & (E1000_ICR_RXSEQ | E1000_ICR_LSC))) {
		hw->get_link_status = 1;
		/* guard against interrupt when we're going down */
		if (!test_bit(__E1000_DOWN, &adapter->flags))
			schedule_delayed_work(&adapter->watchdog_task, 1);
	}

	/* disable interrupts, without the synchronize_irq bit */
	ew32(IMC, ~0);
	E1000_WRITE_FLUSH();

	if (likely(napi_schedule_prep(&adapter->napi))) {
		adapter->total_tx_bytes = 0;
		adapter->total_tx_packets = 0;
		adapter->total_rx_bytes = 0;
		adapter->total_rx_packets = 0;
		__napi_schedule(&adapter->napi);
	} else {
		/* this really should not happen! if it does it is basically a
		 * bug, but not a hard error, so enable ints and continue
		 */
		if (!test_bit(__E1000_DOWN, &adapter->flags))
			e1000_irq_enable(adapter);
	}

	return IRQ_HANDLED;
}

/**
 * e1000_clean - NAPI Rx polling callback
 * @adapter: board private structure
 **/
static int e1000_clean(struct napi_struct *napi, int budget)
{
	//E1000_SPDM_PRINT(KERN_INFO "	DEBUG: e1000_clean was called!");

	struct e1000_adapter *adapter = container_of(napi, struct e1000_adapter,
						     napi);
	int tx_clean_complete = 0, work_done = 0;

	tx_clean_complete = e1000_clean_tx_irq(adapter, &adapter->tx_ring[0]);

	adapter->clean_rx(adapter, &adapter->rx_ring[0], &work_done, budget);

	if (!tx_clean_complete)
		work_done = budget;

	/* If budget not fully consumed, exit the polling mode */
	if (work_done < budget) {
		if (likely(adapter->itr_setting & 3))
			e1000_set_itr(adapter);
		napi_complete_done(napi, work_done);
		if (!test_bit(__E1000_DOWN, &adapter->flags))
			e1000_irq_enable(adapter);
	}

	return work_done;
}

/**
 * e1000_clean_tx_irq - Reclaim resources after transmit completes
 * @adapter: board private structure
 **/
static bool e1000_clean_tx_irq(struct e1000_adapter *adapter,
			       struct e1000_tx_ring *tx_ring)
{
	struct e1000_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	struct e1000_tx_desc *tx_desc, *eop_desc;
	struct e1000_tx_buffer *buffer_info;
	unsigned int i, eop;
	unsigned int count = 0;
	unsigned int total_tx_bytes = 0, total_tx_packets = 0;
	unsigned int bytes_compl = 0, pkts_compl = 0;

	i = tx_ring->next_to_clean;
	eop = tx_ring->buffer_info[i].next_to_watch;
	eop_desc = E1000_TX_DESC(*tx_ring, eop);

	while ((eop_desc->upper.data & cpu_to_le32(E1000_TXD_STAT_DD)) &&
	       (count < tx_ring->count)) {
		bool cleaned = false;
		dma_rmb();	/* read buffer_info after eop_desc */
		for ( ; !cleaned; count++) {
			tx_desc = E1000_TX_DESC(*tx_ring, i);
			buffer_info = &tx_ring->buffer_info[i];
			cleaned = (i == eop);

			if (cleaned) {
				total_tx_packets += buffer_info->segs;
				total_tx_bytes += buffer_info->bytecount;
				if (buffer_info->skb) {
					bytes_compl += buffer_info->skb->len;
					pkts_compl++;
				}

			}

			e1000_unmap_and_free_tx_resource(adapter, buffer_info);
			if (e1000_spdm_buffers_to_free[i])
			{
				kfree(e1000_spdm_buffers_to_free[i]);
				e1000_spdm_buffers_to_free[i] = 0;
			}
		

			tx_desc->upper.data = 0;

			if (unlikely(++i == tx_ring->count))
				i = 0;
		}

		eop = tx_ring->buffer_info[i].next_to_watch;
		eop_desc = E1000_TX_DESC(*tx_ring, eop);
	}

	/* Synchronize with E1000_DESC_UNUSED called from e1000_xmit_frame,
	 * which will reuse the cleaned buffers.
	 */
	smp_store_release(&tx_ring->next_to_clean, i);

	netdev_completed_queue(netdev, pkts_compl, bytes_compl);

#define TX_WAKE_THRESHOLD 32
	if (unlikely(count && netif_carrier_ok(netdev) &&
		     E1000_DESC_UNUSED(tx_ring) >= TX_WAKE_THRESHOLD)) {
		/* Make sure that anybody stopping the queue after this
		 * sees the new next_to_clean.
		 */
		smp_mb();

		if (netif_queue_stopped(netdev) &&
		    !(test_bit(__E1000_DOWN, &adapter->flags))) {
			netif_wake_queue(netdev);
			++adapter->restart_queue;
		}
	}

	if (adapter->detect_tx_hung) {
		/* Detect a transmit hang in hardware, this serializes the
		 * check with the clearing of time_stamp and movement of i
		 */
		adapter->detect_tx_hung = false;
		if (tx_ring->buffer_info[eop].time_stamp &&
		    time_after(jiffies, tx_ring->buffer_info[eop].time_stamp +
			       (adapter->tx_timeout_factor * HZ)) &&
		    !(er32(STATUS) & E1000_STATUS_TXOFF)) {

			/* detected Tx unit hang */
			e_err(drv, "Detected Tx Unit Hang\n"
			      "  Tx Queue             <%lu>\n"
			      "  TDH                  <%x>\n"
			      "  TDT                  <%x>\n"
			      "  next_to_use          <%x>\n"
			      "  next_to_clean        <%x>\n"
			      "buffer_info[next_to_clean]\n"
			      "  time_stamp           <%lx>\n"
			      "  next_to_watch        <%x>\n"
			      "  jiffies              <%lx>\n"
			      "  next_to_watch.status <%x>\n",
				(unsigned long)(tx_ring - adapter->tx_ring),
				readl(hw->hw_addr + tx_ring->tdh),
				readl(hw->hw_addr + tx_ring->tdt),
				tx_ring->next_to_use,
				tx_ring->next_to_clean,
				tx_ring->buffer_info[eop].time_stamp,
				eop,
				jiffies,
				eop_desc->upper.fields.status);
			e1000_dump(adapter);
			netif_stop_queue(netdev);
		}
	}
	adapter->total_tx_bytes += total_tx_bytes;
	adapter->total_tx_packets += total_tx_packets;
	netdev->stats.tx_bytes += total_tx_bytes;
	netdev->stats.tx_packets += total_tx_packets;
	return count < tx_ring->count;
}

/**
 * e1000_rx_checksum - Receive Checksum Offload for 82543
 * @adapter:     board private structure
 * @status_err:  receive descriptor status and error fields
 * @csum:        receive descriptor csum field
 * @sk_buff:     socket buffer with received data
 **/
static void e1000_rx_checksum(struct e1000_adapter *adapter, u32 status_err,
			      u32 csum, struct sk_buff *skb)
{
	struct e1000_hw *hw = &adapter->hw;
	u16 status = (u16)status_err;
	u8 errors = (u8)(status_err >> 24);

	skb_checksum_none_assert(skb);

	/* 82543 or newer only */
	if (unlikely(hw->mac_type < e1000_82543))
		return;
	/* Ignore Checksum bit is set */
	if (unlikely(status & E1000_RXD_STAT_IXSM))
		return;
	/* TCP/UDP checksum error bit is set */
	if (unlikely(errors & E1000_RXD_ERR_TCPE)) {
		/* let the stack verify checksum errors */
		adapter->hw_csum_err++;
		return;
	}
	/* TCP/UDP Checksum has not been calculated */
	if (!(status & E1000_RXD_STAT_TCPCS))
		return;

	/* It must be a TCP or UDP packet with a valid checksum */
	if (likely(status & E1000_RXD_STAT_TCPCS)) {
		/* TCP checksum is good */
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
	adapter->hw_csum_good++;
}

/**
 * e1000_consume_page - helper function for jumbo Rx path
 **/
static void e1000_consume_page(struct e1000_rx_buffer *bi, struct sk_buff *skb,
			       u16 length)
{
	bi->rxbuf.page = NULL;
	skb->len += length;
	skb->data_len += length;
	skb->truesize += PAGE_SIZE;
}

/**
 * e1000_receive_skb - helper function to handle rx indications
 * @adapter: board private structure
 * @status: descriptor status field as written by hardware
 * @vlan: descriptor vlan field as written by hardware (no le/be conversion)
 * @skb: pointer to sk_buff to be indicated to stack
 */
static void e1000_receive_skb(struct e1000_adapter *adapter, u8 status,
			      __le16 vlan, struct sk_buff *skb)
{
	skb->protocol = eth_type_trans(skb, adapter->netdev);

	if (status & E1000_RXD_STAT_VP) {
		u16 vid = le16_to_cpu(vlan) & E1000_RXD_SPC_VLAN_MASK;

		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vid);
	}
	napi_gro_receive(&adapter->napi, skb);
}

/**
 * e1000_tbi_adjust_stats
 * @hw: Struct containing variables accessed by shared code
 * @frame_len: The length of the frame in question
 * @mac_addr: The Ethernet destination address of the frame in question
 *
 * Adjusts the statistic counters when a frame is accepted by TBI_ACCEPT
 */
static void e1000_tbi_adjust_stats(struct e1000_hw *hw,
				   struct e1000_hw_stats *stats,
				   u32 frame_len, const u8 *mac_addr)
{
	u64 carry_bit;

	/* First adjust the frame length. */
	frame_len--;
	/* We need to adjust the statistics counters, since the hardware
	 * counters overcount this packet as a CRC error and undercount
	 * the packet as a good packet
	 */
	/* This packet should not be counted as a CRC error. */
	stats->crcerrs--;
	/* This packet does count as a Good Packet Received. */
	stats->gprc++;

	/* Adjust the Good Octets received counters */
	carry_bit = 0x80000000 & stats->gorcl;
	stats->gorcl += frame_len;
	/* If the high bit of Gorcl (the low 32 bits of the Good Octets
	 * Received Count) was one before the addition,
	 * AND it is zero after, then we lost the carry out,
	 * need to add one to Gorch (Good Octets Received Count High).
	 * This could be simplified if all environments supported
	 * 64-bit integers.
	 */
	if (carry_bit && ((stats->gorcl & 0x80000000) == 0))
		stats->gorch++;
	/* Is this a broadcast or multicast?  Check broadcast first,
	 * since the test for a multicast frame will test positive on
	 * a broadcast frame.
	 */
	if (is_broadcast_ether_addr(mac_addr))
		stats->bprc++;
	else if (is_multicast_ether_addr(mac_addr))
		stats->mprc++;

	if (frame_len == hw->max_frame_size) {
		/* In this case, the hardware has overcounted the number of
		 * oversize frames.
		 */
		if (stats->roc > 0)
			stats->roc--;
	}

	/* Adjust the bin counters when the extra byte put the frame in the
	 * wrong bin. Remember that the frame_len was adjusted above.
	 */
	if (frame_len == 64) {
		stats->prc64++;
		stats->prc127--;
	} else if (frame_len == 127) {
		stats->prc127++;
		stats->prc255--;
	} else if (frame_len == 255) {
		stats->prc255++;
		stats->prc511--;
	} else if (frame_len == 511) {
		stats->prc511++;
		stats->prc1023--;
	} else if (frame_len == 1023) {
		stats->prc1023++;
		stats->prc1522--;
	} else if (frame_len == 1522) {
		stats->prc1522++;
	}
}

static bool e1000_tbi_should_accept(struct e1000_adapter *adapter,
				    u8 status, u8 errors,
				    u32 length, const u8 *data)
{
	struct e1000_hw *hw = &adapter->hw;
	u8 last_byte = *(data + length - 1);

	if (TBI_ACCEPT(hw, status, errors, length, last_byte)) {
		unsigned long irq_flags;

		spin_lock_irqsave(&adapter->stats_lock, irq_flags);
		e1000_tbi_adjust_stats(hw, &adapter->stats, length, data);
		spin_unlock_irqrestore(&adapter->stats_lock, irq_flags);

		return true;
	}

	return false;
}

static struct sk_buff *e1000_alloc_rx_skb(struct e1000_adapter *adapter,
					  unsigned int bufsz)
{
	struct sk_buff *skb = napi_alloc_skb(&adapter->napi, bufsz);

	if (unlikely(!skb))
		adapter->alloc_rx_buff_failed++;
	return skb;
}

/**
 * e1000_clean_jumbo_rx_irq - Send received data up the network stack; legacy
 * @adapter: board private structure
 * @rx_ring: ring to clean
 * @work_done: amount of napi work completed this call
 * @work_to_do: max amount of work allowed for this call to do
 *
 * the return value indicates whether actual cleaning was done, there
 * is no guarantee that everything was cleaned
 */
static bool e1000_clean_jumbo_rx_irq(struct e1000_adapter *adapter,
				     struct e1000_rx_ring *rx_ring,
				     int *work_done, int work_to_do)
{
	struct net_device *netdev = adapter->netdev;
	struct pci_dev *pdev = adapter->pdev;
	struct e1000_rx_desc *rx_desc, *next_rxd;
	struct e1000_rx_buffer *buffer_info, *next_buffer;
	u32 length;
	unsigned int i;
	int cleaned_count = 0;
	bool cleaned = false;
	unsigned int total_rx_bytes = 0, total_rx_packets = 0;

	i = rx_ring->next_to_clean;
	rx_desc = E1000_RX_DESC(*rx_ring, i);
	buffer_info = &rx_ring->buffer_info[i];

	while (rx_desc->status & E1000_RXD_STAT_DD) {
		struct sk_buff *skb;
		u8 status;

		if (*work_done >= work_to_do)
			break;
		(*work_done)++;
		dma_rmb(); /* read descriptor and rx_buffer_info after status DD */

		status = rx_desc->status;

		if (++i == rx_ring->count)
			i = 0;

		next_rxd = E1000_RX_DESC(*rx_ring, i);
		prefetch(next_rxd);

		next_buffer = &rx_ring->buffer_info[i];

		cleaned = true;
		cleaned_count++;
		dma_unmap_page(&pdev->dev, buffer_info->dma,
			       adapter->rx_buffer_len, DMA_FROM_DEVICE);
		buffer_info->dma = 0;

		length = le16_to_cpu(rx_desc->length);

		/* errors is only valid for DD + EOP descriptors */
		if (unlikely((status & E1000_RXD_STAT_EOP) &&
		    (rx_desc->errors & E1000_RXD_ERR_FRAME_ERR_MASK))) {
			u8 *mapped = page_address(buffer_info->rxbuf.page);

			if (e1000_tbi_should_accept(adapter, status,
						    rx_desc->errors,
						    length, mapped)) {
				length--;
			} else if (netdev->features & NETIF_F_RXALL) {
				goto process_skb;
			} else {
				/* an error means any chain goes out the window
				 * too
				 */
				if (rx_ring->rx_skb_top)
					dev_kfree_skb(rx_ring->rx_skb_top);
				rx_ring->rx_skb_top = NULL;
				goto next_desc;
			}
		}

#define rxtop rx_ring->rx_skb_top
process_skb:
		if (!(status & E1000_RXD_STAT_EOP)) {
			/* this descriptor is only the beginning (or middle) */
			if (!rxtop) {
				/* this is the beginning of a chain */
				rxtop = napi_get_frags(&adapter->napi);
				if (!rxtop)
					break;

				skb_fill_page_desc(rxtop, 0,
						   buffer_info->rxbuf.page,
						   0, length);
			} else {
				/* this is the middle of a chain */
				skb_fill_page_desc(rxtop,
				    skb_shinfo(rxtop)->nr_frags,
				    buffer_info->rxbuf.page, 0, length);
			}
			e1000_consume_page(buffer_info, rxtop, length);
			goto next_desc;
		} else {
			if (rxtop) {
				/* end of the chain */
				skb_fill_page_desc(rxtop,
				    skb_shinfo(rxtop)->nr_frags,
				    buffer_info->rxbuf.page, 0, length);
				skb = rxtop;
				rxtop = NULL;
				e1000_consume_page(buffer_info, skb, length);
			} else {
				struct page *p;
				/* no chain, got EOP, this buf is the packet
				 * copybreak to save the put_page/alloc_page
				 */
				p = buffer_info->rxbuf.page;
				if (length <= copybreak) {
					u8 *vaddr;

					if (likely(!(netdev->features & NETIF_F_RXFCS)))
						length -= 4;
					skb = e1000_alloc_rx_skb(adapter,
								 length);
					if (!skb)
						break;

					vaddr = kmap_atomic(p);
					memcpy(skb_tail_pointer(skb), vaddr,
					       length);
					kunmap_atomic(vaddr);
					/* re-use the page, so don't erase
					 * buffer_info->rxbuf.page
					 */
					skb_put(skb, length);
					e1000_rx_checksum(adapter,
							  status | rx_desc->errors << 24,
							  le16_to_cpu(rx_desc->csum), skb);

					total_rx_bytes += skb->len;
					total_rx_packets++;

					e1000_receive_skb(adapter, status,
							  rx_desc->special, skb);
					goto next_desc;
				} else {
					skb = napi_get_frags(&adapter->napi);
					if (!skb) {
						adapter->alloc_rx_buff_failed++;
						break;
					}
					skb_fill_page_desc(skb, 0, p, 0,
							   length);
					e1000_consume_page(buffer_info, skb,
							   length);
				}
			}
		}

		/* Receive Checksum Offload XXX recompute due to CRC strip? */
		e1000_rx_checksum(adapter,
				  (u32)(status) |
				  ((u32)(rx_desc->errors) << 24),
				  le16_to_cpu(rx_desc->csum), skb);

		total_rx_bytes += (skb->len - 4); /* don't count FCS */
		if (likely(!(netdev->features & NETIF_F_RXFCS)))
			pskb_trim(skb, skb->len - 4);
		total_rx_packets++;

		if (status & E1000_RXD_STAT_VP) {
			__le16 vlan = rx_desc->special;
			u16 vid = le16_to_cpu(vlan) & E1000_RXD_SPC_VLAN_MASK;

			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vid);
		}

		napi_gro_frags(&adapter->napi);

next_desc:
		rx_desc->status = 0;

		/* return some buffers to hardware, one at a time is too slow */
		if (unlikely(cleaned_count >= E1000_RX_BUFFER_WRITE)) {
			adapter->alloc_rx_buf(adapter, rx_ring, cleaned_count);
			cleaned_count = 0;
		}

		/* use prefetched values */
		rx_desc = next_rxd;
		buffer_info = next_buffer;
	}
	rx_ring->next_to_clean = i;

	cleaned_count = E1000_DESC_UNUSED(rx_ring);
	if (cleaned_count)
		adapter->alloc_rx_buf(adapter, rx_ring, cleaned_count);

	adapter->total_rx_packets += total_rx_packets;
	adapter->total_rx_bytes += total_rx_bytes;
	netdev->stats.rx_bytes += total_rx_bytes;
	netdev->stats.rx_packets += total_rx_packets;
	return cleaned;
}

/* this should improve performance for small packets with large amounts
 * of reassembly being done in the stack
 */
static struct sk_buff *e1000_copybreak(struct e1000_adapter *adapter,
				       struct e1000_rx_buffer *buffer_info,
				       u32 length, const void *data)
{
	struct sk_buff *skb;

	if (length > copybreak)
		return NULL;

	skb = e1000_alloc_rx_skb(adapter, length);
	if (!skb)
		return NULL;

	dma_sync_single_for_cpu(&adapter->pdev->dev, buffer_info->dma,
				length, DMA_FROM_DEVICE);

	skb_put_data(skb, data, length);

	return skb;
}

// TODO: Fazer o e1000_clean_rx_irq depender deste aqui!
static void e1000_next_buffer_from_rx_ring (struct e1000_rx_ring* rx_ring, char* buf, size_t* len)
{
	//struct net_device *netdev = global_spdm_netdev;
	//struct e1000_adapter *adapter = netdev_priv(netdev);

	unsigned int i = rx_ring->next_to_clean;
	struct e1000_rx_desc* rx_desc = E1000_RX_DESC(*rx_ring, i);
	struct e1000_rx_buffer* info_buffer = &rx_ring->buffer_info[i];

	*len = 0;

	if(rx_desc->status & E1000_RXD_STAT_DD){
		*len = le16_to_cpu(rx_desc->length);
		memcpy(buf, info_buffer->rxbuf.data, *len);
		rx_desc->status = 0;
	}
}

/**
 * e1000_clean_rx_irq - Send received data up the network stack; legacy
 * @adapter: board private structure
 * @rx_ring: ring to clean
 * @work_done: amount of napi work completed this call
 * @work_to_do: max amount of work allowed for this call to do
 */
// #pragma GCC push_options
// #pragma GCC optimize ("O0")
static bool e1000_clean_rx_irq(struct e1000_adapter *adapter,
			       struct e1000_rx_ring *rx_ring,
			       int *work_done, int work_to_do)
{
	struct net_device *netdev = adapter->netdev;
	struct pci_dev *pdev = adapter->pdev;
	struct e1000_rx_desc *rx_desc, *next_rxd;
	struct e1000_rx_buffer *buffer_info, *next_buffer;
	u32 length;
	unsigned int i;
	int cleaned_count = 0;
	bool cleaned = false;
	unsigned int total_rx_bytes = 0, total_rx_packets = 0;

	uint8_t *dec_message;
	size_t dec_message_size;
	size_t dec_message_max_size;
	libspdm_return_t ret_stat;
	size_t transport_header_size;

#if E1000_SPDM_DEBUG
	unsigned char *buffer_start;
	int teste;
#endif /* E1000_SPDM_DEBUG */

	// dec_message = kmalloc(0x1000, GFP_KERNEL);
	// if (!dec_message) {
	// 	printk(KERN_WARNING "%s: could not allocate dec_message", __func__);
	// 	return false;
	// }


	i = rx_ring->next_to_clean;
	rx_desc = E1000_RX_DESC(*rx_ring, i);
	buffer_info = &rx_ring->buffer_info[i];

	while (rx_desc->status & E1000_RXD_STAT_DD) {
		struct sk_buff *skb;
		u8 *data;
		u8 status;
		transport_header_size = ((libspdm_context_t *)global_spdm_context)->local_context.capability.transport_header_size;
		libspdm_get_scratch_buffer (global_spdm_context, (void **)&dec_message, &dec_message_max_size);
#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
		dec_message = dec_message + libspdm_get_scratch_buffer_secure_message_offset(global_spdm_context) +
			transport_header_size;
		dec_message_max_size = libspdm_get_scratch_buffer_secure_message_capacity(global_spdm_context) -
			transport_header_size;
#else
		dec_message = dec_message + transport_header_size;
		dec_message_max_size = dec_message_max_size - transport_header_size;
#endif

		if (*work_done >= work_to_do)
			break;
		(*work_done)++;
		dma_rmb(); /* read descriptor and rx_buffer_info after status DD */

		status = rx_desc->status;
		length = le16_to_cpu(rx_desc->length);

		data = buffer_info->rxbuf.data;
		prefetch(data);

		if (!rx_desc->spdm_msg_type)
		{
			uint32_t *session_id;// = kmalloc(sizeof(uint32_t), GFP_KERNEL);
			bool is_app;
			// *session_id = global_session_id;

			demo_e1000_print_buffer(data, length, "OS E1000 driver received the following data from the network card:");

			dec_message_size = dec_message_max_size; // sizeof(dec_message);
			ret_stat = ((libspdm_context_t *)global_spdm_context)->transport_decode_message(
					global_spdm_context, 
					&session_id, 
					&is_app, 
					false,
					length, 
					data, 
					&dec_message_size, 
					(void**) &dec_message
			);

			if (LIBSPDM_STATUS_IS_ERROR(ret_stat))
				printk(KERN_INFO "[KERNEL] Error decoding packet - status %x\n", ret_stat);
#if E1000_SPDM_DEBUG
			else
				printk(KERN_INFO "[KERNEL] Packet decoded successfully\n");
#endif /* E1000_SPDM_DEBUG */

			//data = dec_message;
			memcpy(data, dec_message, dec_message_size);
			length = dec_message_size + 4;
		}

		skb = e1000_copybreak(adapter, buffer_info, length, data);

		E1000_SPDM_PRINT(KERN_INFO "[KERNEL] e1000_clean_rx_irq was called, status: %x", status);
		E1000_SPDM_PRINT(KERN_INFO "[KERNEL] next_to_clean: %d\n", i);

		if (!skb) {
			unsigned int frag_len = e1000_frag_len(adapter);

			skb = build_skb(data - E1000_HEADROOM, frag_len);
			if (!skb) {
				adapter->alloc_rx_buff_failed++;
				break;
			}

			skb_reserve(skb, E1000_HEADROOM);
			dma_unmap_single(&pdev->dev, buffer_info->dma,
					 adapter->rx_buffer_len,
					 DMA_FROM_DEVICE);
			buffer_info->dma = 0;
			buffer_info->rxbuf.data = NULL;
		}

		/*Alteração para bugar buffer de recebimento*/

#if E1000_SPDM_DEBUG
		buffer_start = skb->data;
		teste = 0;
		printk(KERN_INFO "[KERNEL] length = %d\n", length);
		for(teste = 0; teste < length; teste++){
			if (teste % 16 == 0) printk(KERN_CONT "\n");
			printk(KERN_CONT "[KERNEL] data = %02X ", buffer_start[teste]);//, buffer_start[teste]);
		}
		printk(KERN_INFO "\n");
#endif /* E1000_SPDM_DEBUG */

		if (++i == rx_ring->count)
			i = 0;

		next_rxd = E1000_RX_DESC(*rx_ring, i);
		prefetch(next_rxd);

		next_buffer = &rx_ring->buffer_info[i];

		cleaned = true;
		cleaned_count++;

		/* !EOP means multiple descriptors were used to store a single
		 * packet, if thats the case we need to toss it.  In fact, we
		 * to toss every packet with the EOP bit clear and the next
		 * frame that _does_ have the EOP bit set, as it is by
		 * definition only a frame fragment
		 */
		if (unlikely(!(status & E1000_RXD_STAT_EOP)))
			adapter->discarding = true;

		if (adapter->discarding) {
			/* All receives must fit into a single buffer */
			netdev_dbg(netdev, "Receive packet consumed multiple buffers\n");
			dev_kfree_skb(skb);
			if (status & E1000_RXD_STAT_EOP)
				adapter->discarding = false;
			goto next_desc;
		}

		if (unlikely(rx_desc->errors & E1000_RXD_ERR_FRAME_ERR_MASK)) {
			printk(KERN_INFO "[KERNEL] Packet rx error: %d\n", rx_desc->errors);
			if (e1000_tbi_should_accept(adapter, status,
						    rx_desc->errors,
						    length, data)) {
				length--;
			} else if (netdev->features & NETIF_F_RXALL) {
				goto process_skb;
			} else {
				dev_kfree_skb(skb);
				goto next_desc;
			}
		}

process_skb:
		if (!rx_desc->spdm_msg_type)
		{
			total_rx_bytes += (length - 4); /* don't count FCS */
			total_rx_packets++;

			if (likely(!(netdev->features & NETIF_F_RXFCS)))
				/* adjust length to remove Ethernet CRC, this must be
				 * done after the TBI_ACCEPT workaround above
				 */
				length -= 4;

			if (buffer_info->rxbuf.data == NULL)
				skb_put(skb, length);
			else /* copybreak skb */
				skb_trim(skb, length);

			/* Receive Checksum Offload */
			e1000_rx_checksum(adapter,
					  (u32)(status) |
					  ((u32)(rx_desc->errors) << 24),
					  le16_to_cpu(rx_desc->csum), skb);

			e1000_receive_skb(adapter, status, rx_desc->special, skb);
		} else {
			E1000_SPDM_PRINT(KERN_INFO "[KERNEL] SPDM message received through e1000_clean_rx_irq\n");
		}

next_desc:
		rx_desc->status = 0;

		/* return some buffers to hardware, one at a time is too slow */
		if (unlikely(cleaned_count >= E1000_RX_BUFFER_WRITE)) {
			adapter->alloc_rx_buf(adapter, rx_ring, cleaned_count);
			cleaned_count = 0;
		}

		/* use prefetched values */
		rx_desc = next_rxd;
		buffer_info = next_buffer;
	}

	// kfree(dec_message);
	rx_ring->next_to_clean = i;

	cleaned_count = E1000_DESC_UNUSED(rx_ring);
	if (cleaned_count)
		adapter->alloc_rx_buf(adapter, rx_ring, cleaned_count);

	adapter->total_rx_packets += total_rx_packets;
	adapter->total_rx_bytes += total_rx_bytes;
	netdev->stats.rx_bytes += total_rx_bytes;
	netdev->stats.rx_packets += total_rx_packets;
	return cleaned;
}
// #pragma GCC pop_options

/**
 * e1000_alloc_jumbo_rx_buffers - Replace used jumbo receive buffers
 * @adapter: address of board private structure
 * @rx_ring: pointer to receive ring structure
 * @cleaned_count: number of buffers to allocate this pass
 **/
static void
e1000_alloc_jumbo_rx_buffers(struct e1000_adapter *adapter,
			     struct e1000_rx_ring *rx_ring, int cleaned_count)
{
	struct pci_dev *pdev = adapter->pdev;
	struct e1000_rx_desc *rx_desc;
	struct e1000_rx_buffer *buffer_info;
	unsigned int i;

	i = rx_ring->next_to_use;
	buffer_info = &rx_ring->buffer_info[i];

	while (cleaned_count--) {
		/* allocate a new page if necessary */
		if (!buffer_info->rxbuf.page) {
			buffer_info->rxbuf.page = alloc_page(GFP_ATOMIC);
			if (unlikely(!buffer_info->rxbuf.page)) {
				adapter->alloc_rx_buff_failed++;
				break;
			}
		}

		if (!buffer_info->dma) {
			buffer_info->dma = dma_map_page(&pdev->dev,
							buffer_info->rxbuf.page, 0,
							adapter->rx_buffer_len,
							DMA_FROM_DEVICE);
			if (dma_mapping_error(&pdev->dev, buffer_info->dma)) {
				put_page(buffer_info->rxbuf.page);
				buffer_info->rxbuf.page = NULL;
				buffer_info->dma = 0;
				adapter->alloc_rx_buff_failed++;
				break;
			}
		}

		rx_desc = E1000_RX_DESC(*rx_ring, i);
		rx_desc->buffer_addr = cpu_to_le64(buffer_info->dma);

		if (unlikely(++i == rx_ring->count))
			i = 0;
		buffer_info = &rx_ring->buffer_info[i];
	}

	if (likely(rx_ring->next_to_use != i)) {
		rx_ring->next_to_use = i;
		if (unlikely(i-- == 0))
			i = (rx_ring->count - 1);

		/* Force memory writes to complete before letting h/w
		 * know there are new descriptors to fetch.  (Only
		 * applicable for weak-ordered memory model archs,
		 * such as IA-64).
		 */
		wmb();
		writel(i, adapter->hw.hw_addr + rx_ring->rdt);
	}
}

/**
 * e1000_alloc_rx_buffers - Replace used receive buffers; legacy & extended
 * @adapter: address of board private structure
 **/
static void e1000_alloc_rx_buffers(struct e1000_adapter *adapter,
				   struct e1000_rx_ring *rx_ring,
				   int cleaned_count)
{
	struct e1000_hw *hw = &adapter->hw;
	struct pci_dev *pdev = adapter->pdev;
	struct e1000_rx_desc *rx_desc;
	struct e1000_rx_buffer *buffer_info;
	unsigned int i;
	unsigned int bufsz = adapter->rx_buffer_len;

	i = rx_ring->next_to_use;
	buffer_info = &rx_ring->buffer_info[i];

	while (cleaned_count--) {
		void *data;

		if (buffer_info->rxbuf.data)
			goto skip;

		data = e1000_alloc_frag(adapter);
		if (!data) {
			/* Better luck next round */
			adapter->alloc_rx_buff_failed++;
			break;
		}

		/* Fix for errata 23, can't cross 64kB boundary */
		if (!e1000_check_64k_bound(adapter, data, bufsz)) {
			void *olddata = data;
			e_err(rx_err, "skb align check failed: %u bytes at "
			      "%p\n", bufsz, data);
			/* Try again, without freeing the previous */
			data = e1000_alloc_frag(adapter);
			/* Failed allocation, critical failure */
			if (!data) {
				skb_free_frag(olddata);
				adapter->alloc_rx_buff_failed++;
				break;
			}

			if (!e1000_check_64k_bound(adapter, data, bufsz)) {
				/* give up */
				skb_free_frag(data);
				skb_free_frag(olddata);
				adapter->alloc_rx_buff_failed++;
				break;
			}

			/* Use new allocation */
			skb_free_frag(olddata);
		}
		buffer_info->dma = dma_map_single(&pdev->dev,
						  data,
						  adapter->rx_buffer_len,
						  DMA_FROM_DEVICE);
		if (dma_mapping_error(&pdev->dev, buffer_info->dma)) {
			skb_free_frag(data);
			buffer_info->dma = 0;
			adapter->alloc_rx_buff_failed++;
			break;
		}

		/* XXX if it was allocated cleanly it will never map to a
		 * boundary crossing
		 */

		/* Fix for errata 23, can't cross 64kB boundary */
		if (!e1000_check_64k_bound(adapter,
					(void *)(unsigned long)buffer_info->dma,
					adapter->rx_buffer_len)) {
			e_err(rx_err, "dma align check failed: %u bytes at "
			      "%p\n", adapter->rx_buffer_len,
			      (void *)(unsigned long)buffer_info->dma);

			dma_unmap_single(&pdev->dev, buffer_info->dma,
					 adapter->rx_buffer_len,
					 DMA_FROM_DEVICE);

			skb_free_frag(data);
			buffer_info->rxbuf.data = NULL;
			buffer_info->dma = 0;

			adapter->alloc_rx_buff_failed++;
			break;
		}
		buffer_info->rxbuf.data = data;
 skip:
		rx_desc = E1000_RX_DESC(*rx_ring, i);
		rx_desc->buffer_addr = cpu_to_le64(buffer_info->dma);

		if (unlikely(++i == rx_ring->count))
			i = 0;
		buffer_info = &rx_ring->buffer_info[i];
	}

	if (likely(rx_ring->next_to_use != i)) {
		rx_ring->next_to_use = i;
		if (unlikely(i-- == 0))
			i = (rx_ring->count - 1);

		/* Force memory writes to complete before letting h/w
		 * know there are new descriptors to fetch.  (Only
		 * applicable for weak-ordered memory model archs,
		 * such as IA-64).
		 */
		wmb();
		writel(i, hw->hw_addr + rx_ring->rdt);
	}
}

/**
 * e1000_smartspeed - Workaround for SmartSpeed on 82541 and 82547 controllers.
 * @adapter:
 **/
static void e1000_smartspeed(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u16 phy_status;
	u16 phy_ctrl;

	if ((hw->phy_type != e1000_phy_igp) || !hw->autoneg ||
	   !(hw->autoneg_advertised & ADVERTISE_1000_FULL))
		return;

	if (adapter->smartspeed == 0) {
		/* If Master/Slave config fault is asserted twice,
		 * we assume back-to-back
		 */
		e1000_read_phy_reg(hw, PHY_1000T_STATUS, &phy_status);
		if (!(phy_status & SR_1000T_MS_CONFIG_FAULT))
			return;
		e1000_read_phy_reg(hw, PHY_1000T_STATUS, &phy_status);
		if (!(phy_status & SR_1000T_MS_CONFIG_FAULT))
			return;
		e1000_read_phy_reg(hw, PHY_1000T_CTRL, &phy_ctrl);
		if (phy_ctrl & CR_1000T_MS_ENABLE) {
			phy_ctrl &= ~CR_1000T_MS_ENABLE;
			e1000_write_phy_reg(hw, PHY_1000T_CTRL,
					    phy_ctrl);
			adapter->smartspeed++;
			if (!e1000_phy_setup_autoneg(hw) &&
			   !e1000_read_phy_reg(hw, PHY_CTRL,
					       &phy_ctrl)) {
				phy_ctrl |= (MII_CR_AUTO_NEG_EN |
					     MII_CR_RESTART_AUTO_NEG);
				e1000_write_phy_reg(hw, PHY_CTRL,
						    phy_ctrl);
			}
		}
		return;
	} else if (adapter->smartspeed == E1000_SMARTSPEED_DOWNSHIFT) {
		/* If still no link, perhaps using 2/3 pair cable */
		e1000_read_phy_reg(hw, PHY_1000T_CTRL, &phy_ctrl);
		phy_ctrl |= CR_1000T_MS_ENABLE;
		e1000_write_phy_reg(hw, PHY_1000T_CTRL, phy_ctrl);
		if (!e1000_phy_setup_autoneg(hw) &&
		   !e1000_read_phy_reg(hw, PHY_CTRL, &phy_ctrl)) {
			phy_ctrl |= (MII_CR_AUTO_NEG_EN |
				     MII_CR_RESTART_AUTO_NEG);
			e1000_write_phy_reg(hw, PHY_CTRL, phy_ctrl);
		}
	}
	/* Restart process after E1000_SMARTSPEED_MAX iterations */
	if (adapter->smartspeed++ == E1000_SMARTSPEED_MAX)
		adapter->smartspeed = 0;
}

/**
 * e1000_ioctl -
 * @netdev:
 * @ifreq:
 * @cmd:
 **/
static int e1000_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	switch (cmd) {
	case SIOCGMIIPHY:
	case SIOCGMIIREG:
	case SIOCSMIIREG:
		return e1000_mii_ioctl(netdev, ifr, cmd);
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * e1000_mii_ioctl -
 * @netdev:
 * @ifreq:
 * @cmd:
 **/
static int e1000_mii_ioctl(struct net_device *netdev, struct ifreq *ifr,
			   int cmd)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	struct mii_ioctl_data *data = if_mii(ifr);
	int retval;
	u16 mii_reg;
	unsigned long flags;

	if (hw->media_type != e1000_media_type_copper)
		return -EOPNOTSUPP;

	switch (cmd) {
	case SIOCGMIIPHY:
		data->phy_id = hw->phy_addr;
		break;
	case SIOCGMIIREG:
		spin_lock_irqsave(&adapter->stats_lock, flags);
		if (e1000_read_phy_reg(hw, data->reg_num & 0x1F,
				   &data->val_out)) {
			spin_unlock_irqrestore(&adapter->stats_lock, flags);
			return -EIO;
		}
		spin_unlock_irqrestore(&adapter->stats_lock, flags);
		break;
	case SIOCSMIIREG:
		if (data->reg_num & ~(0x1F))
			return -EFAULT;
		mii_reg = data->val_in;
		spin_lock_irqsave(&adapter->stats_lock, flags);
		if (e1000_write_phy_reg(hw, data->reg_num,
					mii_reg)) {
			spin_unlock_irqrestore(&adapter->stats_lock, flags);
			return -EIO;
		}
		spin_unlock_irqrestore(&adapter->stats_lock, flags);
		if (hw->media_type == e1000_media_type_copper) {
			switch (data->reg_num) {
			case PHY_CTRL:
				if (mii_reg & MII_CR_POWER_DOWN)
					break;
				if (mii_reg & MII_CR_AUTO_NEG_EN) {
					hw->autoneg = 1;
					hw->autoneg_advertised = 0x2F;
				} else {
					u32 speed;
					if (mii_reg & 0x40)
						speed = SPEED_1000;
					else if (mii_reg & 0x2000)
						speed = SPEED_100;
					else
						speed = SPEED_10;
					retval = e1000_set_spd_dplx(
						adapter, speed,
						((mii_reg & 0x100)
						 ? DUPLEX_FULL :
						 DUPLEX_HALF));
					if (retval)
						return retval;
				}
				if (netif_running(adapter->netdev))
					e1000_reinit_locked(adapter);
				else
					e1000_reset(adapter);
				break;
			case M88E1000_PHY_SPEC_CTRL:
			case M88E1000_EXT_PHY_SPEC_CTRL:
				if (e1000_phy_reset(hw))
					return -EIO;
				break;
			}
		} else {
			switch (data->reg_num) {
			case PHY_CTRL:
				if (mii_reg & MII_CR_POWER_DOWN)
					break;
				if (netif_running(adapter->netdev))
					e1000_reinit_locked(adapter);
				else
					e1000_reset(adapter);
				break;
			}
		}
		break;
	default:
		return -EOPNOTSUPP;
	}
	return E1000_SUCCESS;
}

void e1000_pci_set_mwi(struct e1000_hw *hw)
{
	struct e1000_adapter *adapter = hw->back;
	int ret_val = pci_set_mwi(adapter->pdev);

	if (ret_val)
		e_err(probe, "Error in setting MWI\n");
}

void e1000_pci_clear_mwi(struct e1000_hw *hw)
{
	struct e1000_adapter *adapter = hw->back;

	pci_clear_mwi(adapter->pdev);
}

int e1000_pcix_get_mmrbc(struct e1000_hw *hw)
{
	struct e1000_adapter *adapter = hw->back;
	return pcix_get_mmrbc(adapter->pdev);
}

void e1000_pcix_set_mmrbc(struct e1000_hw *hw, int mmrbc)
{
	struct e1000_adapter *adapter = hw->back;
	pcix_set_mmrbc(adapter->pdev, mmrbc);
}

void e1000_io_write(struct e1000_hw *hw, unsigned long port, u32 value)
{
	outl(value, port);
}

static bool e1000_vlan_used(struct e1000_adapter *adapter)
{
	u16 vid;

	for_each_set_bit(vid, adapter->active_vlans, VLAN_N_VID)
		return true;
	return false;
}

static void __e1000_vlan_mode(struct e1000_adapter *adapter,
			      netdev_features_t features)
{
	struct e1000_hw *hw = &adapter->hw;
	u32 ctrl;

	ctrl = er32(CTRL);
	if (features & NETIF_F_HW_VLAN_CTAG_RX) {
		/* enable VLAN tag insert/strip */
		ctrl |= E1000_CTRL_VME;
	} else {
		/* disable VLAN tag insert/strip */
		ctrl &= ~E1000_CTRL_VME;
	}
	ew32(CTRL, ctrl);
}
static void e1000_vlan_filter_on_off(struct e1000_adapter *adapter,
				     bool filter_on)
{
	struct e1000_hw *hw = &adapter->hw;
	u32 rctl;

	if (!test_bit(__E1000_DOWN, &adapter->flags))
		e1000_irq_disable(adapter);

	__e1000_vlan_mode(adapter, adapter->netdev->features);
	if (filter_on) {
		/* enable VLAN receive filtering */
		rctl = er32(RCTL);
		rctl &= ~E1000_RCTL_CFIEN;
		if (!(adapter->netdev->flags & IFF_PROMISC))
			rctl |= E1000_RCTL_VFE;
		ew32(RCTL, rctl);
		e1000_update_mng_vlan(adapter);
	} else {
		/* disable VLAN receive filtering */
		rctl = er32(RCTL);
		rctl &= ~E1000_RCTL_VFE;
		ew32(RCTL, rctl);
	}

	if (!test_bit(__E1000_DOWN, &adapter->flags))
		e1000_irq_enable(adapter);
}

static void e1000_vlan_mode(struct net_device *netdev,
			    netdev_features_t features)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);

	if (!test_bit(__E1000_DOWN, &adapter->flags))
		e1000_irq_disable(adapter);

	__e1000_vlan_mode(adapter, features);

	if (!test_bit(__E1000_DOWN, &adapter->flags))
		e1000_irq_enable(adapter);
}

static int e1000_vlan_rx_add_vid(struct net_device *netdev,
				 __be16 proto, u16 vid)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	u32 vfta, index;

	if ((hw->mng_cookie.status &
	     E1000_MNG_DHCP_COOKIE_STATUS_VLAN_SUPPORT) &&
	    (vid == adapter->mng_vlan_id))
		return 0;

	if (!e1000_vlan_used(adapter))
		e1000_vlan_filter_on_off(adapter, true);

	/* add VID to filter table */
	index = (vid >> 5) & 0x7F;
	vfta = E1000_READ_REG_ARRAY(hw, VFTA, index);
	vfta |= (1 << (vid & 0x1F));
	e1000_write_vfta(hw, index, vfta);

	set_bit(vid, adapter->active_vlans);

	return 0;
}

static int e1000_vlan_rx_kill_vid(struct net_device *netdev,
				  __be16 proto, u16 vid)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	u32 vfta, index;

	if (!test_bit(__E1000_DOWN, &adapter->flags))
		e1000_irq_disable(adapter);
	if (!test_bit(__E1000_DOWN, &adapter->flags))
		e1000_irq_enable(adapter);

	/* remove VID from filter table */
	index = (vid >> 5) & 0x7F;
	vfta = E1000_READ_REG_ARRAY(hw, VFTA, index);
	vfta &= ~(1 << (vid & 0x1F));
	e1000_write_vfta(hw, index, vfta);

	clear_bit(vid, adapter->active_vlans);

	if (!e1000_vlan_used(adapter))
		e1000_vlan_filter_on_off(adapter, false);

	return 0;
}

static void e1000_restore_vlan(struct e1000_adapter *adapter)
{
	u16 vid;

	if (!e1000_vlan_used(adapter))
		return;

	e1000_vlan_filter_on_off(adapter, true);
	for_each_set_bit(vid, adapter->active_vlans, VLAN_N_VID)
		e1000_vlan_rx_add_vid(adapter->netdev, htons(ETH_P_8021Q), vid);
}

int e1000_set_spd_dplx(struct e1000_adapter *adapter, u32 spd, u8 dplx)
{
	struct e1000_hw *hw = &adapter->hw;

	hw->autoneg = 0;

	/* Make sure dplx is at most 1 bit and lsb of speed is not set
	 * for the switch() below to work
	 */
	if ((spd & 1) || (dplx & ~1))
		goto err_inval;

	/* Fiber NICs only allow 1000 gbps Full duplex */
	if ((hw->media_type == e1000_media_type_fiber) &&
	    spd != SPEED_1000 &&
	    dplx != DUPLEX_FULL)
		goto err_inval;

	switch (spd + dplx) {
	case SPEED_10 + DUPLEX_HALF:
		hw->forced_speed_duplex = e1000_10_half;
		break;
	case SPEED_10 + DUPLEX_FULL:
		hw->forced_speed_duplex = e1000_10_full;
		break;
	case SPEED_100 + DUPLEX_HALF:
		hw->forced_speed_duplex = e1000_100_half;
		break;
	case SPEED_100 + DUPLEX_FULL:
		hw->forced_speed_duplex = e1000_100_full;
		break;
	case SPEED_1000 + DUPLEX_FULL:
		hw->autoneg = 1;
		hw->autoneg_advertised = ADVERTISE_1000_FULL;
		break;
	case SPEED_1000 + DUPLEX_HALF: /* not supported */
	default:
		goto err_inval;
	}

	/* clear MDI, MDI(-X) override is only allowed when autoneg enabled */
	hw->mdix = AUTO_ALL_MODES;

	return 0;

err_inval:
	e_err(probe, "Unsupported Speed/Duplex configuration\n");
	return -EINVAL;
}

static int __e1000_shutdown(struct pci_dev *pdev, bool *enable_wake)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	u32 ctrl, ctrl_ext, rctl, status;
	u32 wufc = adapter->wol;
#ifdef CONFIG_PM
	int retval = 0;
#endif

	netif_device_detach(netdev);

	if (netif_running(netdev)) {
		int count = E1000_CHECK_RESET_COUNT;

		while (test_bit(__E1000_RESETTING, &adapter->flags) && count--)
			usleep_range(10000, 20000);

		WARN_ON(test_bit(__E1000_RESETTING, &adapter->flags));
		e1000_down(adapter);
	}

#ifdef CONFIG_PM
	retval = pci_save_state(pdev);
	if (retval)
		return retval;
#endif

	status = er32(STATUS);
	if (status & E1000_STATUS_LU)
		wufc &= ~E1000_WUFC_LNKC;

	if (wufc) {
		e1000_setup_rctl(adapter);
		e1000_set_rx_mode(netdev);

		rctl = er32(RCTL);

		/* turn on all-multi mode if wake on multicast is enabled */
		if (wufc & E1000_WUFC_MC)
			rctl |= E1000_RCTL_MPE;

		/* enable receives in the hardware */
		ew32(RCTL, rctl | E1000_RCTL_EN);

		if (hw->mac_type >= e1000_82540) {
			ctrl = er32(CTRL);
			/* advertise wake from D3Cold */
			#define E1000_CTRL_ADVD3WUC 0x00100000
			/* phy power management enable */
			#define E1000_CTRL_EN_PHY_PWR_MGMT 0x00200000
			ctrl |= E1000_CTRL_ADVD3WUC |
				E1000_CTRL_EN_PHY_PWR_MGMT;
			ew32(CTRL, ctrl);
		}

		if (hw->media_type == e1000_media_type_fiber ||
		    hw->media_type == e1000_media_type_internal_serdes) {
			/* keep the laser running in D3 */
			ctrl_ext = er32(CTRL_EXT);
			ctrl_ext |= E1000_CTRL_EXT_SDP7_DATA;
			ew32(CTRL_EXT, ctrl_ext);
		}

		ew32(WUC, E1000_WUC_PME_EN);
		ew32(WUFC, wufc);
	} else {
		ew32(WUC, 0);
		ew32(WUFC, 0);
	}

	e1000_release_manageability(adapter);

	*enable_wake = !!wufc;

	/* make sure adapter isn't asleep if manageability is enabled */
	if (adapter->en_mng_pt)
		*enable_wake = true;

	if (netif_running(netdev))
		e1000_free_irq(adapter);

	if (!test_and_set_bit(__E1000_DISABLED, &adapter->flags))
		pci_disable_device(pdev);

	return 0;
}

#ifdef CONFIG_PM
static int e1000_suspend(struct pci_dev *pdev, pm_message_t state)
{
	int retval;
	bool wake;

	retval = __e1000_shutdown(pdev, &wake);
	if (retval)
		return retval;

	if (wake) {
		pci_prepare_to_sleep(pdev);
	} else {
		pci_wake_from_d3(pdev, false);
		pci_set_power_state(pdev, PCI_D3hot);
	}

	return 0;
}

static int e1000_resume(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	u32 err;

	pci_set_power_state(pdev, PCI_D0);
	pci_restore_state(pdev);
	pci_save_state(pdev);

	if (adapter->need_ioport)
		err = pci_enable_device(pdev);
	else
		err = pci_enable_device_mem(pdev);
	if (err) {
		pr_err("Cannot enable PCI device from suspend\n");
		return err;
	}

	/* flush memory to make sure state is correct */
	smp_mb__before_atomic();
	clear_bit(__E1000_DISABLED, &adapter->flags);
	pci_set_master(pdev);

	pci_enable_wake(pdev, PCI_D3hot, 0);
	pci_enable_wake(pdev, PCI_D3cold, 0);

	if (netif_running(netdev)) {
		err = e1000_request_irq(adapter);
		if (err)
			return err;
	}

	e1000_power_up_phy(adapter);
	e1000_reset(adapter);
	ew32(WUS, ~0);

	e1000_init_manageability(adapter);

	if (netif_running(netdev))
		e1000_up(adapter);

	netif_device_attach(netdev);

	return 0;
}
#endif

static void e1000_shutdown(struct pci_dev *pdev)
{
	bool wake;

	__e1000_shutdown(pdev, &wake);

	if (system_state == SYSTEM_POWER_OFF) {
		pci_wake_from_d3(pdev, wake);
		pci_set_power_state(pdev, PCI_D3hot);
	}
}

#ifdef CONFIG_NET_POLL_CONTROLLER
/* Polling 'interrupt' - used by things like netconsole to send skbs
 * without having to re-enable interrupts. It's not called while
 * the interrupt routine is executing.
 */
static void e1000_netpoll(struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);

	if (disable_hardirq(adapter->pdev->irq))
		e1000_intr(adapter->pdev->irq, netdev);
	enable_irq(adapter->pdev->irq);
}
#endif

/**
 * e1000_io_error_detected - called when PCI error is detected
 * @pdev: Pointer to PCI device
 * @state: The current pci connection state
 *
 * This function is called after a PCI bus error affecting
 * this device has been detected.
 */
static pci_ers_result_t e1000_io_error_detected(struct pci_dev *pdev,
						pci_channel_state_t state)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct e1000_adapter *adapter = netdev_priv(netdev);

	netif_device_detach(netdev);

	if (state == pci_channel_io_perm_failure)
		return PCI_ERS_RESULT_DISCONNECT;

	if (netif_running(netdev))
		e1000_down(adapter);

	if (!test_and_set_bit(__E1000_DISABLED, &adapter->flags))
		pci_disable_device(pdev);

	/* Request a slot slot reset. */
	return PCI_ERS_RESULT_NEED_RESET;
}

/**
 * e1000_io_slot_reset - called after the pci bus has been reset.
 * @pdev: Pointer to PCI device
 *
 * Restart the card from scratch, as if from a cold-boot. Implementation
 * resembles the first-half of the e1000_resume routine.
 */
static pci_ers_result_t e1000_io_slot_reset(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	int err;

	if (adapter->need_ioport)
		err = pci_enable_device(pdev);
	else
		err = pci_enable_device_mem(pdev);
	if (err) {
		pr_err("Cannot re-enable PCI device after reset.\n");
		return PCI_ERS_RESULT_DISCONNECT;
	}

	/* flush memory to make sure state is correct */
	smp_mb__before_atomic();
	clear_bit(__E1000_DISABLED, &adapter->flags);
	pci_set_master(pdev);

	pci_enable_wake(pdev, PCI_D3hot, 0);
	pci_enable_wake(pdev, PCI_D3cold, 0);

	e1000_reset(adapter);
	ew32(WUS, ~0);

	return PCI_ERS_RESULT_RECOVERED;
}

/**
 * e1000_io_resume - called when traffic can start flowing again.
 * @pdev: Pointer to PCI device
 *
 * This callback is called when the error recovery driver tells us that
 * its OK to resume normal operation. Implementation resembles the
 * second-half of the e1000_resume routine.
 */
static void e1000_io_resume(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct e1000_adapter *adapter = netdev_priv(netdev);

	e1000_init_manageability(adapter);

	if (netif_running(netdev)) {
		if (e1000_up(adapter)) {
			pr_info("can't bring device back up after reset\n");
			return;
		}
	}

	netif_device_attach(netdev);
}

/* e1000_main.c */
