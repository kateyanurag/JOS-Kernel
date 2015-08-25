#ifndef JOS_KERN_E1000_H
#define JOS_KERN_E1000_H

#include <kern/pci.h>

#define E1000_TDBAL    0x03800  /* TX Descriptor Base Address Low - RW */
#define E1000_TDBAH    0x03804  /* TX Descriptor Base Address High - RW */
#define E1000_TDLEN    0x03808  /* TX Descriptor Length - RW */
#define E1000_TDH      0x03810  /* TX Descriptor Head - RW */
#define E1000_TDT      0x03818  /* TX Descripotr Tail - RW */
#define E1000_TCTL     0x00400  /* TX Control - RW */
#define E1000_TIPG     0x00410  /* TX Inter-packet gap -RW */



struct tx_desc
{
	uint64_t addr;
	uint16_t length;
	uint8_t cso;
	uint8_t cmd;
	uint8_t status;
	uint8_t css;
	uint16_t special;
};

struct rx_desc
{
	uint64_t addr;
	uint16_t length;
	uint16_t csum;
	uint8_t status;
	uint8_t error;
	uint16_t special;
};

extern void pci_func_enable(struct pci_func *f);
extern int init_attach_e1000(struct pci_func *func);
extern int transmit_packets(char *buf, int size);
extern int recieve_packets(char *packet, int *size);
extern void get_mac_address(void *mac_address);

#endif	// JOS_KERN_E1000_H
