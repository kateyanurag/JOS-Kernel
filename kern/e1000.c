#include <kern/e1000.h>
#include <kern/pci.h>
#include <kern/pmap.h>
#include <inc/string.h>
#define SIZEOF_QUEUE 128
#define PKT_SIZE 2048

// LAB 6: Your driver code here

volatile uint32_t *mapped_regs; 
struct tx_desc trans_desc[SIZEOF_QUEUE];
struct rx_desc recv_desc[SIZEOF_QUEUE];
char buffer[SIZEOF_QUEUE][PKT_SIZE];
char rx_buffer[SIZEOF_QUEUE][PKT_SIZE];
uint32_t head=0, tail=0;
uint32_t *tdbal, *tdbah, *tdlen, *tdh, *tdt;
uint32_t *tctl, *tipg;

static uint32_t recv_head = 0;
uint32_t *rah, *ral;
uint32_t *rdbah, *rdbal, *rdlen, *rdh, *rdt, *rctl, *ims, *rdtr;
uint32_t *mta_start, *mta_end;
uint8_t mac_part1, mac_part2, mac_part3, mac_part4, mac_part5, mac_part6;

void find_mac_addr(int word_num){
	uint16_t read_addr1 = 0x00, read_addr2 = 0x01, read_addr3 = 0x02;
	char *temp = (char *)mapped_regs;
	uint32_t *eeprom_read_reg = (uint32_t *)(temp + 0x0014);
	memset(eeprom_read_reg, 0, sizeof(uint32_t));
	if(word_num == 1){
		*eeprom_read_reg = (read_addr1 << 0x08) | 0x01;
	}
	if(word_num == 2){
		*eeprom_read_reg = (read_addr2 << 0x08) | 0x01;
	}
	if(word_num == 3){
		*eeprom_read_reg = (read_addr3 << 0x008) | 0x01;
	}

	uint16_t done = 0;
	while(1){
		done = *eeprom_read_reg & 16;
		if(done)
			break;
	}

	if(word_num == 1){
		mac_part1 = ((uint16_t)(*eeprom_read_reg >> 16));
		mac_part2 = ((uint16_t)(*eeprom_read_reg >> 16)) >> 8;
		cprintf("\n MAC ADDRESS WORD1 : %016x", *eeprom_read_reg);
	}
	if(word_num == 2){
		mac_part3 = ((uint16_t)(*eeprom_read_reg >> 16));
		mac_part4 = ((uint16_t)(*eeprom_read_reg >> 16)) >> 8;
		cprintf("\n MAC ADDRESS WORD1 : %016x", *eeprom_read_reg);
	}
	if(word_num == 3){
		mac_part5 = ((uint16_t)(*eeprom_read_reg >> 16));
		mac_part6 = ((uint16_t)(*eeprom_read_reg >> 16)) >> 8;
		cprintf("\n MAC ADDRESS WORD1 : %016x", *eeprom_read_reg);
	}
}

void
get_mac_address(void *mac_address){
	uint8_t *mac_addr = (uint8_t *)mac_address;
	mac_addr[0] = mac_part1;
	mac_addr[1] = mac_part2;
	mac_addr[2] = mac_part3;
	mac_addr[3] = mac_part4;
	mac_addr[4] = mac_part5;
	mac_addr[5] = mac_part6;
}


void
set_trans_desc_fields(){
	int i = 0;
	while(i < SIZEOF_QUEUE){
		trans_desc[i].cso = 0;
		trans_desc[i].cmd = 0x09;
		trans_desc[i].status = 1;
		trans_desc[i].css = 0;
		trans_desc[i].special = 0;
		trans_desc[i].addr = PADDR(buffer[i]);
		trans_desc[i].length = 0x2a;	
		i++;
	}
}

void
set_recv_desc_fields(){
	int i = 0;
	while(i < SIZEOF_QUEUE){
		recv_desc[i].addr = PADDR(rx_buffer[i]);
		recv_desc[i].status = 0x1;
		i++;
	}
}

int
recieve_packets(char *packet, int *size){
	char *temp = (char *)mapped_regs;
	int size_new = 0;
	uint32_t rdt = *(temp + 0x02818);
	int next_rdt = (rdt + 1)%SIZEOF_QUEUE;
	if(recv_desc[next_rdt].status & 0x01){
		cprintf("\n XXXXXXXXXXXXXXXXX  SIZE : %d", *size);
		if (*size > recv_desc[next_rdt].length){
			size_new = recv_desc[next_rdt].length;
			cprintf("\n +++++++++++ NEXT-rdt-len : %d     SIZE : %d", recv_desc[next_rdt].length, size_new);
		}
		memmove(packet, rx_buffer[next_rdt], size_new);
		recv_desc[next_rdt].status = 0x0;
		*(temp + 0x02818) = next_rdt;
		return size_new;
	}
	cprintf("\n Read QUEUE IS Empty ... !!!"); 
	return -1;
	
}


int 
transmit_packets(char *buf, int size){
	char *temp = (char *)mapped_regs;
	uint32_t tdt = *(temp + E1000_TDT);
	tail = (tdt + 1) % SIZEOF_QUEUE;
	if(trans_desc[tdt].status & 0x01){
		memmove(buffer[tdt], buf, size);
		trans_desc[tdt].status &= ~0x01;	
		trans_desc[tdt].cmd |= 0x09;	
		trans_desc[tdt].length = size;
		*(temp + E1000_TDT) = tail;
	//	trans_desc[tdt].cmd |= 0x01;	
		//cprintf("\nMY e1000: index %d: %x : %d%d%d%d%d %d\n", tail, buffer, trans_desc[tail].cmd, trans_desc[tail].cso, trans_desc[tail].length, trans_desc[tail].special, trans_desc[tail].css, trans_desc[tail].status);
		return 0;
	}
	cprintf("\n QUEUE IS FULL ... Dropping Packets !!!"); 
	return -1;
}


int
init_attach_e1000(struct pci_func *func){

	pci_func_enable(func);
	mapped_regs = (uint32_t *)mmio_map_region((physaddr_t)func->reg_base[0], (size_t)func->reg_size[0]);
	char *temp = (char *)mapped_regs;
	cprintf("\n Device Status Register: %08x\n", *((uint32_t *)(temp + 8)));
	
	find_mac_addr(1);
	cprintf("\n EEPROM_REG1 : %x   %x", (uint8_t)mac_part1, mac_part2);
	find_mac_addr(2);
	cprintf("\n EEPROM_REG1 : %x   %x", (uint8_t)mac_part3, mac_part4);
	find_mac_addr(3);
	cprintf("\n EEPROM_REG1 : %x   %x", (uint8_t)mac_part5, mac_part6);
	
	set_trans_desc_fields();
	tdbal = (uint32_t *)(temp + E1000_TDBAL);
	tdbah = (uint32_t *)(temp + E1000_TDBAH);
	tdlen = (uint32_t *)(temp + E1000_TDLEN);
	tdh = (uint32_t *)(temp + E1000_TDH);
	tdt = (uint32_t *)(temp + E1000_TDT);
	tctl = (uint32_t *)(temp + E1000_TCTL);
	tipg = (uint32_t *)(temp + E1000_TIPG);

	*tdbal = PADDR(trans_desc);
	*tdbah = 0;
	*tdlen = 16*SIZEOF_QUEUE;
	*tdt = 0;
	*tctl = 0x4010A;
	*tipg = 0x60200A;

	
	
	set_recv_desc_fields();
	mta_start = (uint32_t *)(temp + 0x5200);
	mta_end = (uint32_t *)(temp + 0x053FC);
	int i = (int)(mta_start);
	while(i < (int)mta_end){
		*((int *)i) = 0x0;
		i = i + 4;
	}
	
	rah = (uint32_t *)(temp + 0x5404);  // Doubtful
	//*rah = 0x80005634;
	*rah = *rah | (uint32_t)mac_part6 << 8;
	*rah = *rah | (uint32_t)mac_part5 | 0x80000000;
	ral = (uint32_t *)(temp + 0x5400);
	//*ral = 0x12005452;
	*ral = (uint32_t)mac_part1;
	*ral = *ral | (uint32_t)mac_part2 << 8;
	*ral = *ral | (uint32_t)mac_part3 << 16;
	*ral = *ral | (uint32_t)mac_part4 << 24;  

	ims = (uint32_t *)(temp + 0x000D0); *ims = 0;
	rdtr = (uint32_t *)(temp + 0x02820); *rdtr = 0;
	rdbah = (uint32_t *)(temp + 0x02804); *rdbah = 0;
	rdbal = (uint32_t *)(temp + 0x02800); *rdbal = PADDR(recv_desc);
	rdlen = (uint32_t *)(temp + 0x02808); *rdlen = 16*SIZEOF_QUEUE;
	rdh = (uint32_t *)(temp + 0x02810); *rdh = 0;
	rdt = (uint32_t *)(temp + 0x02818); *rdt = 125;
	rctl = (uint32_t *)(temp + 0x00100); *rctl = 0x4808002;
	
	
			

	return 0;
}

