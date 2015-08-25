#include "ns.h"


extern union Nsipc nsipcbuf;

void
sleep(int sec)
{
        unsigned now = sys_time_msec();
        unsigned end = now + sec;

        if ((int)now < 0 && (int)now > -MAXERROR)
                panic("sys_time_msec: %e", (int)now);
        if (end < now)
                panic("sleep: wrap");

        while (sys_time_msec() < end)
                sys_yield();
}

void
input(envid_t ns_envid)
{
	binaryname = "ns_input";

	// LAB 6: Your code here:
	// 	- read a packet from the device driver
	//	- send it to the network server
	// Hint: When you IPC a page to the network server, it will be
	// reading from it for a while, so don't immediately receive
	// another packet in to the same physical page.
	
	int size_new;
	int size = 1518;
	int perms = PTE_P | PTE_W | PTE_U;
	while(1){
		size_new = sys_recieve_packet(nsipcbuf.pkt.jp_data, &size);
		if(size_new < 0){
			continue;
		}
		cprintf("\n ========== SIZE : %d", size_new);
		nsipcbuf.pkt.jp_len = size_new;
		ipc_send(ns_envid, NSREQ_INPUT, &nsipcbuf, perms);
		sleep(200);

	}	


}
