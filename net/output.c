#include "ns.h"
#include <inc/lib.h>

extern union Nsipc nsipcbuf;


void
output(envid_t ns_envid)
{
	binaryname = "ns_output";

	// LAB 6: Your code here:
	// 	- read a packet from the network server
	//	- send the packet to the device driver

	int retval;
	envid_t envid;
	int perms = 0;
	while(1){
		retval = ipc_recv(&envid, &nsipcbuf, &perms);
		if (retval != NSREQ_OUTPUT)
			continue;
		sys_transmit_packet(nsipcbuf.pkt.jp_data, nsipcbuf.pkt.jp_len);
	}	
}


