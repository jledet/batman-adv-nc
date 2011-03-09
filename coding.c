#include "main.h"
#include "coding.h"

void coding_orig(struct ethhdr *ethhdr,
        struct batman_packet *batman_packet)
{
	char from[13];

	pretty_mac(from, ethhdr->h_source);
	printk(KERN_DEBUG "WOMBAT: OGM from %s\n", from);
}
