#ifndef _NET_BATMAN_ADV_CODING_H
#define _NET_BATMAN_ADV_CODING_H

void coding_orig(struct ethhdr *ethhdr, struct batman_packet *batman_packet);

static inline void pretty_mac(char *str_out, char *mac)
{
	int i;

	for (i = 0; i < 6; ++i) {
		snprintf(str_out + 2*i, 3, "%02x", mac[i]);
	}
}

#endif
