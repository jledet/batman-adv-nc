#ifndef _NET_BATMAN_ADV_CODING_H
#define _NET_BATMAN_ADV_CODING_H


int coding_init(struct bat_priv *bat_priv);
void coding_orig_neighbor(struct bat_priv *bat_priv,
		struct orig_node *orig_node,
		struct orig_node *neigh_node);

static inline void pretty_mac(char *asc, char *addr)
{
	snprintf(asc, 18, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
			addr[0], addr[1], addr[2],
			addr[3], addr[4], addr[5]);
}

#endif
