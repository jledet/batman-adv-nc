#ifndef _NET_BATMAN_ADV_CODING_H
#define _NET_BATMAN_ADV_CODING_H

#define CODING_HOLD 1000 /* milliseconds */

int coding_init(struct bat_priv *bat_priv);
void coding_free(struct bat_priv *bat_priv);
void coding_orig_neighbor(struct bat_priv *bat_priv,
		struct orig_node *orig_node,
		struct orig_node *neigh_node);
int add_coding_skb(struct sk_buff *skb, struct neigh_node *neigh_node,
		struct ethhdr *ethhdr);
void coding_packet_free_ref(struct coding_packet *coding_packet);


static inline int choose_coding(void *data, int32_t size)
{
	unsigned char *key = data;
	uint32_t hash = 0;
	size_t i;

	for (i = 0; i < 6; i++) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash % size;
}

static inline int compare_coding(struct hlist_node *node, void *data2)
{
	struct coding_packet *coding_packet1 =
		container_of(node, struct coding_packet, hash_entry);
	struct coding_packet *coding_packet2 =
		(struct coding_packet *)data2;

	if (coding_packet1->id != coding_packet2->id)
		return 0;

	if (memcmp(coding_packet1->next_hop,
				coding_packet2->next_hop, ETH_ALEN))
		return 0;

	if (memcmp(coding_packet1->prev_hop,
				coding_packet2->prev_hop, ETH_ALEN))
		return 0;

	return 1;
}

static inline void pretty_mac(char *asc, char *addr)
{
	snprintf(asc, 18, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
			addr[0], addr[1], addr[2],
			addr[3], addr[4], addr[5]);
}

static inline void memxor(char *data1, const char *data2, int len)
{
	int i;

	for (i = 0; i < len; ++i)
		data1[i] = data1[i] ^ data2[i];
}

#endif /* _NET_BATMAN_ADV_CODING_H */
