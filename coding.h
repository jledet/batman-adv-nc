#ifndef _NET_BATMAN_ADV_CODING_H
#define _NET_BATMAN_ADV_CODING_H

#define DECODING_TIMEOUT 1 /* seconds */
#define CODING_HOLD 100 /* milliseconds */

int coding_init(struct bat_priv *bat_priv);
void coding_free(struct bat_priv *bat_priv);
void coding_orig_neighbor(struct bat_priv *bat_priv,
		struct orig_node *orig_node,
		struct orig_node *neigh_node);
uint16_t get_decoding_id(struct bat_priv *bat_priv);
int receive_coded_packet(struct bat_priv *bat_priv,
		struct coded_packet *coded_packet, int hdr_size);
int add_coding_skb(struct hard_iface *hard_iface, struct sk_buff *skb);
void add_decoding_skb(struct hard_iface *hard_iface, struct sk_buff *skb);


static inline void generate_key(struct coding_packet *decoding_packet,
		uint8_t *data1)
{
	struct ethhdr *ethhdr =
		(struct ethhdr *)skb_mac_header(decoding_packet->skb);
	int i;

	data1[0] = (uint8_t)decoding_packet->id;
	data1[1] = (uint8_t)*(&decoding_packet->id + 1);
	for (i = 2; i < ETH_ALEN; ++i) {
		data1[i] = ethhdr->h_dest[i] ^ ethhdr->h_source[i];
	}
}

static inline int choose_coding(void *data, int32_t size)
{
	uint8_t key[ETH_ALEN];
	uint32_t hash = 0;
	size_t i;
	
	generate_key((struct coding_packet *)data, key);

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

/* returns 1 if they are the same originator */
static inline int compare_coding(struct hlist_node *node, void *data2)
{
	struct coding_packet *decoding_packet =
		container_of(node, struct coding_packet, hash_entry);
	
	uint8_t data1[ETH_ALEN];
	generate_key(decoding_packet, data1);

	return (memcmp(data1, data2, ETH_ALEN) == 0 ? 1 : 0);
}

static inline void pretty_mac(char *asc, char *addr)
{
	snprintf(asc, 18, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
			addr[0], addr[1], addr[2],
			addr[3], addr[4], addr[5]);
}

#endif
