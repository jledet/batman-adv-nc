#ifndef _NET_BATMAN_ADV_CODING_H
#define _NET_BATMAN_ADV_CODING_H

#include "hash.h"

#define CODING_HOLD 1000 /* milliseconds */

int coding_init(struct bat_priv *bat_priv);
void coding_free(struct bat_priv *bat_priv);
void coding_orig_neighbor(struct bat_priv *bat_priv,
		struct orig_node *orig_node,
		struct orig_node *neigh_node);
int add_coding_skb(struct sk_buff *skb, struct neigh_node *neigh_node,
		struct ethhdr *ethhdr);
void coding_packet_free_ref(struct coding_packet *coding_packet);
void coding_path_free_ref(struct coding_path *coding_path);
struct coding_path *get_coding_path(struct hashtable_t *hash, uint8_t *src,
		uint8_t *dst);


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
	struct coding_path *coding_path1 =
		container_of(node, struct coding_path, hash_entry);
	struct coding_path *coding_path2 =
		(struct coding_path *)data2;

	if (memcmp(coding_path1->next_hop,
				coding_path2->next_hop, ETH_ALEN))
		return 0;

	if (memcmp(coding_path1->prev_hop,
				coding_path2->prev_hop, ETH_ALEN))
		return 0;

	return 1;
}

static inline struct coding_path *coding_hash_find(struct hashtable_t *hash,
					       void *data)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct coding_path *coding_path, *coding_path_tmp = NULL;
	int index;

	if (!hash)
		return NULL;

	index = choose_coding(data, hash->size);
	head = &hash->table[index];

	rcu_read_lock();
	hlist_for_each_entry_rcu(coding_path, node, head, hash_entry) {
		if (!compare_coding(node, data))
			continue;

		if (!atomic_inc_not_zero(&coding_path->refcount))
			continue;

		coding_path_tmp = coding_path;
		break;
	}
	rcu_read_unlock();

	return coding_path_tmp;
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
