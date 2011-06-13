#ifndef _NET_BATMAN_ADV_CODING_H
#define _NET_BATMAN_ADV_CODING_H

#include "hash.h"
#include <linux/random.h>

#define CATWOMAN_ENABLED 1 /* CATWOMAN enabled as default */
#define CODING_HOLD 10 /* milliseconds */

int coding_init(struct bat_priv *bat_priv);
void coding_free(struct bat_priv *bat_priv);
int is_coding_neighbor(struct orig_node *orig_node,
		       struct batman_packet *batman_packet);
void coding_orig_neighbor(struct bat_priv *bat_priv,
		struct orig_node *orig_node,
		struct orig_node *neigh_node,
		struct batman_packet *batman_packet);
int add_coding_skb(struct sk_buff *skb, struct neigh_node *neigh_node,
		struct ethhdr *ethhdr);
void coding_packet_free_ref(struct coding_packet *coding_packet);
void coding_path_free_ref(struct coding_path *coding_path);
struct coding_path *get_coding_path(struct hashtable_t *hash, uint8_t *src,
		uint8_t *dst);
int show_coding_neighbors(struct seq_file *seq, void *offset);
int coding_stats(struct seq_file *seq, void *offset);
int coding_stats_reset(struct seq_file *seq, void *offset);
void stats_init(struct bat_priv *bat_priv);
void stats_reset(struct bat_priv *bat_priv);
void stats_update(struct bat_priv *bat_priv, uint32_t flags);
void topology_stats_update(struct bat_priv *bat_priv,
			   struct coding_node *in_coding_node,
			   struct coding_node *out_coding_node);

#define STAT_XMIT	1
#define STAT_RECV	(STAT_XMIT	<< 1)
#define STAT_FORWARD	(STAT_RECV	<< 1)
#define STAT_CODE	(STAT_FORWARD	<< 1)
#define STAT_DECODE	(STAT_CODE	<< 1)
#define STAT_FAIL	(STAT_DECODE	<< 1)
#define STAT_CODED_AB	(STAT_FAIL	<< 1)
#define STAT_CODED_X	(STAT_CODED_AB	<< 1)

#define TOPOLOGY_AB 1
#define TOPOLOGY_X 2

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
	struct coding_path *coding_path =
		container_of(node, struct coding_path, hash_entry);
	int i;
	uint8_t hash_key[ETH_ALEN];

	for (i = 0; i < ETH_ALEN; i++)
		hash_key[i] = coding_path->prev_hop[i] ^ coding_path->next_hop[ETH_ALEN-1-i];

	if (compare_eth(hash_key, data2))
		return 1;

	return 0;
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

		/*
		if (!atomic_inc_not_zero(&coding_path->refcount))
			continue;
		*/

		coding_path_tmp = coding_path;
		break;
	}
	rcu_read_unlock();

	return coding_path_tmp;
}

static inline void memxor(char *data1, const char *data2, int len)
{
	int i;

	for (i = 0; i < len; ++i)
		data1[i] = data1[i] ^ data2[i];
}

static inline uint8_t random_scale_tq(uint8_t orig_tq)
{
	uint8_t rand_val;

	get_random_bytes(&rand_val, 1);

	return TQ_MAX_VALUE - (rand_val * (TQ_MAX_VALUE - orig_tq)) / TQ_MAX_VALUE;
}

#endif /* _NET_BATMAN_ADV_CODING_H */
