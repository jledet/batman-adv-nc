#include "main.h"
#include "coding.h"
#include "send.h"
#include "originator.h"
#include "hash.h"

int coding_thread(void *data);

int coding_init(struct bat_priv *bat_priv)
{
	atomic_set(&bat_priv->coding_hash_count, 0);
	bat_priv->coding_hash = hash_new(1024);

	if (!bat_priv->coding_hash)
		return -1;

	bat_priv->coding_thread = kthread_create(coding_thread,
			(void *)bat_priv, "BATMAN Coding");
	wake_up_process(bat_priv->coding_thread);

	return 0;
}

int orig_has_neighbor(struct orig_node *orig_node,
		struct orig_node *neigh_orig_node)
{
	struct coding_node *tmp_coding_node;
	struct hlist_node *node;
	int ret = 0;

	rcu_read_lock();
	hlist_for_each_entry_rcu(tmp_coding_node, node,
				 &orig_node->out_coding_list, list) {
		if (compare_eth(tmp_coding_node->addr,
				neigh_orig_node->orig)) {
			ret = 1;
			break;
		}
	}
	rcu_read_unlock();

	return ret;
}

int add_coding_node(struct orig_node *orig_node,
		struct orig_node *neigh_orig_node)
{
	struct coding_node *in_coding_node =
		kzalloc(sizeof(struct coding_node), GFP_ATOMIC);
	struct coding_node *out_coding_node =
		kzalloc(sizeof(struct coding_node), GFP_ATOMIC);

	if (!in_coding_node)
		return -1;

	INIT_HLIST_NODE(&in_coding_node->list);
	memcpy(in_coding_node->addr, orig_node->orig, ETH_ALEN);
	in_coding_node->orig_node = neigh_orig_node;
	atomic_set(&in_coding_node->refcount, 1);

	INIT_HLIST_NODE(&out_coding_node->list);
	memcpy(out_coding_node->addr, neigh_orig_node->orig, ETH_ALEN);
	out_coding_node->orig_node = orig_node;
	atomic_set(&out_coding_node->refcount, 1);

	spin_lock_bh(&orig_node->in_coding_list_lock);
	hlist_add_head_rcu(&in_coding_node->list, &neigh_orig_node->in_coding_list);
	spin_unlock_bh(&orig_node->in_coding_list_lock);

	spin_lock_bh(&orig_node->out_coding_list_lock);
	hlist_add_head_rcu(&out_coding_node->list, &orig_node->out_coding_list);
	spin_unlock_bh(&orig_node->out_coding_list_lock);

	return 0;
}

void coding_orig_neighbor(struct bat_priv *bat_priv,
		struct orig_node *orig_node,
		struct orig_node *neigh_orig_node)
{
	if (!orig_has_neighbor(orig_node, neigh_orig_node)) {
		printk(KERN_DEBUG "WOMBAT: Adding coding neighbor\n");
		if (add_coding_node(orig_node, neigh_orig_node) < 0) {
			printk(KERN_DEBUG "Adding coding node failed\n");
		}
	}
}

void coding_packet_free_rcu(struct rcu_head *rcu)
{
	struct coding_packet *coding_packet;
	coding_packet = container_of(rcu, struct coding_packet, rcu);

	if (coding_packet->skb)
		dev_kfree_skb(coding_packet->skb);

	kfree(coding_packet);
}

void coding_packet_free_ref(struct coding_packet *coding_packet)
{
	if (atomic_dec_and_test(&coding_packet->refcount))
		call_rcu(&coding_packet->rcu, coding_packet_free_rcu);
}

static inline int send_coding_packet(struct coding_packet *coding_packet)
{
	struct timespec now = current_kernel_time();
	struct timespec timeout = {0, CODING_HOLD * NSEC_PER_MSEC};
	timeout = timespec_sub(now, timeout);

	return timespec_compare(&coding_packet->timespec, &timeout) < 0 ? 1 : 0;
}

void coding_send_packet(struct coding_packet *coding_packet)
{
	send_skb_packet(coding_packet->skb, coding_packet->hard_iface,
			coding_packet->next_hop);
	coding_packet->skb = NULL;
	coding_packet_free_ref(coding_packet);
}

void work_coding_packets(struct bat_priv *bat_priv)
{
	struct hashtable_t *hash = bat_priv->coding_hash;
	struct hlist_node *node, *node_tmp;
	struct hlist_head *head;
	spinlock_t *list_lock; /* spinlock to protect write access */
	struct coding_packet *coding_packet;
	int i;

	if (!hash)
		return;

	for (i = 0; i < hash->size; i++) {
		head = &hash->table[i];
		list_lock = &hash->list_locks[i];

		spin_lock_bh(list_lock);
		hlist_for_each_entry_safe(coding_packet, node, node_tmp,
					  head, hash_entry) {
			if (send_coding_packet(coding_packet)) {
				hlist_del_rcu(node);
				atomic_dec(&bat_priv->coding_hash_count);
				coding_send_packet(coding_packet);
			}
		}
		spin_unlock_bh(list_lock);
	}
}

int coding_thread(void *data)
{
	struct bat_priv *bat_priv = (struct bat_priv *)data;

	while (!kthread_should_stop()) {
		msleep(CODING_HOLD);
		work_coding_packets(bat_priv);
	}

	return 0;
}

void code_packets(struct sk_buff *skb, struct ethhdr *ethhdr,
		struct coding_packet *coding_packet,
		struct neigh_node *neigh_node)
{
	const int unicast_size = sizeof(struct unicast_packet);
	const int header_add =
		sizeof(struct coded_packet) - sizeof(struct unicast_packet);
	unsigned int data_len;
	struct sk_buff *skb_dest, *skb_src;
	struct unicast_packet unicast_packet_tmp;
	struct unicast_packet *unicast_packet1;
	struct unicast_packet *unicast_packet2;
	struct coded_packet *coded_packet;
	uint8_t *first_source, *first_dest, *second_source, *second_dest;

	/* Instead of zero padding the smallest data buffer, we
	 * code into the largest. */
	if (skb->data_len >= coding_packet->skb->data_len) {
		skb_dest = skb;
		skb_src = coding_packet->skb;
		first_dest = neigh_node->addr;
		first_source = ethhdr->h_source;
		second_dest = coding_packet->next_hop;
		second_source = coding_packet->prev_hop;
	} else {
		skb_dest = coding_packet->skb;
		skb_src = skb;
		first_dest = coding_packet->next_hop;
		first_source = coding_packet->prev_hop;
		second_dest = neigh_node->addr;
		second_source = ethhdr->h_source;
	}

	data_len = skb_src->len - unicast_size - ETH_HLEN;
	unicast_packet1 = (struct unicast_packet *)skb_dest->data;
	unicast_packet2 = (struct unicast_packet *)skb_src->data;

	if(skb_cow(skb_dest, header_add) < 0)
		return;

	/* Save original header before writing new in place */
	memcpy(&unicast_packet_tmp, unicast_packet1,
			sizeof(struct unicast_packet));

	/* Make room for our coded header */
	skb_push(skb_dest, header_add);
	coded_packet = (struct coded_packet *)skb_dest->data;
	skb_reset_mac_header(skb_dest);

	coded_packet->packet_type = BAT_CODED;
	coded_packet->version = COMPAT_VERSION;

	/* Info about first unicast packet */
	memcpy(coded_packet->first_source, first_source, ETH_ALEN);
	memcpy(coded_packet->first_orig_dest, unicast_packet1->dest, ETH_ALEN);
	coded_packet->first_id = unicast_packet1->decoding_id;
	coded_packet->first_ttl = unicast_packet1->ttl;

	/* Info about second unicast packet */
	memcpy(coded_packet->second_dest, second_dest, ETH_ALEN);
	memcpy(coded_packet->second_source, second_source, ETH_ALEN);
	memcpy(coded_packet->second_orig_dest, unicast_packet2->dest, ETH_ALEN);
	coded_packet->second_id = unicast_packet2->decoding_id;
	coded_packet->second_ttl = unicast_packet2->ttl;
	coded_packet->second_len = htons(data_len);

	memxor((char *)unicast_packet1 + unicast_size, (char *)unicast_packet2 + unicast_size,
			data_len);

	send_skb_packet(skb_dest, neigh_node->if_incoming, first_dest);
}

struct coding_packet *find_coding_packet(struct bat_priv *bat_priv,
		struct coding_node *in_coding_node, struct ethhdr *ethhdr)
{
	struct hashtable_t *hash = bat_priv->coding_hash;
	struct hlist_node *node, *p_node, *p_node_tmp;
	struct orig_node *orig_node = get_orig_node(bat_priv, ethhdr->h_source);
	struct coding_node *out_coding_node;
	struct coding_packet *coding_packet;
	spinlock_t *lock;
	int index, i;
	uint8_t hash_key[ETH_ALEN];

	rcu_read_lock();
	hlist_for_each_entry_rcu(out_coding_node, node,
			&orig_node->out_coding_list, list) {
		/* Create almost unique path key */
		for (i = 0; i < ETH_ALEN; ++i)
			hash_key[i] =
				out_coding_node->addr[i] ^ in_coding_node->addr[i];
		index = choose_coding(hash_key, hash->size);
		lock = &hash->list_locks[index];

		spin_lock_bh(lock);
		hlist_for_each_entry_safe(coding_packet, p_node, p_node_tmp,
				&hash->table[index], hash_entry) {
			if (compare_eth(coding_packet->prev_hop,
						in_coding_node->addr) &&
					compare_eth(coding_packet->next_hop,
						out_coding_node->addr))
				goto out;
		}
		spin_unlock_bh(lock);
	}
	rcu_read_unlock();

	return NULL;

out:
	atomic_dec(&bat_priv->coding_hash_count);
	hlist_del_rcu(p_node);
	spin_unlock_bh(lock);
	rcu_read_unlock();

	return coding_packet;
}

int send_coded_packet(struct sk_buff *skb,
		struct neigh_node *neigh_node, struct ethhdr *ethhdr)
{
	struct bat_priv *bat_priv =
		netdev_priv(neigh_node->if_incoming->soft_iface);
	struct hlist_node *node;
	struct orig_node *orig_node = neigh_node->orig_node;
	struct coding_node *coding_node;
	struct coding_packet *coding_packet;
	uint8_t eth1[18], eth2[18];

	/* for neighbor of orig_node */
	rcu_read_lock();
	hlist_for_each_entry_rcu(coding_node, node,
			&orig_node->in_coding_list, list) {
		coding_packet =
			find_coding_packet(bat_priv, coding_node, ethhdr);

		if (coding_packet) {
			pretty_mac(eth1, coding_packet->next_hop);
			pretty_mac(eth2, neigh_node->addr);
			printk(KERN_DEBUG "WOMBAT: X Coding posibility to:\n");
			printk(KERN_DEBUG "            %s\n", eth1);
			printk(KERN_DEBUG "            %s\n", eth2);
			code_packets(skb, ethhdr, coding_packet,
					neigh_node);
			goto out;
		}
	}
	rcu_read_unlock();

	return 0;

out:
	rcu_read_unlock();
	return 1;
}

int add_coding_skb(struct sk_buff *skb, struct neigh_node *neigh_node,
	struct ethhdr *ethhdr)
{
	int hash_added;
	int i, index;
	uint8_t hash_key[ETH_ALEN];
	struct bat_priv *bat_priv
		= netdev_priv(neigh_node->if_incoming->soft_iface);
	struct unicast_packet *unicast_packet =
		(struct unicast_packet *)skb_network_header(skb);
	struct coding_packet *coding_packet;

	/* We only handle unicast packets */
	if (unicast_packet->packet_type != BAT_UNICAST)
		return NET_RX_DROP;

	if (send_coded_packet(skb, neigh_node, ethhdr))
		return NET_RX_SUCCESS;

	coding_packet = kzalloc(sizeof(struct coding_packet), GFP_ATOMIC);

	if (!coding_packet)
		return NET_RX_DROP;

	atomic_set(&coding_packet->refcount, 1);
	memcpy(coding_packet->next_hop, neigh_node->addr, ETH_ALEN);
	memcpy(coding_packet->prev_hop, ethhdr->h_source, ETH_ALEN);
	coding_packet->timestamp = jiffies;
	coding_packet->id = unicast_packet->decoding_id;
	coding_packet->skb = skb;
	coding_packet->hard_iface = neigh_node->if_incoming;
	coding_packet->timespec = current_kernel_time();

	for (i = 0; i < ETH_ALEN; ++i)
		hash_key[i] = coding_packet->prev_hop[i] ^
			coding_packet->next_hop[i];
	index = choose_coding(hash_key, bat_priv->coding_hash->size);

	hash_added = hash_add(bat_priv->coding_hash, compare_coding,
			      choose_coding, hash_key,
			      &coding_packet->hash_entry);
	if (hash_added < 0)
		goto free_coding_packet;

	atomic_inc(&bat_priv->coding_hash_count);

	return NET_RX_SUCCESS;

free_coding_packet:
	kfree(coding_packet);
	return NET_RX_DROP;
}

void coding_free(struct bat_priv *bat_priv)
{
	struct hashtable_t *coding_hash = bat_priv->coding_hash;
	struct hlist_node *node, *node_tmp;
	struct hlist_head *head;
	spinlock_t *list_lock; /* spinlock to protect write access */
	struct coding_packet *coding_packet;
	int i;

	if (!coding_hash)
		return;

	printk(KERN_DEBUG "Starting coding_packet deletion\n");
	kthread_stop(bat_priv->coding_thread);

	for (i = 0; i < coding_hash->size; i++) {
		head = &coding_hash->table[i];
		list_lock = &coding_hash->list_locks[i];

		spin_lock_bh(list_lock);
		hlist_for_each_entry_safe(coding_packet, node, node_tmp,
					  head, hash_entry) {
			hlist_del_rcu(node);
			coding_packet_free_ref(coding_packet);
		}
		spin_unlock_bh(list_lock);
	}

	hash_destroy(coding_hash);
}
