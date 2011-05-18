#include "main.h"
#include "send.h"
#include "originator.h"
#include "coding.h"
#include "decoding.h"
#include "hash.h"
#include <linux/netdevice.h>
#include <linux/random.h>
#include <net/sch_generic.h>

static void forward_coding_packets(struct work_struct *work);

static void start_coding_timer(struct bat_priv *bat_priv)
{
        unsigned long hold = atomic_read(&bat_priv->catwoman_hold);
	INIT_DELAYED_WORK(&bat_priv->coding_work, forward_coding_packets);
	queue_delayed_work(bat_event_workqueue, &bat_priv->coding_work,
			(hold * HZ)/MSEC_PER_SEC);
}

/* Init coding hash table and kthread */
int coding_init(struct bat_priv *bat_priv)
{
	atomic_set(&bat_priv->coding_hash_count, 0);
	bat_priv->coding_hash = hash_new(1024);

	if (!bat_priv->coding_hash)
		return -1;

	start_coding_timer(bat_priv);

	return 0;
}

/* Return true if neigh_orig_node is neighbor to orig_node */
int orig_has_neighbor(struct orig_node *orig_node,
		      struct orig_node *neigh_orig_node)
{
	struct coding_node *tmp_coding_node;
	int ret = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(tmp_coding_node,
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
	struct coding_node *in_coding_node, *out_coding_node;

	in_coding_node = kzalloc(sizeof(struct coding_node), GFP_ATOMIC);
	if (!in_coding_node)
		return -1;
	
	out_coding_node = kzalloc(sizeof(struct coding_node), GFP_ATOMIC);
	if (!out_coding_node) {
		kfree(in_coding_node);
		return -1;
	}

	if (compare_eth(orig_node->orig, neigh_orig_node->orig)) {
		in_coding_node->topology = TOPOLOGY_AB;
		out_coding_node->topology = TOPOLOGY_AB;
	} else {
		in_coding_node->topology = TOPOLOGY_X;
		out_coding_node->topology = TOPOLOGY_X;
	}

	INIT_LIST_HEAD(&in_coding_node->list);
	memcpy(in_coding_node->addr, orig_node->orig, ETH_ALEN);
	in_coding_node->orig_node = neigh_orig_node;
	atomic_set(&in_coding_node->refcount, 1);

	INIT_LIST_HEAD(&out_coding_node->list);
	memcpy(out_coding_node->addr, neigh_orig_node->orig, ETH_ALEN);
	out_coding_node->orig_node = orig_node;
	atomic_set(&out_coding_node->refcount, 1);

	spin_lock_bh(&orig_node->in_coding_list_lock);
	list_add_tail_rcu(&in_coding_node->list, &neigh_orig_node->in_coding_list);
	spin_unlock_bh(&orig_node->in_coding_list_lock);

	spin_lock_bh(&orig_node->out_coding_list_lock);
	list_add_tail_rcu(&out_coding_node->list, &orig_node->out_coding_list);
	spin_unlock_bh(&orig_node->out_coding_list_lock);

	return 0;
}

int is_coding_neighbor(struct orig_node *orig_node,
		       struct batman_packet *batman_packet)
{
	if (orig_node->last_real_seqno != batman_packet->seqno)
		return 0;
	if (orig_node->last_ttl != batman_packet->ttl + 1)
		return 0;
	if (!compare_eth(batman_packet->orig, batman_packet->prev_sender))
		return 0;
	
	return 1;
}

void coding_orig_neighbor(struct bat_priv *bat_priv,
			  struct orig_node *orig_node,
			  struct orig_node *neigh_orig_node,
			  struct batman_packet *batman_packet)
{
	if (!orig_has_neighbor(orig_node, neigh_orig_node)) {
		printk(KERN_DEBUG "CW: Adding coding neighbor:\n");
		printk(KERN_DEBUG "  %pM -> %pM\n", orig_node->orig,
				neigh_orig_node->orig);

		if (add_coding_node(orig_node, neigh_orig_node) < 0) {
			printk(KERN_DEBUG "  Adding coding node failed\n");
		}
	}
}

/* Coding packet RCU callback */
void coding_packet_free_rcu(struct rcu_head *rcu)
{
	struct coding_packet *coding_packet;
	coding_packet = container_of(rcu, struct coding_packet, rcu);

	if (coding_packet->skb)
		dev_kfree_skb(coding_packet->skb);

	kfree(coding_packet);
}

/* Decrement coding packet refcount and call RCU callback if zero */
void coding_packet_free_ref(struct coding_packet *coding_packet)
{
	if (atomic_dec_and_test(&coding_packet->refcount))
		call_rcu(&coding_packet->rcu, coding_packet_free_rcu);
}

/* Coding path RCU callback */
void coding_path_free_rcu(struct rcu_head *rcu)
{
	struct coding_path *coding_path;
	coding_path = container_of(rcu, struct coding_path, rcu);

	kfree(coding_path);
}

/* Decrement coding path refcount and call RCU callback if zero */
void coding_path_free_ref(struct coding_path *coding_path)
{
	if (atomic_dec_and_test(&coding_path->refcount))
		call_rcu(&coding_path->rcu, coding_path_free_rcu);
}

/* Return true if coding packet has timed out */
static inline int coding_packet_timeout(struct bat_priv *bat_priv,
					struct coding_packet *coding_packet)
{
	unsigned int hold = atomic_read(&bat_priv->catwoman_hold);
	return time_is_before_jiffies(
			coding_packet->timestamp + (hold*HZ) / MSEC_PER_SEC);
}

/* Send coded packet */
void coding_send_packet(struct coding_packet *coding_packet)
{
	send_skb_packet(coding_packet->skb, coding_packet->neigh_node->if_incoming,
			coding_packet->coding_path->next_hop);
	coding_packet->skb = NULL;
	coding_packet_free_ref(coding_packet);
}

/* Traverse coding packet pool and send timed out packets */
static void _forward_coding_packets(struct bat_priv *bat_priv)
{
	struct hashtable_t *hash = bat_priv->coding_hash;
	struct hlist_node *node;
	struct hlist_head *head;
	spinlock_t *packet_list_lock;
	struct coding_packet *coding_packet;
	struct coding_path *coding_path;
	int i, count = 0;

	if (!hash)
		return;

	/* Loop hash table bins */
	for (i = 0; i < hash->size; i++) {
		head = &hash->table[i];

		/* Loop coding paths */
		rcu_read_lock();
		hlist_for_each_entry_rcu(coding_path, node, head, hash_entry) {
			packet_list_lock = &coding_path->packet_list_lock;

			/* Loop packets */
			spin_lock_bh(packet_list_lock);
			list_for_each_entry_rcu(coding_packet, &coding_path->packet_list, list) {
				/* Packets are added to tail */
				if (!coding_packet_timeout(bat_priv, coding_packet))
					break;

				list_del_rcu(&coding_packet->list);
				atomic_dec(&bat_priv->coding_hash_count);
				stats_update(bat_priv, STAT_FORWARD);
				coding_send_packet(coding_packet);
                                count++;
			}
			spin_unlock_bh(packet_list_lock);
		}
		rcu_read_unlock();
	}
}

static void forward_coding_packets(struct work_struct *work)
{
	struct delayed_work *delayed_work =
		container_of(work, struct delayed_work, work);
	struct bat_priv *bat_priv =
		container_of(delayed_work, struct bat_priv, coding_work);

	_forward_coding_packets(bat_priv);
	start_coding_timer(bat_priv);
}

/* Code packets and create coding packet */
void code_packets(struct bat_priv *bat_priv,
		  struct sk_buff *skb,
		  struct ethhdr *ethhdr,
		  struct coding_packet *coding_packet,
		  struct neigh_node *neigh_node)
{
	const int unicast_size = sizeof(struct unicast_packet);
	const int coded_size = sizeof(struct coded_packet);
	const int header_add =
		sizeof(struct coded_packet) - sizeof(struct unicast_packet);
	unsigned int coding_len;
	uint8_t coding_packet_first = 0, tq_avg_neigh, tq_avg_coding;
	uint8_t rand_tq_neigh, rand_tq_coding;
	struct sk_buff *skb_dest, *skb_src;
	struct unicast_packet *unicast_packet1;
	struct unicast_packet *unicast_packet2;
	struct coded_packet *coded_packet;
	uint8_t *first_source, *first_dest, *second_source, *second_dest;

	/* If enabled, choose random mac-dest based on weighted link quality. 
	 * Otherwise, always use weakest node */
	tq_avg_neigh = neigh_node->orig_node->router->tq_avg;
	tq_avg_coding = coding_packet->neigh_node->orig_node->router->tq_avg;
	if (atomic_read(&bat_priv->catwoman_random_tq)) {
		rand_tq_neigh = random_scale_tq(tq_avg_neigh);
		rand_tq_coding = random_scale_tq(tq_avg_coding);
		printk(KERN_DEBUG "NTQ: %d NRTQ: %d CTQ: %d CRTQ: %d\n",
				tq_avg_neigh, rand_tq_neigh,
				tq_avg_coding, rand_tq_coding);
		if (rand_tq_neigh >= rand_tq_coding) {
			coding_packet_first = 1;
			atomic_inc(&bat_priv->catstat.coded_first);
		} else {
			atomic_inc(&bat_priv->catstat.neigh_first);
		}
	} else {
		if (tq_avg_neigh >= tq_avg_coding)
			coding_packet_first = 1;
	}

	/* Instead of zero padding the smallest data buffer, we
	 * code into the largest. */
	if (skb->len <= coding_packet->skb->len) {
		skb_dest = coding_packet->skb;
		skb_src = skb;
	} else {
		skb_dest = skb;
		skb_src = coding_packet->skb;
	}

	/* The skb is also used for decoding, so copy before code */
	/*skb_dest = skb_copy(skb_dest, GFP_ATOMIC);
	if(!skb_dest)
		return;*/

	coding_len = skb_src->len - unicast_size;

	/* Setup variables for use in header */
	if (coding_packet_first) {
		first_dest = coding_packet->coding_path->next_hop;
		first_source = coding_packet->coding_path->prev_hop;
		second_dest = neigh_node->addr;
		second_source = ethhdr->h_source;
		unicast_packet1 = (struct unicast_packet *)coding_packet->skb->data;
		unicast_packet2 = (struct unicast_packet *)skb->data;
	} else {
		first_dest = neigh_node->addr;
		first_source = ethhdr->h_source;
		second_dest = coding_packet->coding_path->next_hop;
		second_source = coding_packet->coding_path->prev_hop;
		unicast_packet1 = (struct unicast_packet *)skb->data;
		unicast_packet2 = (struct unicast_packet *)coding_packet->skb->data;
	}

	/*
	printk(KERN_DEBUG "CW: Coding packets: %hu xor %hu\n",
			unicast_packet1->decoding_id, unicast_packet2->decoding_id);
	*/

	if(skb_cow(skb_dest, header_add) < 0)
		return;

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
	coded_packet->coded_len = htons(coding_len);

	/* This is where the magic happens:
	 *   Code skb_src into skb_dest */
	memxor(skb_dest->data + coded_size, skb_src->data + unicast_size, coding_len);

	dev_kfree_skb(skb_src);
	coding_packet->skb = NULL;
	coding_packet_free_ref(coding_packet);

	stats_update(bat_priv, STAT_CODE);
	send_skb_packet(skb_dest, neigh_node->if_incoming, first_dest);
}

/* Find suitable packet to code with */
struct coding_packet *find_coding_packet(struct bat_priv *bat_priv,
					 struct coding_node *in_coding_node,
					 struct ethhdr *ethhdr)
{
	struct hashtable_t *hash = bat_priv->coding_hash;
	struct hlist_node *node;
	struct orig_node *orig_node = get_orig_node(bat_priv, ethhdr->h_source);
	struct coding_node *out_coding_node;
	struct coding_packet *coding_packet = NULL;
	struct coding_path *coding_path;
	int index, i;
	uint8_t hash_key[ETH_ALEN];

	rcu_read_lock();
	list_for_each_entry_rcu(out_coding_node,
			&orig_node->out_coding_list, list) {
		/* Create almost unique path key */
		for (i = 0; i < ETH_ALEN; ++i)
			hash_key[i] = in_coding_node->addr[i] ^ 
				out_coding_node->addr[ETH_ALEN-1-i];
		index = choose_coding(hash_key, hash->size);

		hlist_for_each_entry_rcu(coding_path, node,
				&hash->table[index], hash_entry) {
			if (!compare_eth(coding_path->prev_hop,
						in_coding_node->addr))
				continue;

			if (!compare_eth(coding_path->next_hop,
						out_coding_node->addr))
				continue;

			spin_lock_bh(&coding_path->packet_list_lock);

			if (!list_empty(&coding_path->packet_list)) {
				coding_packet =
					list_first_entry(&coding_path->packet_list,
						struct coding_packet, list);
				list_del_rcu(&coding_packet->list);
				atomic_dec(&bat_priv->coding_hash_count);

				spin_unlock_bh(&coding_path->packet_list_lock);

				topology_stats_update(bat_priv, in_coding_node, out_coding_node);

				goto out;
			}

			spin_unlock_bh(&coding_path->packet_list_lock);
		}
	}

out:
	rcu_read_unlock();
	return coding_packet;
}

/* Send coded packet */
int send_coded_packet(struct sk_buff *skb,
		      struct neigh_node *neigh_node,
		      struct ethhdr *ethhdr)
{
	struct bat_priv *bat_priv =
		netdev_priv(neigh_node->if_incoming->soft_iface);
	struct orig_node *orig_node = neigh_node->orig_node;
	struct coding_node *coding_node;
	struct coding_packet *coding_packet;

	/* for neighbor of orig_node */
	rcu_read_lock();
	list_for_each_entry_rcu(coding_node,
			&orig_node->in_coding_list, list) {
		if (compare_eth(coding_node->addr, ethhdr->h_source))
			continue;

		coding_packet =
			find_coding_packet(bat_priv, coding_node, ethhdr);

		if (coding_packet) {
			/* Save packets for later decoding */
			/*add_decoding_skb(coding_packet->neigh_node->if_incoming, coding_packet->skb);*/
			/*add_decoding_skb(neigh_node->if_incoming, skb);*/
			code_packets(bat_priv, skb, ethhdr, coding_packet,
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

/* Get existing coding path or allocate a new one */
struct coding_path *get_coding_path(struct hashtable_t *hash, uint8_t *src,
				    uint8_t *dst)
{
	int hash_added, i;
	uint8_t hash_key[ETH_ALEN];
	struct coding_path *coding_path;

	for (i = 0; i < ETH_ALEN; ++i)
		hash_key[i] = src[i] ^ dst[ETH_ALEN-1-i];
	
	coding_path = coding_hash_find(hash, hash_key);

	if (coding_path)
		return coding_path;

	coding_path = kzalloc(sizeof(struct coding_path), GFP_ATOMIC);

	if (!coding_path)
		return NULL;

	INIT_LIST_HEAD(&coding_path->packet_list);
	spin_lock_init(&coding_path->packet_list_lock);
	atomic_set(&coding_path->refcount, 1);
	memcpy(coding_path->next_hop, dst, ETH_ALEN);
	memcpy(coding_path->prev_hop, src, ETH_ALEN);

	hash_added = hash_add(hash, compare_coding,
			      choose_coding, hash_key,
			      &coding_path->hash_entry);

	if (hash_added < 0) {
		kfree(coding_path);
		return NULL;
	}

	return coding_path;
}

/* Add skb to coding packet pool */
int add_coding_skb(struct sk_buff *skb,
		   struct neigh_node *neigh_node,
		   struct ethhdr *ethhdr)
{
	struct bat_priv *bat_priv
		= netdev_priv(neigh_node->if_incoming->soft_iface);
	struct unicast_packet *unicast_packet =
		(struct unicast_packet *)skb_network_header(skb);
	struct coding_path *coding_path;
	struct coding_packet *coding_packet;

	/* We only handle unicast packets */
	if (unicast_packet->packet_type != BAT_UNICAST)
		return NET_RX_DROP;

	if (send_coded_packet(skb, neigh_node, ethhdr)) {
		return NET_RX_SUCCESS;
	}

	coding_packet = kzalloc(sizeof(struct coding_packet), GFP_ATOMIC);

	if (!coding_packet)
		return NET_RX_DROP;

	coding_path = get_coding_path(bat_priv->coding_hash,
			ethhdr->h_source, neigh_node->addr);

	if (!coding_path)
		goto free_coding_packet;
	
	/* Initialize coding_packet */
	atomic_set(&coding_packet->refcount, 1);
	coding_packet->timestamp = jiffies;
	coding_packet->id = unicast_packet->decoding_id;
	coding_packet->skb = skb;
	coding_packet->neigh_node = neigh_node;
	coding_packet->coding_path = coding_path;

	/* Add coding packet to list */
	spin_lock_bh(&coding_path->packet_list_lock);
	list_add_tail_rcu(&coding_packet->list, &coding_path->packet_list);
	spin_unlock_bh(&coding_path->packet_list_lock);

	atomic_inc(&bat_priv->coding_hash_count);

	return NET_RX_SUCCESS;

free_coding_packet:
	kfree(coding_packet);
	return NET_RX_DROP;
}

/* Clean up coding packet pool */
void coding_free(struct bat_priv *bat_priv)
{
	struct hashtable_t *coding_hash = bat_priv->coding_hash;
	struct hlist_node *node, *node_tmp;
	struct hlist_head *head;
	spinlock_t *list_lock; /* spinlock to protect write access */
	struct coding_packet *coding_packet, *coding_packet_tmp;
	struct coding_path *coding_path;
	int i;

	if (!coding_hash)
		return;

	printk(KERN_DEBUG "Starting coding_packet deletion\n");
	cancel_delayed_work_sync(&bat_priv->coding_work);

	for (i = 0; i < coding_hash->size; i++) {
		head = &coding_hash->table[i];
		list_lock = &coding_hash->list_locks[i];

		spin_lock_bh(list_lock);
		hlist_for_each_entry_safe(coding_path, node, node_tmp,
					  head, hash_entry) {
			hlist_del_rcu(node);
			spin_lock_bh(&coding_path->packet_list_lock);
			list_for_each_entry_safe(coding_packet, coding_packet_tmp,
					&coding_path->packet_list, list) {
				list_del_rcu(&coding_packet->list);
				coding_packet_free_ref(coding_packet);
			}
			spin_unlock_bh(&coding_path->packet_list_lock);
			coding_path_free_ref(coding_path);
		}
		spin_unlock_bh(list_lock);
	}

	hash_destroy(coding_hash);
}

/* debugfs function to show coding neighbors */
int show_coding_neighbors(struct seq_file *seq, void *offset)
{
	struct net_device *net_dev = (struct net_device *)seq->private;
	struct bat_priv *bat_priv = netdev_priv(net_dev);
	struct hashtable_t *hash = bat_priv->orig_hash;
	struct hlist_node *node;
	struct hlist_head *head;
	struct orig_node *orig_node;
	struct coding_node *coding_node;
	int i;

	for (i = 0; i < hash->size; i++) {
		head = &hash->table[i];

		rcu_read_lock();
		hlist_for_each_entry_rcu(orig_node, node, head, hash_entry) {
			seq_printf(seq, "Node:      %pM\n", orig_node->orig);
			
			seq_printf(seq, " Ingoing:  ");
			list_for_each_entry_rcu(coding_node, &orig_node->in_coding_list, list)
				seq_printf(seq, "%pM ", coding_node->addr);
			seq_printf(seq, "\n");

			seq_printf(seq, " Outgoing: ");
			list_for_each_entry_rcu(coding_node, &orig_node->out_coding_list, list)
				seq_printf(seq, "%pM ", coding_node->addr);
			seq_printf(seq, "\n");

		}
		rcu_read_unlock();
	}

	return 0;
}

void stats_reset(struct bat_priv *bat_priv)
{
	write_seqlock(&bat_priv->catstat.lock);
	atomic_set(&bat_priv->catstat.transmitted, 0);
	atomic_set(&bat_priv->catstat.received, 0);
	atomic_set(&bat_priv->catstat.forwarded, 0);
	atomic_set(&bat_priv->catstat.coded, 0);
	atomic_set(&bat_priv->catstat.coded_ab, 0);
	atomic_set(&bat_priv->catstat.coded_x, 0);
	atomic_set(&bat_priv->catstat.dropped, 0);
	atomic_set(&bat_priv->catstat.decoded, 0);
	atomic_set(&bat_priv->catstat.failed, 0);
	atomic_set(&bat_priv->catstat.coded_first, 0);
	atomic_set(&bat_priv->catstat.neigh_first, 0);
	write_sequnlock(&bat_priv->catstat.lock);
}

void stats_init(struct bat_priv *bat_priv)
{
	seqlock_init(&bat_priv->catstat.lock);
	stats_reset(bat_priv);
}

void stats_update(struct bat_priv *bat_priv, uint32_t flags)
{
	if (bat_priv && flags) {
		write_seqlock(&bat_priv->catstat.lock);
		if (flags & STAT_XMIT)
			atomic_inc(&bat_priv->catstat.transmitted);
		if (flags & STAT_RECV)
			atomic_inc(&bat_priv->catstat.received);
		if (flags & STAT_FORWARD)
			atomic_inc(&bat_priv->catstat.forwarded);
		if (flags & STAT_CODE)
			atomic_inc(&bat_priv->catstat.coded);
		if (flags & STAT_DECODE)
			atomic_inc(&bat_priv->catstat.decoded);
		if (flags & STAT_FAIL)
			atomic_inc(&bat_priv->catstat.failed);
		if (flags & STAT_CODED_AB)
			atomic_inc(&bat_priv->catstat.coded_ab);
		if (flags & STAT_CODED_X)
			atomic_inc(&bat_priv->catstat.coded_x);
		write_sequnlock(&bat_priv->catstat.lock);
	}
}

void topology_stats_update(struct bat_priv *bat_priv,
			   struct coding_node *in_coding_node,
			   struct coding_node *out_coding_node)
{
	switch (in_coding_node->topology) {
		case TOPOLOGY_AB:
			stats_update(bat_priv, STAT_CODED_AB);
			break;

		case TOPOLOGY_X:
			stats_update(bat_priv, STAT_CODED_X);
			break;
	}

	switch (out_coding_node->topology) {
		case TOPOLOGY_AB:
			stats_update(bat_priv, STAT_CODED_AB);
			break;

		case TOPOLOGY_X:
			stats_update(bat_priv, STAT_CODED_X);
			break;
	}
}

/* debugfs function to list network coding statistics */
int coding_stats(struct seq_file *seq, void *offset)
{
	struct net_device *net_dev = (struct net_device *)seq->private;
	struct bat_priv *bat_priv = netdev_priv(net_dev);
	struct catwoman_stats *catstat = &bat_priv->catstat;
	seqlock_t *lock = &catstat->lock;
	int transmitted, received, forwarded, coded, dropped, decoded, failed,
	    coding_list, decoding_list, coded_x, coded_ab;
	unsigned long sval;

	do {
		sval = read_seqbegin(lock);
		transmitted = atomic_read(&catstat->transmitted);
		received    = atomic_read(&catstat->received);
		forwarded   = atomic_read(&catstat->forwarded);
		coded       = atomic_read(&catstat->coded);
		dropped     = atomic_read(&catstat->dropped);
		decoded     = atomic_read(&catstat->decoded);
		failed      = atomic_read(&catstat->failed);
		coded_ab    = atomic_read(&catstat->coded_ab);
		coded_x     = atomic_read(&catstat->coded_x);
	} while (read_seqretry(lock, sval));

	coding_list = atomic_read(&bat_priv->coding_hash_count);
	decoding_list = atomic_read(&bat_priv->decoding_hash_count);

	seq_printf(seq, "Transmitted:  %d\n", transmitted);
	seq_printf(seq, "Received:     %d\n", received);
	seq_printf(seq, "Forwarded:    %d\n", forwarded);
	seq_printf(seq, "Coded:        %d\n", coded);
	seq_printf(seq, "Coded_ab:     %d\n", coded_ab);
	seq_printf(seq, "Coded_x:      %d\n", coded_x);
	seq_printf(seq, "Dropped:      %d\n", dropped);
	seq_printf(seq, "Decoded:      %d\n", decoded);
	seq_printf(seq, "Failed:       %d\n", failed);
	seq_printf(seq, "\n");
	seq_printf(seq, "Coding packets:   %d\n", coding_list);
	seq_printf(seq, "Decoding packets: %d\n", decoding_list);
	
	return 0;
}

int coding_stats_reset(struct seq_file *seq, void *offset)
{
	struct net_device *net_dev = (struct net_device *)seq->private;
	struct bat_priv *bat_priv = netdev_priv(net_dev);
	stats_reset(bat_priv);

	return 0;
}

