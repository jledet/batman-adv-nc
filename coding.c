#include "main.h"
#include "coding.h"
#include "hash.h"

static void purge_decoding(struct work_struct *work);

static void start_coding_timer(struct bat_priv *bat_priv)
{
	INIT_DELAYED_WORK(&bat_priv->decoding_work, purge_decoding);
	queue_delayed_work(bat_event_workqueue, &bat_priv->decoding_work, 1 * HZ);
}

int coding_init(struct bat_priv *bat_priv)
{
	if (bat_priv->decoding_hash)
		return 0;

	bat_priv->decoding_hash = hash_new(1024);

	if (!bat_priv->decoding_hash)
		return -1;

	start_coding_timer(bat_priv);

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
				 &orig_node->coding_list, list) {
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
	struct coding_node *coding_node = kzalloc(sizeof(struct coding_node), GFP_ATOMIC);
	if (!coding_node)
		return -1;

	INIT_HLIST_NODE(&coding_node->list);

	memcpy(coding_node->addr, neigh_orig_node->orig, ETH_ALEN);
	coding_node->orig_node = neigh_orig_node;

	atomic_set(&coding_node->refcount, 1);

	spin_lock_bh(&orig_node->coding_list_lock);
	hlist_add_head_rcu(&coding_node->list, &orig_node->coding_list);
	spin_unlock_bh(&orig_node->coding_list_lock);

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

int receive_coding_packet(struct bat_priv *bat_priv,
		struct coding_packet *coding_packet, int hdr_size)
{

	return -1;
}

uint16_t get_decoding_id(struct bat_priv *bat_priv)
{
	return (uint16_t)atomic_inc_return(&bat_priv->last_decoding_id);
}

void add_decoding_skb(struct bat_priv *bat_priv, struct sk_buff *skb)
{
	int hash_added;
	struct unicast_packet *unicast_packet = 
		(struct unicast_packet *)skb->data;
	struct sk_buff *decoding_skb = skb_clone(skb, GFP_ATOMIC);

	struct decoding_packet *decoding_packet = 
		kmalloc(sizeof(struct decoding_packet), GFP_ATOMIC);

	atomic_set(&decoding_packet->refcount, 1);
	decoding_packet->timestamp = jiffies;
	decoding_packet->id = unicast_packet->decoding_id;
	decoding_packet->skb = decoding_skb;
	
	hash_added = hash_add(bat_priv->decoding_hash, compare_decoding,
			      choose_decoding, decoding_packet, &decoding_packet->hash_entry);
	if (hash_added < 0)
		goto free_decoding_packet;

	return;

free_decoding_packet:
	dev_kfree_skb(decoding_skb);
	kfree(decoding_packet);
}

void decoding_packet_free_rcu(struct rcu_head *rcu)
{
	struct decoding_packet *decoding_packet;
	decoding_packet = container_of(rcu, struct decoding_packet, rcu);

	dev_kfree_skb(decoding_packet->skb);
	kfree(decoding_packet);
}

void decoding_packet_free_ref(struct decoding_packet *decoding_packet)
{
	if (atomic_dec_and_test(&decoding_packet->refcount))
		call_rcu(&decoding_packet->rcu, decoding_packet_free_rcu);
}

static inline int purge_decoding_packet(struct decoding_packet *decoding_packet)
{
	return time_is_before_jiffies(
			decoding_packet->timestamp + DECODING_TIMEOUT * HZ);
}

static void _purge_decoding(struct bat_priv *bat_priv)
{
	struct hashtable_t *hash = bat_priv->decoding_hash;
	struct hlist_node *node, *node_tmp;
	struct hlist_head *head;
	spinlock_t *list_lock; /* spinlock to protect write access */
	struct decoding_packet *decoding_packet;
	int i;

	if (!hash)
		return;

	for (i = 0; i < hash->size; i++) {
		head = &hash->table[i];
		list_lock = &hash->list_locks[i];

		spin_lock_bh(list_lock);
		hlist_for_each_entry_safe(decoding_packet, node, node_tmp,
					  head, hash_entry) {
			if (purge_decoding_packet(decoding_packet)) {
				hlist_del_rcu(node);
				decoding_packet_free_ref(decoding_packet);
			}
		}
		spin_unlock_bh(list_lock);
	}
}

static void purge_decoding(struct work_struct *work)
{
	struct delayed_work *delayed_work =
		container_of(work, struct delayed_work, work);
	struct bat_priv *bat_priv =
		container_of(delayed_work, struct bat_priv, decoding_work);

	printk(KERN_DEBUG "Removing old decodings %p\n", bat_priv);
	_purge_decoding(bat_priv);
	start_coding_timer(bat_priv);
}

void coding_free(struct bat_priv *bat_priv)
{
	struct hashtable_t *hash = bat_priv->decoding_hash;
	struct hlist_node *node, *node_tmp;
	struct hlist_head *head;
	spinlock_t *list_lock; /* spinlock to protect write access */
	struct decoding_packet *decoding_packet;
	int i;

	if (!hash)
		return;

	printk(KERN_DEBUG "Starting decoding_packet deletion\n");
	cancel_delayed_work_sync(&bat_priv->decoding_work);

	for (i = 0; i < hash->size; i++) {
		head = &hash->table[i];
		list_lock = &hash->list_locks[i];

		spin_lock_bh(list_lock);
		hlist_for_each_entry_safe(decoding_packet, node, node_tmp,
					  head, hash_entry) {
			hlist_del_rcu(node);
			decoding_packet_free_ref(decoding_packet);
		}
		spin_unlock_bh(list_lock);
	}

	hash_destroy(hash);
}
