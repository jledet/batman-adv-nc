#include "main.h"
#include "coding.h"
#include "routing.h"
#include "hash.h"

static void purge_decoding(struct work_struct *work);
int coding_thread(void *data);

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
	atomic_set(&bat_priv->last_decoding_id, 1);
	atomic_set(&bat_priv->coding_hash_count, 0);

	if (!bat_priv->decoding_hash)
		return -1;

	bat_priv->coding_hash = hash_new(1024);

	if (!bat_priv->coding_hash)
		return -1;

	start_coding_timer(bat_priv);

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

int receive_coded_packet(struct bat_priv *bat_priv,
		struct coded_packet *coded_packet, int hdr_size)
{

	return -1;
}

void coding_packet_free_rcu(struct rcu_head *rcu)
{
	struct coding_packet *coding_packet;
	coding_packet = container_of(rcu, struct coding_packet, rcu);

	if (coding_packet->skb) {
		printk(KERN_DEBUG "WOMBAT: Freeing skb\n");
		dev_kfree_skb(coding_packet->skb);
	}

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
	route_unicast_packet(coding_packet->skb, coding_packet->hard_iface);
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
	int i, sending = 0;

	if (!hash)
		return;

	for (i = 0; i < hash->size; i++) {
		head = &hash->table[i];
		list_lock = &hash->list_locks[i];

		spin_lock_bh(list_lock);
		hlist_for_each_entry_safe(coding_packet, node, node_tmp,
					  head, hash_entry) {
			if (send_coding_packet(coding_packet))
				printk(KERN_DEBUG "WOMBAT: Found hold packet\n");
				hlist_del_rcu(node);
				coding_send_packet(coding_packet);
				sending = 1;
		}
		spin_unlock_bh(list_lock);
	}
	if (sending)
		printk(KERN_DEBUG "WOMBAT: List traversed\n");
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

int add_coding_skb(struct hard_iface *hard_iface, struct sk_buff *skb)
{
	int hash_added;
	struct bat_priv *bat_priv = netdev_priv(hard_iface->soft_iface);
	struct unicast_packet *unicast_packet =
		(struct unicast_packet *)skb_network_header(skb);
	struct coding_packet *coding_packet;

	/* We only handle unicast packets */
	if (unicast_packet->packet_type != BAT_UNICAST)
		return NET_RX_DROP;

	coding_packet = kzalloc(sizeof(struct coding_packet), GFP_ATOMIC);

	if (!coding_packet)
		return NET_RX_DROP;

	atomic_set(&coding_packet->refcount, 1);
	coding_packet->timestamp = jiffies;
	coding_packet->id = unicast_packet->decoding_id;
	coding_packet->skb = skb;
	coding_packet->hard_iface = hard_iface;
	coding_packet->timespec = current_kernel_time();

	hash_added = hash_add(bat_priv->coding_hash, compare_coding,
			      choose_coding, coding_packet,
			      &coding_packet->hash_entry);
	if (hash_added < 0)
		goto free_coding_packet;

	atomic_inc(&bat_priv->coding_hash_count);

	return NET_RX_SUCCESS;

free_coding_packet:
	kfree(coding_packet);
	return NET_RX_DROP;
}

uint16_t get_decoding_id(struct bat_priv *bat_priv)
{
	printk(KERN_DEBUG "WOMBAT: Increment decoding_id\n");
	return (uint16_t)atomic_inc_return(&bat_priv->last_decoding_id);
}

void add_decoding_skb(struct hard_iface *hard_iface, struct sk_buff *skb)
{
	int hash_added;
	struct bat_priv *bat_priv = netdev_priv(hard_iface->soft_iface);
	struct unicast_packet *unicast_packet =
		(struct unicast_packet *)skb_network_header(skb);
	struct sk_buff *decoding_skb;
	struct coding_packet *decoding_packet;

	/* We only handle unicast packets */
	if (unicast_packet->packet_type != BAT_UNICAST)
		return;

	decoding_skb = skb_clone(skb, GFP_ATOMIC);

	if (!decoding_skb)
		return;

	decoding_packet = kzalloc(sizeof(struct coding_packet), GFP_ATOMIC);

	if (!decoding_packet)
		goto free_skb;

	atomic_set(&decoding_packet->refcount, 1);
	decoding_packet->timestamp = jiffies;
	decoding_packet->id = unicast_packet->decoding_id;
	decoding_packet->skb = decoding_skb;

	hash_added = hash_add(bat_priv->decoding_hash, compare_coding,
			      choose_coding, decoding_packet,
			      &decoding_packet->hash_entry);
	if (hash_added < 0)
		goto free_decoding_packet;

	return;

free_decoding_packet:
	kfree(decoding_packet);

free_skb:
	dev_kfree_skb(decoding_skb);
}

static inline int purge_decoding_packet(struct coding_packet *decoding_packet)
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
	struct coding_packet *decoding_packet;
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
				coding_packet_free_ref(decoding_packet);
				atomic_dec(&bat_priv->coding_hash_count);
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

	_purge_decoding(bat_priv);
	start_coding_timer(bat_priv);
}

void coding_free(struct bat_priv *bat_priv)
{
	struct hashtable_t *decoding_hash = bat_priv->decoding_hash;
	struct hashtable_t *coding_hash = bat_priv->coding_hash;
	struct hlist_node *node, *node_tmp;
	struct hlist_head *head;
	spinlock_t *list_lock; /* spinlock to protect write access */
	struct coding_packet *decoding_packet;
	struct coding_packet *coding_packet;
	int i;

	if (!decoding_hash || !coding_hash)
		return;

	printk(KERN_DEBUG "Starting coding_packet deletion\n");
	cancel_delayed_work_sync(&bat_priv->decoding_work);
	kthread_stop(bat_priv->coding_thread);

	for (i = 0; i < decoding_hash->size; i++) {
		head = &decoding_hash->table[i];
		list_lock = &decoding_hash->list_locks[i];

		spin_lock_bh(list_lock);
		hlist_for_each_entry_safe(decoding_packet, node, node_tmp,
					  head, hash_entry) {
			hlist_del_rcu(node);
			coding_packet_free_ref(decoding_packet);
		}
		spin_unlock_bh(list_lock);
	}

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

	hash_destroy(decoding_hash);
	hash_destroy(coding_hash);
}
