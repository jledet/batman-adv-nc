#include "main.h"
#include "decoding.h"
#include "coding.h"
#include "send.h"
#include "originator.h"
#include "hash.h"
#include <linux/netdevice.h>
#include <net/sch_generic.h>
#include <linux/rtnetlink.h>

static void purge_decoding(struct work_struct *work);

static void start_decoding_timer(struct bat_priv *bat_priv)
{
	INIT_DELAYED_WORK(&bat_priv->decoding_work, purge_decoding);
	queue_delayed_work(bat_event_workqueue, &bat_priv->decoding_work, 1 * HZ);
}

/* Init decoding packet hash table, start purge delayed work */ 
int decoding_init(struct bat_priv *bat_priv)
{
	if (bat_priv->decoding_hash)
		return 0;

	atomic_set(&bat_priv->coding_hash_count, 0);
	bat_priv->decoding_hash = hash_new(1024);
	atomic_set(&bat_priv->last_decoding_id, 1);

	if (!bat_priv->decoding_hash)
		return -1;

	start_decoding_timer(bat_priv);

	return 0;
}

/* Get next available decoding id */
uint16_t get_decoding_id(struct bat_priv *bat_priv)
{
	return (uint16_t)atomic_inc_return(&bat_priv->last_decoding_id);
}

/* Decode coded packet in skb with decoding_packet */
struct unicast_packet *decode_packet(struct sk_buff *skb,
		struct coding_packet *decoding_packet)
{
	const int header_diff = sizeof(struct coded_packet) -
		sizeof(struct unicast_packet);
	const int header_size = sizeof(struct unicast_packet);
	struct unicast_packet *unicast_packet;
	struct coded_packet coded_packet_tmp;
	struct ethhdr *ethhdr, ethhdr_tmp;
	uint8_t *orig_dest, ttl;
	uint16_t id;
	unsigned int coding_len;

	memcpy(&coded_packet_tmp, skb->data, sizeof(struct coded_packet));
	memcpy(&ethhdr_tmp, skb_mac_header(skb), sizeof(struct ethhdr));

	if (skb_cow(skb, 0) < 0) {
		printk(KERN_DEBUG "CW: skb_cow failed\n");
		return NULL;
	}

	if (unlikely(!skb_pull_rcsum(skb, header_diff))) {
		printk(KERN_DEBUG "CW: skb_pull_rcsum failed\n");
		return NULL;
	}

	/* Realign mac header */
	skb_set_mac_header(skb, -ETH_HLEN);
	ethhdr = (struct ethhdr *)skb_mac_header(skb);
	memcpy(ethhdr, &ethhdr_tmp, sizeof(struct ethhdr));

	/* Read unicast attributes */
	if (is_my_mac(coded_packet_tmp.second_dest)) {
		/* If we are the second destination the packet was overheard,
		 * so the Ethernet address must be copied to h_dest and 
		 * pkt_type changed from PACKET_OTHERHOST to PACKET_HOST */
		memcpy(ethhdr->h_dest, coded_packet_tmp.second_dest, ETH_ALEN);
		skb->pkt_type = PACKET_HOST;

		orig_dest = coded_packet_tmp.second_orig_dest;
		ttl = coded_packet_tmp.second_ttl;
		id = coded_packet_tmp.second_id;
	} else {
		orig_dest = coded_packet_tmp.first_orig_dest;
		ttl = coded_packet_tmp.first_ttl;
		id = coded_packet_tmp.first_id;
	}

	coding_len = ntohs(coded_packet_tmp.coded_len);

	/* Here the magic is reversed:
	 *   extract the missing packet from the received coded packet */
	memxor(skb->data + header_size,
			decoding_packet->skb->data + header_size,
			coding_len);

	/* Resize decoded skb if decoded with larger packet */
	if (decoding_packet->skb->len > coding_len + header_size)
		pskb_trim_rcsum(skb, coding_len + header_size);

	/* Create decoded unicast packet */
	unicast_packet = (struct unicast_packet *)skb->data;
	unicast_packet->packet_type = BAT_UNICAST;
	unicast_packet->version = COMPAT_VERSION;
	memcpy(unicast_packet->dest, orig_dest, ETH_ALEN);
	unicast_packet->ttl = ttl;
	unicast_packet->decoding_id = id;

	/*
	printk(KERN_DEBUG "CW: Decoded: %hu xor %hu\n",
			unicast_packet->decoding_id, decoding_packet->id);
	*/

	return unicast_packet;
}

/* Find necessary packet for decoding skb */
struct coding_packet *find_decoding_packet(struct bat_priv *bat_priv,
					   struct sk_buff *skb)
{
	struct hashtable_t *hash = bat_priv->decoding_hash;
	struct hlist_node *hnode;
	struct coded_packet *coded_packet = (struct coded_packet *)skb->data;
	struct coding_packet *decoding_packet;
	struct coding_path *coding_path;
	uint8_t *dest, *source;
	uint16_t id;
	struct ethhdr *ethhdr = (struct ethhdr *)skb_mac_header(skb);
	uint8_t hash_key[6];
	int index, i;

	if (!hash)
		return NULL;

	dest = ethhdr->h_source;
	if (!is_my_mac(coded_packet->second_dest)) {
		source = coded_packet->second_source;
		id = coded_packet->second_id;
	} else {
		source = coded_packet->first_source;
		id = coded_packet->first_id;
	}

	/* TODO: Include id in hash_key */
	for (i = 0; i < ETH_ALEN; ++i)
		hash_key[i] = source[i] ^ dest[ETH_ALEN-1-i];

	index = choose_coding(hash_key, hash->size);

	/* Search for matching coding path */
	rcu_read_lock();
	hlist_for_each_entry_rcu(coding_path, hnode, &hash->table[index],
			hash_entry) {
		if (!compare_eth(dest, coding_path->next_hop))
			continue;

		if (!compare_eth(source, coding_path->prev_hop))
			continue;
		
		/* Find matching decoding_packet */
		list_for_each_entry_rcu(decoding_packet,
					&coding_path->packet_list, list) {
			if (id == decoding_packet->id) {
				atomic_dec(&bat_priv->decoding_hash_count);
				spin_lock_bh(&coding_path->packet_list_lock);
				list_del_rcu(&decoding_packet->list);
				spin_unlock_bh(&coding_path->packet_list_lock);
				rcu_read_unlock();
				return decoding_packet;
			}
		}
	}
	rcu_read_unlock();

	printk(KERN_DEBUG "CW: No decoding packet found for %d\n", id);
	return NULL;
}

/* Attempt to decode coded packet and return decoded unicast packet */
struct unicast_packet *receive_coded_packet(struct bat_priv *bat_priv,
		struct sk_buff *skb, int hdr_size)
{
	struct unicast_packet *unicast_packet;
	struct coding_packet *decoding_packet =
		find_decoding_packet(bat_priv, skb);

	if (!decoding_packet)
		return NULL;

	unicast_packet = decode_packet(skb, decoding_packet);
	coding_packet_free_ref(decoding_packet);

	return unicast_packet;
}

/* Add decoding skb to pool */
void add_decoding_skb(struct hard_iface *hard_iface, struct sk_buff *skb)
{
	struct bat_priv *bat_priv = netdev_priv(hard_iface->soft_iface);
	struct unicast_packet *unicast_packet =
		(struct unicast_packet *)skb->data;
	struct coding_packet *decoding_packet;
	struct coding_path *decoding_path;
	struct ethhdr *ethhdr = (struct ethhdr *)skb_mac_header(skb);

	/* We only handle unicast packets */
	if (unicast_packet->packet_type != BAT_UNICAST)
		goto free_skb;

	decoding_packet = kzalloc(sizeof(struct coding_packet), GFP_ATOMIC);

	if (!decoding_packet)
		goto free_skb;

	decoding_path = get_coding_path(bat_priv->decoding_hash,
			ethhdr->h_source, ethhdr->h_dest);

	if (!decoding_path)
		goto free_decoding_packet;

	atomic_set(&decoding_packet->refcount, 1);
	decoding_packet->timestamp = jiffies;
	decoding_packet->id = unicast_packet->decoding_id;
	decoding_packet->skb = skb;
	decoding_packet->coding_path = decoding_path;

	/* Add coding packet to list */
	spin_lock_bh(&decoding_path->packet_list_lock);
	list_add_tail_rcu(&decoding_packet->list, &decoding_path->packet_list);
	spin_unlock_bh(&decoding_path->packet_list_lock);

	atomic_inc(&bat_priv->decoding_hash_count);

	return;

free_decoding_packet:
	kfree(decoding_packet);
free_skb:
	dev_kfree_skb(skb);
}

/* Return true if decoding packet has timed out */
static inline int decoding_packet_timeout(struct bat_priv *bat_priv,
		struct coding_packet *decoding_packet)
{
	return time_is_before_jiffies(
			decoding_packet->timestamp + 
			(atomic_read(&bat_priv->catwoman_purge) * HZ) / MSEC_PER_SEC);
}

/* Purge decoding packets that have timed out */
static void _purge_decoding(struct bat_priv *bat_priv)
{
	struct hashtable_t *hash = bat_priv->decoding_hash;
	struct hlist_node *node;
	struct hlist_head *head;
	spinlock_t *list_lock; /* spinlock to protect write access */
	struct coding_packet *decoding_packet, *decoding_packet_tmp;
	struct coding_path *decoding_path;
	int i;

	if (!hash)
		return;

	for (i = 0; i < hash->size; i++) {
		head = &hash->table[i];
		list_lock = &hash->list_locks[i];

		spin_lock_bh(list_lock);
		hlist_for_each_entry(decoding_path, node, head, hash_entry) {
			spin_lock_bh(&decoding_path->packet_list_lock);
			list_for_each_entry_safe(decoding_packet, decoding_packet_tmp,
					&decoding_path->packet_list, list) {
				if (decoding_packet_timeout(bat_priv, decoding_packet)) {
					list_del_rcu(&decoding_packet->list);
					coding_packet_free_ref(decoding_packet);
					atomic_dec(&bat_priv->decoding_hash_count);
					printk(KERN_DEBUG "Decoding packet id %d purged", decoding_packet->id);
				}
			}
			spin_unlock_bh(&decoding_path->packet_list_lock);
		}
		spin_unlock_bh(list_lock);
	}
}

/* Run purge function and reschedule purge loop */
static void purge_decoding(struct work_struct *work)
{
	struct delayed_work *delayed_work =
		container_of(work, struct delayed_work, work);
	struct bat_priv *bat_priv =
		container_of(delayed_work, struct bat_priv, decoding_work);

	_purge_decoding(bat_priv);
	start_decoding_timer(bat_priv);
}

/* Cleanup all decoding packets */
void decoding_free(struct bat_priv *bat_priv)
{
	struct hashtable_t *decoding_hash = bat_priv->decoding_hash;
	struct hlist_node *node, *node_tmp;
	struct hlist_head *head;
	spinlock_t *list_lock; /* spinlock to protect write access */
	struct coding_packet *decoding_packet, *decoding_packet_tmp;
	struct coding_path *decoding_path;
	int i;

	if (!decoding_hash)
		return;

	printk(KERN_DEBUG "Starting decoding_packet deletion\n");
	cancel_delayed_work_sync(&bat_priv->decoding_work);

	for (i = 0; i < decoding_hash->size; i++) {
		head = &decoding_hash->table[i];
		list_lock = &decoding_hash->list_locks[i];

		spin_lock_bh(list_lock);
		hlist_for_each_entry_safe(decoding_path, node, node_tmp,
					  head, hash_entry) {
			hlist_del_rcu(node);
			spin_lock_bh(&decoding_path->packet_list_lock);
			list_for_each_entry_safe(decoding_packet, 
					decoding_packet_tmp, 
					&decoding_path->packet_list, list) {
				list_del_rcu(&decoding_packet->list);
				coding_packet_free_ref(decoding_packet);
			}
			spin_unlock_bh(&decoding_path->packet_list_lock);
			coding_path_free_ref(decoding_path);
		}
		spin_unlock_bh(list_lock);

	}

	hash_destroy(decoding_hash);
}

/* Update interface promiscuous mode from catwoman sysfs entry */
void update_promisc(struct net_device *soft_iface)
{
	int catwoman, promisc;
	struct net_device *hard_iface;
	struct bat_priv *bat_priv = netdev_priv(soft_iface);
		
	if (!bat_priv || !bat_priv->primary_if || !bat_priv->primary_if->net_dev)
		return;

	hard_iface = bat_priv->primary_if->net_dev;
	catwoman = atomic_read(&bat_priv->catwoman);
	promisc = atomic_read(&bat_priv->catwoman_promisc);

	if (catwoman != promisc) {
		rtnl_lock();
		dev_set_promiscuity(hard_iface, catwoman ? 1 : -1);
		rtnl_unlock();
		atomic_set(&bat_priv->catwoman_promisc, catwoman);
	}
}
