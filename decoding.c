#include "main.h"
#include "decoding.h"
#include "coding.h"
#include "send.h"
#include "originator.h"
#include "hash.h"

static void purge_decoding(struct work_struct *work);

static void start_decoding_timer(struct bat_priv *bat_priv)
{
	INIT_DELAYED_WORK(&bat_priv->decoding_work, purge_decoding);
	queue_delayed_work(bat_event_workqueue, &bat_priv->decoding_work, 1 * HZ);
}

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

uint16_t get_decoding_id(struct bat_priv *bat_priv)
{
	return (uint16_t)atomic_inc_return(&bat_priv->last_decoding_id);
}

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
	uint8_t *byte1, *byte2;

	memcpy(&coded_packet_tmp, skb->data, sizeof(struct coded_packet));
	memcpy(&ethhdr_tmp, skb_mac_header(skb), sizeof(struct ethhdr));

	if (skb_cow(skb, 0) < 0) {
		printk(KERN_DEBUG "WOMBAT: skb_cow failed\n");
		return NULL;
	}                                                                                                                                                                                                                                                                                           

	if (unlikely(!skb_pull_rcsum(skb, header_diff))) {
		printk(KERN_DEBUG "WOMBAT: skb_pull_rcsum failed\n");
		return NULL;
	}

	/* Realign mac header */
	skb_set_mac_header(skb, -ETH_HLEN);
	ethhdr = (struct ethhdr *)skb_mac_header(skb);
	memcpy(ethhdr, &ethhdr_tmp, sizeof(struct ethhdr));

	if (is_my_mac(coded_packet_tmp.second_dest)) {
		memcpy(ethhdr->h_dest, coded_packet_tmp.second_dest, ETH_ALEN);
		skb_trim(skb, coded_packet_tmp.second_len + header_size);
		orig_dest = coded_packet_tmp.second_orig_dest;
		ttl = coded_packet_tmp.second_ttl;
		id = coded_packet_tmp.second_id;
	} else {
		orig_dest = coded_packet_tmp.first_orig_dest;
		ttl = coded_packet_tmp.first_ttl;
		id = coded_packet_tmp.first_id;
	}

	memxor(skb->data + header_size,
			decoding_packet->skb->data + header_size,
			ntohs(coded_packet_tmp.second_len));

	/* Setup decoded unicast packet */
	unicast_packet = (struct unicast_packet *)skb->data;
	unicast_packet->packet_type = BAT_UNICAST;
	unicast_packet->version = COMPAT_VERSION;
	memcpy(unicast_packet->dest, orig_dest, ETH_ALEN);
	unicast_packet->ttl = ttl;
	unicast_packet->decoding_id = id;

	byte1 = skb->data + header_size;
	byte2 = decoding_packet->skb->data + header_size;

	printk(KERN_DEBUG "CW: Decoded: %hu xor %hu (%02x xor %02x)\n",
			unicast_packet->decoding_id, decoding_packet->id,
			*byte1, *byte2);

	return unicast_packet;
}

struct coding_packet *find_decoding_packet(struct bat_priv *bat_priv,
		struct sk_buff *skb)
{
	struct hashtable_t *hash = bat_priv->decoding_hash;
	struct hlist_node *hnode;
	spinlock_t *list_lock;
	struct coded_packet *coded_packet =
		(struct coded_packet *)skb->data;
	struct coding_packet *decoding_packet, *decoding_packet_tmp;
	struct coding_path *coding_path;
	uint8_t *dest, *source;
	uint16_t id;
	struct ethhdr *ethhdr = (struct ethhdr *)skb_mac_header(skb);
	uint8_t hash_key[6];
	int index, i;

	if (!hash)
		return NULL;

	if (!is_my_mac(coded_packet->second_dest)) {
		dest = ethhdr->h_source;
		source = coded_packet->second_source;
		id = coded_packet->second_id;
	} else {
		dest = ethhdr->h_source;
		source = coded_packet->first_source;
		id = coded_packet->first_id;
	}

	printk(KERN_DEBUG "CW: Received packet: %hu xor %hu\n",
			coded_packet->first_id, coded_packet->second_id);

	/* TODO: Include id in hash_key */
	for (i = 0; i < ETH_ALEN; ++i)
		hash_key[i] = dest[i] ^ source[i];

	index = choose_coding(hash_key, hash->size);
	list_lock = &hash->list_locks[index];

	/* Search for matching decoding_packet */
	spin_lock_bh(list_lock);
	hlist_for_each_entry(coding_path, hnode, &hash->table[index],
			hash_entry) {
		if (!compare_eth(dest, coding_path->next_hop))                                                                                                    
			continue;

		if (!compare_eth(source, coding_path->prev_hop))
			continue;
		
		spin_lock_bh(&coding_path->packet_list_lock);
		list_for_each_entry_safe(decoding_packet, decoding_packet_tmp, 
				&coding_path->packet_list, list) {
			if (id != decoding_packet->id)
				continue;
			goto out;
		}
		spin_unlock_bh(&coding_path->packet_list_lock);
	}
	spin_unlock_bh(list_lock);

	printk(KERN_DEBUG "WOMBAT: No decoding packet found\n");
	return NULL;

out:
	atomic_dec(&bat_priv->decoding_hash_count);
	list_del_rcu(&decoding_packet->list);
	spin_unlock_bh(&coding_path->packet_list_lock);
	spin_unlock_bh(list_lock);
	printk(KERN_DEBUG "CW: Found decoding id %hu\n", decoding_packet->id);
	return decoding_packet;
}

struct unicast_packet *receive_coded_packet(struct bat_priv *bat_priv,
		struct sk_buff *skb, int hdr_size)
{
	struct coding_packet *decoding_packet =
		find_decoding_packet(bat_priv, skb);
	struct unicast_packet *unicast_packet;

	if (!decoding_packet)
		return NULL;

	unicast_packet = decode_packet(skb, decoding_packet);
	coding_packet_free_ref(decoding_packet);

	if (!unicast_packet)
		return NULL;

	return unicast_packet;
}

void add_decoding_skb(struct hard_iface *hard_iface, struct sk_buff *skb)
{
	struct bat_priv *bat_priv = netdev_priv(hard_iface->soft_iface);
	struct unicast_packet *unicast_packet =
		(struct unicast_packet *)skb_network_header(skb);
	struct coding_packet *decoding_packet;
	struct coding_path *decoding_path;
	struct ethhdr *ethhdr = (struct ethhdr *)skb_mac_header(skb);

	/* We only handle unicast packets */
	if (unicast_packet->packet_type != BAT_UNICAST)
		return;

	decoding_packet = kzalloc(sizeof(struct coding_packet), GFP_ATOMIC);

	if (!decoding_packet)
		return;

	decoding_path = get_coding_path(bat_priv, ethhdr->h_source,
			ethhdr->h_dest);

	if (!decoding_path)
		goto free_decoding_packet;

	/* Adjust skb-data to point at batman-packet */
	skb_pull_rcsum(skb, ETH_HLEN);

	atomic_set(&decoding_packet->refcount, 1);
	decoding_packet->timestamp = jiffies;
	decoding_packet->id = unicast_packet->decoding_id;
	decoding_packet->skb = skb;

	/* Add coding packet to list */
	spin_lock_bh(&decoding_path->packet_list_lock);
	list_add_tail_rcu(&decoding_packet->list, &decoding_path->packet_list);
	spin_unlock_bh(&decoding_path->packet_list_lock);

	atomic_inc(&bat_priv->decoding_hash_count);

	return;

free_decoding_packet:
	kfree(decoding_packet);
}

static inline int decoding_packet_timeout(struct coding_packet *decoding_packet)
{
	return time_is_before_jiffies(
			decoding_packet->timestamp + DECODING_TIMEOUT * HZ);
}

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
				if (decoding_packet_timeout(decoding_packet)) {
					list_del_rcu(&decoding_packet->list);
					coding_packet_free_ref(decoding_packet);
					atomic_dec(&bat_priv->decoding_hash_count);
				}
			}
			spin_unlock_bh(&decoding_path->packet_list_lock);
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
	start_decoding_timer(bat_priv);
}

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


