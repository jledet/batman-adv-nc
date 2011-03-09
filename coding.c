#include "main.h"
#include "coding.h"

int coding_init(struct bat_priv *bat_priv)
{

	return 1;
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
			printk(KERN_DEBUG "Coding neighbor exists\n");
			break;
		}
	}
	rcu_read_unlock();

	return ret;
}

int add_coding_node(struct orig_node *orig_node,
		struct orig_node *neigh_orig_node)
{
	struct coding_node *coding_node = kmalloc(sizeof(struct coding_node), GFP_ATOMIC);
	if (!coding_node)
		return -1;

	memcpy(coding_node->addr, neigh_orig_node->orig, ETH_ALEN);
	coding_node->orig_node = neigh_orig_node;

	spin_lock_bh(&orig_node->coding_list_lock);
	hlist_add_head_rcu(&coding_node->list, &orig_node->coding_list);
	spin_unlock_bh(&orig_node->coding_list_lock);

	return 0;
}

void coding_orig_neighbor(struct bat_priv *bat_priv,
		struct orig_node *orig_node,
		struct orig_node *neigh_orig_node)
{
	char neigh_mac[18];
	char orig_mac[18];

	pretty_mac(neigh_mac, neigh_orig_node->orig);
	pretty_mac(orig_mac, orig_node->orig);

	printk(KERN_DEBUG "WOMBAT: neighbor %s knows %s\n",
			neigh_mac, orig_mac);

	if (!orig_has_neighbor(orig_node, neigh_orig_node)) {
		printk(KERN_DEBUG "WOMBAT: Adding coding neighbor\n");
		if (add_coding_node(orig_node, neigh_orig_node) < 0) {
			printk(KERN_DEBUG "Adding coding node failed\n");
		}
	}
}
