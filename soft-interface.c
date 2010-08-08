/*
 * Copyright (C) 2007-2010 B.A.T.M.A.N. contributors:
 *
 * Marek Lindner, Simon Wunderlich
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */

#include "main.h"
#include "soft-interface.h"
#include "hard-interface.h"
#include "translation-table.h"
#include "gateway_client.h"
#include "send.h"
#include <linux/slab.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include "compat.h"
#include "unicast.h"

static uint32_t bcast_seqno = 1; /* give own bcast messages seq numbers to avoid
				  * broadcast storms */

unsigned char main_if_addr[ETH_ALEN];
static int bat_get_settings(struct net_device *dev, struct ethtool_cmd *cmd);
static void bat_get_drvinfo(struct net_device *dev,
			    struct ethtool_drvinfo *info);
static u32 bat_get_msglevel(struct net_device *dev);
static void bat_set_msglevel(struct net_device *dev, u32 value);
static u32 bat_get_link(struct net_device *dev);
static u32 bat_get_rx_csum(struct net_device *dev);
static int bat_set_rx_csum(struct net_device *dev, u32 data);

static const struct ethtool_ops bat_ethtool_ops = {
	.get_settings = bat_get_settings,
	.get_drvinfo = bat_get_drvinfo,
	.get_msglevel = bat_get_msglevel,
	.set_msglevel = bat_set_msglevel,
	.get_link = bat_get_link,
	.get_rx_csum = bat_get_rx_csum,
	.set_rx_csum = bat_set_rx_csum
};

void set_main_if_addr(uint8_t *addr)
{
	memcpy(main_if_addr, addr, ETH_ALEN);
}

int my_skb_head_push(struct sk_buff *skb, unsigned int len)
{
	int result;

	/**
	 * TODO: We must check if we can release all references to non-payload
	 * data using skb_header_release in our skbs to allow skb_cow_header to
	 * work optimally. This means that those skbs are not allowed to read
	 * or write any data which is before the current position of skb->data
	 * after that call and thus allow other skbs with the same data buffer
	 * to write freely in that area.
	 */
	result = skb_cow_head(skb, len);

	if (result < 0)
		return result;

	skb_push(skb, len);
	return 0;
}

static int interface_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}

static int interface_release(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

static struct net_device_stats *interface_stats(struct net_device *dev)
{
	struct bat_priv *priv = netdev_priv(dev);
	return &priv->stats;
}

static int interface_set_mac_addr(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	/* only modify hna-table if it has been initialised before */
	if (atomic_read(&module_state) == MODULE_ACTIVE) {
		hna_local_remove(dev->dev_addr, "mac address changed");
		hna_local_add(addr->sa_data);
	}

	memcpy(dev->dev_addr, addr->sa_data, ETH_ALEN);

	return 0;
}

static int interface_change_mtu(struct net_device *dev, int new_mtu)
{
	/* check ranges */
	if ((new_mtu < 68) || (new_mtu > hardif_min_mtu()))
		return -EINVAL;

	dev->mtu = new_mtu;

	return 0;
}

int interface_tx(struct sk_buff *skb, struct net_device *dev)
{
	struct ethhdr *ethhdr = (struct ethhdr *)skb->data;
	struct bat_priv *bat_priv = netdev_priv(dev);
	struct bcast_packet *bcast_packet;
	int data_len = skb->len, ret;
	bool bcast_dst = false, do_bcast = true;

	if (atomic_read(&module_state) != MODULE_ACTIVE)
		goto dropped;

	dev->trans_start = jiffies;
	/* TODO: check this for locks */
	hna_local_add(ethhdr->h_source);

	if (is_bcast(ethhdr->h_dest) || is_mcast(ethhdr->h_dest))
		bcast_dst = true;

	if ((bcast_dst) && gw_is_target(bat_priv, skb))
		do_bcast = false;

	/* ethernet packet should be broadcasted */
	if (bcast_dst && do_bcast) {
		if (my_skb_head_push(skb, sizeof(struct bcast_packet)) < 0)
			goto dropped;

		bcast_packet = (struct bcast_packet *)skb->data;
		bcast_packet->version = COMPAT_VERSION;
		bcast_packet->ttl = TTL;

		/* batman packet type: broadcast */
		bcast_packet->packet_type = BAT_BCAST;

		/* hw address of first interface is the orig mac because only
		 * this mac is known throughout the mesh */
		memcpy(bcast_packet->orig, main_if_addr, ETH_ALEN);

		/* set broadcast sequence number */
		bcast_packet->seqno = htonl(bcast_seqno);

		/* broadcast packet. on success, increase seqno. */
		if (add_bcast_packet_to_list(skb) == NETDEV_TX_OK)
			bcast_seqno++;

		/* a copy is stored in the bcast list, therefore removing
		 * the original skb. */
		kfree_skb(skb);

	/* unicast packet */
	} else {
		ret = unicast_send_skb(skb, bat_priv);
		if (ret != 0) {
			bat_priv->stats.tx_dropped++;
			goto end;
		}
	}

	bat_priv->stats.tx_packets++;
	bat_priv->stats.tx_bytes += data_len;
	goto end;

dropped:
	bat_priv->stats.tx_dropped++;
	kfree_skb(skb);
end:
	return NETDEV_TX_OK;
}

void interface_rx(struct sk_buff *skb, int hdr_size)
{
	struct net_device *dev = soft_device;
	struct bat_priv *priv = netdev_priv(dev);

	/* check if enough space is available for pulling, and pull */
	if (!pskb_may_pull(skb, hdr_size)) {
		kfree_skb(skb);
		return;
	}
	skb_pull_rcsum(skb, hdr_size);
/*	skb_set_mac_header(skb, -sizeof(struct ethhdr));*/

	skb->dev = dev;
	skb->protocol = eth_type_trans(skb, dev);

	/* should not be neccesary anymore as we use skb_pull_rcsum()
	 * TODO: please verify this and remove this TODO
	 * -- Dec 21st 2009, Simon Wunderlich */

/*	skb->ip_summed = CHECKSUM_UNNECESSARY;*/

	/* TODO: set skb->pkt_type to PACKET_BROADCAST, PACKET_MULTICAST,
	 * PACKET_OTHERHOST or PACKET_HOST */

	priv->stats.rx_packets++;
	priv->stats.rx_bytes += skb->len;

	dev->last_rx = jiffies;

	netif_rx(skb);
}

#ifdef HAVE_NET_DEVICE_OPS
static const struct net_device_ops bat_netdev_ops = {
	.ndo_open = interface_open,
	.ndo_stop = interface_release,
	.ndo_get_stats = interface_stats,
	.ndo_set_mac_address = interface_set_mac_addr,
	.ndo_change_mtu = interface_change_mtu,
	.ndo_start_xmit = interface_tx,
	.ndo_validate_addr = eth_validate_addr
};
#endif

void interface_setup(struct net_device *dev)
{
	struct bat_priv *priv = netdev_priv(dev);
	char dev_addr[ETH_ALEN];

	ether_setup(dev);

#ifdef HAVE_NET_DEVICE_OPS
	dev->netdev_ops = &bat_netdev_ops;
#else
	dev->open = interface_open;
	dev->stop = interface_release;
	dev->get_stats = interface_stats;
	dev->set_mac_address = interface_set_mac_addr;
	dev->change_mtu = interface_change_mtu;
	dev->hard_start_xmit = interface_tx;
#endif
	dev->destructor = free_netdev;

	dev->mtu = ETH_DATA_LEN;	/* can't call min_mtu, because the
					 * needed variables have not been
					 * initialized yet */
	dev->hard_header_len = BAT_HEADER_LEN; /* reserve more space in the
						* skbuff for our header */

	/* generate random address */
	random_ether_addr(dev_addr);
	memcpy(dev->dev_addr, dev_addr, ETH_ALEN);

	SET_ETHTOOL_OPS(dev, &bat_ethtool_ops);

	memset(priv, 0, sizeof(struct bat_priv));
}

/* ethtool */
static int bat_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	cmd->supported = 0;
	cmd->advertising = 0;
	cmd->speed = SPEED_10;
	cmd->duplex = DUPLEX_FULL;
	cmd->port = PORT_TP;
	cmd->phy_address = 0;
	cmd->transceiver = XCVR_INTERNAL;
	cmd->autoneg = AUTONEG_DISABLE;
	cmd->maxtxpkt = 0;
	cmd->maxrxpkt = 0;

	return 0;
}

static void bat_get_drvinfo(struct net_device *dev,
			    struct ethtool_drvinfo *info)
{
	strcpy(info->driver, "B.A.T.M.A.N. advanced");
	strcpy(info->version, SOURCE_VERSION);
	strcpy(info->fw_version, "N/A");
	strcpy(info->bus_info, "batman");
}

static u32 bat_get_msglevel(struct net_device *dev)
{
	return -EOPNOTSUPP;
}

static void bat_set_msglevel(struct net_device *dev, u32 value)
{
}

static u32 bat_get_link(struct net_device *dev)
{
	return 1;
}

static u32 bat_get_rx_csum(struct net_device *dev)
{
	return 0;
}

static int bat_set_rx_csum(struct net_device *dev, u32 data)
{
	return -EOPNOTSUPP;
}
