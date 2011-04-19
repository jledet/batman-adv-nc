#ifndef _NET_BATMAN_ADV_DECODING_H
#define _NET_BATMAN_ADV_DECODING_H

#define DECODING_TIMEOUT 100 /* milliseconds */

int decoding_init(struct bat_priv *bat_priv);
void decoding_free(struct bat_priv *bat_priv);
struct unicast_packet *receive_coded_packet(struct bat_priv *bat_priv,
		struct sk_buff *skb, int hdr_size);
uint16_t get_decoding_id(struct bat_priv *bat_priv);
void add_decoding_skb(struct hard_iface *hard_iface, struct sk_buff *skb);

#endif /* _NET_BATMAN_ADV_DECODING_H */
