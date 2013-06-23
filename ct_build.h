#include "wl_def.h"

#define CONN_MAX 255		/* We will hardly have more than 255 guys */

/*
int ct_list_append(int id, in_addr_t saddr, in_addr_t daddr, uint16_t sport, uint16_t dport, uint8_t proto);
*/
int ct_list_append(int id, struct nf_conntrack *ct, char *saddr, char *daddr, char *sport, char *dport);
struct conntrack_t *ct_list_get(int n);
void ct_list_random(void);
void ct_remove_from_id(int id);

