/*
 * Connection tracking builder
 * for Wolfenstein 3d
 * (C) Sebastien Tricaud 2007
 *
 */

#include <stdlib.h>
#include "ct_build.h"

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>


/* int current = 0; */
struct conntrack_t *list[CONN_MAX];

static struct nfct_handle *h = NULL;

static actor_id;

void ct_list_clear(int destroy)
{
    unsigned int i;
    struct conntrack_t *entry;
    if (destroy) {
        for (i=0; i<CONN_MAX; i++) {
            entry = list[i];
            if (!entry)
                continue;
            nfct_destroy(entry->ct);
            free(entry->saddr);
            free(entry->daddr);
            free(entry->sport);
            free(entry->dport);
            free(entry);
        }
    }
    memset(list, 0, sizeof(list));
}

extern int
//ct_list_append(int id, in_addr_t saddr, in_addr_t daddr, uint16_t sport, uint16_t dport, uint8_t proto)
ct_list_append(int id, struct nf_conntrack *ct, char *saddr, char *daddr, char *sport, char *dport)
{

  struct conntrack_t *conntrack;

  conntrack = malloc(sizeof(*conntrack));
  conntrack->ct = ct;
  conntrack->saddr = saddr;
  conntrack->daddr = daddr;
  conntrack->sport = sport;
  conntrack->dport = dport;

  list[id] = conntrack;

  return 0;
}

extern struct conntrack_t *
ct_list_get(int n)
{
  return list[n];
}

/* Test function */
void ct_list_random(void)
{
        int valaddr = 0;
        int valsport = 0;
        int valdport = 0;
        char *saddr;
        char *daddr;
        char *sport;
        char *dport;
        int i = 0;

        int portlist[6] = {21,22,80,443,993,123};


        while ( i < CONN_MAX ) {

                srand(time(NULL));
                valaddr = 1 + (int) (210.0 * (rand() / (RAND_MAX + 1.0)));
                srand(time(NULL));
                valsport = 5042 + (int) (22000.0 * (rand() / (RAND_MAX + 1.0)));
                srand(time(NULL));
                valdport = 0 + (int) (5.0 * (rand() / (RAND_MAX + 1.0)));

                saddr = malloc(2048);
                daddr = malloc(2048);
                sport = malloc(2048);
                dport = malloc(2048);

                sprintf(saddr, "ip_source:192.168.1.%d", valaddr+45);
                sprintf(daddr, "ip_dest:192.168.1.%d", valaddr);
                sprintf(sport, "port_source:%d", valsport);
                sprintf(dport, "port_dest:%d", portlist[valdport]);

                ct_list_append(i, NULL, saddr, daddr, sport, dport);

                i++;
        }
}


static char *port_ntoa(uint16_t port)
{
        char *buf = malloc(16);
        sprintf(buf, "%d", htons(port));
        return buf;
}

static int actor_id_incr(void)
{
        actor_id++;
        if (actor_id >= CONN_MAX) actor_id = 0;
}

static int ct_cb(enum nf_conntrack_msg_type type,
                struct nf_conntrack *ct,
                void *data)
{
        uint32_t ip_src, ip_dst;
        uint16_t port_src, port_dst;
        char *saddr, *daddr, *sport, *dport;

        if (nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO) != AF_INET) {
            return NFCT_CB_CONTINUE;
        }

        ip_src = nfct_get_attr_u32(ct, ATTR_IPV4_SRC);
        saddr = strdup((const char*)inet_ntoa(ip_src));

        ip_dst = nfct_get_attr_u32(ct, ATTR_IPV4_DST);
        daddr = strdup((const char*)inet_ntoa(ip_dst));

        port_src = nfct_get_attr_u16(ct, ATTR_PORT_SRC);
        sport = port_ntoa(port_src);

        port_dst = nfct_get_attr_u16(ct, ATTR_PORT_DST);
        dport = port_ntoa(port_dst);

        while (ActorIdDead(actor_id)) {
                actor_id_incr();
        }
        ct_list_append(actor_id, ct, saddr, daddr, sport, dport);

        actor_id_incr();

        return NFCT_CB_STOLEN;
}

/*
 * The real function \o/
 * \\\\\\\\\\\///////////
 * Carmack: pay your cat!
 */
void ct_list_create(void)
{
        int ret;
        u_int8_t family = AF_INET;

        if (!player) return;

        ct_list_clear(h != NULL);

        if (!h) {
            h = nfct_open(CONNTRACK, 0);
            if (!h) {
                perror("nfct_open error: Oh my god! this is terrible! you cannot kill conntracks out from Netfilter!!");
                return;
            }
        }

        actor_id = 0;
        nfct_callback_register(h, NFCT_T_ALL, ct_cb, NULL);
        ret = nfct_query(h, NFCT_Q_DUMP, &family);
        if ( ret == -1 ) {
                perror("nfct_query error: Oh my god! this is terrible! you cannot kill conntracks out from Netfilter!!");
                exit(EXIT_FAILURE);
        }

}

void ct_close(void)
{
        nfct_close(h);
}

void ct_remove_from_id(int id)
{
        struct conntrack_t *entry;
        int res;
        entry = ct_list_get(id);
        if (!entry)
            return;
        res = nfct_query(h, NFCT_Q_DESTROY, entry->ct);
        if (res < 0) {
                fprintf(stderr, "Cannot destroy connection: error (%d)\n", res);
        }
}
