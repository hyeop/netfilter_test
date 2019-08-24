#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include "net_header.h"
#include <libnetfilter_queue/libnetfilter_queue.h>

const char * filter;
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data);

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
    printf("\n\n");
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb, struct nfq_q_handle *qh, char * filter)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    dump(data, ret);
    //char * packet = &data;
    struct ip_header * ip_pack = (struct ip_header *)data;
    int8_t ip_size = (ip_pack->vhl & 0x0F)* 4;
    int16_t ip_total = ntohs(ip_pack->total_length);
    if(ip_pack->protocol == 0x6){
        struct tcp_header * tcp_pack = (struct tcp_header *)(data+ip_size);
        int8_t tcp_size = (tcp_pack->hlen_res & 0xF0)>>2;

        printf("i_total : %d  ip_header :  %d  tcp_header : %d\n", ip_total, ip_size, tcp_size);
        if( ip_total > (ip_size + tcp_size)){
            if(tcp_pack->dest_port == ntohs(0x50)){
                char * res = (char *)malloc(ip_total);
                memcpy(res, (char *)tcp_pack + tcp_size, ip_total);
                printf("%s", (char *)tcp_pack + tcp_size);

                char * server_name;
                strtok(res, ":");
                server_name = strtok(NULL, "\x0d");
                free(res);
                if(!strcmp(&server_name[1], filter)){
                    printf("AAAAA");
                    return id * -1;
                }
            }
        }
    }
    printf("protocol : %d\n", ip_pack->protocol);
    printf("payload_len=%d\n ", ret);
    fputc('\n', stdout);

    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa, qh, filter);
    if(id < 0){
        id = id * -1;
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }else{
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    printf("entering callback\n");

}


int main(int argc, char * argv[])
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    filter = argv[1];
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    if(argc != 2){
        printf("usage : netfilter_test [ site ]\n");
        exit(1);
    }

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);


    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
