#include "../lp12-parentR2/parentR2_head.c"
#include "seam_natt.c"
#include "seam_host_peerB.c"
#include "seam_x509_list.c"
#include "seam_gi_sha256_group14.c"
#include "seam_ikev2_sendI1.c"
#include "seam_finish.c"
#include "seam_kernel.c"

#define TESTNAME "peerA-rI2"
#include "../lp122-peerB-R1/peerB.c"

#define PCAP_INPUT_COUNT 3
extern void key_peerA(const char *pcap_out);

#include "seam_parentR2v2.c"
#include "../lp130-peerB-rekeyI1/keyPeerA.c"

void recv_pcap_packet_rekeyA(u_char *user
                             , const struct pcap_pkthdr *h
                             , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);
    run_one_continuation(crypto_req);

    rekey_to_peerA();

#if 0
    /* close pcap file from before */
    finish_pcap();

    /* open it again, to just get this packet */
    const char *pcap_out = "OUTPUT/peerB-rI2.pcap";
    DBG_log("%u: output to %s\n", 4, pcap_out);
    send_packet_setup_pcap(pcap_out);
#endif

}

void recv_pcap_packet_rekeyA2(u_char *user
		      , const struct pcap_pkthdr *h
		      , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);

    /* find st involved */
    st = state_with_serialno(3);
    if(st) {
        st->st_connection->extra_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;

        /* now fill in the KE values from a constant.. not calculated */
        clonetowirechunk(&kn->thespace, kn->space, &kn->n,   SS(nr.ptr), SS(nr.len));
        clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  SS(gr.ptr), SS(gr.len));

        run_one_continuation(crypto_req);
    }
}

recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet_with_ke,
    recv_pcap_packet_rekeyA,
    recv_pcap_packet_rekeyA2,
};

#include "../lp12-parentR2/parentR2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
