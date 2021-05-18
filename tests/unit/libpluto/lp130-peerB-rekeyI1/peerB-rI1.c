#include "../lp12-parentR2/parentR2_head.c"
#include "seam_natt.c"
#include "seam_host_peerB.c"
#include "seam_x509_list.c"
#include "seam_gi_sha256_group14.c"
#include "seam_ikev2_sendI1.c"
#include "seam_finish.c"
#include "seam_kernel.c"

#define TESTNAME "peerA-rI1"
#include "../lp122-peerB-R1/peerB.c"

#define PCAP_INPUT_COUNT 2
extern void key_peerA(const char *pcap_out);
#define AFTER_CONN() key_peerA(pcap_out)
#include "seam_parentR2v2.c"
recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet_with_ke,
    recv_pcap_packet2_with_ke,
};

#include "../lp12-parentR2/parentR2_main.c"
#include "../lp130-peerB-rekeyI1/keyPeerA.c"

void key_peerA(const char *pcap_out)
{
    /* close pcap file from before */
    finish_pcap();

    /* open it again, to just get this packet */
    DBG_log("%u: output to %s\n", 3, pcap_out);
    send_packet_setup_pcap(pcap_out);

    DBG_log("now re-keying to peerA\n");
    show_states_status();

    rekey_to_peerA();
    send_packet_close();
}

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
