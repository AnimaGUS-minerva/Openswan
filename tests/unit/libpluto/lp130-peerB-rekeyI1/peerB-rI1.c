#include "../lp12-parentR2/parentR2_head.c"
#include "seam_natt.c"
#include "seam_host_peerB.c"
#include "seam_x509_list.c"
#include "seam_gi_sha256_group14.c"
#include "seam_ikev2_sendI1.c"
#include "seam_finish.c"
#include "seam_kernel.c"

#define TESTNAME "peerA-rI1"

static void init_local_interface(void)
{
    init_peerB_interface();
}

static void init_fake_secrets(void)
{
    prompt_pass_t pass;
    memset(&pass, 0, sizeof(pass));
    osw_init_ipsecdir_str(SAMPLEDIR "carol");

    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , SAMPLEDIR "carol.secrets"
			       , &pass, NULL);
}

static void init_loaded(void) {
    cur_debugging |= DBG_X509;

    oco = osw_init_options();

    /* loading X.509 CA certificates */
    load_authcerts("CA cert", oco->cacerts_dir, AUTH_CA);
    /* loading X.509 AA certificates */
    load_authcerts("AA cert", oco->aacerts_dir, AUTH_AA);
    /* loading X.509 OCSP certificates */
    load_authcerts("OCSP cert", oco->ocspcerts_dir, AUTH_OCSP);

    /* loading X.509 CRLs */
    load_crls();
    /* loading attribute certificates (experimental) */
    load_acerts();

    list_certs(1);

    list_authcerts("CA", AUTH_CA, 1);
}

#define PCAP_INPUT_COUNT 2
extern void key_peerA(const char *pcap_out);
#define AFTER_CONN() key_peerA(pcap_out)
#include "seam_parentR2v2.c"
recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet_with_ke,
    recv_pcap_packet2_with_ke,
};

#include "../lp12-parentR2/parentR2_main.c"

void key_peerA(const char *pcap_out)
{
    struct state *st = NULL;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;
    struct connection *c1;

    /* close pcap file */
    finish_pcap();

    /* open it again, to just get this packet */
    fprintf(stderr, "%u: output to %s\n", 3, pcap_out);
    send_packet_setup_pcap(pcap_out);

    fprintf(stderr, "now re-keying to peerA\n");
    show_states_status();

    timer_list();

    rnd_offset++;

    c1 = con_by_name("peerB--peerA", TRUE);
    st = sendI1(c1, DBG_CONTROL, TRUE);

    run_continuation(crypto_req);
    send_packet_close();
}

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
