#include "../lp13-parentI3/parentI3_head.c"
#include "seam_gi_sha1.c"
#include "seam_gi_sha256_group14.c"
#include "seam_ikev2_sendI1.c"
#include "oswconf.h"
#include "seam_x509_list.c"
#include "seam_host_peerA.c"
#include "seam_rsasig.c"
#include "seam_finish.c"

#define TESTNAME "peerA-rekeyR1"

static void init_local_interface(void)
{
    init_peerA_interface();
}

static void init_fake_secrets(void)
{
    prompt_pass_t pass;
    memset(&pass, 0, sizeof(pass));
    osw_init_ipsecdir_str(SAMPLEDIR "davecert");

    rnd_offset = 13;

    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , SAMPLEDIR "davecert.secrets"
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

#define PCAP_INPUT_COUNT 4
#include "seam_parentI2.c"

void recv_pcap_packet_with_rekey(u_char *user
                               , const struct pcap_pkthdr *h
                               , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    DBG_log("initial rekey results\n");
    show_connections_status(NULL);
    show_states_status();
    timer_list();

    DBG_log("packet 3 -- rekey starting\n");
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
    recv_pcap_packet,
    recv_pcap_packet,
    recv_pcap_packet_with_rekey,
    recv_pcap_packet,
};

#include "../lp13-parentI3/parentI3_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
