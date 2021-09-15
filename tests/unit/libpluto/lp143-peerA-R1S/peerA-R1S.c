#define GLOBAL_TWEAK 0xe0

#include "../lp13-parentI3/parentI3_head.c"
#include "seam_gi_sha256_group14.c"
#include "seam_ikev2_sendI1n.c"
#include "oswconf.h"
#include "seam_x509_list.c"
#include "seam_host_peerA.c"
#include "seam_rsasig.c"
#include "seam_finish.c"

#define TESTNAME "peerA-I1S"

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

#define PCAP_INPUT_COUNT 1

#include "seam_parentR2v2.c"

recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet_with_ke,
};

#include "../lp13-parentI3/parentI3_main.c"


 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
