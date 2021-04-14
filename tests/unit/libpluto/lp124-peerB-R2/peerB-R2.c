#include "../lp12-parentR2/parentR2_head.c"
#include "seam_natt.c"
#include "seam_host_peerB.c"
#include "seam_x509_list.c"
#include "seam_gi_sha256_group14.c"
#include "seam_finish.c"
#include "seam_kernel.c"

#define TESTNAME "peerB-R2"

static void init_local_interface(void)
{
    init_peerB_interface();
}

static void init_fake_secrets(void)
{
    prompt_pass_t pass;
    memset(&pass, 0, sizeof(pass));
    osw_init_ipsecdir_str("../samples/carol");

    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , "../samples/carol.secrets"
			       , &pass, NULL);
}
static void init_loaded(void) {}

#include "../lp12-parentR2/parentR2_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
