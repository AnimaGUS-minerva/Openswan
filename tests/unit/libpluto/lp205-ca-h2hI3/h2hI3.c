#include "../lp13-parentI3/parentI3_head.c"
#include "seam_gi_sha256_group14.c"
#include "seam_finish.c"
#include "seam_ikev2_sendI1.c"
#include "oswconf.h"
#include "seam_x509_list.c"
#include "seam_rsasig.c"
#include "seam_kernel.c"
#include "../../programs/pluto/x509keys.c"

#define TESTNAME "h2hI3"

static void init_fake_secrets(void)
{
    osw_init_ipsecdir_str("../samples/davecert");
    osw_load_preshared_secrets(&pluto_secrets
			       , TRUE
			       , SAMPLEDIR "parker.secrets"
			       , NULL, NULL);
    load_authcerts("CA cert", SAMPLEDIR "davecert/cacerts", AUTH_CA);
}

static void init_local_interface(void) {
    init_parker_interface(TRUE);
}

static void init_loaded(void)
{   /* nothing */ }

#include "seam_parentI2.c"
#include "../lp13-parentI3/parentI3_main.c"

 /*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */
