#include <stdlib.h>
#include "constants.h"
#include "oswalloc.h"
#include "pluto/defs.h"
#include "pluto/state.h"
#include "oswlog.h"
#include "seam_exitlog.c"

const char *progname=NULL;

int main(int argc, char *argv[])
{
    char *infile;
    char *conn_name;
    unsigned char n1[] = { 0x12, 0x23, 0x34, 0x45 };
    unsigned char n2[] = { 0x23, 0x34, 0x45, 0x56 };
    unsigned char n3[] = { 0x23, 0x34, 0x45, 0x56, 0x55 };

    progname = argv[0];
    leak_detective = 1;

    tool_init_log();

    struct state *s1 = alloc_thing(struct state, "s1");
    struct state *s2 = alloc_thing(struct state, "s2");

    /* first test identical nonces */
    setchunk(s1->st_ni, n1, 4);  setchunk(s1->st_nr, n2, 4);
    setchunk(s2->st_ni, n1, 4);  setchunk(s2->st_nr, n2, 4);

    passert(compare_nonce_set(s1, s2) == FALSE);

    /* now test with different initiator nonces */
    setchunk(s2->st_ni, n2, 4);
    passert(compare_nonce_set(s1, s2) == TRUE);

    /* now try with nonce sa1 nonce being longer, therefore "higher" */
    setchunk(s2->st_ni, n3, 5);
    passert(compare_nonce_set(s1, s2) == FALSE);

    /* now try with identical first nonces, but second nonce different */
    setchunk(s1->st_ni, n1, 4);  setchunk(s1->st_nr, n1, 4);
    setchunk(s2->st_ni, n1, 4);  setchunk(s2->st_nr, n2, 4);

    passert(compare_nonce_set(s1, s2) == TRUE);

    tool_close_log();

    report_leaks();

    exit(0);
}


/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * compile-command: "make check"
 * End:
 */

