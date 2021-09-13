
#include "openswan.h"
#include "constants.h"
#include "oswalloc.h"
#include "pluto/defs.h"
#include "pluto/state.h"

/* return <0 if thatnonce lower,
 * return >0 if thisnonce lower,
 * return =0 if identical
 */
static int  compare_nonce(chunk_t thatnonce, chunk_t thisnonce)
{
    unsigned int nonce_len = thatnonce.len;
    if(nonce_len > thisnonce.len) nonce_len = thatnonce.len;

    unsigned int equal = memcmp(thatnonce.ptr, thisnonce.ptr, nonce_len);
    if(equal != 0) {
        return equal;  /* that or this wins */
    }

    /* if same, but "this" is longer, then that is lower */
    if(thisnonce.len > thatnonce.len) {
        return -1;
    }

    /* if same, but "that" is longer, then that wins, return FALSE */
    if(thisnonce.len < thatnonce.len) {
        return 1;
    }

    /* must be exactly the same */
    return 0;
}

/* figure out which one has the lowest nonces */
/* compare this with that, return true if *that* wins */
bool compare_nonce_set(struct state *that
                       , struct state *this)
{

    int inonce_cmp = compare_nonce(that->st_ni, this->st_ni);
    if(inonce_cmp < 0) {
        return TRUE;
    }
    if(inonce_cmp > 0) {
        return FALSE;
    }

    int rnonce_cmp = compare_nonce(that->st_nr, this->st_nr);
    if(rnonce_cmp < 0) {
        return TRUE;
    }
    if(rnonce_cmp > 0) {
        return FALSE;
    }

    /* all the same?  preposterous! */
    return FALSE;
}


