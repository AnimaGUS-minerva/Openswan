#ifndef __seam_ikev2_sendI1_h__
#define __seam_ikev2_sendI1_h__

#ifndef GLOBAL_TWEAK
#define GLOBAL_TWEAK 0
#endif

/* This varies from sendI1.c, because it calls with variation of nonce by serial number */

void sendI1b(struct connection *c1, int debugging, int calculate, so_serial_t num)
{
	struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;  /* r is a global in the seams */

	cur_debugging = debugging;
	c1->extra_debugging = debugging;

        if(continuation) {
          if(calculate) {
            calc_ke(crypto_req);
            calc_nonce(crypto_req);
          } else {
            passert(kn->oakley_group == SS(oakleygroup));
            /* now fill in the KE values from a constant.. not calculated */
            clonetowirechunk(&kn->thespace, kn->space, &kn->secret, SS(secret.ptr),SS(secret.len));
            clonetowirechunk(&kn->thespace, kn->space, &kn->n,   SS(ni.ptr), SS(ni.len));
            clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  SS(gi.ptr), SS(gi.len));

            /* mutate the nonce slightly with the serial number */
            if(num) {
              unsigned char *nptr = wire_chunk_ptr(kn, &kn->n);
              nptr[0] = nptr[0] | num | GLOBAL_TWEAK;
            }
          }
        }

	run_continuation(crypto_req);
}

struct state *sendI1(struct connection *c1, int debugging, int calculate)
{
	struct state *st;
	so_serial_t newone;

	newone = ipsecdoi_initiate(/* whack-sock=stdout */1
                                   , NULL, NULL
                                   , c1
                                   , c1->policy
                                   , 0 /* try */
                                   , FALSE /* replacing */
                                   , pcim_demand_crypto, USER_SEC_CTX_NULL);

	/* find st involved */
	st = state_with_serialno(newone);
	enable_debugging_on_sa(1);

        if(st == NULL) return NULL;

        sendI1b(c1, debugging, calculate, st->st_serialno);

        return st;
}

#endif
