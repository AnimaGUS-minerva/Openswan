/* this is replicated in the unit test cases since
 * the patching up of the crypto values is case specific */

#ifndef CRYPTO_DEBUGGING
#define CRYPTO_DEBUGGING DBG_PRIVATE|DBG_CRYPT|DBG_PARSING|DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE
#endif

/* make the stateno specific */
void recv_pcap_packet_with_ke0(u_char *user
                              , const struct pcap_pkthdr *h
                              , const u_char *bytes
                              , unsigned int stateno)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);

    /* find st involved */
    st = state_with_serialno(stateno);
    if(st) {
        /* now fill in the KE values from a constant.. not calculated */
        clonetowirechunk(&kn->thespace, kn->space, &kn->n,   SS(nr.ptr), SS(nr.len));
        clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  SS(gr.ptr), SS(gr.len));

        run_one_continuation(crypto_req);
    }
}

void recv_pcap_packet_with_ke(u_char *user
                              , const struct pcap_pkthdr *h
                              , const u_char *bytes)
{
  recv_pcap_packet_with_ke0(user, h, bytes, 1);
}

/* a second negotiation */
void recv_pcap_packet_with_ke2(u_char *user
                               , const struct pcap_pkthdr *h
                               , const u_char *bytes)
{
  recv_pcap_packet_with_ke0(user, h, bytes, 2);
}

void recv_pcap_packet2_with_ke0(u_char *user
                               , const struct pcap_pkthdr *h
                               , const u_char *bytes
                               , unsigned int stateno)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);

    /* find st involved */
    st = state_with_serialno(stateno);
    if(st) {  /* might be deleted already */
      st->st_connection->extra_debugging = CRYPTO_DEBUGGING;
    }
    clonetowirechunk(&kn->thespace, kn->space, &kn->secret, SS(secret.ptr),SS(secret.len));

    run_one_continuation(crypto_req);
}

void recv_pcap_packet2_with_ke(u_char *user
                               , const struct pcap_pkthdr *h
                               , const u_char *bytes) {
  recv_pcap_packet2_with_ke0(user, h, bytes, 1);
}

void recv_pcap_packet2_with_ke2(u_char *user
                               , const struct pcap_pkthdr *h
                               , const u_char *bytes) {
  recv_pcap_packet2_with_ke0(user, h, bytes, 2);
}


#ifndef PCAP_INPUT_COUNT
#define PCAP_INPUT_COUNT 2
recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet_with_ke,
    recv_pcap_packet2_with_ke,
};
#endif
