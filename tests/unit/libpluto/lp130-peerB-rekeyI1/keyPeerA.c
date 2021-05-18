void rekey_to_peerA(void)
{
    struct state *st = NULL;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;
    struct connection *c1;

    timer_list();

    rnd_offset++;

    c1 = con_by_name("peerB--peerA", TRUE);
    st = sendI1(c1, DBG_CONTROL, TRUE);

    run_continuation(crypto_req);
}
