#include <libgen.h>

#ifndef AFTER_CONN
#define AFTER_CONN() do {} while(0)
#endif

#ifndef PCAP_INPUT_COUNT
#define PCAP_INPUT_COUNT 2
recv_pcap recv_inputs[PCAP_INPUT_COUNT]={
    recv_pcap_packet,
    recv_pcap_packet2,
};
#endif

#ifndef PCAP_CAPTURE_COUNT
#define PCAP_CAPTURE_COUNT 0
#endif


int main(int argc, char *argv[])
{
    char *infile;
    char *conn_name;
    char *pcapin[PCAP_INPUT_COUNT];
    int   i;
    char *pcap_out;
    int  regression = 0;
    int  bootstrap  = 0;
    int  output_already_open = 0;
    struct connection *c1;
    struct state *st;

#ifdef HAVE_EFENCE
    EF_PROTECT_FREE=1;
#endif

    progname = argv[0];
    leak_detective = 1;

    /* skip argv0 */
    argc--; argv++;

    if(strcmp(argv[0], "-B")==0) {
        bootstrap = 1;
        argc--; argv++;
    }
    if(strcmp(argv[0], "-r")==0) {
        regression = 1;
        argc--; argv++;
    }
    if(argc < 4) {
        fprintf(stderr, "Wrong number of arguments: %d >= %d\n", argc, 4);
	fprintf(stderr, "Usage: %s [-r] <whackrecord> <conn-name> <pcapout> <pcapR1..>\n", progname);
	exit(9);
    }

    tool_init_log();
    init_crypto();
    load_oswcrypto();
    init_fake_vendorid();
    init_local_interface();
    init_seam_kernelalgs();
    init_fake_secrets();
    enable_debugging();
    init_demux();
    init_seam_kernelalgs();

    infile = argv[0];
    conn_name = argv[1];
    pcap_out  = argv[2];
    for(i=0; i<PCAP_INPUT_COUNT; i++) {
        if(3+i > argc) {
            fprintf(stderr, "%u pcap files wanted, only %u provided\n",
                    PCAP_INPUT_COUNT, argc-3);
            exit(8);
        }
        pcapin[i] = argv[3+i];
    }

    cur_debugging = DBG_CONTROL|DBG_CONTROLMORE;
    if(readwhackmsg(infile) == 0) exit(10);
    c1 = con_by_name(conn_name, TRUE);
    assert(c1 != NULL);

    assert(orient(c1, 500));
    show_one_connection(c1, whack_log);
    init_loaded();

    if(bootstrap) {
        send_packet_setup_pcap(pcap_out);
    }
    st = sendI1(c1, DBG_CONTROL, regression == 0);

    if(bootstrap) {
        /* exit before trying to read files that might not exist */
        exit(2);
    }

    for(i=0; i<PCAP_INPUT_COUNT; i++) {
        if((i+1) < (PCAP_INPUT_COUNT-PCAP_CAPTURE_COUNT)) {
            /* omit the PCAP_IGNORE_COUNT replies, usually 1 */
            send_packet_setup_pcap("/dev/null");
        } else if (output_already_open == 0) {
            fprintf(stderr, "%u: output to %s\n", i, pcap_out);
            send_packet_setup_pcap(pcap_out);
            output_already_open = 1;
        } else {
            /* if *output_already_open* then make new numbered files */
            char namebuf[256];
            char namebuf2[256];
            memset(namebuf2, 0, 256);
            strncpy(namebuf2, pcap_out, sizeof(namebuf)-1);
            char *base= basename(namebuf2);
            char *dir = dirname(namebuf2);
            snprintf(namebuf, sizeof(namebuf), "%s/%02d_%s"
                     , dir
                     , ++output_already_open
                     , base);
            fprintf(stderr, "%u: output to %s\n", i, namebuf);
            send_packet_setup_pcap(namebuf);
        }

        /* setup to process the n'th packet */
        fprintf(stderr, "%u: input from %s\n", i, pcapin[i]);
        recv_pcap_setup(pcapin[i]);

        /* process i'th packet */
        cur_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE;
        assert(recv_inputs[i] != NULL);
        pcap_dispatch(pt, -1, recv_inputs[i], NULL);
    }

    AFTER_CONN();

    show_states_status();

    /* dump the delete message that comes out */
    send_packet_setup_pcap("/dev/null");
    delete_connection(c1, TRUE, FALSE);

    st = state_with_serialno(1);
    if(st!=NULL) {
        free_state(st);
    }

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
