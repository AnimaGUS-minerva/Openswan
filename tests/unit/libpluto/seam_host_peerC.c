#ifndef __seam_host_peerC_c__
#define __seam_host_peerC_c__
struct iface_dev  peerC_ifd1 = {
	.id_count = 1,
	.id_vname = "ipsec0",
	.id_rname = "eth0"
};

struct iface_port peerC_if1 = {
	.ip_dev = &peerC_ifd1,
	.port   = 500,
        .socktypename = "AF_INET6",
	.ip_addr.u.v6.sin6_family = AF_INET6,
	.fd     = -1,
	.next   = NULL,
	.ike_float = 0,
	.change    = IFN_KEEP
};

void init_peerC_interface(void)
{
  inet_pton(AF_INET6, "fe80::ec68:7cff:fe0c:1c1c", &peerC_if1.ip_addr.u.v6.sin6_addr);
  init_iface_port(&peerC_if1);
  peerC_if1.next = interfaces;
  interfaces = &peerC_if1;
}
#endif
