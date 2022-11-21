/* generated from whack.cddl */

/*
; this is a CDDL file that defines the API from other programs into
; pluto for loading policy.
; This file is converted by the "cddlc" program into include/whack_values.h
; This is a manual process, do: cddlc --to=enum whack.cddl >whack_values.h
*/

#ifndef WHACKVALUES_H
#define WHACKVALUES_H
enum whack_message_keys {
  WHACK_STATUS = 1,
  WHACK_SHUTDOWN = 2,
  WHACK_OPTIONS = 3,
  WHACK_CONNECTION = 4,
  WHACK_ROUTE = 5,
  WHACK_UNROUTE = 6,
  WHACK_INITIATE = 7,
  WHACK_INITIATE_OPPO = 8,
  WHACK_TERMINATE = 9,
  WHACK_ADD_KEY = 10,
  WHACK_DELETE = 11,
  WHACK_LISTEN = 13,
  WHACK_UNLISTEN = 14,
  WHACK_LIST = 15,
  WHACK_PURGE_OCSP = 16,
  WHACK_REREAD = 17,
  WHACK_MYID = 22,
  WHACK_DELETESTATE = 23,
  WHACK_CRASHPEER = 24,
  WHACK_ASYNC = 25,
  WHACK_NOOP = 99,
};
enum initoptions_keys {
  WHACK_OPT_INITTYPE = 146,
};
enum statusoptions_keys {
  WHACK_STAT_OPTIONS = 1,
  WHACK_STAT_ALGORITHMS = 2,
  WHACK_STAT_JSON = 3,
  WHACK_STAT_POLICY = 4,
  WHACK_STAT_STATES = 5,
};
enum publickey_keys {
  WHACK_OPT_KEYID = 16,
  WHACK_OPT_KEYALG = 17,
  WHACK_OPT_KEYVAL = 15,
};
enum connection_keys {
  WHACK_OPT_NAME = 1,
  WHACK_OPT_LEFT = 3,
  WHACK_OPT_RIGHT = 4,
  WHACK_OPT_CONNALIAS = 21,
  WHACK_OPT_IKE = 5,
  WHACK_OPT_ESP = 6,
  WHACK_OPT_POLICYLABEL = 128,
  WHACK_OPT_DPD_DELAY = 181,
  WHACK_OPT_DPD_TIMEOUT = 182,
  WHACK_OPT_DPD_ACTION = 183,
  WHACK_OPT_DPD_COUNT = 184,
  WHACK_OPT_POLICY = 127,
  WHACK_OPT_LIFETIME_IKE = 146,
  WHACK_OPT_LIFETIME_IPSEC = 147,
  WHACK_OPT_LIFETIME_REKEY_MARGIN = 148,
  WHACK_OPT_LIFETIME_REKEY_FUZZ = 149,
  WHACK_OPT_LIFETIME_REKEY_TRIES = 150,
  WHACK_OPT_END_ADDR_FAMILY = 18,
};
enum connectionend_keys {
  WHACK_OPT_END_ID = 5,
  WHACK_OPT_END_CERT = 6,
  WHACK_OPT_END_CA = 7,
  WHACK_OPT_END_GROUPS = 8,
  WHACK_OPT_END_VIRT = 9,
  WHACK_OPT_END_XAUTH_NAME = 137,
  WHACK_OPT_END_HOST_ADDRNAME = 10,
  WHACK_OPT_HOST_TYPE = 15,
  WHACK_OPT_END_HOST_ADDR = 11,
  WHACK_OPT_KEYTYPE = 16,
  WHACK_OPT_HAS_CLIENT = 17,
  WHACK_OPT_HAS_CLIENT_WILDCARD = 18,
  WHACK_OPT_HAS_PORT_WILDCARD = 19,
  WHACK_OPT_HOST_PORT = 20,
  WHACK_OPT_PORT = 138,
  WHACK_OPT_XAUTH_SERVER = 139,
  WHACK_OPT_XAUTH_CLIENT = 140,
  WHACK_OPT_MODECFG_SERVER = 141,
  WHACK_OPT_MODECFG_CLIENT = 142,
  WHACK_OPT_CERTPOLICY = 143,
  WHACK_OPT_CERTTYPE = 144,
  WHACK_OPT_VTINUM = 145,
  WHACK_OPT_END_HOST_NEXTHOP = 12,
  WHACK_OPT_END_HOST_SRCIP = 13,
  WHACK_OPT_END_CLIENT = 14,
};
enum optionscommand_keys {
  WHACK_OPT_COREDIR = 151,
  WHACK_OPT_NHELPERS = 152,
  WHACK_OPT_SECCTX = 153,
  WHACK_OPT_FORKDESIRED = 154,
  WHACK_OPT_STDERR_DESIRED = 155,
  WHACK_OPT_LOG_WITH_TIMESTAMP = 156,
  WHACK_OPT_KERN_INTERFACE = 157,
  WHACK_OPT_SET_DEBUGGING = 158,
  WHACK_OPT_LISTENADDR = 159,
  WHACK_OPT_ADD_DEBUGGING = 160,
  WHACK_OPT_SAME_ADDR_OK = 161,
  WHACK_OPT_FORCE_BUSY = 162,
  WHACK_OPT_CERT_SEND = 163,
  WHACK_OPT_STRICT_CRL_POLICY = 164,
  WHACK_OPT_NO_RETRANSMITS = 165,
  WHACK_OPT_CRL_CHECK_INTERVAL = 166,
  WHACK_OPT_OCSPURI = 167,
  WHACK_OPT_UNIQUE_IDS = 168,
  WHACK_OPT_USE_INTERFACE = 169,
  WHACK_OPT_IKE_PORT = 170,
  WHACK_OPT_CTRL_BASE = 171,
  WHACK_OPT_SHARED_SECRETS_FILE = 172,
  WHACK_OPT_IPSEC_DIR = 173,
  WHACK_OPT_PERPEER_LOGDIR = 174,
  WHACK_OPT_PERPEER_ENABLED = 175,
  WHACK_OPT_NAT_TRAVERSAL = 176,
  WHACK_OPT_NAT_KEEP_ALIVE = 177,
  WHACK_OPT_NAT_FORCE_KEEP_ALIVE = 178,
  WHACK_OPT_NAT_PORT_FLOAT = 179,
  WHACK_OPT_VIRTUAL_PRIVATE = 180,
  WHACK_OPT_SET = 129,
  WHACK_OPT_RECORDFILE = 130,
  WHACK_OPT_LISTEN_ON_LINK_SCOPE = 181,
};
enum initiateoppo_keys {
  WHACK_OPT_OPPO_MY_CLIENT = 143,
  WHACK_OPT_OPPO_PEER_CLIENT = 144,
};

#endif /* WHACKVALUES_H */
