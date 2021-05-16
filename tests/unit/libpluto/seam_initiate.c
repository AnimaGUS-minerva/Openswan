#ifndef __seam_initiate_c__
#ifndef OMIT_SEAM_INITIATE
#define __seam_initiate_c__

void connection_check_phase2(void) {}

/* initiate.c SEAM */
void initiate_connection(enum initiate_type it
                         , const char *name, int whackfd
			 , lset_t moredebug
			 , enum crypto_importance importance) {
  DBG_log("initiating conn %s\n", name);
}

int initiate_ondemand(const ip_address *our_client
                              , const ip_address *peer_client
                              , int transport_proto
                              , bool held
                              , int whackfd
                              , struct xfrm_user_sec_ctx_ike *uctx
                              , err_t why)
{
	return 0;
}

#endif /* OMIT_SEAM_INITIATE */
#endif
