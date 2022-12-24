/*
 * Copyright [2022] <mcr@sandelman.ca>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 *
 */

//use std::net::Ipv6Addr;
//use std::sync::Arc;

// probably not rtnetlink, but needs to be xfrmnetlink!
use std::io::Error;
use rtnetlink::sys::SocketAddr;
use rtnetlink::{packet::{NetlinkMessage, RtnlMessage}, Handle, proto::Connection, new_connection};
use futures::channel::mpsc::UnboundedReceiver;

//#[derive(Debug)]
//pub struct XfrmErouteManager
//    pub handle:    Some(Handle)
//}

pub struct XfrmErouteHandle {
    connection: Connection<RtnlMessage>,
    handle:     Handle,
    messages:   UnboundedReceiver<(NetlinkMessage<RtnlMessage>, SocketAddr)>,
}

pub type IPsec_SPI = u32;

#[no_mangle]
pub extern "C" fn xfrm_eroute_initialize() -> *mut XfrmErouteHandle {
    Box::into_raw(Box::new(XfrmErouteHandle::new()))
}

impl XfrmErouteHandle {
    fn new() -> XfrmErouteHandle {
        let (connection, handle, messages) = new_connection().map_err(|e| format!("{}", e)).unwrap();

        XfrmErouteHandle {
            handle: handle,
            connection: connection,
            messages: messages
        }
    }
}

#[no_mangle]
pub extern "C" fn xfrm_eroute_free(ptr: *mut XfrmErouteHandle) {
    if ptr.is_null() {
        return;
    };
    unsafe { drop(Box::from_raw(ptr)); } // the underlying contents then get freed
}

#[no_mangle]
pub extern "C" fn xfrm_raw_eroute(ptr: *mut XfrmErouteHandle
                                  , const ip_address *this_host
		                  , const ip_subnet *this_client
		                  , const ip_address *that_host
		                  , const ip_subnet *that_client
		                  spi:   IPsec_SPI,
		                  proto: u16,
		                  transport_proto: u16,
		                  , enum eroute_type esatype
		                  , const struct pfkey_proto_info *proto_info
		                  , time_t use_lifetime UNUSED
		                  , enum pluto_sadb_operations sadb_op
		                  text_said: String,
                                  , uint32_t if_id) -> Result<(), Error> {

    if ptr.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData, "bad xfrm pointer".to_string()));
    };
    let xfrmhandle = unsafe { Box::from_raw(ptr) };

    Ok(())
}

//#[no_mangle]
//pub extern "C" fn xfrm_eroute_populate(ptr: *mut XfrmErouteHandle) {
//    let manager = unsafe {
//        assert!(!ptr.is_null());
//        &mut *ptr
//    };
//    //database.populate();
//}

