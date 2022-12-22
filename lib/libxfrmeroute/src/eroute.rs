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
use rtnetlink::{Handle};

//#[derive(Debug)]
//pub struct XfrmErouteManager
//    pub handle:    Some(Handle)
//}

#[derive(Debug)]
pub struct XfrmErouteHandle {
    handle:    Option<Handle>,
    //manager: Arc<XfrmErouteManager>,
}

#[no_mangle]
pub extern "C" fn xfrm_eroute_initialize() -> *mut XfrmErouteHandle {
    Box::into_raw(Box::new(XfrmErouteHandle::new()))
}

impl XfrmErouteHandle {
    fn new() -> XfrmErouteHandle {
        XfrmErouteHandle {
            handle: None
            //manager: Arc::new(XfrmErouteManager::new()),
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

//#[no_mangle]
//pub extern "C" fn xfrm_eroute_populate(ptr: *mut XfrmErouteHandle) {
//    let manager = unsafe {
//        assert!(!ptr.is_null());
//        &mut *ptr
//    };
//    //database.populate();
//}

