#[no_mangle]
pub extern "C" fn xfrm_route_add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = xfrm_route_add(2, 2);
        assert_eq!(result, 4);
    }
}
