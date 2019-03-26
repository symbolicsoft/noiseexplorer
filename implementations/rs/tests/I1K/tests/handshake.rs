#![allow(non_snake_case, non_upper_case_globals)]

use /*pattern_name*/;

fn decode_str(s: &str) -> Vec<u8> {
    if let Ok(x) = hex::decode(s) {
        x
    } else {
        panic!("{:X?}", hex::decode(s).err());
    }
}

#[test]
fn test() {
    /*test_code*/
}