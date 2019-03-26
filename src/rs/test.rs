#![allow(non_snake_case, non_upper_case_globals)]

use $NOISE2RS_N$;

fn decode_str(s: &str) -> Vec<u8> {
    if let Ok(x) = hex::decode(s) {
        x
    } else {
        panic!("{:X?}", hex::decode(s).err());
    }
}

#[test]
fn test() {
    $NOISE2RS_T$
}