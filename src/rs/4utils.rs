/* ---------------------------------------------------------------- *
 * UTILITY FUNCTIONS                                                *
 * ---------------------------------------------------------------- */

macro_rules! copy_slices {
	($inslice:expr, $outslice:expr) => {
		$outslice[..$inslice.len()].clone_from_slice(&$inslice[..])
	};
}

fn from_slice_HASHLEN(bytes: &[u8]) -> [u8; HASHLEN] {
	let mut array = [0u8; HASHLEN];
	let bytes = &bytes[..array.len()];
	array.copy_from_slice(bytes);
	array
}

// TEST ONLY
pub fn decode_str_32(s: &str) -> [u8; 32] {
	if let Ok(x) = hex::decode(s) {
		if x.len() == 32 {
			let mut temp: [u8; 32] = [0u8; 32];
			temp.copy_from_slice(&x[..]);
			temp
		} else {
			panic!("Invalid input length; decode_32");
		}
	} else {
		panic!("Invalid input length; decode_32");
	}
}
