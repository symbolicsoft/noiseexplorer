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

fn is_empty(k: &[u8]) -> bool {
	crypto::util::fixed_time_eq(k, &EMPTY_KEY[..])
}