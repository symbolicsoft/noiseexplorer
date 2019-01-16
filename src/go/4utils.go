/* ---------------------------------------------------------------- *
 * UTILITY FUNCTIONS                                                *
 * ---------------------------------------------------------------- */

func getPublicKey(kp keypair) [32]byte {
	return kp.pk
}

func isEmptyKey(k [32]byte) bool {
	for _, v := range k {
		if v != 0 {
			return false
		}
	}
	return true
}