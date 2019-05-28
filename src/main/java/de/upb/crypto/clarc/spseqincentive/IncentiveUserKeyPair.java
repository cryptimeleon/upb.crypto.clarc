package de.upb.crypto.clarc.spseqincentive;

public class IncentiveUserKeyPair {
	IncentiveUserSecretKey userSecretKey;
	IncentiveUserPublicKey userPublicKey;

	public IncentiveUserKeyPair(IncentiveUserSecretKey userSecretKey, IncentiveUserPublicKey userPublicKey) {
		this.userSecretKey = userSecretKey;
		this.userPublicKey = userPublicKey;
	}
}
