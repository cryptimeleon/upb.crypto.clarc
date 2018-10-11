package de.upb.crypto.clarc.incentive;

public class IncentiveUserKeyPair {
	IncentiveUserSecretKey userSecretKey;
	IncentiveUserPublicKey userPublicKey;

	public IncentiveUserKeyPair(IncentiveUserSecretKey userSecretKey, IncentiveUserPublicKey userPublicKey) {
		this.userSecretKey = userSecretKey;
		this.userPublicKey = userPublicKey;
	}
}
