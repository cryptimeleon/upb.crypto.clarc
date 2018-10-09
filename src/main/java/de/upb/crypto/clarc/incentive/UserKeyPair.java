package de.upb.crypto.clarc.incentive;

public class UserKeyPair {
	IncentiveUserSecretKey userSecretKey;
	IncentiveUserPublicKey userPublicKey;

	public UserKeyPair(IncentiveUserSecretKey userSecretKey, IncentiveUserPublicKey userPublicKey) {
		this.userSecretKey = userSecretKey;
		this.userPublicKey = userPublicKey;
	}
}
