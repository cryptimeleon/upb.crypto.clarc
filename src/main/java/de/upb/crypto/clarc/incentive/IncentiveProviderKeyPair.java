package de.upb.crypto.clarc.incentive;

import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSigningKey;

public class IncentiveProviderKeyPair {
	PSExtendedVerificationKey providerPublicKey;
	PSSigningKey providerSecretKey;

	public IncentiveProviderKeyPair(PSExtendedVerificationKey providerPublicKey, PSSigningKey providerSecretKey) {
		this.providerPublicKey = providerPublicKey;
		this.providerSecretKey = providerSecretKey;
	}
}
