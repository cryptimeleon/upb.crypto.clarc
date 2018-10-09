package de.upb.crypto.clarc.incentive;

import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSigningKey;

public class ProviderKeyPair {
	PSExtendedVerificationKey providerPublicKey;
	PSSigningKey providerSecretKey;

	public ProviderKeyPair(PSExtendedVerificationKey providerPublicKey, PSSigningKey providerSecretKey) {
		this.providerPublicKey = providerPublicKey;
		this.providerSecretKey = providerSecretKey;
	}
}
