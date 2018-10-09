package de.upb.crypto.clarc.incentive;

import de.upb.crypto.craco.interfaces.signature.SignatureKeyPair;
import de.upb.crypto.craco.sig.ps.*;

public class ProviderSetup {

	public ProviderKeyPair generateProviderKeys(IncentiveSystemPublicParameters pp) {
		PSExtendedSignatureScheme signatureScheme = new PSExtendedSignatureScheme(new PSPublicParameters(pp.group.getBilinearMap()));

		SignatureKeyPair<? extends PSExtendedVerificationKey, ? extends PSSigningKey> signatureKeyPair = signatureScheme.generateKeyPair(4);

		return new ProviderKeyPair(signatureKeyPair.getVerificationKey(), signatureKeyPair.getSigningKey());
	}
}
