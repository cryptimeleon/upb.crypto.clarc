package de.upb.crypto.clarc.incentive;

import de.upb.crypto.craco.interfaces.signature.SignatureKeyPair;
import de.upb.crypto.craco.sig.ps.*;

public class IncentiveProviderSetup {

	public IncentiveProviderKeyPair generateProviderKeys(IncentiveSystemPublicParameters pp) {
		PSExtendedSignatureScheme signatureScheme = new PSExtendedSignatureScheme(new PSPublicParameters(pp.group.getBilinearMap()));

		SignatureKeyPair<? extends PSExtendedVerificationKey, ? extends PSSigningKey> signatureKeyPair = signatureScheme.generateKeyPair(4);

		return new IncentiveProviderKeyPair(signatureKeyPair.getVerificationKey(), signatureKeyPair.getSigningKey());
	}
}
