package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSigningKey;
import de.upb.crypto.craco.sig.ps.PSVerificationKey;
import de.upb.crypto.craco.sig.sps.eq.SPSEQPublicParameters;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSigningKey;
import de.upb.crypto.craco.sig.sps.eq.SPSEQVerificationKey;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

public class IncentiveProviderKeyPair {
	PSVerificationKey psVerificationKey;
	PSSigningKey psSigningKey;
	SPSEQSigningKey spseqSigningKey;
	SPSEQVerificationKey spseqVerificationKey;
	SPSEQPublicParameters spseqPublicParameters;
	GroupElement[] h1to6;
	Zp.ZpElement[] q;
	IncentiveProviderPublicKey providerPublicKey;
	IncentiveProviderSecretKey providerSecretKey;

	public IncentiveProviderKeyPair(PSVerificationKey psVerificationKey, PSSigningKey psSigningKey, SPSEQSigningKey spseqSigningKey, SPSEQVerificationKey spseqVerificationKey, SPSEQPublicParameters spseqPublicParameters, GroupElement[] h1to6, Zp.ZpElement[] q) {
		this.psVerificationKey = psVerificationKey;
		this.psSigningKey = psSigningKey;
		this.spseqSigningKey = spseqSigningKey;
		this.spseqVerificationKey = spseqVerificationKey;
		this.spseqPublicParameters = spseqPublicParameters;
		this.h1to6 = h1to6;
		this.q = q;
		this.providerPublicKey = new IncentiveProviderPublicKey(psVerificationKey,spseqVerificationKey, spseqPublicParameters, h1to6);
		this.providerSecretKey = new IncentiveProviderSecretKey(psSigningKey, spseqSigningKey, q);
	}
}
