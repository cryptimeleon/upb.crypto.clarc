package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSigningKey;
import de.upb.crypto.craco.sig.ps.PSVerificationKey;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSigningKey;
import de.upb.crypto.craco.sig.sps.eq.SPSEQVerificationKey;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

public class IncentiveProviderKeyPair {
	PSVerificationKey psVerificationKey;
	PSSigningKey psSigningKey;
	SPSEQSigningKey spseqSigningKey;
	SPSEQVerificationKey spseqVerificationKey;
	GroupElement[] h1to6;
	Zp.ZpElement[] q;
	IncentiveProviderPublicKey providerPublicKey;

	public IncentiveProviderKeyPair(PSVerificationKey psVerificationKey, PSSigningKey psSigningKey, SPSEQSigningKey spseqSigningKey, SPSEQVerificationKey spseqVerificationKey, GroupElement[] h1to6, Zp.ZpElement[] q) {
		this.psVerificationKey = psVerificationKey;
		this.psSigningKey = psSigningKey;
		this.spseqSigningKey = spseqSigningKey;
		this.spseqVerificationKey = spseqVerificationKey;
		this.h1to6 = h1to6;
		this.q = q;
		this.providerPublicKey = new IncentiveProviderPublicKey(psVerificationKey,spseqVerificationKey,h1to6);
	}
}
