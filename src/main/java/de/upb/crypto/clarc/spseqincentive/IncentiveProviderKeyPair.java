package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSigningKey;
import de.upb.crypto.craco.sig.ps.PSVerificationKey;
import de.upb.crypto.craco.sig.sps.eq.SPSEQPublicParameters;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSigningKey;
import de.upb.crypto.craco.sig.sps.eq.SPSEQVerificationKey;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.List;

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
	GroupElement digitsig_public_x, digitsig_public_y, digitsig_g2;
	List<GroupElement> digitsig_sigma_on_i;
	List<GroupElement> digitsig_h_on_i;

	public IncentiveProviderKeyPair(PSVerificationKey psVerificationKey, PSSigningKey psSigningKey, SPSEQSigningKey spseqSigningKey, SPSEQVerificationKey spseqVerificationKey, SPSEQPublicParameters spseqPublicParameters, GroupElement[] h1to6, Zp.ZpElement[] q, GroupElement digitsig_public_x, GroupElement digitsig_public_y, List<GroupElement> digitsig_sigma_on_i, List<GroupElement> digitsig_h_on_i, GroupElement digitsig_g2) {
		this.psVerificationKey = psVerificationKey;
		this.psSigningKey = psSigningKey;
		this.spseqSigningKey = spseqSigningKey;
		this.spseqVerificationKey = spseqVerificationKey;
		this.spseqPublicParameters = spseqPublicParameters;
		this.h1to6 = h1to6;
		this.q = q;
		this.providerPublicKey = new IncentiveProviderPublicKey(psVerificationKey,spseqVerificationKey, spseqPublicParameters, h1to6, digitsig_public_x, digitsig_public_y, digitsig_sigma_on_i, digitsig_h_on_i, digitsig_g2);
		this.providerSecretKey = new IncentiveProviderSecretKey(psSigningKey, spseqSigningKey, q);
		this.digitsig_public_x = digitsig_public_x;
		this.digitsig_public_y = digitsig_public_y;
		this.digitsig_sigma_on_i = digitsig_sigma_on_i;
		this.digitsig_h_on_i = digitsig_h_on_i;
		this.digitsig_g2 = digitsig_g2;
	}
}
