package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.craco.interfaces.signature.SignatureKeyPair;
import de.upb.crypto.craco.sig.ps.*;
import de.upb.crypto.craco.sig.sps.eq.SPSEQPublicParameters;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSignatureScheme;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSigningKey;
import de.upb.crypto.craco.sig.sps.eq.SPSEQVerificationKey;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class IncentiveProviderSetup {

	public IncentiveProviderKeyPair generateProviderKeys(IncentiveSystemPublicParameters pp) {
		SPSEQPublicParameters spseqPublicParameters = new SPSEQPublicParameters(pp.group.getBilinearMap());
		SPSEQSignatureScheme spseqSignatureScheme = new SPSEQSignatureScheme(spseqPublicParameters);


		// sps eq key pair
		SignatureKeyPair<? extends SPSEQVerificationKey, ? extends SPSEQSigningKey> spsSignatureKeyPair = spseqSignatureScheme.generateKeyPair(2);


		// normal digital signature key pair
		PSExtendedSignatureScheme signatureScheme = new PSExtendedSignatureScheme(new PSPublicParameters(pp.group.getBilinearMap()));

		SignatureKeyPair<? extends PSExtendedVerificationKey, ? extends PSSigningKey> signatureKeyPair = signatureScheme.generateKeyPair(4);


		// pedersen commitment parameters
		// pick q1 to q_6
		// generate the corresponding hi's
		Group g1 = pp.group.getG1();
		Zp zp = new Zp(g1.size());
		Zp.ZpElement[] q = new Zp.ZpElement[6];
		GroupElement[] h1to6 = new GroupElement[6];

		do {
			for (int i = 0; i < 6; i++) {
				q[i] = zp.getUniformlyRandomElement();
				h1to6[i] = pp.g1.pow(q[i]);
			}
		}while (Arrays.asList(q).stream().distinct().count() != 6);



		//PedersenCommitmentScheme pedersenCommitmentScheme = new PedersenCommitmentScheme(new PedersenPublicParameters(pp.g1,h1to6,pp.group.getG1()));


		// signatures on base elements for range proofs. Pointcheval Sanders
		GroupElement digitsig_g1 = pp.group.getG1().getUniformlyRandomElement();
		GroupElement digitsig_g2 = pp.group.getG2().getUniformlyRandomElement();
		Zp.ZpElement digitsig_x = zp.getUniformlyRandomElement();
		Zp.ZpElement digitsig_y = zp.getUniformlyRandomElement();
		GroupElement digitsig_public_x = digitsig_g2.pow(digitsig_x);
		GroupElement digitsig_public_y = digitsig_g2.pow(digitsig_y);

		List<GroupElement> digitsig_sigma_on_i = new ArrayList<>();
		List<GroupElement> digitsig_h_on_i = new ArrayList<>();
		for (int i=0;i<SpendInstance.BASE.intValue();i++) {
			GroupElement h = pp.group.getG1().getUniformlyRandomNonNeutral();
			digitsig_h_on_i.add(h);
			digitsig_sigma_on_i.add(h.pow(digitsig_x.add(digitsig_y.mul(zp.valueOf(i)))));
		}

		return new IncentiveProviderKeyPair(signatureKeyPair.getVerificationKey(), signatureKeyPair.getSigningKey(), spsSignatureKeyPair.getSigningKey(), spsSignatureKeyPair.getVerificationKey(), spseqPublicParameters,h1to6, q, digitsig_public_x, digitsig_public_y, digitsig_sigma_on_i, digitsig_h_on_i, digitsig_g2);
	}
}
