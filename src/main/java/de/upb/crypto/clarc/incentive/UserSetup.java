package de.upb.crypto.clarc.incentive;

import de.upb.crypto.craco.enc.asym.elgamal.ElgamalPublicKey;
import de.upb.crypto.craco.interfaces.signature.SignatureKeyPair;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
import de.upb.crypto.craco.sig.ps.PSSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSSigningKey;
import de.upb.crypto.craco.sig.ps.PSVerificationKey;
import de.upb.crypto.math.structures.zn.Zp;

public class UserSetup {

	public UserKeyPair generateUserKeys(IncentiveSystemPublicParameters pp) {

		Zp zp = new Zp(pp.group.getG1().size());
		Zp.ZpElement usk = zp.getUniformlyRandomElement();

		return new UserKeyPair(new IncentiveUserSecretKey(usk), new IncentiveUserPublicKey(pp.w.pow(usk)));
	}
}
