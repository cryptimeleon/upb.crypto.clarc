package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.math.structures.zn.Zp;


// DONE for weeting
public class IncentiveUserSetup {

	public IncentiveUserKeyPair generateUserKeys(IncentiveSystemPublicParameters pp) {

		Zp zp = new Zp(pp.group.getG1().size());
		Zp.ZpElement usk = zp.getUniformlyRandomElement();

		return new IncentiveUserKeyPair(new IncentiveUserSecretKey(usk), new IncentiveUserPublicKey(pp.w.pow(usk)));
	}
}
