package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.math.structures.zn.Zp;

public class IncentiveUserSecretKey {
	Zp.ZpElement usk;

	public IncentiveUserSecretKey(Zp.ZpElement usk) {
		this.usk = usk;
	}
}
