package de.upb.crypto.clarc.incentive;

import de.upb.crypto.craco.enc.asym.elgamal.ElgamalCipherText;
import de.upb.crypto.math.structures.zn.Zp;

public class DoubleSpendTag {
	Zp.ZpElement c;
	Zp.ZpElement gamma;
	ElgamalCipherText ctrace;

	public DoubleSpendTag(Zp.ZpElement c, Zp.ZpElement gamma, ElgamalCipherText ctrace) {
		this.c = c;
		this.gamma = gamma;
		this.ctrace = ctrace;
	}
}
