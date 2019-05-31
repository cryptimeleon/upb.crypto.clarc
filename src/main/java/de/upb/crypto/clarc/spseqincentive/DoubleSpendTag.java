package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.craco.enc.asym.elgamal.ElgamalCipherText;
import de.upb.crypto.math.structures.zn.Zp;

public class DoubleSpendTag {
	Zp.ZpElement c0, c1;
	Zp.ZpElement gamma;
	ElgamalCipherText ctrace;

	public DoubleSpendTag(Zp.ZpElement c0, Zp.ZpElement c1, Zp.ZpElement gamma, ElgamalCipherText ctrace) {
		this.c0 = c0;
		this.c1 = c1;
		this.gamma = gamma;
		this.ctrace = ctrace;
	}
}
