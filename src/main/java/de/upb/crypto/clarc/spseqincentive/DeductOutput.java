package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.craco.sig.ps.PSSignature;

public class DeductOutput {
	PSSignature issuedSignature;
	boolean b;
	DoubleSpendTag dstag;

	public DeductOutput(PSSignature blindedSig, boolean b, DoubleSpendTag dstag) {
		this.issuedSignature = blindedSig;
		this.b = b;
		this.dstag = dstag;
	}
}
