package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.craco.sig.sps.eq.SPSEQSignature;

public class DeductOutput {
	SPSEQSignature issuedSignature;
	boolean b;
	DoubleSpendTag dstag;

	public DeductOutput(SPSEQSignature blindedSig, boolean b, DoubleSpendTag dstag) {
		this.issuedSignature = blindedSig;
		this.b = b;
		this.dstag = dstag;
	}
}
