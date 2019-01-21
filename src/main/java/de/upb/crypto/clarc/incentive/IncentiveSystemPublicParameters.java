package de.upb.crypto.clarc.incentive;

import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.interfaces.structures.GroupElement;

import java.math.BigInteger;

public class IncentiveSystemPublicParameters {
	BilinearGroup group;

	/** shared base for ElGamal encryption */
	GroupElement w;

	/** maximum point score */
	BigInteger maxValue;

	/** group elements for malleable commitment (ElGamal) */
	GroupElement g, h;

	public IncentiveSystemPublicParameters(BilinearGroup group, GroupElement w, GroupElement h, GroupElement g, BigInteger maxValue) {
		this.group = group;
		this.w = w;
		this.maxValue = maxValue;
		this.g = g;
		this.h = h;
	}
}
