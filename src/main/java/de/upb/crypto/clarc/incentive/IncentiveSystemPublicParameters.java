package de.upb.crypto.clarc.incentive;

import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.interfaces.structures.GroupElement;

import java.math.BigInteger;

public class IncentiveSystemPublicParameters {
	BilinearGroup group;

	GroupElement w;

	BigInteger maxValue;

	public IncentiveSystemPublicParameters(BilinearGroup group, GroupElement w, BigInteger maxValue) {
		this.group = group;
		this.w = w;
		this.maxValue = maxValue;
	}
}
