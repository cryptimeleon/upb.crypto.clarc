package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofPublicParameters;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParameters;
import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.interfaces.structures.GroupElement;

import java.math.BigInteger;

public class IncentiveSystemPublicParameters {
	BilinearGroup group;

	/** shared base for ElGamal encryption */
	GroupElement w;

	/** maximum point score */
	BigInteger maxValue;

	/** group elements for commitment */
	GroupElement g1, h7;

	NguyenAccumulatorPublicParameters nguyenPP;

	private ZeroToUPowLRangeProofPublicParameters spendDeductRangePP;

	public IncentiveSystemPublicParameters(BilinearGroup group, GroupElement w, GroupElement h7, GroupElement g1, BigInteger maxValue, NguyenAccumulatorPublicParameters nguyenPP, ZeroToUPowLRangeProofPublicParameters spendDeductRangePP) {
		this.group = group;
		this.w = w;
		this.maxValue = maxValue;
		this.g1 = g1;
		this.h7 = h7;
		this.nguyenPP = nguyenPP;
		this.spendDeductRangePP = spendDeductRangePP;
	}

	public ZeroToUPowLRangeProofPublicParameters getSpendDeductRangePP(GroupElement commitment) {
		return new ZeroToUPowLRangeProofPublicParameters(spendDeductRangePP, commitment);
	}
}
