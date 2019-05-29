package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofProtocolFactory;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofPublicParameters;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParameters;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParametersGen;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.factory.BilinearGroupFactory;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.pairings.mcl.MclBilinearGroupProvider;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.Collections;

/**
 * Setup of the incentive system.
 */
public class IncentiveSystemSetup {

	public IncentiveSystemPublicParameters generatePublicParameter(int securityParameter) {
		BilinearGroupFactory fac = new BilinearGroupFactory(securityParameter);
		fac.setRequirements(BilinearGroup.Type.TYPE_3);
		fac.registerProvider(Collections.singletonList(new MclBilinearGroupProvider()));
		BilinearGroup group = fac.createBilinearGroup();

		Group groupG1 = group.getG1();
		// w <- G1
		GroupElement w = groupG1.getUniformlyRandomNonNeutral();
		// vMax = p-1
		BigInteger vMax = groupG1.size().subtract(BigInteger.ONE);
		// g1,h7 <- G1
		GroupElement g1 = groupG1.getUniformlyRandomNonNeutral();
		GroupElement h7 = groupG1.getUniformlyRandomNonNeutral();

		int baseRangeProof = 32;
		NguyenAccumulatorPublicParametersGen nguyenGen = new NguyenAccumulatorPublicParametersGen();
		NguyenAccumulatorPublicParameters nguyenPP = nguyenGen.setup(group.getBilinearMap(), baseRangeProof+1);

		PedersenPublicParameters pedersenPP = new PedersenPublicParameters(g1, new GroupElement[] { h7 }, groupG1);
		Zp zp = new Zp(group.getG1().size());
		PedersenCommitmentScheme pedersen = new PedersenCommitmentScheme(pedersenPP);

		ZeroToUPowLRangeProofPublicParameters spendDeductRangePP = new ZeroToUPowLRangeProofProtocolFactory(pedersen.commit(new RingElementPlainText(zp.getZeroElement())).getCommitmentValue(), pedersenPP, BigInteger.valueOf(baseRangeProof), Math.max(1, (int) (32) / ((int) Math.log(baseRangeProof))), 0, zp, nguyenPP, "Spend/Deduct").getVerifierProtocol().getPublicParameters();

		return new IncentiveSystemPublicParameters(group, w, h7, g1, vMax, nguyenPP, spendDeductRangePP);
	}
}
