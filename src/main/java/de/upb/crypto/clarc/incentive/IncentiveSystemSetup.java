package de.upb.crypto.clarc.incentive;

import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParameters;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParametersGen;
import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.factory.BilinearGroupFactory;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;

import java.math.BigInteger;

/**
 * Setup of the incentive system.
 */
public class IncentiveSystemSetup {

	public IncentiveSystemPublicParameters generatePublicParameter(int securityParameter) {
		BilinearGroupFactory fac = new BilinearGroupFactory(securityParameter);
		fac.setRequirements(BilinearGroup.Type.TYPE_3);
		BilinearGroup group = fac.createBilinearGroup();

		Group g1 = group.getG1();
		// w <- G1
		GroupElement w = g1.getUniformlyRandomElement();
		// vMax = p-1
		BigInteger vMax = g1.size().subtract(BigInteger.ONE);
		// g,h <- G1
		GroupElement g = g1.getUniformlyRandomElement();
		GroupElement h = g1.getUniformlyRandomElement();

		NguyenAccumulatorPublicParametersGen nguyenGen = new NguyenAccumulatorPublicParametersGen();
		NguyenAccumulatorPublicParameters nguyenPP = nguyenGen.setup(group.getBilinearMap(), 100);

		return new IncentiveSystemPublicParameters(group, w, h, g, vMax, nguyenPP);
	}
}
