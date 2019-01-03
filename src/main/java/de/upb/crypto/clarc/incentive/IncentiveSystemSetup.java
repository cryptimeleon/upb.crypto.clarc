package de.upb.crypto.clarc.incentive;

import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.factory.BilinearGroupFactory;
import de.upb.crypto.math.pairings.bn.BarretoNaehrigProvider;
import de.upb.crypto.math.pairings.mcl.MclBilinearGroupProvider;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;

/**
 * Setup of the incentive system.
 */
public class IncentiveSystemSetup {

	public IncentiveSystemPublicParameters generatePublicParameter(int securityParameter) {
		BilinearGroupFactory fac = new BilinearGroupFactory(securityParameter);
		fac.setRequirements(BilinearGroup.Type.TYPE_3);
		fac.registerProvider(Arrays.asList(new MclBilinearGroupProvider(), new BarretoNaehrigProvider()));
		BilinearGroup group = fac.createBilinearGroup();

		return new IncentiveSystemPublicParameters(group, group.getG1().getUniformlyRandomElement(), group.getG1().size().subtract(BigInteger.ONE));
	}
}
