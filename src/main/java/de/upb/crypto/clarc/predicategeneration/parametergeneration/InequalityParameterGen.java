package de.upb.crypto.clarc.predicategeneration.parametergeneration;

import de.upb.crypto.clarc.predicategeneration.inequalityproofs.InequalityProofProtocol;
import de.upb.crypto.clarc.predicategeneration.inequalityproofs.InequalityPublicParameters;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

public class InequalityParameterGen {

    /**
     * Generate {@link InequalityPublicParameters} to create an instance of {@link InequalityProofProtocol} to prove
     * inequality of a committed value to a given public value.
     *
     * @param pedersenPublicParameters the public parameters of the commitment scheme used in the system
     * @param bilinearMap              the bilinear map used in the pairing operations of the system
     * @param positionInCredential     position in the space / credential of the value inequality in proven for
     * @param publicValue              value for which the inequality shall be proven
     * @return parameters to create {@link InequalityProofProtocol} to prove inequality of a committed value to the
     * given public value
     */
    public static InequalityPublicParameters createInequalityPP(PedersenPublicParameters pedersenPublicParameters,
                                                                BilinearMap bilinearMap, int positionInCredential,
                                                                Zp.ZpElement publicValue, Zp zp) {

        GroupElement g2 = bilinearMap.getGT().getGenerator();
        GroupElement y = g2.pow(publicValue);

        GroupElement h = pedersenPublicParameters.getH()[0];
        GroupElement g1 = pedersenPublicParameters.getG();
        return new InequalityPublicParameters(g1, h, g2, y, positionInCredential, zp);
    }
}
