package de.upb.crypto.clarc.acs.protocols.impl.clarc.mastercred;

import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.VerifierIncludingMasterProtocolFactory;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.systemmanager.SystemManager;
import de.upb.crypto.clarc.protocols.expressions.arith.*;
import de.upb.crypto.clarc.protocols.expressions.comparison.ArithComparisonExpression;
import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.protocolfactory.GeneralizedSchnorrProtocolFactory;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.GroupElement;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Factory for generating a verifier protocol for verifying possession of a valid master credential.
 * <p>
 * The resulting protocol is an intermediate protocol used during proveCred with additional verification of a valid
 * master credential. (see {@link VerifierIncludingMasterProtocolFactory})
 */
public class MasterCredentialVerifierProtocolFactory extends MasterCredentialProtocolFactory {

    /**
     * Creates a factory which is able to generate a verifier protocol for proving possession of a valid master
     * credential.
     *
     * @param pp                     the system's public parameters
     * @param systemManagerPublicKey public key of the {@link SystemManager}
     * @param masterCredential       the prover's master credential to be verified
     */
    public MasterCredentialVerifierProtocolFactory(PublicParameters pp,
                                                   PSExtendedVerificationKey systemManagerPublicKey,
                                                   PSSignature masterCredential) {
        super(pp, systemManagerPublicKey, masterCredential);
    }

    @Override
    public GeneralizedSchnorrProtocol getProtocol() {
        // Create a GeneralizedSchnorrProtocol verifying that the master credential is a valid signature over the usk
        // of the prover. See construction 4.9

        BilinearMap map = pp.getBilinearMap();

        GroupElement e_left = map.apply(masterCredential.getGroup1ElementSigma1(),
                systemManagerPublicKey.getGroup2ElementsTildeYi()[0]);
        ArithGroupElementExpression e_left_expr = new NumberGroupElementLiteral(e_left);
        ArithZnElementExpression userSecret = new ZnVariable("usk");

        PairingGroupElementExpression e_left_top = new PairingGroupElementExpression(map,
                new NumberGroupElementLiteral(masterCredential.getGroup1ElementSigma2()),
                new NumberGroupElementLiteral(systemManagerPublicKey.getGroup2ElementTildeG()));
        PairingGroupElementExpression e_left_bottom = new PairingGroupElementExpression(map,
                new NumberGroupElementLiteral(masterCredential.getGroup1ElementSigma1()),
                new NumberGroupElementLiteral(systemManagerPublicKey.getGroup2ElementTildeX()),
                BigInteger.ONE.negate());
        ProductGroupElementExpression leftSide = new ProductGroupElementExpression(e_left_top, e_left_bottom);

        ArithGroupElementExpression rightSide = new PowerGroupElementExpression(e_left_expr, userSecret);
        List<ArithGroupElementExpression> rightSideList = new ArrayList<>();
        rightSideList.add(rightSide);
        ArithGroupElementExpression rightExpression = new ProductGroupElementExpression(rightSideList);

        ArithComparisonExpression equality = new GroupElementEqualityExpression(leftSide, rightExpression);

        ArithComparisonExpression[] listOfProblems = {equality};
        GeneralizedSchnorrProtocolFactory generalizedSchnorrProtocolFactory =
                new GeneralizedSchnorrProtocolFactory(listOfProblems, pp.getZp());

        return generalizedSchnorrProtocolFactory.createVerifierGeneralizedSchnorrProtocol();
    }
}
