package de.upb.crypto.clarc.acs.protocols.impl.clarc.mastercred;

import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.ProverIncludingMasterProtocolFactory;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.systemmanager.SystemManager;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserSecret;
import de.upb.crypto.clarc.protocols.expressions.arith.*;
import de.upb.crypto.clarc.protocols.expressions.comparison.ArithComparisonExpression;
import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.protocolfactory.GeneralizedSchnorrProtocolFactory;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Factory for generating a prover protocol for proving possession of a valid master credential.
 * <p>
 * The resulting protocol is an intermediate protocol used during proveCred with additional verification of a valid
 * master credential. (see {@link ProverIncludingMasterProtocolFactory})
 */
public class MasterCredentialProverProtocolFactory extends MasterCredentialProtocolFactory {

    private final UserSecret usk;

    /**
     * Creates a factory which is able to generate a prover protocol for proving possession of a valid master
     * credential.
     *
     * @param pp                     the system's public parameters
     * @param systemManagerPublicKey public key of the {@link SystemManager}
     * @param masterCredential       the master credential to be verified
     * @param usk                    the {@link de.upb.crypto.clarc.acs.user.UserSecret} used to join the system
     */
    public MasterCredentialProverProtocolFactory(PublicParameters pp,
                                                 PSExtendedVerificationKey systemManagerPublicKey,
                                                 PSSignature masterCredential,
                                                 UserSecret usk) {
        super(pp, systemManagerPublicKey, masterCredential);
        this.usk = usk;
    }

    @Override
    public GeneralizedSchnorrProtocol getProtocol() {
        // Create a GeneralizedSchnorrProtocol proving that the master credential is a valid signature over the usk
        // of the prover. See construction 4.9

        BilinearMap map = pp.getBilinearMap();

        ArithGroupElementExpression e_left_expr = new PairingGroupElementExpression(map,
                new NumberGroupElementLiteral(masterCredential.getGroup1ElementSigma1()),
                new NumberGroupElementLiteral(systemManagerPublicKey.getGroup2ElementsTildeYi()[0]));
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

        HashMap<String, Zp.ZpElement> witnessMapping = new HashMap<>();
        witnessMapping.put("usk", usk.getUsk());

        return generalizedSchnorrProtocolFactory.createProverGeneralizedSchnorrProtocol(witnessMapping);
    }
}
