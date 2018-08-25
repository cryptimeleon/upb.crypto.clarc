package de.upb.crypto.clarc.acs.protocols.impl.clarc;

import de.upb.crypto.clarc.acs.protocols.ProtocolFactory;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserPublicKey;
import de.upb.crypto.clarc.protocols.expressions.arith.*;
import de.upb.crypto.clarc.protocols.expressions.comparison.ArithComparisonExpression;
import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.protocolfactory.GeneralizedSchnorrProtocolFactory;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.math.interfaces.structures.GroupElement;

import java.util.ArrayList;
import java.util.List;

public class JoinVerifyProtocolFactory implements ProtocolFactory {
    private PublicParameters pp;
    private UserPublicKey userPublicKey;
    private PSExtendedVerificationKey systemManagerVerificationKey;

    public JoinVerifyProtocolFactory(PublicParameters pp,
                                     UserPublicKey userPublicKey,
                                     PSExtendedVerificationKey systemManagerVerificationKey) {
        this.pp = pp;
        this.userPublicKey = userPublicKey;
        this.systemManagerVerificationKey = systemManagerVerificationKey;
    }

    @Override
    public GeneralizedSchnorrProtocol getProtocol() {
        GroupElement upkElement = pp.getBilinearMap().getG1().getElement(userPublicKey.getUpk());
        ArithGroupElementExpression upk = new NumberGroupElementLiteral(upkElement);
        ArithGroupElementExpression g =
                new NumberGroupElementLiteral(systemManagerVerificationKey.getGroup1ElementG());
        ArithZnElementExpression usk = new ZnVariable("usk");
        ArithGroupElementExpression g_usk = new PowerGroupElementExpression(g, usk);


        List<ArithGroupElementExpression> expression = new ArrayList<>();
        expression.add(g_usk);
        ArithGroupElementExpression rightSideExpression = new ProductGroupElementExpression(expression);

        ArithComparisonExpression equality = new GroupElementEqualityExpression(upk, rightSideExpression);

        ArithComparisonExpression[] listOfProblems = {equality};
        GeneralizedSchnorrProtocolFactory generalizedSchnorrProtocolFactory = new GeneralizedSchnorrProtocolFactory(listOfProblems, pp.getZp());

        return generalizedSchnorrProtocolFactory.createVerifierGeneralizedSchnorrProtocol();
    }
}
