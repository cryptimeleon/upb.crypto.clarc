package de.upb.crypto.clarc.acs.protocols.impl.clarc;

import de.upb.crypto.clarc.acs.protocols.ProtocolFactory;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserKeyPair;
import de.upb.crypto.clarc.protocols.expressions.arith.*;
import de.upb.crypto.clarc.protocols.expressions.comparison.ArithComparisonExpression;
import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.protocolfactory.GeneralizedSchnorrProtocolFactory;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class JoinProtocolFactory implements ProtocolFactory {
    private PublicParameters pp;
    private UserKeyPair userKeyPair;
    private PSExtendedVerificationKey systemManagerPublicKey;

    public JoinProtocolFactory(PublicParameters pp,
                               UserKeyPair userKeyPair,
                               PSExtendedVerificationKey systemManagerPublicKey) {
        this.pp = pp;
        this.userKeyPair = userKeyPair;
        this.systemManagerPublicKey = systemManagerPublicKey;
    }

    @Override
    public GeneralizedSchnorrProtocol getProtocol() {
        GroupElement upkElement = pp.getBilinearMap().getG1().getElement(userKeyPair.getUserPublicKey().getUpk());
        ArithGroupElementExpression upk = new NumberGroupElementLiteral(upkElement);
        ArithGroupElementExpression g = new NumberGroupElementLiteral(systemManagerPublicKey.getGroup1ElementG());
        ArithZnElementExpression usk = new ZnVariable("usk");
        ArithGroupElementExpression g_usk = new PowerGroupElementExpression(g, usk);

        List<ArithGroupElementExpression> expression = new ArrayList<>();
        expression.add(g_usk);
        ArithGroupElementExpression rightSideExpression = new ProductGroupElementExpression(expression);


        ArithComparisonExpression equality = new GroupElementEqualityExpression(upk, rightSideExpression);


        ArithComparisonExpression[] listOfProblems = {equality};
        GeneralizedSchnorrProtocolFactory generalizedSchnorrProtocolFactory = new GeneralizedSchnorrProtocolFactory
                (listOfProblems, pp.getZp());

        HashMap<String, Zp.ZpElement> witnessMapping = new HashMap<>();
        witnessMapping.put("usk", userKeyPair.getUserSecret().getUsk());

        return generalizedSchnorrProtocolFactory.createProverGeneralizedSchnorrProtocol(witnessMapping);
    }
}
