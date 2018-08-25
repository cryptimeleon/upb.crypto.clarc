package de.upb.crypto.clarc.acs.protocols.impl.clarc;

import de.upb.crypto.clarc.acs.protocols.ProtocolFactory;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Identity;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserSecret;
import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.damgardtechnique.DamgardTechnique;
import de.upb.crypto.clarc.protocols.expressions.arith.*;
import de.upb.crypto.clarc.protocols.expressions.comparison.ArithComparisonExpression;
import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.protocolfactory.GeneralizedSchnorrProtocolFactory;
import de.upb.crypto.craco.commitment.interfaces.CommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class RequestCredentialProtocolFactory implements ProtocolFactory {
    private PedersenPublicParameters pedersenPublicParameters;
    private Identity clarcIdentity;
    private PedersenCommitmentPair commitment;
    private PublicParameters pp;
    private UserSecret usk;

    public RequestCredentialProtocolFactory(
            PedersenPublicParameters pedersenPublicParameters, Identity clarcIdentity,
            PedersenCommitmentPair commitment, PublicParameters pp,
            UserSecret usk) {
        this.pedersenPublicParameters = pedersenPublicParameters;
        this.clarcIdentity = clarcIdentity;
        this.commitment = commitment;
        this.pp = pp;
        this.usk = usk;
    }

    @Override
    public InteractiveThreeWayAoK getProtocol() {
        ArithGroupElementExpression one = new NumberGroupElementLiteral(pedersenPublicParameters.getG().getStructure
                ().getNeutralElement());
        ArithGroupElementExpression nym = new NumberGroupElementLiteral(clarcIdentity.getPseudonym().getCommitmentValue().getCommitmentElement());
        ArithGroupElementExpression c = new NumberGroupElementLiteral(commitment.getCommitmentValue()
                .getCommitmentElement());

        // gnym^(r_1)
        ArithGroupElementExpression gnym = new NumberGroupElementLiteral(pp.getSingleMessageCommitmentPublicParameters().getG());
        ArithZnElementExpression r1 = new ZnVariable("r1");
        ArithGroupElementExpression gnym_r1 = new PowerGroupElementExpression(gnym, r1);

        // h^usk
        ArithGroupElementExpression hnym = new NumberGroupElementLiteral(pp.getSingleMessageCommitmentPublicParameters().getH()[0]);
        ArithZnElementExpression uskExpression = new ZnVariable("usk");
        ArithGroupElementExpression hnym_usk = new PowerGroupElementExpression(hnym, uskExpression);

        // g^(r_2)
        ArithGroupElementExpression g = new NumberGroupElementLiteral(pedersenPublicParameters.getG());
        ArithZnElementExpression r2 = new ZnVariable("r2");
        ArithGroupElementExpression g_r2 = new PowerGroupElementExpression(g, r2);

        // Y_0^usk
        ArithGroupElementExpression Y0 = new NumberGroupElementLiteral(pedersenPublicParameters.getH()[0]);
        ArithGroupElementExpression Y0_usk = new PowerGroupElementExpression(Y0, uskExpression);

        // 1^(r_1)
        ArithGroupElementExpression one_r1 = new PowerGroupElementExpression(one, r1);

        // 1^(r_2)
        ArithGroupElementExpression one_r2 = new PowerGroupElementExpression(one, r2);

        // g^(r_1) h^usk 1^(r_2)
        List<ArithGroupElementExpression> leftSide = new ArrayList<>();
        leftSide.add(gnym_r1);
        leftSide.add(hnym_usk);
        leftSide.add(one_r2);
        ArithGroupElementExpression leftSideExpression = new ProductGroupElementExpression(leftSide);

        // 1^(r_1) Y0^usk g^(r_2)
        List<ArithGroupElementExpression> rightSide = new ArrayList<>();
        rightSide.add(one_r1);
        rightSide.add(Y0_usk);
        rightSide.add(g_r2);
        ArithGroupElementExpression rightSideExpression = new ProductGroupElementExpression(rightSide);

        // nym = g^(r_1) h^usk 1^(r_2)
        ArithComparisonExpression leftEquality = new GroupElementEqualityExpression(nym, leftSideExpression);

        // C = 1^(r_1) Y0^usk g^(r_2)
        ArithComparisonExpression rightEquality = new GroupElementEqualityExpression(c, rightSideExpression);

        ArithComparisonExpression[] listOfProblems = {leftEquality, rightEquality};
        GeneralizedSchnorrProtocolFactory generalizedSchnorrProtocolFactory = new GeneralizedSchnorrProtocolFactory
                (listOfProblems, pp.getZp());

        HashMap<String, Zp.ZpElement> witnessMapping = new HashMap<>();
        witnessMapping.put("usk", usk.getUsk());
        witnessMapping.put("r1", clarcIdentity.getPseudonymSecret().getRandomValue());
        witnessMapping.put("r2", commitment.getOpenValue().getRandomValue());
        return applyDamgardsTechnique(generalizedSchnorrProtocolFactory
                .createProverGeneralizedSchnorrProtocol(witnessMapping));
    }

    InteractiveThreeWayAoK applyDamgardsTechnique(GeneralizedSchnorrProtocol protocol) {
        CommitmentScheme commitmentScheme =
                PublicParametersFactory.getMultiMessageCommitmentScheme(pp);
        return new DamgardTechnique(protocol, commitmentScheme);
    }
}
