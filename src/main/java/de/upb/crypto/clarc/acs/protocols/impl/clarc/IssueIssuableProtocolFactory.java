package de.upb.crypto.clarc.acs.protocols.impl.clarc;

import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerKeyPairFactory;
import de.upb.crypto.clarc.acs.protocols.ProtocolFactory;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Pseudonym;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.damgardtechnique.DamgardTechnique;
import de.upb.crypto.clarc.protocols.expressions.arith.*;
import de.upb.crypto.clarc.protocols.expressions.comparison.ArithComparisonExpression;
import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.protocolfactory.GeneralizedSchnorrProtocolFactory;
import de.upb.crypto.craco.commitment.interfaces.CommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;

import java.util.ArrayList;
import java.util.List;

public class IssueIssuableProtocolFactory implements ProtocolFactory {
    private PublicParameters pp;
    private PSExtendedVerificationKey issuerVerificationKey;
    private PedersenCommitmentValue pseudonymCommitment;
    private PedersenCommitmentValue commitment;

    public IssueIssuableProtocolFactory(PublicParameters pp,
                                        PSExtendedVerificationKey issuerVerificationKey,
                                        Pseudonym pseudonym,
                                        PedersenCommitmentValue commitment) {
        this.pp = pp;
        this.issuerVerificationKey = issuerVerificationKey;
        this.pseudonymCommitment = pseudonym.getCommitmentValue();
        this.commitment = commitment;
    }

    @Override
    public InteractiveThreeWayAoK getProtocol() {
        // Proof of knowledge with User for usk and pseudonym
        final PedersenPublicParameters pedersenPublicParameters =
                IssuerKeyPairFactory.getPedersenPPForSingleValueFromIssuerPK(pp, issuerVerificationKey);
        ArithGroupElementExpression one = new NumberGroupElementLiteral(pedersenPublicParameters.getG().getStructure
                ().getNeutralElement());
        ArithGroupElementExpression nym = new NumberGroupElementLiteral(pseudonymCommitment.getCommitmentElement());
        ArithGroupElementExpression c = new NumberGroupElementLiteral(commitment.getCommitmentElement());

        // gnym^(r_1)
        ArithGroupElementExpression gnym = new NumberGroupElementLiteral(pp.getSingleMessageCommitmentPublicParameters().getG());
        ArithZnElementExpression r1 = new ZnVariable("r1");
        ArithGroupElementExpression gnym_r1 = new PowerGroupElementExpression(gnym, r1);

        // h^usk
        ArithGroupElementExpression hnym = new NumberGroupElementLiteral(pp.getSingleMessageCommitmentPublicParameters().getH()[0]);
        ArithZnElementExpression usk = new ZnVariable("usk");
        ArithGroupElementExpression hnym_usk = new PowerGroupElementExpression(hnym, usk);

        // g^(r_2)
        ArithGroupElementExpression g = new NumberGroupElementLiteral(pedersenPublicParameters.getG());
        ArithZnElementExpression r2 = new ZnVariable("r2");
        ArithGroupElementExpression g_r2 = new PowerGroupElementExpression(g, r2);

        // Y_0^usk
        ArithGroupElementExpression Y0 = new NumberGroupElementLiteral(pedersenPublicParameters.getH()[0]);
        ArithGroupElementExpression Y0_usk = new PowerGroupElementExpression(Y0, usk);

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

        // C = //1^(r_1) Y0^usk g^(r_2)
        ArithComparisonExpression rightEquality = new GroupElementEqualityExpression(c, rightSideExpression);

        ArithComparisonExpression[] listOfProblems = {leftEquality, rightEquality};
        GeneralizedSchnorrProtocolFactory generalizedSchnorrProtocolFactory = new GeneralizedSchnorrProtocolFactory
                (listOfProblems, pp.getZp());

        return applyDamgardsTechnique(generalizedSchnorrProtocolFactory.createVerifierGeneralizedSchnorrProtocol());
    }

    InteractiveThreeWayAoK applyDamgardsTechnique(GeneralizedSchnorrProtocol protocol) {
        CommitmentScheme commitmentScheme =
                PublicParametersFactory.getMultiMessageCommitmentScheme(pp);
        return new DamgardTechnique(protocol, commitmentScheme);
    }

}
