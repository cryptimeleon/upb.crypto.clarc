package de.upb.crypto.clarc.predicategeneration.equalityproofs;

import de.upb.crypto.clarc.predicategeneration.parametergeneration.EqualityParameterGen;
import de.upb.crypto.clarc.protocols.expressions.arith.NumberGroupElementLiteral;
import de.upb.crypto.clarc.protocols.expressions.arith.PowerGroupElementExpression;
import de.upb.crypto.clarc.protocols.expressions.arith.ProductGroupElementExpression;
import de.upb.crypto.clarc.protocols.expressions.arith.ZnVariable;
import de.upb.crypto.clarc.protocols.expressions.comparison.ArithComparisonExpression;
import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.protocolfactory.GeneralizedSchnorrProtocolFactory;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.HashMap;
import java.util.Map;

import static de.upb.crypto.clarc.predicategeneration.fixedprotocols.PredicateTypePrimitive.EQUALITY_2_ATTRIBUTES;
import static de.upb.crypto.clarc.predicategeneration.fixedprotocols.PredicateTypePrimitive.EQUALITY_DLOG;

public class EqualityProtocolFactory {

    private static final String PREFIX_COMMITMENT_RANDOM = "r_";
    private static final String PREFIX_ALPHA = "alpha_";
    private EqualityPublicParameters epp;
    private String uniqueName;

    /**
     * Constructor taking predefined {@link EqualityPublicParameters} (generated using the {@link EqualityParameterGen}
     * and unique name of the protocol, for an equality-proof (Construction 5.1.1 or Construction 5.1.2),
     * depending on the {@link EqualityPublicParameters}
     *
     * @param equailtyPP for the proof
     * @param uniqueName unique name for the protocol
     */
    public EqualityProtocolFactory(EqualityPublicParameters equailtyPP, String uniqueName) {
        epp = equailtyPP;
        this.uniqueName = uniqueName;
    }

    /**
     * Returns a prover protocol for an equality proof.
     *
     * @param commitmentPair          for the attribute
     * @param zpRepresentationOfAlpha used to proof equally to
     * @return a prover protocol.
     */
    public GeneralizedSchnorrProtocol getProverProtocol(PedersenCommitmentPair commitmentPair,
                                                        Zp.ZpElement zpRepresentationOfAlpha) {
        ArithComparisonExpression[] problems;
        GeneralizedSchnorrProtocolFactory factory;
        Map<String, Zp.ZpElement> witnesses;

        switch (epp.getType()) {
            case EQUALITY_DLOG:
                problems = getFirstConstructionProblems(uniqueName);
                factory =
                        new GeneralizedSchnorrProtocolFactory(problems, epp.getZp());
                witnesses =
                        getWitnessesForFirstConstruction(commitmentPair, zpRepresentationOfAlpha, uniqueName);
                return factory.createProverGeneralizedSchnorrProtocol(witnesses);

            case EQUALITY_PUBLIC_VALUE:
                problems = getSecondConstructionProblems(uniqueName);
                factory = new GeneralizedSchnorrProtocolFactory(problems, epp.getZp());
                witnesses =
                        getWitnessesForSecondConstruction(commitmentPair.getOpenValue().getRandomValue(), uniqueName);
                return factory.createProverGeneralizedSchnorrProtocol(witnesses);

            default:
                throw new IllegalArgumentException("Cannot use this constructor, since inequality of two commitments " +
                        "needs to be proven");
        }
    }

    /**
     * Creates a prover protocol for proving inequality of two attributes.
     * Note that the position of the second commitment needs to be set in the {@link EqualityPublicParameters}
     *
     * @param commitmentPair1 random value used in first commitment
     * @param commitmentPair2 random value used in second commitment
     * @return a prover protocol
     */
    public GeneralizedSchnorrProtocol getProverProtocol(PedersenCommitmentPair commitmentPair1,
                                                        PedersenCommitmentPair commitmentPair2) {
        if (epp.getType() == EQUALITY_2_ATTRIBUTES) {
            ArithComparisonExpression[] problems = getSecondConstructionProblems(uniqueName);
            GeneralizedSchnorrProtocolFactory factory =
                    new GeneralizedSchnorrProtocolFactory(problems, epp.getZp());
            Zp.ZpElement randomValueOfCommitment =
                    (Zp.ZpElement) commitmentPair1.getOpenValue().getRandomValue()
                            .sub(commitmentPair2.getOpenValue().getRandomValue());
            Map<String, Zp.ZpElement> witnesses =
                    getWitnessesForSecondConstruction(randomValueOfCommitment, uniqueName);
            return factory.createProverGeneralizedSchnorrProtocol(witnesses);
        } else {
            throw new IllegalArgumentException("Cannot use this constructor, since inequality of two commitments " +
                    "needs to be proven");
        }
    }

    /**
     * @return a verifier protocol for an equality proof.
     */
    public GeneralizedSchnorrProtocol getVerifierProtocol() {
        if (epp.getType() == EQUALITY_DLOG) {
            ArithComparisonExpression[] problems = getFirstConstructionProblems(uniqueName);
            GeneralizedSchnorrProtocolFactory factory =
                    new GeneralizedSchnorrProtocolFactory(problems, epp.getZp());
            return factory.createVerifierGeneralizedSchnorrProtocol();
        } else {
            ArithComparisonExpression[] problems = getSecondConstructionProblems(uniqueName);
            GeneralizedSchnorrProtocolFactory factory =
                    new GeneralizedSchnorrProtocolFactory(problems, epp.getZp());
            return factory.createVerifierGeneralizedSchnorrProtocol();
        }
    }


    private ArithComparisonExpression[] getFirstConstructionProblems(String uniqueName) {
        ArithComparisonExpression[] expressions = new ArithComparisonExpression[2];
        // To ensure that all witnesses values are mapped correctly, the unique name is used as postfix

        // Create first equation as C = g_1^r \op h ^\alpha
        ProductGroupElementExpression rhs1 = new ProductGroupElementExpression();
        rhs1.addElement(new PowerGroupElementExpression(new NumberGroupElementLiteral(epp.getG1()),
                new ZnVariable(PREFIX_COMMITMENT_RANDOM + uniqueName)));
        rhs1.addElement(new PowerGroupElementExpression(new NumberGroupElementLiteral(epp.getH()),
                new ZnVariable(PREFIX_ALPHA + uniqueName)));
        expressions[0] = new GroupElementEqualityExpression(new NumberGroupElementLiteral(epp.getCommitment()), rhs1);

        // Create second equation y = g_2 ^\alpha
        if (!(epp instanceof EqualityPublicParameterUnknownValue)) {
            throw new IllegalArgumentException("The created public parameter are not valid!");
        }
        EqualityPublicParameterUnknownValue eppUnknown = (EqualityPublicParameterUnknownValue) epp;
        ProductGroupElementExpression rhs2 = new ProductGroupElementExpression();
        rhs2.addElement(new PowerGroupElementExpression(new NumberGroupElementLiteral(eppUnknown.getG2()),
                new ZnVariable(PREFIX_ALPHA + uniqueName)));
        expressions[1] = new GroupElementEqualityExpression(new NumberGroupElementLiteral(eppUnknown.getY()), rhs2);

        return expressions;
    }

    private Map<String, Zp.ZpElement> getWitnessesForFirstConstruction(PedersenCommitmentPair commitmentPair,
                                                                       Zp.ZpElement zpRepresentationOfAlpha,
                                                                       String uniqueName) {
        Map<String, Zp.ZpElement> witnesses = new HashMap<>();
        witnesses.put(PREFIX_COMMITMENT_RANDOM + uniqueName, commitmentPair.getOpenValue().getRandomValue());
        witnesses.put(PREFIX_ALPHA + uniqueName, zpRepresentationOfAlpha);
        return witnesses;
    }


    private ArithComparisonExpression[] getSecondConstructionProblems(String uniqueName) {
        ArithComparisonExpression[] expressions = new ArithComparisonExpression[1];
        // To ensure that all witnesses values are mapped correctly, the unique name is used as postfix

        // Create first equation as C \op h^(-s)= g_1^r
        EqualityPublicParameterAdvancedProof eppAdvanced = (EqualityPublicParameterAdvancedProof) epp;
        GroupElement lhs = epp.getCommitment().op(epp.getH().pow(eppAdvanced.getKnownDlog().neg()));

        ProductGroupElementExpression rhs = new ProductGroupElementExpression();
        rhs.addElement(new PowerGroupElementExpression(new NumberGroupElementLiteral(epp.getG1()),
                new ZnVariable(PREFIX_COMMITMENT_RANDOM + uniqueName)));
        expressions[0] = new GroupElementEqualityExpression(new NumberGroupElementLiteral(lhs), rhs);
        return expressions;
    }

    private Map<String, Zp.ZpElement> getWitnessesForSecondConstruction(Zp.ZpElement randomValueOfCommitment,
                                                                        String uniqueName) {
        Map<String, Zp.ZpElement> witnesses = new HashMap<>();
        witnesses.put(PREFIX_COMMITMENT_RANDOM + uniqueName, randomValueOfCommitment);
        return witnesses;
    }
}