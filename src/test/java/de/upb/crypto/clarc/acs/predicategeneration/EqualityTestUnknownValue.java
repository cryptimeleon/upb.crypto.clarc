package de.upb.crypto.clarc.acs.predicategeneration;

import de.upb.crypto.clarc.acs.testdataprovider.IssuerTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.ParameterTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.PredicatePrimitiveTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.UserAndSystemManagerTestdataProvider;
import de.upb.crypto.clarc.predicategeneration.equalityproofs.EqualityProtocolFactory;
import de.upb.crypto.clarc.predicategeneration.equalityproofs.EqualityPublicParameterUnknownValue;
import de.upb.crypto.clarc.protocols.InteractiveThreeWayAoKTester;
import de.upb.crypto.clarc.protocols.expressions.comparison.ArithComparisonExpression;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProblem;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.protocolfactory.GeneralizedSchnorrProtocolFactory;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class EqualityTestUnknownValue {

    private static final String NAME = "test";

    private GeneralizedSchnorrProtocol protocolProver;
    // different prover-protocol for negative test cases
    private GeneralizedSchnorrProtocol secondProtocolProver;
    private GeneralizedSchnorrProtocol protocolVerifier;


    @BeforeAll
    public void setUp() {
        ParameterTestdataProvider clarcProvider = new ParameterTestdataProvider();
        UserAndSystemManagerTestdataProvider userProvider =
                new UserAndSystemManagerTestdataProvider(clarcProvider.getPublicParameters());
        IssuerTestdataProvider issuerProvider = new IssuerTestdataProvider(clarcProvider.getPublicParameters(),
                clarcProvider.getSignatureScheme(), userProvider.getUserSecret());
        PredicatePrimitiveTestdataProvider predicateProvider =
                new PredicatePrimitiveTestdataProvider(clarcProvider.getPublicParameters(),
                        issuerProvider.getCredentialWitfDefaultAttributeSpace());
        protocolProver = createEqualityProofProtocolForAttributeAtPosition(predicateProvider, 0);
        Announcement[] protocolProverAnnouncement = protocolProver.generateAnnouncements();
        do {
            secondProtocolProver = createEqualityProofProtocolForAttributeAtPosition(predicateProvider, 0);

        } while (protocolProver.equals(secondProtocolProver));
        GeneralizedSchnorrProtocolFactory factory = new GeneralizedSchnorrProtocolFactory(Arrays
                .stream(protocolProver.getProblems())
                .map(p -> ((GeneralizedSchnorrProblem) p).getProblemEquation())
                .toArray(ArithComparisonExpression[]::new)
                , clarcProvider.getPublicParameters().getZp());
        protocolVerifier = factory.createVerifierGeneralizedSchnorrProtocol();
    }

    private static GeneralizedSchnorrProtocol createEqualityProofProtocolForAttributeAtPosition(
            PredicatePrimitiveTestdataProvider predProvider, int pos) {
        PedersenCommitmentPair com = predProvider.getCommitmentForAttribute(pos);
        EqualityPublicParameterUnknownValue epp = predProvider.getEqualityUnknownDlogPP(pos, com);
        EqualityProtocolFactory factory = new EqualityProtocolFactory(epp, NAME);
        return factory.getProverProtocol(com, predProvider.getZPRepresentationForAttrAtPos(pos));
    }

    /**
     * Positive test checking that for a correct protocol execution the verifier accepts.
     * The test is checking the protocol execution with internal randomness.
     */
    @Test
    void testEqualityInternalRandomness() {
        InteractiveThreeWayAoKTester.protocolExecutionInternalRandomnessTest(protocolProver, protocolVerifier);
        assertArrayEquals(protocolVerifier.getProblems(), protocolProver.getProblems(), "The problems of the " +
                "Generalized Schnorr protocols with internal randomness are unequal!");
    }

    /**
     * This negative test checks cases where the verify method is called with not matching parameters and therefore
     * should return false for internal randomness.
     */
    @Test
    void testNeqEqualityInternalRandomness() {
        InteractiveThreeWayAoKTester.protocolExecutionInternalRandomnessNegativeTest(protocolProver,
                secondProtocolProver, protocolVerifier);
        assertArrayEquals(protocolVerifier.getProblems(), protocolProver.getProblems(), "The problems of the " +
                "Generalized Schnorr protocols with internal randomness are unequal!");
    }

    /**
     * This test checks the representation usage within the protocol execution. In this case a correct protocol
     * execution is performed checking the representation for announcement, challenge and response; then a correct
     * protocol execution is performed checking the representation the GeneralizedSchnorrProtocol itself.
     */
    @Test
    void protocolExecutionRepresentationTest() {
        InteractiveThreeWayAoKTester.representationForProtocolExecutionTest(protocolProver, protocolVerifier);
    }

    /**
     * This test checks the representation usage within the execution. In this case a correct protocol
     * execution is performed checking the representation for announcement, challenge and response; then a correct
     * protocol execution is performed checking the representation the GeneralizedSchnorrProtocol itself.
     */
    @Test
    void representationForProtocolExecutionTest() {
        InteractiveThreeWayAoKTester.representationForProtocolExecutionTest(protocolProver, protocolVerifier);
    }

    @Test
    void recreateTest() {
        InteractiveThreeWayAoKTester.recreateTest(protocolProver, protocolVerifier);
        FixedProtocolsMessageSerializationTest.testProtocolMessageSerialization(protocolProver,
                protocolVerifier.chooseChallenge());
    }
}
