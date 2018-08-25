package de.upb.crypto.clarc.acs.predicategeneration;

import de.upb.crypto.clarc.acs.testdataprovider.IssuerTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.ParameterTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.PredicatePrimitiveTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.UserAndSystemManagerTestdataProvider;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.ArbitraryRangeProofProtocol;
import de.upb.crypto.clarc.protocols.InteractiveThreeWayAoKTester;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.function.Executable;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class ArbitraryRangeProofTest {
    private static final String NAME = "test";
    private ParameterTestdataProvider clarcProvider;
    private PredicatePrimitiveTestdataProvider predicateProvider;

    private ArbitraryRangeProofProtocol protocolProver;
    // different prover-protocol for negative test cases
    private ArbitraryRangeProofProtocol secondProtocolProver;
    private ArbitraryRangeProofProtocol protocolVerifier;

    @BeforeAll
    public void setUp() {
        clarcProvider = new ParameterTestdataProvider();
        UserAndSystemManagerTestdataProvider userProvider =
                new UserAndSystemManagerTestdataProvider(clarcProvider.getPublicParameters());
        IssuerTestdataProvider issuerProvider = new IssuerTestdataProvider(clarcProvider.getPublicParameters(),
                clarcProvider.getSignatureScheme(), userProvider.getUserSecret());
        predicateProvider =
                new PredicatePrimitiveTestdataProvider(clarcProvider.getPublicParameters(),
                        issuerProvider.getCredentialWitfDefaultAttributeSpace());
        protocolProver = predicateProvider.getArbitraryRangeProofProtocol(0, NAME);
        do {
            secondProtocolProver = predicateProvider.getArbitraryRangeProofProtocol(0, NAME);
        } while (protocolProver.equals(secondProtocolProver));
        protocolVerifier = new ArbitraryRangeProofProtocol(protocolProver.getPublicParameters(), null, NAME);
    }


    @Test
    public void testProtocolFulfillment() {
        assertTrue(protocolProver.isFulfilled(),
                "The prover protocol which possesses a fulfilling credential must be fulfilled");

        assertTrue(secondProtocolProver.isFulfilled(),
                "The prover protocol which possesses a fulfilling credential must be fulfilled");

        assertFalse(protocolVerifier.isFulfilled(), "The verifier protocol must not be fulfilled.");
    }

    /**
     * Positive test checking that for a correct protocol execution the verifier accepts.
     * The test is checking the protocol execution with internal randomness.
     */
    @Test
    void testRangeInternalRandomness() {
        InteractiveThreeWayAoKTester.protocolExecutionInternalRandomnessTest(protocolProver, protocolVerifier);
        assertArrayEquals(protocolVerifier.getProblems(), protocolProver.getProblems(),
                "The problems of the Generalized Schnorr protocols with internal randomness are unequal!");
    }

    /**
     * This negative test checks cases where the verify method is called with not matching parameters and therefore
     * should return false for internal randomness.
     */
    @Test
    void testNeqRangeInternalRandomness() {
        InteractiveThreeWayAoKTester.protocolExecutionInternalRandomnessNegativeTest(protocolProver,
                secondProtocolProver, protocolVerifier);
        assertArrayEquals(protocolVerifier.getProblems(), protocolProver.getProblems(),
                "The problems of the Generalized Schnorr protocols with internal randomness are unequal!");
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
    void representationForProtocolExecutionWithDisclosedElementsTest() {
        InteractiveThreeWayAoKTester.representationForProtocolExecutionTest(protocolProver, protocolVerifier);
    }

    @Test
    void recreateTest() {
        InteractiveThreeWayAoKTester.recreateTest(protocolProver, protocolVerifier);
        FixedProtocolsMessageSerializationTest.testProtocolMessageSerialization(protocolProver,
                protocolVerifier.chooseChallenge());
    }

    @Test
    void differentIntervalsTest() {
        // The attribute value for age that's used in this test in the credential is 18
        // Check that, if the attribute in the credential is not in the range, the verify evaluates to false
        assertThrows(IllegalArgumentException.class, () ->
                checkRange(BigInteger.valueOf(1), BigInteger.valueOf(5), false,
                        "The attribute-value is not in the range, thus the protocol must fail"));
        assertThrows(IllegalArgumentException.class, () ->
                checkRange(BigInteger.valueOf(14), BigInteger.valueOf(17), false,
                        "The attribute-value is not in the range, thus the protocol must fail"));
        assertThrows(IllegalArgumentException.class, () ->
                checkRange(BigInteger.valueOf(19), BigInteger.valueOf(25), false,
                        "The attribute-value is not in the range, thus the protocol must fail"));
        assertThrows(IllegalArgumentException.class, () ->
                checkRange(BigInteger.valueOf(22), BigInteger.valueOf(25), false,
                        "The attribute-value is not in the range, thus the protocol must fail"));
        //Check that the protocol accepts, if the attribute value is equal to lower or upper bound
        checkRange(BigInteger.valueOf(18), BigInteger.valueOf(25), true,
                "The attribute-value is the lower bound , thus the protocol must accept");
        checkRange(BigInteger.valueOf(12), BigInteger.valueOf(18), true,
                "The attribute-value is the upper bound, thus the protocol must accept");
    }

    @Test
    void invalidIntervalTest() {
        // Check an interval where the upper bound is smaller than the lower bound
        Executable invalidBounds = () -> checkRange(BigInteger.valueOf(10), BigInteger.valueOf(8), false,
                "lower bound needs to be smaller than upper bound");
        assertThrows(IllegalArgumentException.class, invalidBounds);

        // Check that p  is are invalid
        Executable invalidP = () -> checkRange(BigInteger.valueOf(0),
                clarcProvider.getPublicParameters().getZp().size(), false,
                "this");
        assertThrows(IllegalArgumentException.class, invalidP);

        // Check interval [0, p-1]. It is invalid , since it must hold that p-1 < 2^l <= p,
        // thus p must be of the form 2^l, but then it would not be prime anymore
        Executable invalidPMinus1 = () -> checkRange(BigInteger.valueOf(0),
                clarcProvider.getPublicParameters().getZp().size().subtract(BigInteger.ONE), false,
                "this");
        assertThrows(IllegalArgumentException.class, invalidPMinus1);
    }

    private void checkRange(BigInteger lowerBound, BigInteger upperBound, boolean expectedResult, String errorMsg) {
        ArbitraryRangeProofProtocol prover =
                predicateProvider.getArbitraryRangeProofProtocol(0, NAME, lowerBound, upperBound);
        ArbitraryRangeProofProtocol verifier =
                new ArbitraryRangeProofProtocol(prover.getPublicParameters(), null, NAME);
        Announcement[] announcements = prover.generateAnnouncements();
        Challenge challenge = verifier.chooseChallenge();
        Response[] responses = prover.generateResponses(challenge);
        assertEquals(expectedResult, verifier.verify(announcements, challenge, responses), errorMsg);
    }

}
