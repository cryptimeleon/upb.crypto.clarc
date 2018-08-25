package de.upb.crypto.clarc.acs.predicategeneration;

import de.upb.crypto.clarc.acs.testdataprovider.IssuerTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.ParameterTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.PredicatePrimitiveTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.UserAndSystemManagerTestdataProvider;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofProtocol;
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
public class ZeroToUPowLRangeProofTest {

    private static final String NAME = "test";
    private ParameterTestdataProvider clarcProvider;
    private PredicatePrimitiveTestdataProvider predicateProvider;

    private ZeroToUPowLRangeProofProtocol protocolProver;
    // different prover-protocol for negative test cases
    private ZeroToUPowLRangeProofProtocol secondProtocolProver;
    private ZeroToUPowLRangeProofProtocol protocolVerifier;

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
        protocolProver = predicateProvider.getZeroToUPowLRangeProofProtocol(0, NAME);
        do {
            secondProtocolProver = predicateProvider.getZeroToUPowLRangeProofProtocol(0, NAME);
        } while (protocolProver.equals(secondProtocolProver));
        protocolVerifier = new ZeroToUPowLRangeProofProtocol(protocolProver
                .getPublicParameters(), NAME, null);
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
        // Since the value is 18 and this is impossible to write as 2^x or something else, the values
        // 17^1, 18^1 and 19^1 are tested, where only 19^1 should be tested positive.
        assertThrows(IllegalArgumentException.class, () ->
                checkRange(BigInteger.valueOf(17), 1, false,
                        "The attribute-value is not in the range, thus the protocol must fail"));
        assertThrows(IllegalArgumentException.class, () -> checkRange(BigInteger.valueOf(18), 1, false,
                "The attribute-value is not in the range, thus the protocol must fail"));
        checkRange(BigInteger.valueOf(19), 1, true,
                "The attribute-value is in the range, thus the protocol must accept");

    }

    @Test
    void invalidIntervalTest() {
        // Check u and l s.t. u^l-1 >= p, since p has the size of 2^80, u=2 and l=100 is used
        Executable invalidP =
                () -> checkRange(clarcProvider.getPublicParameters().getZp().size(), 2, false, "this");
        assertThrows(IllegalArgumentException.class, invalidP);

        // Check u, s.t. u > q
        BigInteger u = clarcProvider.getPublicParameters().getNguyenAccumulatorPP()
                .getUpperBoundForAccumulatableIdentities().add(BigInteger.ONE);
        Executable invalidPMinus1 = () -> checkRange(u, 2, false, "this");
        assertThrows(IllegalArgumentException.class, invalidPMinus1);

    }

    private void checkRange(BigInteger base, int exponent, boolean expectedResult, String errorMsg) {
        ZeroToUPowLRangeProofProtocol prover =
                predicateProvider.getZeroToUPowLRangeProofProtocol(0, NAME, base, exponent);
        ZeroToUPowLRangeProofProtocol verifier =
                new ZeroToUPowLRangeProofProtocol(prover.getPublicParameters(), NAME, null);
        Announcement[] announcements = prover.generateAnnouncements();
        Challenge challenge = verifier.chooseChallenge();
        Response[] responses = prover.generateResponses(challenge);
        assertEquals(expectedResult, verifier.verify(announcements, challenge, responses), errorMsg);
    }
}
