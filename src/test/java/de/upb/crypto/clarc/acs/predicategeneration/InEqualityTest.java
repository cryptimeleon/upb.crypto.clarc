package de.upb.crypto.clarc.acs.predicategeneration;

import de.upb.crypto.clarc.acs.testdataprovider.IssuerTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.ParameterTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.PredicatePrimitiveTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.UserAndSystemManagerTestdataProvider;
import de.upb.crypto.clarc.predicategeneration.inequalityproofs.InequalityProofProtocol;
import de.upb.crypto.clarc.predicategeneration.inequalityproofs.InequalityPublicParameters;
import de.upb.crypto.clarc.protocols.InteractiveThreeWayAoKTester;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class InEqualityTest {

    private static final String NAME = "test";
    private Zp zp;
    private InequalityProofProtocol protocolProver;
    // different prover-protocol for negative test cases
    private InequalityProofProtocol secondProtocolProver;
    private InequalityProofProtocol protocolVerifier;

    private InequalityProofProtocol protocolNegTestProver;
    private InequalityProofProtocol protocolNegTestVerifier;


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
        protocolProver = predicateProvider.getInequalityProtocol(0, NAME,
                predicateProvider.getZPRepresentationForAttrAtPos(0).getInteger().add(BigInteger.ONE));
        protocolProver.generateAnnouncements();

        do {
            secondProtocolProver = predicateProvider.getInequalityProtocol(0, NAME,
                    predicateProvider.getZPRepresentationForAttrAtPos(0).getInteger().add(BigInteger.ONE));
            secondProtocolProver.generateAnnouncements();
        } while (protocolProver.equals(secondProtocolProver));
        protocolVerifier = new InequalityProofProtocol((InequalityPublicParameters) protocolProver
                .getPublicParameters(), NAME);


        // setup a prover and a verifier, where the credential does not fulfill the policy
        protocolNegTestProver = predicateProvider.getInequalityProtocol(0, NAME,
                predicateProvider.getZPRepresentationForAttrAtPos(0).getInteger());
        protocolNegTestProver.generateAnnouncements();
        protocolNegTestVerifier = new InequalityProofProtocol((InequalityPublicParameters) protocolProver
                .getPublicParameters(), NAME);

    }

    /**
     * Positive test checking that for a correct protocol execution the verifier accepts.
     * The test is checking the protocol execution with internal randomness.
     */
    @Test
    void testInequalityInternalRandomness() {
        InteractiveThreeWayAoKTester.protocolExecutionInternalRandomnessTest(protocolProver, protocolVerifier);
        assertArrayEquals(protocolVerifier.getProblems(), protocolProver.getProblems(),
                "The problems of the Generalized Schnorr protocols with internal randomness are inequal!");
    }

    /**
     * This negative test checks cases where the verify method is called with not matching parameters and therefore
     * should return false for internal randomness.
     */
    @Test
    void testNeqInequalityInternalRandomness() {
        InteractiveThreeWayAoKTester.protocolExecutionInternalRandomnessNegativeTest(protocolProver,
                secondProtocolProver, protocolVerifier);
        assertArrayEquals(protocolVerifier.getProblems(), protocolProver.getProblems(),
                "The problems of the Generalized Schnorr protocols with internal randomness are inequal!");
    }


    /**
     * This test checks if the negative test works, where the prover has a credential not fulfilling the given policy.
     * This is done by putting the actual value of the attribute into the proof as "value attribute needs to be
     * unequal to"
     */
    @Test
    void testNotFulfillingCredential() {
        Announcement[] announcements = protocolNegTestProver.generateAnnouncements();
        Challenge challenge = protocolNegTestVerifier.chooseChallenge();
        Response[] responses = protocolNegTestProver.generateResponses(challenge);
        assertFalse(protocolNegTestVerifier
                .verify(announcements, challenge, responses), "This execution needs to fail");
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
}
