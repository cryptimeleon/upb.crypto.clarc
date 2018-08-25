package de.upb.crypto.clarc.acs.predicategeneration;

import de.upb.crypto.clarc.acs.testdataprovider.IssuerTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.ParameterTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.PredicatePrimitiveTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.UserAndSystemManagerTestdataProvider;
import de.upb.crypto.clarc.predicategeneration.setmembershipproofs.SetMembershipProofProtocol;
import de.upb.crypto.clarc.predicategeneration.setmembershipproofs.SetMembershipPublicParameters;
import de.upb.crypto.clarc.protocols.InteractiveThreeWayAoKTester;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;


@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class SetMembershipTest {

    private static final String NAME = "test";
    private SetMembershipProofProtocol protocolProver;
    // different prover-protocol for negative test cases
    private SetMembershipProofProtocol secondProtocolProver;
    private SetMembershipProofProtocol protocolVerifier;

    private SetMembershipProofProtocol protocolNotValidSetProver;
    private SetMembershipProofProtocol protocolNotValidSetVerifier;


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
        protocolProver = predicateProvider.getSetMembershipProtocol(0, NAME);
        do {
            secondProtocolProver = predicateProvider.getSetMembershipProtocol(1, NAME);
        } while (protocolProver.equals(secondProtocolProver));
        protocolVerifier = new SetMembershipProofProtocol((SetMembershipPublicParameters) protocolProver
                .getPublicParameters(), NAME);

        // Set up protocols with set of members, where attribute Value is not contained
        Set<Zp.ZpElement> members = new HashSet<>();
        Zp.ZpElement element = predicateProvider.getZPRepresentationForAttrAtPos(0);
        members.add(element.add(element.getStructure().getElement(42)));
        protocolNotValidSetProver = predicateProvider.getSetMembershipProtocol(0, NAME, members);
        protocolNotValidSetVerifier = new SetMembershipProofProtocol(
                (SetMembershipPublicParameters) protocolNotValidSetProver.getPublicParameters(), NAME);

    }

    @Test
    public void testProtocolFulfillment() {
        assertTrue(protocolProver.isFulfilled(),
                "The prover protocol which possesses a fulfilling credential must be fulfilled");

        assertTrue(secondProtocolProver.isFulfilled(),
                "The prover protocol which possesses a fulfilling credential must be fulfilled");

        assertFalse(protocolNotValidSetProver.isFulfilled(),
                "The prover protocol without a fulfilling credential must not be fulfilled.");

        assertFalse(protocolVerifier.isFulfilled(), "The verifier protocol must not be fulfilled.");
        assertFalse(protocolNotValidSetVerifier.isFulfilled(), "The verifier protocol must not be fulfilled.");
    }

    /**
     * Positive test checking that for a correct protocol execution the verifier accepts.
     * The test is checking the protocol execution with internal randomness.
     */
    @Test
    void testSetMembershipInternalRandomness() {
        InteractiveThreeWayAoKTester.protocolExecutionInternalRandomnessTest(protocolProver, protocolVerifier);
        assertArrayEquals(protocolVerifier.getProblems(), protocolProver.getProblems(),
                "The problems of the Generalized Schnorr protocols with internal randomness are unequal!");
    }

    /**
     * This negative test checks cases where the verify method is called with not matching parameters and therefore
     * should return false for internal randomness.
     */
    @Test
    void testNeqSetMembershipInternalRandomness() {
        InteractiveThreeWayAoKTester.protocolExecutionInternalRandomnessNegativeTest(protocolProver,
                secondProtocolProver, protocolVerifier);
        assertArrayEquals(protocolVerifier.getProblems(), protocolProver.getProblems(),
                "The problems of the Generalized Schnorr protocols with internal randomness are unequal!");
    }

    /**
     * Checks that, if the attribute value is not in the set, the protocol does not accepts
     */
    @Test
    void testElementNotInRange() {
        Announcement[] announcements = protocolNotValidSetProver.generateAnnouncements();
        Challenge challenge = protocolNotValidSetVerifier.chooseChallenge();
        Response[] responses = protocolNotValidSetProver.generateResponses(challenge);
        assertFalse(protocolNotValidSetVerifier.verify(announcements, challenge, responses),
                "Since the attribute is not contained in the set, the verify should be false");
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