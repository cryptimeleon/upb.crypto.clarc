package de.upb.crypto.clarc.acs.predicategeneration;

import de.upb.crypto.clarc.acs.protocols.proveNym.ProveNymProtocol;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Identity;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.testdataprovider.ParameterTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.UserAndSystemManagerTestdataProvider;
import de.upb.crypto.clarc.protocols.InteractiveThreeWayAoKTester;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class ProveNymTest {

    private static final String NAME = "test";
    private ProveNymProtocol protocolProver;
    // different prover-protocol for negative test cases

    private ProveNymProtocol protocolVerifier;
    private ProveNymProtocol secondProtocolProver;

    private ProveNymProtocol wrongNymRandomProver;
    private ProveNymProtocol wrongUSKProver;
    private ProveNymProtocol wrongCommitmentProver;
    private ProveNymProtocol wrongCommitmentVerifier;


    @BeforeAll
    public void setUp() {

        ParameterTestdataProvider clarcProvider = new ParameterTestdataProvider();
        PublicParameters clarcPP = clarcProvider.getPP();
        UserAndSystemManagerTestdataProvider userProvider =
                new UserAndSystemManagerTestdataProvider(clarcPP);
        Identity identity = userProvider.getIdentity();
        Zp.ZpElement usk = identity.getPseudonymSecret().getMessages()[0];
        Zp.ZpElement nymRandom = identity.getPseudonymSecret().getRandomValue();
        Zp.ZpElement wrongUsk =
                identity.getPseudonymSecret().getMessages()[0].add(clarcPP.getZp().getElement(1));
        Zp.ZpElement wrongNymRandom =
                identity.getPseudonymSecret().getRandomValue().add(clarcPP.getZp().getElement(1));
        GroupElement commitment = identity.getPseudonym().getCommitmentValue().getCommitmentElement();
        GroupElement wrongCommitment;
        do {
            wrongCommitment = commitment.op(commitment.getStructure().getUniformlyRandomNonNeutral());
        } while (commitment.equals(wrongCommitment));
        PedersenCommitmentValue wrongCommitmentValue = new PedersenCommitmentValue(wrongCommitment);

        protocolProver = new ProveNymProtocol(nymRandom, usk, clarcPP.getSingleMessageCommitmentPublicParameters(),
                identity.getPseudonym().getCommitmentValue());
        secondProtocolProver =
                new ProveNymProtocol(nymRandom, usk, clarcPP.getSingleMessageCommitmentPublicParameters(),
                        identity.getPseudonym().getCommitmentValue());
        wrongUSKProver = new ProveNymProtocol(nymRandom, wrongUsk, clarcPP.getSingleMessageCommitmentPublicParameters(),
                identity.getPseudonym().getCommitmentValue());
        wrongNymRandomProver = new ProveNymProtocol(nymRandom, wrongUsk,
                clarcPP.getSingleMessageCommitmentPublicParameters(), identity.getPseudonym().getCommitmentValue());
        wrongCommitmentProver = new ProveNymProtocol(wrongNymRandom, usk,
                clarcPP.getSingleMessageCommitmentPublicParameters(), wrongCommitmentValue);
        protocolVerifier = new ProveNymProtocol(clarcPP.getSingleMessageCommitmentPublicParameters(),
                identity.getPseudonym().getCommitmentValue());
        wrongCommitmentVerifier = new ProveNymProtocol(clarcPP.getSingleMessageCommitmentPublicParameters(),
                wrongCommitmentValue);

    }

    /**
     * Positive test checking that for a correct protocol execution the verifier accepts.
     * The test is checking the protocol execution with internal randomness.
     */
    @Test
    void testProveNymInternalRandomness() {
        InteractiveThreeWayAoKTester.protocolExecutionInternalRandomnessTest(protocolProver, protocolVerifier);
        assertArrayEquals(protocolVerifier.getProblems(), protocolProver.getProblems(),
                "The problems of the Generalized Schnorr protocols with internal randomness are inequal!");
    }

    /**
     * This negative test checks cases where the verify method is called with not matching parameters and therefore
     * should return false for internal randomness.
     */
    @Test
    void testNeqProveNymInternalRandomness() {
        InteractiveThreeWayAoKTester.protocolExecutionInternalRandomnessNegativeTest(protocolProver,
                secondProtocolProver, protocolVerifier);
        assertArrayEquals(protocolVerifier.getProblems(), protocolProver.getProblems(),
                "The problems of the Generalized Schnorr protocols with internal randomness are inequal!");

        // Check that a wrong usk / nymRandom does not work for a valid commitment
        InteractiveThreeWayAoKTester
                .protocolNegativeExecutionInternalRandomnessTest(wrongUSKProver, protocolVerifier);
        InteractiveThreeWayAoKTester
                .protocolNegativeExecutionInternalRandomnessTest(wrongNymRandomProver, protocolVerifier);

        // Check that a wrong commitment value does not work
        InteractiveThreeWayAoKTester
                .protocolNegativeExecutionInternalRandomnessTest(wrongCommitmentProver, wrongCommitmentVerifier);
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

    @Test
    void recreateTest() {
        InteractiveThreeWayAoKTester.recreateTest(protocolProver, protocolVerifier);
        FixedProtocolsMessageSerializationTest.testProtocolMessageSerialization(protocolProver,
                protocolVerifier.chooseChallenge());
    }
}
