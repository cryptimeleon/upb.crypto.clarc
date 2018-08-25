package de.upb.crypto.clarc.predicategeneration.pssignatureschnorrprotocol;

import de.upb.crypto.clarc.acs.testdataprovider.IssuerTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.ParameterTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.UserAndSystemManagerTestdataProvider;
import de.upb.crypto.clarc.protocols.InteractiveThreeWayAoKTester;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrPublicParameter;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;


@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class PSSignatureSchnorrProtocolTest {

    private Zp zp;
    private GeneralizedSchnorrProtocol protocolProver;
    // different prover-protocol for negative test cases
    private GeneralizedSchnorrProtocol secondProtocolProver;
    private GeneralizedSchnorrProtocol protocolVerifier;
    private GeneralizedSchnorrProtocol protocolWithDisclosureProver;
    private GeneralizedSchnorrProtocol protocolWithDisclosureVerifier;
    private ParameterTestdataProvider clarcProvider;
    private UserAndSystemManagerTestdataProvider userProvider;
    private IssuerTestdataProvider issuerProvider;


    @BeforeAll
    public void setUp() {
        clarcProvider = new ParameterTestdataProvider();
        userProvider = new UserAndSystemManagerTestdataProvider(clarcProvider.getPublicParameters());
        issuerProvider = new IssuerTestdataProvider(clarcProvider.getPublicParameters(),
                clarcProvider.getSignatureScheme(), userProvider.getUserSecret());
        GenSchnorrTestdataProvider gsProvider =
                new GenSchnorrTestdataProvider(clarcProvider.getPublicParameters(),
                        issuerProvider.getCredentialWitfDefaultAttributeSpace(), issuerProvider.getIssuer(),
                        userProvider.getIdentity(), userProvider.getUserSecret());
        Group[] groups = gsProvider.generateGenSchnorrGroups();
        zp = gsProvider.generateGenSchnorrZPGroup(groups[0]);
        protocolProver = gsProvider.getPSSigSchnorrSigma();
        do {
            secondProtocolProver = gsProvider.getPSSigSchnorrSigma();
        } while (protocolProver.equals(secondProtocolProver));
        protocolVerifier = new GeneralizedSchnorrProtocol(protocolProver.getProblems(),
                null, (GeneralizedSchnorrPublicParameter) protocolProver.getPublicParameters());
        protocolWithDisclosureProver = gsProvider.getPSSigSchnorrSigmaWithDisclosure();
        protocolWithDisclosureVerifier = new GeneralizedSchnorrProtocol(
                protocolWithDisclosureProver.getProblems(),
                null, (GeneralizedSchnorrPublicParameter) protocolWithDisclosureProver.getPublicParameters());
    }

    /**
     * Positive test checking that for a correct protocol execution the verifier accepts.
     * The test is checking the protocol execution with internal randomness.
     */
    @Test
    void testPSGenSchnorrInternalRandomness() {
        InteractiveThreeWayAoKTester.protocolExecutionInternalRandomnessTest(protocolProver, protocolVerifier);
        assertArrayEquals(protocolVerifier.getProblems(), protocolProver.getProblems(),
                "The problems of the Generalized Schnorr protocols with internal randomness are inequal!");
    }


    /**
     * This negative test checks cases where the verify method is called with not matching parameters and therefore
     * should return false for internal randomness.
     */
    @Test
    void testNeqGenSchnorrInternalRandomness() {
        InteractiveThreeWayAoKTester.protocolExecutionInternalRandomnessNegativeTest(protocolProver,
                secondProtocolProver, protocolVerifier);
        assertArrayEquals(protocolVerifier.getProblems(), protocolProver.getProblems(),
                "The problems of the Generalized Schnorr protocols with internal randomness are inequal!");
    }

    /**
     * Positive test checking that for a correct protocol execution with disclosed elements the verifier accepts. An
     * interactive correct protocol execution with prover and verifier is performed. In the end it is checked that
     * verify returns true. The test is checking the protocol execution with internal randomness.
     */
    @Test
    void testPSGenSchnorrInternalRandomnessAndDisclosedElements() {
        InteractiveThreeWayAoKTester.protocolExecutionInternalRandomnessTest(protocolWithDisclosureProver,
                protocolWithDisclosureVerifier);
        assertArrayEquals(protocolVerifier.getProblems(), protocolProver.getProblems(),
                "The problems of the Generalized Schnorr protocols with internal randomness are inequal!");
    }

    /**
     * This negative test checks cases where the verify method is called with not matching parameters and therefore
     * should return false for internal randomness and disclosed elements.
     */
    @Test
    void testNeqGenSchnorrInternalRandomnessAndDisclosedElements() {
        // option for protocol execution with two different prover-protocols is not chosen here, because the generation
        // of protocols with disclosure does not provide protocols with the same parameters
        InteractiveThreeWayAoKTester.protocolExecutionInternalRandomnessNegativeTest(protocolWithDisclosureProver,
                protocolWithDisclosureProver, protocolWithDisclosureVerifier);
        assertArrayEquals(protocolVerifier.getProblems(), protocolProver.getProblems(),
                "The problems of the Generalized Schnorr protocols with internal randomness are inequal!");
    }

    @Test
    public void recreateTest() {
        InteractiveThreeWayAoKTester.recreateTest(protocolProver, protocolVerifier);
    }
}
