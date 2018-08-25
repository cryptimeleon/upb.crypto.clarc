package de.upb.crypto.clarc.acs.predicategeneration;

import de.upb.crypto.clarc.acs.subpolicyproving.SubPolicyProvingProtocol;
import de.upb.crypto.clarc.acs.testdataprovider.ExtendetProveCredTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.IssuerTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.ParameterTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.UserAndSystemManagerTestdataProvider;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.simulator.SigmaProtocolTranscript;
import de.upb.crypto.clarc.protocols.simulator.Transcript;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A test to check, if serialization and deserialization of transcripts work
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class FixedTranscriptSerializationTest {

    private ParameterTestdataProvider clarcProvider;
    private UserAndSystemManagerTestdataProvider userProvider;
    private IssuerTestdataProvider issuerProvider;
    private ExtendetProveCredTestdataProvider protocolProvider;

    @BeforeAll
    public void setUp() {
        clarcProvider = new ParameterTestdataProvider();
        userProvider = new UserAndSystemManagerTestdataProvider(clarcProvider.getPublicParameters());
        issuerProvider = new IssuerTestdataProvider(clarcProvider.getPublicParameters(),
                clarcProvider.getSignatureScheme(), userProvider.getUserSecret());
        protocolProvider = new ExtendetProveCredTestdataProvider(clarcProvider.getPublicParameters(), userProvider
                .getIdentity(), issuerProvider.getIssuer(),
                IssuerTestdataProvider.AGE, IssuerTestdataProvider.GENDER, issuerProvider
                .getCredentialWitfDefaultAttributeSpace(), clarcProvider.getSignatureScheme(), clarcProvider
                .getPedersenCommitmentScheme());
    }

    @Test
    public void testSubPolicyProvingProtocolTranscript() {
        SubPolicyProvingProtocol subPolicyProvingProtocol = protocolProvider.getSubPolicyProvingProtocol();
        Challenge c = subPolicyProvingProtocol.chooseChallenge();
        Transcript beforeRecreation = subPolicyProvingProtocol.getSimulator().simulate(c);
        Transcript afterRecreation = new SigmaProtocolTranscript(beforeRecreation.getRepresentation());
        assertTrue(beforeRecreation.equals(afterRecreation), "The objects needs to be equal!");
    }

    @Test
    public void testPredicateProvingProtocolTranscript() {
        SubPolicyProvingProtocol subPolicyProvingProtocol = protocolProvider.getSubPolicyProvingProtocol();
        subPolicyProvingProtocol.generateAnnouncements();
        Challenge c = subPolicyProvingProtocol.chooseChallenge();
        Transcript beforeRecreation =
                subPolicyProvingProtocol.getPredicateProvingProtocol().getSimulator().simulate(c);
        Transcript afterRecreation = new SigmaProtocolTranscript(beforeRecreation.getRepresentation());
        assertTrue(beforeRecreation.equals(afterRecreation), "The objects needs to be equal!");
    }
}
