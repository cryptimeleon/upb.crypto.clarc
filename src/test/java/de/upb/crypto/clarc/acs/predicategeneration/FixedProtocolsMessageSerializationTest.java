package de.upb.crypto.clarc.acs.predicategeneration;

import de.upb.crypto.clarc.acs.subpolicyproving.SubPolicyProvingProtocol;
import de.upb.crypto.clarc.acs.testdataprovider.ExtendetProveCredTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.IssuerTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.ParameterTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.UserAndSystemManagerTestdataProvider;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.popk.ProofOfPartialKnowledgeProtocol;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.math.serialization.ListRepresentation;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * A test to check, if serialization and deserialization of newly created announcements and responses works.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class FixedProtocolsMessageSerializationTest {

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
        protocolProvider = new ExtendetProveCredTestdataProvider(clarcProvider.getPublicParameters(),
                userProvider.getIdentity(), issuerProvider
                .getIssuer(), IssuerTestdataProvider.AGE, IssuerTestdataProvider.GENDER,
                issuerProvider.getCredentialWitfDefaultAttributeSpace(), clarcProvider.getSignatureScheme(),
                clarcProvider.getPedersenCommitmentScheme());
    }

    @Test
    public void testSubPolMessageSerialization() {
        SubPolicyProvingProtocol protocol = protocolProvider.getSubPolicyProvingProtocol();
        testProtocolMessageSerialization(protocol);
    }

    @Test
    public void testPoPKMessageSerialization() {
        ProofOfPartialKnowledgeProtocol protocol = protocolProvider.getPoPKProtocol();
        testProtocolMessageSerialization(protocol);
    }


    /**
     * Test whether this protocol instance fulfills the recreation contract of all its messages.
     *
     * <p>
     * M = protocol.generate[Announcements/Challenge/Responses]
     * M' = for each m in M : protocol.recreate[Announcements/Challenge/Responses](m.getRepresentation)
     * M.equals(M')
     * </p>
     *
     * @param protocol the protocol to verify the serialization of messages for
     */
    public static void testProtocolMessageSerialization(SigmaProtocol protocol) {
        testProtocolMessageSerialization(protocol, null);
    }

    /**
     * Test whether this protocol instance fulfills the recreation contract of all its messages.
     *
     * <p>
     * M = protocol.generate[Announcements/Challenge/Responses]
     * M' = for each m in M : protocol.recreate[Announcements/Challenge/Responses](m.getRepresentation)
     * M.equals(M')
     * </p>
     *
     * @param protocol  the protocol to verify the serialization of messages for
     * @param challenge optional challenge in case the protocol instance does not support choosing a challenge
     */
    public static void testProtocolMessageSerialization(SigmaProtocol protocol, Challenge challenge) {

        Announcement[] originalAnnouncements = protocol.generateAnnouncements();

        for (Announcement announcement : originalAnnouncements) {
            assertEquals(announcement, protocol.recreateAnnouncement(announcement.getRepresentation()),
                    "Announcement recreation failed");
        }

        if (challenge == null) {
            challenge = protocol.chooseChallenge();
            Challenge recreatedChallenge = protocol.recreateChallenge(challenge.getRepresentation());
            assertEquals(challenge, recreatedChallenge,
                    "The challenge of " + protocol.getClass().getSimpleName() + " needs to be reconstructed equally");
        }

        Response[] originalResponses = protocol.generateResponses(challenge);

        for (Response response : originalResponses) {
            assertEquals(response, protocol.recreateResponse(response.getRepresentation()),
                    "Response recreation failed");
        }
    }
}
