package de.upb.crypto.clarc.acs.predicategeneration;


import de.upb.crypto.clarc.acs.protocols.proveNym.ProveNymProtocol;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Identity;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.subpolicyproving.SubPolicyProvingProtocol;
import de.upb.crypto.clarc.acs.testdataprovider.*;
import de.upb.crypto.clarc.predicategeneration.inequalityproofs.InequalityProofProtocol;
import de.upb.crypto.clarc.predicategeneration.inequalityproofs.InequalityPublicParameters;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.ArbitraryRangeProofProtocol;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.ArbitraryRangeProofPublicParameters;
import de.upb.crypto.clarc.predicategeneration.setmembershipproofs.SetMembershipProofProtocol;
import de.upb.crypto.clarc.predicategeneration.setmembershipproofs.SetMembershipPublicParameters;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.simulator.SpecialHonestVerifierSimulator;
import de.upb.crypto.clarc.protocols.simulator.Transcript;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertTrue;


@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class SimulatorTest {

    private ExtendetProveCredTestdataProvider protocolProvider;
    private PredicatePrimitiveTestdataProvider predicateProvider;
    private ParameterTestdataProvider clarcProvider;
    private UserAndSystemManagerTestdataProvider userProvider;

    @BeforeAll
    public void setUp() {
        clarcProvider = new ParameterTestdataProvider();
        userProvider = new UserAndSystemManagerTestdataProvider(clarcProvider.getPublicParameters());
        IssuerTestdataProvider issuerProvider = new IssuerTestdataProvider(clarcProvider.getPublicParameters(),
                clarcProvider.getSignatureScheme(), userProvider.getUserSecret());
        predicateProvider = new PredicatePrimitiveTestdataProvider(clarcProvider.getPublicParameters(),
                issuerProvider.getCredentialWitfDefaultAttributeSpace());
        protocolProvider = new ExtendetProveCredTestdataProvider(clarcProvider.getPublicParameters(), userProvider
                .getIdentity(), issuerProvider.getIssuer(),
                IssuerTestdataProvider.AGE, IssuerTestdataProvider.GENDER, issuerProvider
                .getCredentialWitfDefaultAttributeSpace(), clarcProvider.getSignatureScheme(), clarcProvider
                .getPedersenCommitmentScheme());
    }


    @Test
    public void testProveNymSimulator() {
        Identity identity = userProvider.getIdentity();
        PublicParameters clarcPP = clarcProvider.getPublicParameters();
        Zp.ZpElement usk = identity.getPseudonymSecret().getMessages()[0];
        Zp.ZpElement nymRandom = identity.getPseudonymSecret().getRandomValue();

        ProveNymProtocol protocolProver =
                new ProveNymProtocol(nymRandom, usk, clarcPP.getSingleMessageCommitmentPublicParameters(),
                        identity.getPseudonym().getCommitmentValue());
        ProveNymProtocol protocolVerifier = new ProveNymProtocol(clarcPP.getSingleMessageCommitmentPublicParameters(),
                identity.getPseudonym().getCommitmentValue());

        testSimulation(protocolProver, protocolVerifier, protocolProver.chooseChallenge());
    }

    @Test
    public void testSubPolicyProvingProtcolSimulator() {
        SubPolicyProvingProtocol protocol = protocolProvider.getSubPolicyProvingProtocol();
        testSimulation(protocol, protocolProvider.getSubPolicyProvingProtocolFactory().getVerifieryProtocol(),
                protocol.chooseChallenge());
    }

    @Test
    public void testProveCredANdPredicateProtocolSimulator() {
        SubPolicyProvingProtocol protocol = protocolProvider.getSubPolicyProvingProtocol();
        testSimulation(protocol, protocolProvider.getSubPolicyProvingProtocolFactory().getVerifieryProtocol(),
                protocol.chooseChallenge());
    }

    @Test
    public void testPredicateProfingProtocolSimulator() {
        SubPolicyProvingProtocol protocol = protocolProvider.getSubPolicyProvingProtocol();
        testSimulation(protocol.getPredicateProvingProtocol(),
                protocolProvider.getSubPolicyProvingProtocolFactory().getVerifieryProtocol()
                        .getPredicateProvingProtocol(),
                protocol.chooseChallenge());
    }

    @Test
    public void testInequalityProofSimulator() {
        InequalityProofProtocol protocol = predicateProvider.getInequalityProtocol(0, "",
                predicateProvider.getZPRepresentationForAttrAtPos(0).getInteger().add(BigInteger.ONE));
        InequalityPublicParameters ipp = (InequalityPublicParameters) protocol.getPublicParameters();

        testSimulation(protocol, protocol, protocol.chooseChallenge());
    }

    @Test
    public void testSetMembershipProofSimulator() {
        SetMembershipProofProtocol protocol = predicateProvider.getSetMembershipProtocol(0, "");
        SetMembershipPublicParameters setPP = (SetMembershipPublicParameters) protocol.getPublicParameters();
        testSimulation(protocol, protocol, protocol.chooseChallenge());
    }

    @Test
    public void testRangeProofSimulator() {
        ArbitraryRangeProofProtocol protocol = predicateProvider.getArbitraryRangeProofProtocol(0, "");
        ArbitraryRangeProofPublicParameters setPP =
                (ArbitraryRangeProofPublicParameters) protocol.getPublicParameters();
        testSimulation(protocol, protocol, protocol.chooseChallenge());
    }

    private void testSimulation(SigmaProtocol proverProtocol, SigmaProtocol verifierProtocol, Challenge c) {
        SpecialHonestVerifierSimulator simulator = proverProtocol.getSimulator();
        Transcript transcript = simulator.simulate(c);
        assertTrue(verifierProtocol.verify(transcript.getAnnouncements(), c, transcript.getResponses()),
                "The transcript need to be accepted by the protocol");
        assertTrue(c.equals(transcript.getChallenge()), "The two challenges need to be equal");
    }

}
