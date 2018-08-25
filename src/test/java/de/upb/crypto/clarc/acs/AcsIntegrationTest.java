package de.upb.crypto.clarc.acs;

import de.upb.crypto.clarc.acs.attributes.AttributeDefinition;
import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.acs.attributes.BigIntegerAttributeDefinition;
import de.upb.crypto.clarc.acs.attributes.StringAttributeDefinition;
import de.upb.crypto.clarc.acs.issuer.Issuable;
import de.upb.crypto.clarc.acs.issuer.credentials.Attributes;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssueResponse;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssuer;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssuerPublicIdentity;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.InteractiveIssueCredentialProcess;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.ReviewTokenIssuer;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.Item;
import de.upb.crypto.clarc.acs.policy.PolicyInformation;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Identity;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.InteractiveJoinVerifyProcess;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.JoinResponse;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.SystemManager;
import de.upb.crypto.clarc.acs.user.InteractiveJoinProcess;
import de.upb.crypto.clarc.acs.user.InteractiveProvingProcess;
import de.upb.crypto.clarc.acs.user.NonInteractivePolicyProof;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.acs.user.impl.clarc.NonInteractiveJoinRequest;
import de.upb.crypto.clarc.acs.user.impl.clarc.User;
import de.upb.crypto.clarc.acs.user.impl.clarc.credentials.CredentialNonInteractiveResponseHandler;
import de.upb.crypto.clarc.acs.user.impl.clarc.credentials.InteractiveRequestCredentialProcess;
import de.upb.crypto.clarc.acs.verifier.credentials.InteractiveVerificationProcess;
import de.upb.crypto.clarc.acs.verifier.credentials.VerificationResult;
import de.upb.crypto.clarc.acs.verifier.impl.clarc.credentials.CredentialVerifier;
import de.upb.crypto.clarc.acs.verifier.impl.clarc.reviews.ReviewVerifier;
import de.upb.crypto.clarc.predicategeneration.PredicatePublicParameters;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.PredicateTypePrimitive;
import de.upb.crypto.clarc.predicategeneration.parametergeneration.EqualityParameterGen;
import de.upb.crypto.clarc.predicategeneration.policies.PredicatePolicyFact;
import de.upb.crypto.clarc.predicategeneration.policies.SubPolicyPolicyFact;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static de.upb.crypto.clarc.acs.policy.PolicyBuilder.policy;
import static org.junit.jupiter.api.Assertions.*;


class AcsIntegrationTest {
    private PublicParameters pp;
    private User clarcUser;
    private CredentialIssuer issuer;
    private ReviewTokenIssuer reviewTokenIssuer;
    private Attributes attributes;
    private Identity clarcIdentity;
    private CredentialVerifier verifier;
    private PolicyInformation policyInformation;
    private SystemManager systemManager;
    private Issuable hashOfItem;
    private Item item;
    private ReviewVerifier reviewVerifier;

    @BeforeEach
    void setup() {
        PublicParametersFactory ppFactory = new PublicParametersFactory();
        ppFactory.setDebugMode(true);
        pp = ppFactory.create();
        assertNotNull(pp, "pp");

        systemManager = new SystemManager(pp);
        assertNotNull(systemManager.getPublicIdentity(), "public identity of systemManager");

        final StringAttributeDefinition countryDef = new StringAttributeDefinition("country", "");
        final BigIntegerAttributeDefinition ageDef = new BigIntegerAttributeDefinition("age",
                BigInteger.ONE, BigInteger.valueOf(200));

        final List<AttributeDefinition> attributeDefinitions = Arrays.asList(countryDef, ageDef);

        issuer = new CredentialIssuer(pp, attributeDefinitions);

        final de.upb.crypto.clarc.acs.issuer.credentials.CredentialIssuerPublicIdentity issuerPublicIdentity = issuer.getPublicIdentity();
        clarcUser = new User(pp);

        InteractiveJoinProcess joinProcess = clarcUser.initInteractiveJoinProcess(systemManager.getPublicIdentity());
        Announcement[] joinAnnouncements = joinProcess.getAnnouncements();
        InteractiveJoinVerifyProcess interactiveJoinVerifyProcess = systemManager
                .initInteractiveJoinVerifyProcess(clarcUser.getPublicKey(), joinAnnouncements,
                        joinProcess.getRegistrationInformation());
        Response[] joinResponses = joinProcess.getResponses(interactiveJoinVerifyProcess.getChallenge());
        assertTrue(interactiveJoinVerifyProcess.verify(joinResponses), "the joining protocol should have worked");
        clarcUser.finishRegistration(interactiveJoinVerifyProcess.getResponse());

        assertEquals(0, clarcUser.getIdentities().size(), "expected no pseudonym to exist");
        clarcIdentity = clarcUser.createIdentity();
        assertEquals(1, clarcUser.getIdentities().size(), "expected pseudonym to be generated");

        AttributeNameValuePair country = countryDef.createAttribute("Germany");
        AttributeNameValuePair age = ageDef.createAttribute(BigInteger.valueOf(20));

        attributes = new Attributes(
                new AttributeNameValuePair[]{country, age}
        );

        policyInformation = policy(pp, true).forIssuer(issuerPublicIdentity)
                .attribute(ageDef.getAttributeName()).isInRange(18, 200)
                .attribute(countryDef.getAttributeName()).isInSet("Germany", "USA")
                .build();

        verifier = new CredentialVerifier(pp, systemManager.getPublicIdentity());
    }

    @Test
    void nonInteractiveJoinTest() {
        PublicParametersFactory ppFactory = new PublicParametersFactory();
        ppFactory.setDebugMode(true);
        final PublicParameters pp = ppFactory.create();

        SystemManager systemManager = new SystemManager(pp);
        User user = new User(pp);

        final NonInteractiveJoinRequest joinRequest =
                user.createNonInteractiveJoinRequest(systemManager.getPublicIdentity());
        JoinResponse joinResponse =
                systemManager.nonInteractiveJoinVerification(joinRequest);
        user.finishRegistration(joinResponse);

    }

    @Test
    void interactiveCredentialCreateAndProveTest() {
        final Identity identity = clarcUser.getIdentities().get(0);

        final InteractiveRequestCredentialProcess requestCredentialProcess =
                clarcUser.createInteractiveIssueCredentialRequest(issuer.getPublicIdentity(), identity, attributes);

        final Announcement[] announcements = requestCredentialProcess.getAnnouncements();

        final InteractiveIssueCredentialProcess issueCredentialProcess = issuer.initInteractiveIssueProcess
                (requestCredentialProcess.getUskCommitmentValue(),
                        identity.getPseudonym(),
                        attributes, announcements);

        final Response[] responses = requestCredentialProcess.getResponses(issueCredentialProcess.getChallenge());

        assertTrue(issueCredentialProcess.verify(responses), "the credential issuing should have worked");
        clarcUser.receiveCredentialInteractively(requestCredentialProcess, issueCredentialProcess.getIssueResponse());

        final PSCredential credential = clarcUser.getCredential(issuer.getPublicIdentity());
        assertNotNull(credential, "credential should not be null");

        final InteractiveProvingProcess provingProcess =
                clarcUser.initInteractiveProvingProcess(identity, policyInformation);
        final InteractiveVerificationProcess verificationProcess =
                verifier.initInteractiveVerificationProcess(
                        provingProcess.getProtocolParameters(),
                        provingProcess.getAnnouncements(),
                        policyInformation,
                        provingProcess.getMasterCredential());
        assertTrue(verificationProcess.verify(provingProcess.getResponses(verificationProcess.getChallenge())),
                "user should have the right credentials to fulfill policy");
    }

    @Test
    void nonInteractiveCredentialCreateAndProveTest() {
        final CredentialNonInteractiveResponseHandler credentialResponseHandler =
                clarcUser.createNonInteractiveIssueCredentialRequest(issuer.getPublicIdentity(),
                        clarcIdentity, attributes);
        final CredentialIssueResponse nonInteractiveCredentialResponse =
                issuer.issueNonInteractively(credentialResponseHandler.getRequest());
        clarcUser.receiveCredentialNonInteractively(credentialResponseHandler, nonInteractiveCredentialResponse);

        final PSCredential credential = clarcUser.getCredential(issuer.getPublicIdentity());
        assertNotNull(credential, "credential should not be null");
        final NonInteractivePolicyProof proof =
                clarcUser.createNonInteractivePolicyProof(clarcIdentity, policyInformation, verifier.getIdentity());
        assertNotNull(proof, "Expected proof to be not null");
        VerificationResult verificationResult = verifier.verifyNonInteractiveProof(proof, policyInformation);
        assertTrue(verificationResult.isVerify(),
                "Expected non-interactive verification to succeed");
        assertEquals(systemManager.retrievePublicKey(verificationResult), clarcUser.getPublicKey(),
                "Opening should have worked");

        // Now we also check for the negative case for a non-valid policy. Open should NOT work in this case
        PedersenPublicParameters pedersenPP = PublicParametersFactory.getSingleMessageCommitmentScheme(pp).getPp();
        PredicatePublicParameters predPP =
                EqualityParameterGen.getEqualityPP(pedersenPP, pp.getZp().getZeroElement(), 0);
        PredicatePolicyFact predicatePolicyFact =
                new PredicatePolicyFact(predPP, PredicateTypePrimitive.EQUALITY_PUBLIC_VALUE);
        ThresholdPolicy policy = new ThresholdPolicy(0,
                new SubPolicyPolicyFact(issuer.getPublicIdentity().getRepresentation(),
                        predicatePolicyFact));

        PolicyInformation fakePolicyInformation =
                new PolicyInformation(pp, policy,
                        Collections.singletonList(issuer.getPublicIdentity().getAttributeSpace()),
                        null, true);
        VerificationResult verificationFakeResult = new VerificationResult(
                verificationResult.isVerify(),
                verificationResult.getFiatShamirProof(),
                fakePolicyInformation,
                verificationResult.getPseudonym(),
                verificationResult.getBlindedMasterCredential()
        );

        assertThrows(IllegalArgumentException.class, () -> systemManager.retrievePublicKey(verificationFakeResult));
    }

    @Test
    void createCredentialAndProveWithDisclosureTest() {
        final Identity identity = clarcUser.getIdentities().get(0);

        final InteractiveRequestCredentialProcess requestCredentialProcess =
                clarcUser.createInteractiveIssueCredentialRequest(issuer.getPublicIdentity(), identity, attributes);

        final Announcement[] announcements = requestCredentialProcess.getAnnouncements();

        final InteractiveIssueCredentialProcess issueCredentialProcess = issuer.initInteractiveIssueProcess
                (requestCredentialProcess.getUskCommitmentValue(),
                        identity.getPseudonym(),
                        attributes, announcements);

        final Response[] responses = requestCredentialProcess.getResponses(issueCredentialProcess.getChallenge());

        assertTrue(issueCredentialProcess.verify(responses), "the credential issuing should have worked");
        clarcUser.receiveCredentialInteractively(requestCredentialProcess, issueCredentialProcess.getIssueResponse());


        CredentialIssuerPublicIdentity issuerIdentity = issuer.getPublicIdentity();

        final PSCredential credential = clarcUser.getCredential(issuerIdentity);
        assertNotNull(credential, "credential should not be null");


        String nameOfDisclosedAttribute =
                attributes.getAttributes(issuerIdentity.getAttributeSpace())[0].getAttributeNameWithoutSuffix();

        PolicyInformation policyInformationWithDisclosure =
                policy(pp, true)
                        .forIssuer(issuerIdentity)
                        .disclosedAttribute(nameOfDisclosedAttribute)
                        .isNot("")
                        .build();


        final InteractiveProvingProcess provingProcess =
                clarcUser.initInteractiveProvingProcess(identity, policyInformationWithDisclosure);
        final InteractiveVerificationProcess verificationProcess =
                verifier.initInteractiveVerificationProcess(
                        provingProcess.getProtocolParameters(),
                        provingProcess.getAnnouncements(),
                        policyInformationWithDisclosure,
                        provingProcess.getMasterCredential());
        assertTrue(verificationProcess.verify(provingProcess.getResponses(verificationProcess.getChallenge())),
                "user should have the right credentials to fulfill policy");

        final NonInteractivePolicyProof proof =
                clarcUser.createNonInteractivePolicyProof(clarcIdentity, policyInformationWithDisclosure, verifier
                        .getIdentity());
        assertNotNull(proof, "Expected proof to be not null");
        VerificationResult verificationResult =
                verifier.verifyNonInteractiveProof(proof, policyInformationWithDisclosure);
        assertTrue(verificationResult.isVerify(),
                "Expected non-interactive verification to succeed");
        assertEquals(systemManager.retrievePublicKey(verificationResult), clarcUser
                .getPublicKey(), "Opening should have worked");
    }
}
