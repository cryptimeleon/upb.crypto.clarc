package de.upb.crypto.clarc.acs;

import de.upb.crypto.clarc.acs.attributes.AttributeDefinition;
import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.acs.attributes.BigIntegerAttributeDefinition;
import de.upb.crypto.clarc.acs.attributes.StringAttributeDefinition;
import de.upb.crypto.clarc.acs.issuer.Issuable;
import de.upb.crypto.clarc.acs.issuer.credentials.Attributes;
import de.upb.crypto.clarc.acs.issuer.credentials.CredentialIssuerPublicIdentity;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssueResponse;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssuer;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.ReviewTokenIssuer;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.Item;
import de.upb.crypto.clarc.acs.policy.PolicyInformation;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Identity;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.InteractiveJoinVerifyProcess;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.SystemManager;
import de.upb.crypto.clarc.acs.user.InteractiveJoinProcess;
import de.upb.crypto.clarc.acs.user.NonInteractivePolicyProof;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.acs.user.impl.clarc.User;
import de.upb.crypto.clarc.acs.user.impl.clarc.credentials.CredentialNonInteractiveResponseHandler;
import de.upb.crypto.clarc.acs.verifier.credentials.VerificationResult;
import de.upb.crypto.clarc.acs.verifier.impl.clarc.credentials.CredentialVerifier;
import de.upb.crypto.clarc.acs.verifier.impl.clarc.reviews.ReviewVerifier;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.math.pairings.debug.DebugBilinearMap;
import de.upb.crypto.math.pairings.debug.DebugGroupLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static de.upb.crypto.clarc.acs.policy.PolicyBuilder.policy;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PerformanceTest {
    protected long timerStart = 0;


    private PublicParameters pp;
    private User clarcUser;
    private CredentialIssuer issuer;
    private ReviewTokenIssuer reviewTokenIssuer;
    private Identity clarcIdentity;
    private CredentialVerifier verifier;
    private SystemManager systemManager;
    private Issuable hashOfItem;
    private Item item;
    private ReviewVerifier reviewVerifier;

    // Parameters
    private String name;
    private List<AttributeDefinition> attributeDefinitions;
    private Attributes attributes;
    private PolicyInformation policyInformation;
    private int maxIterations = 1;

    class PerformanceParam {
        String name;
        List<AttributeDefinition> attributeDefinitions;
        Attributes attr;
        PolicyInformation policyInformation;

        public PerformanceParam(String name,
                                List<AttributeDefinition> attributeDefinitions,
                                Attributes attr, PolicyInformation policyInformation) {
            this.name = name;
            this.attributeDefinitions = attributeDefinitions;
            this.attr = attr;
            this.policyInformation = policyInformation;
        }
    }


    @Test
    void evalComplexPolicy() {
        for (int i = 0; i < maxIterations; i++) {
            System.out.println("Evaluate performance of a complex policy with mixed AND/OR over 4 attributes ...");

            measureTime(null);
            final StringAttributeDefinition countryDef = new StringAttributeDefinition("country", "");
            final StringAttributeDefinition residenceDef = new StringAttributeDefinition("residence", "");
            final BigIntegerAttributeDefinition ageDef = new BigIntegerAttributeDefinition("age",
                    BigInteger.ONE, BigInteger.valueOf(200));
            final StringAttributeDefinition statusDef = new StringAttributeDefinition("status", "");

            final List<AttributeDefinition> attributeDefinitions =
                    Arrays.asList(countryDef, ageDef, statusDef, residenceDef);

            issuer = new CredentialIssuer(pp, attributeDefinitions);
            measureTime("Setup issuer");
            final CredentialIssuerPublicIdentity issuerPublicIdentity = issuer.getPublicIdentity();


            AttributeNameValuePair country = countryDef.createAttribute("Germany");
            AttributeNameValuePair residence = residenceDef.createAttribute("Germany");
            AttributeNameValuePair age = ageDef.createAttribute(BigInteger.valueOf(20));
            AttributeNameValuePair status = statusDef.createAttribute("Student");

            attributes = new Attributes(
                    new AttributeNameValuePair[]{country, age, status, residence}
            );

            // issue credential for the defined attributes
            issueCred();

            policyInformation = policy(pp, true)
                    .forIssuer(issuerPublicIdentity)
                    .attribute(countryDef.getAttributeName()).isEqual("Germany")
                    .and()
                    .forIssuer(issuerPublicIdentity)
                    .attribute(statusDef.getAttributeName()).isEqual("Student")
                    .or()
                    .attribute(ageDef.getAttributeName()).isInRange(0, 17)
                    .or()
                    .attribute(ageDef.getAttributeName()).isInRange(66, 200)
                    .and()
                    .forIssuer(issuerPublicIdentity)
                    .attribute(residenceDef.getAttributeName()).isInSet("Germany", "Austria", "Switzerland")
                    .build();

            final NonInteractivePolicyProof proof = createProof();

            VerificationResult verificationResult = verifyProof(proof);

            open(verificationResult);
        }
    }

    private void open(VerificationResult verificationResult) {
        measureTime(null);
        systemManager.retrievePublicKey(verificationResult);
        measureTime("Open");
    }

    private VerificationResult verifyProof(NonInteractivePolicyProof proof) {
        measureTime(null);
        VerificationResult verificationResult = verifier.verifyNonInteractiveProof(proof, policyInformation);
        verificationResult.isVerify();
        measureTime("Verify proof");
        return verificationResult;
    }

    private NonInteractivePolicyProof createProof() {
        measureTime(null);
        DebugGroupLogger.reset();
        final PSCredential credential = clarcUser.getCredential(issuer.getPublicIdentity());
        final NonInteractivePolicyProof proof =
                clarcUser.createNonInteractivePolicyProof(clarcIdentity, policyInformation, verifier.getIdentity());
        DebugGroupLogger.print();
        measureTime("Create proof");
        return proof;
    }

    private void issueCred() {
        measureTime(null);
        final CredentialNonInteractiveResponseHandler credentialResponseHandler =
                clarcUser.createNonInteractiveIssueCredentialRequest(issuer.getPublicIdentity(),
                        clarcIdentity, attributes);
        final CredentialIssueResponse nonInteractiveCredentialResponse =
                issuer.issueNonInteractively(credentialResponseHandler.getRequest());
        clarcUser.receiveCredentialNonInteractively(credentialResponseHandler, nonInteractiveCredentialResponse);
        measureTime("Issue cred");
    }

    private void userInstantiation() {
        measureTime(null);
        clarcUser = new User(pp);
        InteractiveJoinProcess joinProcess = clarcUser.initInteractiveJoinProcess(systemManager.getPublicIdentity());
        Announcement[] joinAnnouncements = joinProcess.getAnnouncements();
        InteractiveJoinVerifyProcess interactiveJoinVerifyProcess = systemManager
                .initInteractiveJoinVerifyProcess(clarcUser.getPublicKey(), joinAnnouncements,
                        joinProcess.getRegistrationInformation());
        Response[] joinResponses = joinProcess.getResponses(interactiveJoinVerifyProcess.getChallenge());
        assertTrue(interactiveJoinVerifyProcess.verify(joinResponses), "the joining protocol should have worked");
        clarcUser.finishRegistration(interactiveJoinVerifyProcess.getResponse());
        measureTime("User create and join");

        measureTime(null);
        clarcIdentity = clarcUser.createIdentity();
        measureTime("Create pseudonym");
    }

    private void setup() {
        measureTime(null);
        PublicParametersFactory ppFactory = new PublicParametersFactory();
        ppFactory.setDebugMode(false);
        ppFactory.setLazygroups(false);

        pp = ppFactory.create();
        //BarretoNaehrigNativeWrapper.getInstance().setEnabled(true);

        systemManager = new SystemManager(pp);
        measureTime("Setup");
    }

    @BeforeEach
    private void setupSystemAndCreateUser() {
        System.out.println();

        setup();

        userInstantiation();

        verifier = new CredentialVerifier(pp, systemManager.getPublicIdentity());
    }

    protected void measureTime(String str) {
        if (timerStart == 0) {
            DebugGroupLogger.reset();
            timerStart = System.currentTimeMillis();
        } else {
            long end = System.currentTimeMillis();
            System.out.println(str + ": " + ((end - timerStart) / 1000) + "s, " + ((end - timerStart) % 1000) + "ms");
            if (pp.getBilinearMap() instanceof DebugBilinearMap)
                DebugGroupLogger.print();
            timerStart = 0;
        }
    }

    @Test
    public void evalEquality() {
        for (int i = 0; i < maxIterations; i++) {
            System.out.println("Evaluate performance for a single attribute (equality)...");

            measureTime(null);
            final StringAttributeDefinition countryDef = new StringAttributeDefinition("country", "");

            issuer = new CredentialIssuer(pp, Collections.singletonList(countryDef));
            measureTime("Setup issuer");

            final CredentialIssuerPublicIdentity issuerPublicIdentity = issuer.getPublicIdentity();

            AttributeNameValuePair country = countryDef.createAttribute("Germany");
            attributes = new Attributes(
                    new AttributeNameValuePair[]{country}
            );

            issueCred();

            policyInformation = policy(pp, true)
                    .forIssuer(issuerPublicIdentity)
                    .attribute(countryDef.getAttributeName()).isEqual("Germany")
                    .build();

            final NonInteractivePolicyProof proof = createProof();

            VerificationResult verificationResult = verifyProof(proof);
        }
    }

    @Test
    public void evalRange() {
        for (int i = 0; i < maxIterations; i++) {
            System.out.println("Evaluate performance for a single attribute (range)...");

            measureTime(null);
            final BigIntegerAttributeDefinition ageDef = new BigIntegerAttributeDefinition("age",
                    BigInteger.ONE, BigInteger.valueOf(200));

            issuer = new CredentialIssuer(pp, Collections.singletonList(ageDef));
            measureTime("Setup issuer");

            final CredentialIssuerPublicIdentity issuerPublicIdentity = issuer.getPublicIdentity();

            AttributeNameValuePair age = ageDef.createAttribute(BigInteger.valueOf(16));
            attributes = new Attributes(
                    new AttributeNameValuePair[]{age}
            );

            issueCred();

            policyInformation = policy(pp, true)
                    .forIssuer(issuerPublicIdentity)
                    .attribute(ageDef.getAttributeName()).isInRange(0, 17)
                    .build();

            final NonInteractivePolicyProof proof = createProof();

            VerificationResult verificationResult = verifyProof(proof);
        }
    }

    @Test
    public void evalAND() {
        for (int i = 0; i < maxIterations; i++) {
            System.out.println("Evaluate performance for an AND of two attributes...");

            measureTime(null);
            final StringAttributeDefinition countryDef = new StringAttributeDefinition("country", "");
            final StringAttributeDefinition statusDef = new StringAttributeDefinition("status", "");

            issuer = new CredentialIssuer(pp, Arrays.asList(countryDef, statusDef));
            measureTime("Setup issuer");

            final CredentialIssuerPublicIdentity issuerPublicIdentity = issuer.getPublicIdentity();

            AttributeNameValuePair country = countryDef.createAttribute("Germany");
            AttributeNameValuePair student = statusDef.createAttribute("Student");
            attributes = new Attributes(
                    new AttributeNameValuePair[]{country, student}
            );

            issueCred();

            policyInformation = policy(pp, true)
                    .forIssuer(issuerPublicIdentity)
                    .attribute(countryDef.getAttributeName()).isEqual("Germany")
                    .attribute(statusDef.getAttributeName()).isEqual("Student")
                    .build();

            final NonInteractivePolicyProof proof = createProof();

            VerificationResult verificationResult = verifyProof(proof);
        }
    }

    @Test
    public void evalOR() {
        for (int i = 0; i < maxIterations; i++) {
            System.out.println("Evaluate performance for an single OR...");

            measureTime(null);
            final StringAttributeDefinition statusDef = new StringAttributeDefinition("status", "");

            issuer = new CredentialIssuer(pp, Arrays.asList(statusDef));
            measureTime("Setup issuer");

            final CredentialIssuerPublicIdentity issuerPublicIdentity = issuer.getPublicIdentity();

            AttributeNameValuePair student = statusDef.createAttribute("Student");
            attributes = new Attributes(
                    new AttributeNameValuePair[]{student}
            );

            issueCred();

            policyInformation = policy(pp, true)
                    .forIssuer(issuerPublicIdentity)
                    .attribute(statusDef.getAttributeName()).isEqual("Student")
                    .or()
                    .attribute(statusDef.getAttributeName()).isEqual("Teacher")
                    .build();

            final NonInteractivePolicyProof proof = createProof();

            VerificationResult verificationResult = verifyProof(proof);
        }
    }


}
