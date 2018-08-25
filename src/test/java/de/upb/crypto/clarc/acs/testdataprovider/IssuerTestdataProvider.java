package de.upb.crypto.clarc.acs.testdataprovider;

import de.upb.crypto.clarc.acs.attributes.*;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssuer;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerKeyPair;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerKeyPairFactory;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.ReviewTokenIssuer;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserSecret;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Setup a Issuer and a credential for the given user
 */
public class IssuerTestdataProvider {

    public static final BigIntegerAttributeDefinition AGE = new BigIntegerAttributeDefinition("age", BigInteger
            .valueOf(1), BigInteger.valueOf(200));
    public static final StringAttributeDefinition GENDER = new StringAttributeDefinition("gender", "[mM]|[fF]");
    private static final List<AttributeDefinition> DEFAULT_ATTRIBUTE_DEFINITIONS = Arrays.asList(AGE, GENDER);

    private static final int NUMBER_OF_ATTRIBUTES = DEFAULT_ATTRIBUTE_DEFINITIONS.size();
    private static final int NUMBER_OF_MESSAGES = NUMBER_OF_ATTRIBUTES + 1;


    private final IssuerKeyPairFactory issuerKeyPairFactory;
    private final PSExtendedSignatureScheme signatureScheme;

    private final PublicParameters clarcPublicParameters;
    private final AttributeSpace issuerAttributeSpace;
    private PSCredential credential;

    private final IssuerKeyPair issuerKeyPair;
    private final CredentialIssuer issuer;
    private ReviewTokenIssuer reviewTokenIssuer;


    /**
     * Default implementation, where the default AttributeSpace (Age, Gender) is used and a credential is already set
     *
     * @param clarcPublicParameters of the system
     * @param signatureScheme       will be used for the credential
     * @param userSecret            to issue credential to
     */
    public IssuerTestdataProvider(PublicParameters clarcPublicParameters,
                                  PSExtendedSignatureScheme signatureScheme,
                                  UserSecret userSecret) {
        this.clarcPublicParameters = clarcPublicParameters;
        this.signatureScheme = signatureScheme;
        issuerKeyPairFactory = new IssuerKeyPairFactory();
        issuerKeyPair = issuerKeyPairFactory.create(clarcPublicParameters, NUMBER_OF_ATTRIBUTES);
        issuer = new CredentialIssuer(clarcPublicParameters, issuerKeyPair, DEFAULT_ATTRIBUTE_DEFINITIONS);

        issuerAttributeSpace = issuer.getPublicIdentity().getAttributeSpace();

        List<AttributeNameValuePair> defaultAttributesForCredential = new ArrayList<>();
        defaultAttributesForCredential.add(AGE.createAttribute(BigInteger.valueOf(18)));
        defaultAttributesForCredential.add(GENDER.createAttribute("f"));

        credential = getCredentialForUser(userSecret, defaultAttributesForCredential);

        reviewTokenIssuer = new ReviewTokenIssuer(clarcPublicParameters);
    }

    /**
     * A more general constructor, where  the attribute space can be chose freely and neither AttributeValues
     * nor User of the credential nor credential is fixed
     *
     * @param attributeSpace        to be used
     * @param clarcPublicParameters of the system
     * @param signatureScheme       used for the credntial
     */
    public IssuerTestdataProvider(List<AttributeDefinition> attributeSpace,
                                  PublicParameters clarcPublicParameters,
                                  PSExtendedSignatureScheme signatureScheme) {
        this.clarcPublicParameters = clarcPublicParameters;
        this.signatureScheme = signatureScheme;
        issuerKeyPairFactory = new IssuerKeyPairFactory();
        issuerKeyPair = issuerKeyPairFactory.create(clarcPublicParameters, attributeSpace.size());
        issuer = new CredentialIssuer(clarcPublicParameters, issuerKeyPair, attributeSpace);

        issuerAttributeSpace = issuer.getPublicIdentity().getAttributeSpace();
        reviewTokenIssuer = new ReviewTokenIssuer(clarcPublicParameters);
    }

    public PSExtendedVerificationKey getIssuerPublicKey() {
        return issuerKeyPair.getVerificationKey();
    }

    /**
     * @return default credential, will only work if default constructor is used!
     */
    public PSCredential getCredentialWitfDefaultAttributeSpace() {
        return credential;
    }

    public List<AttributeSpace> currentAttributeSpaces() {
        return new ArrayList<>(Collections.singletonList(issuerAttributeSpace));
    }

    public IssuerKeyPairFactory getIssuerKeyPairFactory() {
        return issuerKeyPairFactory;
    }

    public IssuerKeyPair getIssuerKeyPair() {
        return issuerKeyPair;
    }

    public AttributeSpace getIssuerAttributeSpace() {
        return issuerAttributeSpace;
    }

    public CredentialIssuer getIssuer() {
        return issuer;
    }

    /**
     * Create a credential for a user with the given {@link AttributeNameValuePair}s
     *
     * @param userSecret              where the credential is issued to
     * @param attributesForCredential the values used inside the credential. <b>MUST match given attribute space!</b>
     * @return a credetial to the given usk with given attributes
     */
    public PSCredential getCredentialForUser(UserSecret userSecret,
                                             List<AttributeNameValuePair> attributesForCredential) {

        attributesForCredential = attributesForCredential.stream()
                .map(attr -> AttributeNameValuePair.getAttributeForIssuer(
                        issuerKeyPair.getVerificationKey(), attr))
                .collect(Collectors.toList());

        List<RingElementPlainText> messages = new ArrayList<>(attributesForCredential.size() + 1);
        messages.add(new RingElementPlainText(userSecret.getUsk()));
        attributesForCredential.stream()
                .map(attr -> new RingElementPlainText(attr
                        .getZpRepresentation(clarcPublicParameters.getHashIntoZp())))
                .forEachOrdered(messages::add);
        MessageBlock messageBlock = new MessageBlock(messages);

        PSSignature signature = (PSSignature) signatureScheme.sign(messageBlock, issuerKeyPair.getSigningKey());
        return new PSCredential(
                signature.getRepresentation(),
                attributesForCredential.toArray(new AttributeNameValuePair[attributesForCredential.size()]),
                issuerKeyPair.getVerificationKey().getRepresentation());
    }

    public ReviewTokenIssuer getReviewTokenIssuer() {
        return reviewTokenIssuer;
    }
}
