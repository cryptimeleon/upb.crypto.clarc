package de.upb.crypto.clarc.acs.serialization.classes;

import de.upb.crypto.clarc.acs.attributes.*;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.interfaces.abe.StringAttribute;
import de.upb.crypto.craco.interfaces.signature.SignatureKeyPair;
import de.upb.crypto.craco.sig.ps.*;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.interfaces.hash.HashFunction;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.structures.zn.HashIntoZp;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

class BuildingBlocksTestdataProvider {

    private static final long DEFAULT_RANDOM_STRING_LENGTH_LOWER_BOUND = 10;
    private static final long DEFAULT_RANDOM_STRING_LENGTH_UPPER_BOUND = 200;

    private static final int SECURITY_PARAM = 260;
    private static final int NUMBER_OF_MESSAGES = 3;

    private final SecureRandom random;

    private final Zp zp;
    private final HashIntoZp hash;

    private final PSExtendedVerificationKey issuerPublicKey;

    private AttributeSpace issuerAttributeSpace;
    private BigIntegerAttributeDefinition age = new BigIntegerAttributeDefinition("age", BigInteger.valueOf(1),
            BigInteger.valueOf(200));
    private StringAttributeDefinition gender = new StringAttributeDefinition("gender", "[mM]|[fF]");

    private PSCredential credential;


    public BuildingBlocksTestdataProvider() {
        //20 Bytes are rather arbitrary, but this example is used in the JavaDoc
        random = new SecureRandom(SecureRandom.getSeed(20));


        SignatureKeyPair<? extends PSExtendedVerificationKey, ? extends PSSigningKey> keyPair;
        PSPublicParameters pp;
        PSPublicParametersGen ppSetup = new PSPublicParametersGen();
        pp = ppSetup.generatePublicParameter(SECURITY_PARAM, true);
        PSExtendedSignatureScheme signatureScheme = new PSExtendedSignatureScheme(pp);
        keyPair = signatureScheme.generateKeyPair(NUMBER_OF_MESSAGES);

        issuerPublicKey = keyPair.getVerificationKey();
        PSSigningKey issuerSecretKey = keyPair.getSigningKey();

        zp = pp.getZp();
        hash = new HashIntoZp(zp);
        Zp.ZpElement usk = zp.getUniformlyRandomUnit();

        List<AttributeDefinition> attributeDefinitions = Arrays.asList(age, gender);
        issuerAttributeSpace = new AttributeSpace(attributeDefinitions, issuerPublicKey.getRepresentation());
        List<AttributeNameValuePair> attributesForCredential = new ArrayList<>();
        attributesForCredential.add(age.createAttribute(BigInteger.valueOf(18)));
        attributesForCredential.add(gender.createAttribute("f"));


        List<RingElementPlainText> messages = new ArrayList<>(NUMBER_OF_MESSAGES);
        messages.add(new RingElementPlainText(usk));
        attributesForCredential.stream()
                .map(attr -> AttributeNameValuePair.getAttributeForIssuer(issuerPublicKey, attr))
                .limit(NUMBER_OF_MESSAGES - 1)
                .map(attr -> new RingElementPlainText(attr.getZpRepresentation(hash)))
                .forEachOrdered(messages::add);

        MessageBlock messageBlock = new MessageBlock(messages);

        PSSignature signature = (PSSignature) signatureScheme.sign(messageBlock, issuerSecretKey);
        credential = new PSCredential(signature.getRepresentation(),
                attributesForCredential.toArray(new AttributeNameValuePair[NUMBER_OF_MESSAGES - 1]),
                issuerPublicKey.getRepresentation());
    }

    public AttributeNameValuePair generateRandomAttribute() {
        return new AttributeNameValuePair(generateRandomString(DEFAULT_RANDOM_STRING_LENGTH_LOWER_BOUND,
                DEFAULT_RANDOM_STRING_LENGTH_UPPER_BOUND),
                new StringAttribute(generateRandomString(DEFAULT_RANDOM_STRING_LENGTH_LOWER_BOUND,
                        DEFAULT_RANDOM_STRING_LENGTH_UPPER_BOUND)));
    }

    public StringAttributeDefinition generateRandomStringAttributeDefinition() {

        String name = generateRandomString(DEFAULT_RANDOM_STRING_LENGTH_LOWER_BOUND,
                DEFAULT_RANDOM_STRING_LENGTH_UPPER_BOUND);

        return new StringAttributeDefinition(name, null);

    }

    public BigIntegerAttributeDefinition generateRandomBigIntAttributeDefinition() {

        String name = generateRandomString(DEFAULT_RANDOM_STRING_LENGTH_LOWER_BOUND,
                DEFAULT_RANDOM_STRING_LENGTH_UPPER_BOUND);

        return new BigIntegerAttributeDefinition(name, BigInteger.ZERO, BigInteger.TEN);
    }

    public RingElementAttributeDefinition generateRandomRingElemenAttributeDefinition() {

        String name = generateRandomString(DEFAULT_RANDOM_STRING_LENGTH_LOWER_BOUND,
                DEFAULT_RANDOM_STRING_LENGTH_UPPER_BOUND);

        return new RingElementAttributeDefinition(name, zp);
    }

    public String generateRandomString(long lowerBoundLength, long upperBoundLength) {
        long length = random.longs(lowerBoundLength, upperBoundLength).findFirst().orElse(lowerBoundLength);
        return generateRandomString(length);
    }

    private String generateRandomString(long length) {
        return random.ints(Character.MIN_CODE_POINT, Character.MAX_CODE_POINT)
                .mapToObj(i -> (char) i)
                .filter(this::useThisCharacter)
                .limit(length)
                .collect(StringBuilder::new, StringBuilder::append, StringBuilder::append)
                .toString();
    }

    private boolean useThisCharacter(char c) {
        //check for range to avoid using all unicode Letter (e.g. some chinese symbols)
        return c >= '0' && c <= 'z' && Character.isLetterOrDigit(c);
    }

    public PSExtendedVerificationKey getIssuerPublicKey() {
        return issuerPublicKey;
    }

    public AttributeSpace getIssuerAttributeSpace() {
        return issuerAttributeSpace;
    }


    private Zp.ZpElement hashInputIntoZp(UniqueByteRepresentable input) {
        return zp.createZnElement(hash.hashIntoStructure(input.getUniqueByteRepresentation()).getInteger());
    }


    public PSCredential getCredential() {
        return credential;
    }

    public Zp.ZpElement[] generateRandomArray(Zp zp, int length) {
        return Stream.generate(zp::getUniformlyRandomUnit).limit(length).toArray(Zp.ZpElement[]::new);
    }

    public HashFunction getHashFunction() {
        return new SHA256HashFunction();
    }
}
