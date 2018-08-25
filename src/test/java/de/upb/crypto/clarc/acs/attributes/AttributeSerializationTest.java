package de.upb.crypto.clarc.acs.attributes;

import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.interfaces.signature.SignatureKeyPair;
import de.upb.crypto.craco.sig.ps.*;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.serialization.converter.JSONConverter;
import de.upb.crypto.math.structures.zn.HashIntoZp;
import de.upb.crypto.math.structures.zn.RingMultiplication;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class AttributeSerializationTest {


    private final String serializedSignatureScheme = "{\"pp\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.craco.sig.ps.PSPublicParameters\"," +
            "\"representation\":{\"bilinearMap\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.structures.zn.RingMultiplication\"," +
            "\"representation\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto" +
            ".math.structures.zn.Zp\",\"representation\":\"<BigInteger>101\"}}}}}";

    private final String serializedIssuerSecretKey = "{\"exponentX\":\"<BigInteger>76\"," +
            "\"exponentsYi\":[\"<BigInteger>4\",\"<BigInteger>9c\",\"<BigInteger>6\"],\"zp\":null}";

    private final String serializedIssuerPublicKey = "{\"group1ElementG\":\"<BigInteger>3d\"," +
            "\"group1ElementsYi\":[\"<BigInteger>f4\",\"<BigInteger>7\",\"<BigInteger>6d\"]," +
            "\"group2ElementTildeG\":\"<BigInteger>c8\",\"group2ElementTildeX\":\"<BigInteger>d5\"," +
            "\"group2ElementsTildeYi\":[\"<BigInteger>1d\",\"<BigInteger>67\",\"<BigInteger>ac\"]}";


    private final String serializedAttributeDefinitionAge = "{\"maxValue\":\"<BigInteger>c8\"," +
            "\"minValue\":\"<BigInteger>1\",\"attributeName\":\"age\"}";

    private final String serializedAttributeDefinitionGender = "{\"attributeName\":\"gender\"," +
            "\"verificationRegex\":\"[mM]|[fF]\"}";

    private final String serializedAttributeSpace =
            "{\"definitions\":[{\"thisIsRepresentableRepresentation\":true," +
                    "\"representableTypeName\":\"de.upb.crypto.clarc.acs.attributes" +
                    ".BigIntegerAttributeDefinition\",\"representation\":{\"attributeName\":\"age\"," +
                    "\"maxValue\":\"<BigInteger>c8\",\"minValue\":\"<BigInteger>1\"}}," +
                    "{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto.clarc" +
                    ".acs.attributes.StringAttributeDefinition\",\"representation\":{\"attributeName\":\"gender\"," +
                    "\"verificationRegex\":\"[mM]|[fF]\"}}],\"issuerPublicKey\":{\"group1ElementG\":\"<BigInteger>3d\"," +
                    "\"group1ElementsYi\":[\"<BigInteger>f4\",\"<BigInteger>7\",\"<BigInteger>6d\"]," +
                    "\"group2ElementTildeG\":\"<BigInteger>c8\",\"group2ElementTildeX\":\"<BigInteger>d5\"," +
                    "\"group2ElementsTildeYi\":[\"<BigInteger>1d\",\"<BigInteger>67\",\"<BigInteger>ac\"]}}";

    private final String serializedCredential =
            "{\"attributes\":[{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto" +
                    ".clarc.acs.attributes.AttributeNameValuePair\"," +
                    "\"representation\":{\"attributeName\":\"age\"," +
                    "\"attributeValue\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de" +
                    ".upb.crypto.craco.interfaces.abe.BigIntegerAttribute\"," +
                    "\"representation\":{\"elem\":\"<BigInteger>12\"}}}},{\"thisIsRepresentableRepresentation\":true," +
                    "\"representableTypeName\":\"de.upb.crypto.clarc.acs.attributes" +
                    ".AttributeNameValuePair\",\"representation\":{\"attributeName\":\"gender\"," +
                    "\"attributeValue\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de" +
                    ".upb.crypto.craco.interfaces.abe.StringAttribute\",\"representation\":\"⟂\"}}}]," +
                    "\"issuerPublicKeyRepresentation\":{\"group1ElementG\":\"<BigInteger>3d\"," +
                    "\"group1ElementsYi\":[\"<BigInteger>f4\",\"<BigInteger>7\",\"<BigInteger>6d\"]," +
                    "\"group2ElementTildeG\":\"<BigInteger>c8\",\"group2ElementTildeX\":\"<BigInteger>d5\"," +
                    "\"group2ElementsTildeYi\":[\"<BigInteger>1d\",\"<BigInteger>67\",\"<BigInteger>ac\"]}," +
                    "\"signatureRepresentation\":{\"group1ElementSigma1\":\"<BigInteger>3b\"," +
                    "\"group1ElementSigma2\":\"<BigInteger>59\",\"groupG1\":null}}";

    private final String serializedHashIntoZp = "{\"hashIntoZn\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.hash.impl.VariableOutputLengthHashFunction\"," +
            "\"representation\":{\"innerFunction\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.hash.impl.SHA256HashFunction\",\"representation\":null}," +
            "\"outputLength\":1}},\"structure\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.structures.zn.Zp\"," +
            "\"representation\":\"<BigInteger>101\"}}";


    private PSExtendedSignatureScheme signatureScheme;
    private PSExtendedVerificationKey issuerPublicKey;
    private PSSigningKey issuerSecretKey;

    private BigIntegerAttributeDefinition age;
    private StringAttributeDefinition gender;

    private HashIntoZp hashIntoZp;

    @BeforeAll
    public void setup() {
        final JSONConverter converter = new JSONConverter();

        hashIntoZp = new HashIntoZp(converter.deserialize(serializedHashIntoZp));

        signatureScheme = new PSExtendedSignatureScheme(converter.deserialize(serializedSignatureScheme));

        issuerPublicKey = signatureScheme.getVerificationKey(converter.deserialize(serializedIssuerPublicKey));
        issuerSecretKey = signatureScheme.getSigningKey(converter.deserialize(serializedIssuerSecretKey));

        age = new BigIntegerAttributeDefinition(converter.deserialize(serializedAttributeDefinitionAge));
        gender = new StringAttributeDefinition(converter.deserialize(serializedAttributeDefinitionGender));
    }


    @Test
    @Disabled
    public void printSerializedSignatureScheme() {
        final JSONConverter converter = new JSONConverter();

        //Need a prime larger 2^8, otherwise VariableOutputLengthHashFunction's internal SHA256 can not be created
        final Zp zp = new Zp(BigInteger.valueOf(257));

        final HashIntoZp hash = new HashIntoZp(zp);

        final BilinearMap bilinearMap = new RingMultiplication(zp);
        final PSPublicParameters psPublicParameters = new PSPublicParameters(bilinearMap);

        final PSExtendedSignatureScheme scheme = new PSExtendedSignatureScheme(psPublicParameters);

        AttributeSpace space = new AttributeSpace(converter.deserialize(serializedAttributeSpace));

        //We need to sign all attributes contained in the AttributeSpace as well as the usk
        int numberOfMessages = space.getDefinitions().size() + 1;
        SignatureKeyPair<? extends PSExtendedVerificationKey, ? extends PSSigningKey> pair =
                scheme.generateKeyPair(numberOfMessages);


        space = new AttributeSpace(space.getDefinitions(), pair.getVerificationKey().getRepresentation());

        System.out.println("Printing parameters for attribute and credential serialization:");
        System.out.println("-- HashIntoZp --");
        System.out.println(converter.serialize(hash.getRepresentation()));
        System.out.println("-- SignatureScheme --");
        System.out.println(converter.serialize(scheme.getRepresentation()));
        System.out.println("-- signing key --");
        System.out.println(converter.serialize(pair.getSigningKey().getRepresentation()));
        System.out.println("-- verification key --");
        System.out.println(converter.serialize(pair.getVerificationKey().getRepresentation()));
        System.out.println("-- AttributeSpace --");
        System.out.println(converter.serialize(space.getRepresentation()));
        System.out.println("...Done");
    }

    @Test
    public void attributeSpaceSerializationTest() {
        final JSONConverter converter = new JSONConverter();

        AttributeSpace space = new AttributeSpace(Arrays.asList(age, gender), issuerPublicKey.getRepresentation());
        assertEquals(converter.serialize(space.getRepresentation()), serializedAttributeSpace);
    }

    @Test
    public void attributeSpaceDeserializationTest() {
        final JSONConverter converter = new JSONConverter();

        AttributeSpace space = new AttributeSpace(converter.deserialize(serializedAttributeSpace));

        assertNotNull(space.getIssuerPublicKey(), "issuer public key must not be null");
        assertEquals(space.getDefinitions()
                .size(), 2, "there should be exactly two definitions in the AttributeSpace");
    }

    @Test
    public void credentialSerializationTest() {
        final JSONConverter converter = new JSONConverter();

        List<AttributeNameValuePair> attributesForCredential = new ArrayList<>();
        attributesForCredential.add(age.createAttribute(BigInteger.valueOf(18)));
        attributesForCredential.add(gender.createUndefinedAttribute());

        Zp zp = signatureScheme.getPp().getZp();

        List<RingElementPlainText> messages = new ArrayList<>();
        //Add some usk
        messages.add(new RingElementPlainText(zp.getUniformlyRandomUnit()));
        attributesForCredential.stream()
                .map(attr -> AttributeNameValuePair.getAttributeForIssuer(issuerPublicKey, attr))
                .map(attr -> new RingElementPlainText(attr.getZpRepresentation(hashIntoZp)))
                .forEachOrdered(messages::add);


        MessageBlock messageBlock = new MessageBlock(messages);

        PSSignature signature = (PSSignature) signatureScheme.sign(messageBlock, issuerSecretKey);

        PSCredential credential = new PSCredential(signature.getRepresentation(),
                attributesForCredential.toArray(new AttributeNameValuePair[2]),
                issuerPublicKey.getRepresentation()
        );

        //Since the signature has a random component we can only compare the "non-signature" part of the credential
        String serializedNewCredential = converter.serialize(credential.getRepresentation());

        System.out.println(serializedNewCredential);

        int indexOfSerializedSignature = serializedNewCredential.indexOf("group1ElementSigma1");
        String serializedNewCredentialWithoutSignature = serializedNewCredential.substring(0,
                indexOfSerializedSignature);

        indexOfSerializedSignature = serializedCredential.indexOf("group1ElementSigma1");
        String referenceSerializedCredentialWithoutSignature = serializedCredential.substring(0,
                indexOfSerializedSignature);
        assertEquals(serializedNewCredentialWithoutSignature, referenceSerializedCredentialWithoutSignature);
    }

    @Test
    public void credentialDeserializationTest() {
        final JSONConverter converter = new JSONConverter();

        PSCredential credential = new PSCredential(converter.deserialize(serializedCredential));
        AttributeSpace space = new AttributeSpace(converter.deserialize(serializedAttributeSpace));

        assertNotNull(credential.getSignatureRepresentation(), "the credential's signature must not be null");
        assertEquals(credential.getAttributes().length, space.getDefinitions().size(),
                "there should be exactly one attribute in the credential");
    }


}
