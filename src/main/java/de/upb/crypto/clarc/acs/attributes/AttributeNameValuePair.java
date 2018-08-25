package de.upb.crypto.clarc.acs.attributes;

import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.craco.interfaces.abe.BigIntegerAttribute;
import de.upb.crypto.craco.interfaces.abe.RingElementAttribute;
import de.upb.crypto.craco.interfaces.abe.StringAttribute;
import de.upb.crypto.craco.interfaces.policy.PolicyFact;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.math.hash.impl.ByteArrayAccumulator;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.HashIntoZp;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Objects;


public class AttributeNameValuePair implements PolicyFact, PlainText {
    private static final String ISSUER_ATTRIBUTE_NAME_SEPARATOR = "\u27C2";
    public static final Attribute UNDEFINED_ATTRIBUTE_VALUE = new StringAttribute("\u27C2"); //\perp

    @Represented
    private String attributeName;
    @Represented
    private Attribute attributeValue;

    public AttributeNameValuePair(String attributeName, Attribute attributeValue) {
        this.attributeName = attributeName;
        this.attributeValue = attributeValue;
    }

    public AttributeNameValuePair(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public String getAttributeName() {
        return attributeName;
    }

    public void setAttributeName(String attributeName) {
        this.attributeName = attributeName;
    }

    public Attribute getAttributeValue() {
        return attributeValue;
    }

    public String getAttributeNameWithoutSuffix() {
        int index = attributeName.indexOf(ISSUER_ATTRIBUTE_NAME_SEPARATOR);
        if (index >= 0) {
            return attributeName.substring(0, attributeName.indexOf(ISSUER_ATTRIBUTE_NAME_SEPARATOR));
        }
        return attributeName;
    }

    /**
     * @deprecated This method is in this case deprecated, since the {@link AttributeNameValuePair} knows its ZP
     * representation.
     * See {@link AttributeNameValuePair#getZpRepresentation}
     */
    @Override
    @Deprecated
    public byte[] getUniqueByteRepresentation() {
        return this.updateAccumulator(new ByteArrayAccumulator()).extractBytes();
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        byteAccumulator.escapeAndSeparate(getAttributeNameWithoutSuffix().getBytes());
        byteAccumulator.escapeAndSeparate(attributeValue);
        return byteAccumulator;
    }

    /**
     * @param issuerPublicKey {@link PSExtendedVerificationKey} to use for computing a unique  suffix
     * @param attribute       {@link AttributeNameValuePair} to compute the suffixed name for
     * @return {@link AttributeNameValuePair} which name will contain a suffix representing the given ipk
     */
    public static AttributeNameValuePair getAttributeForIssuer(PSExtendedVerificationKey issuerPublicKey,
                                                               AttributeNameValuePair attribute) {
        return new AttributeNameValuePair(getAttributeNameForIssuer(issuerPublicKey, attribute.getAttributeName()),
                attribute.getAttributeValue());
    }

    /**
     * @param issuerPublicKey {@link PSExtendedVerificationKey} to use for computing a unique suffix
     * @param attributeName   original name of the {@link AttributeNameValuePair}
     * @return the name of the given {@link AttributeNameValuePair} suffixed with a unique representation of the
     * given ipk
     */
    public static String getAttributeNameForIssuer(PSExtendedVerificationKey issuerPublicKey, String attributeName) {
        return attributeName;
        /*StringBuilder nameBuilder = new StringBuilder();
        nameBuilder.append(attributeName);
        nameBuilder.append(ISSUER_ATTRIBUTE_NAME_SEPARATOR);
        Arrays.stream(issuerPublicKey.getGroup1ElementsYi())
                .map(UniqueByteRepresentable::getUniqueByteRepresentation)
                .map(Base64.getEncoder()::encodeToString)
                .forEachOrdered(nameBuilder::append);
        Arrays.stream(issuerPublicKey.getGroup2ElementsTildeYi())
                .map(UniqueByteRepresentable::getUniqueByteRepresentation)
                .map(Base64.getEncoder()::encodeToString)
                .forEachOrdered(nameBuilder::append);
        nameBuilder.append(Base64.getEncoder().encodeToString(issuerPublicKey.getGroup2ElementTildeX()
                .getUniqueByteRepresentation()));
        nameBuilder.append(Base64.getEncoder().encodeToString(issuerPublicKey.getGroup2ElementTildeG()
                .getUniqueByteRepresentation()));
        nameBuilder.append(Base64.getEncoder().encodeToString(issuerPublicKey.getGroup1ElementG()
                .getUniqueByteRepresentation()));
        return nameBuilder.toString();*/
    }

    /**
     * @param hashIntoZp {@link HashIntoZp} to be used to represent this {@link Attribute} in {@link Zp},
     *                   in case there is no native representation
     * @return an unique {@link Zp.ZpElement} from this {@link Attribute} for the given {@link Zp}
     */
    public Zp.ZpElement getZpRepresentation(HashIntoZp hashIntoZp) {
        Zp zpToBeRepresented = hashIntoZp.getTargetStructure();
        Zp.ZpElement element;
        if (attributeValue instanceof BigIntegerAttribute) {
            BigIntegerAttribute bigIntegerAttribute = (BigIntegerAttribute) attributeValue;
            element = zpToBeRepresented.createZnElement(bigIntegerAttribute.getAttribute());
        } else if (attributeValue instanceof RingElementAttribute &&
                ((RingElementAttribute) attributeValue).getAttribute() instanceof Zp.ZpElement) {
            element = (Zp.ZpElement) ((RingElementAttribute) attributeValue).getAttribute();
            if (!element.getStructure().equals(zpToBeRepresented)) {
                throw new IllegalArgumentException("The represented element does not match the given Zp!");
            }
        } else {
            byte[] bytes = this.updateAccumulator(new ByteArrayAccumulator()).extractBytes();
            element = hashIntoZp.hashIntoStructure(bytes);
        }

        return element;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AttributeNameValuePair that = (AttributeNameValuePair) o;
        return Objects.equals(attributeName, that.attributeName) &&
                Objects.equals(attributeValue, that.attributeValue);
    }

    @Override
    public int hashCode() {
        return Objects.hash(attributeName, attributeValue);
    }
}
