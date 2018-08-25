package de.upb.crypto.clarc.acs.attributes;

import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

public abstract class AttributeDefinition implements StandaloneRepresentable, UniqueByteRepresentable {

    @UniqueByteRepresented
    @Represented
    private String attributeName;

    protected AttributeDefinition() {
        //Empty constructor is only needed to restore the Representation of sub classes appropriately
    }

    public AttributeDefinition(String attributeName) {
        this.attributeName = attributeName;
    }

    public AttributeDefinition(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    /**
     * @param attributeValue value to check
     * @return whether the given object is a legal value for an {@link Attribute} created from this definition
     */
    public abstract boolean isLegalValue(Object attributeValue);


    /**
     * Creates an {@link AttributeNameValuePair} with undefined value according to
     * {@link AttributeNameValuePair#UNDEFINED_ATTRIBUTE_VALUE}.
     *
     * @return an {@link AttributeNameValuePair} with undefined value.
     */
    public final AttributeNameValuePair createUndefinedAttribute() {
        return new AttributeNameValuePair(this.getAttributeName(), AttributeNameValuePair.UNDEFINED_ATTRIBUTE_VALUE);
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

    public String getSuffixedAttributeName(PSExtendedVerificationKey issuerPublicKey) {
        return AttributeNameValuePair.getAttributeNameForIssuer(issuerPublicKey, this.attributeName);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AttributeDefinition that = (AttributeDefinition) o;
        return Objects.equals(attributeName, that.attributeName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(attributeName);
    }
}
