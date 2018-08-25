package de.upb.crypto.clarc.acs.attributes;

import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.craco.interfaces.abe.BigIntegerAttribute;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.math.BigInteger;
import java.util.Objects;

public class BigIntegerAttributeDefinition extends AttributeDefinition {

    @UniqueByteRepresented
    @Represented
    private BigInteger minValue;

    @UniqueByteRepresented
    @Represented
    private BigInteger maxValue;

    public BigIntegerAttributeDefinition(String attributeName, BigInteger minValue, BigInteger maxValue) {
        super(attributeName);
        this.minValue = minValue;
        this.maxValue = maxValue;
    }

    public BigIntegerAttributeDefinition(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    @Override
    public boolean isLegalValue(Object attributeValue) {
        if (attributeValue instanceof BigInteger) {
            BigInteger bigInteger = (BigInteger) attributeValue;
            return bigInteger.compareTo(minValue) >= 0 && bigInteger.compareTo(maxValue) <= 0;
        }
        return false;
    }


    /**
     * Creates an {@link AttributeNameValuePair} with given value.
     *
     * @param attributeValue {@link BigInteger} to be used as value for the {@link AttributeNameValuePair}
     * @return {@link AttributeNameValuePair} with the given value
     * @throws IllegalArgumentException if {@link AttributeDefinition#isLegalValue} returns false for the given value
     */
    public AttributeNameValuePair createAttribute(BigInteger attributeValue) {
        if (!isLegalValue(attributeValue)) {
            throw new IllegalArgumentException("The given value \"" + attributeValue
                    + "\" is not a BigInteger in the given range [" + minValue + ", " + maxValue + "].");
        }

        Attribute value = new BigIntegerAttribute(attributeValue);

        return new AttributeNameValuePair(this.getAttributeName(), value);
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        BigIntegerAttributeDefinition that = (BigIntegerAttributeDefinition) o;
        return Objects.equals(minValue, that.minValue) &&
                Objects.equals(maxValue, that.maxValue);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), minValue, maxValue);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }
}
