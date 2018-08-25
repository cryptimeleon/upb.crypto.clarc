package de.upb.crypto.clarc.acs.attributes;

import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.craco.interfaces.abe.RingElementAttribute;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.Ring;
import de.upb.crypto.math.interfaces.structures.RingElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

public class RingElementAttributeDefinition extends AttributeDefinition {

    @Represented
    private Ring ring;

    public RingElementAttributeDefinition(String attributeName, Ring ring) {
        super(attributeName);
        this.ring = ring;
    }

    public RingElementAttributeDefinition(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    @Override
    public boolean isLegalValue(Object attributeValue) {
        if (attributeValue instanceof RingElement) {
            RingElement element = (RingElement) attributeValue;
            //Check whether the given RingElement can be constructed by the ring and is therefore valid
            try {
                ring.getElement(element.getRepresentation());
                return true;
            } catch (Exception ex) {
                return false;
            }
        }
        return false;
    }

    /**
     * Creates an {@link AttributeNameValuePair} with given value.
     *
     * @param attributeValue {@link RingElement} to be used as value for the {@link AttributeNameValuePair}
     * @return {@link AttributeNameValuePair} with the given value
     * @throws IllegalArgumentException if {@link AttributeDefinition#isLegalValue} returns false for the given value
     */
    public AttributeNameValuePair createAttribute(RingElement attributeValue) {
        if (!isLegalValue(attributeValue)) {
            throw new IllegalArgumentException("The given value \"" + attributeValue + "\" is not an element of the " +
                    "ring \"" + ring + "\"!");
        }

        Attribute value = new RingElementAttribute(attributeValue);

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
        RingElementAttributeDefinition that = (RingElementAttributeDefinition) o;
        return Objects.equals(ring, that.ring);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), ring);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        accumulator = super.updateAccumulator(accumulator);
        accumulator.escapeAndSeparate(ring.getClass().getName());
        accumulator.escapeAndSeparate(ring.getCharacteristic().toByteArray());
        return accumulator;
    }
}
