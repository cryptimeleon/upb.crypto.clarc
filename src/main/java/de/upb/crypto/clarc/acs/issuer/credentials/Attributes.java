package de.upb.crypto.clarc.acs.issuer.credentials;

import de.upb.crypto.clarc.acs.attributes.AttributeDefinition;
import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.acs.attributes.AttributeSpace;
import de.upb.crypto.clarc.acs.issuer.Issuable;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * This class describes the attributes within a requested credential. It extends the class {@link Issuable},
 * which is used in the protocols.
 */
public class Attributes extends Issuable {
    @RepresentedArray(elementRestorer = @Represented)
    private AttributeNameValuePair[] attributes;

    public Attributes(AttributeNameValuePair[] attributes) {
        this.attributes = attributes;
    }

    public Attributes(Collection<AttributeNameValuePair> attributes) {
        this.attributes = attributes.toArray(new AttributeNameValuePair[attributes.size()]);
    }

    public Attributes(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    /**
     * @param attributeSpace the {@link de.upb.crypto.clarc.acs.issuer.Issuer}'s {@link AttributeSpace}
     * @return the containing {@link AttributeNameValuePair} sorted according to the given {@link AttributeSpace}
     */
    public AttributeNameValuePair[] getAttributes(AttributeSpace attributeSpace) {
        // There must not be more attributes than definitions available to ensure a deterministic mapping
        // Missing attributes will be filled with AttributeNameValuePair#UNDEFINED_ATTRIBUTE_VALUE
        if (attributeSpace.getDefinitions().size() < attributes.length) {
            throw new IllegalStateException("There are more attributes present than defined in the attribute space.");
        }

        AttributeNameValuePair[] sorted = new AttributeNameValuePair[attributeSpace.getDefinitions().size()];

        for (AttributeNameValuePair attribute : attributes) {
            int index = attributeSpace.getAttributeIndex(attribute);
            sorted[index] = attribute;
        }

        List<String> attributeNames = attributeSpace.getDefinitions().stream()
                .map(AttributeDefinition::getAttributeName)
                .collect(Collectors.toList());

        Attribute undefined = AttributeNameValuePair.UNDEFINED_ATTRIBUTE_VALUE;
        // Ensure that there is an attribute defined for each corresponding entry in the attribute space
        for (int i = 0; i < sorted.length; i++) {
            if (sorted[i] == null) {
                sorted[i] = new AttributeNameValuePair(attributeNames.get(i), undefined);
            }
        }

        return sorted;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Attributes that = (Attributes) o;
        return Arrays.equals(attributes, that.attributes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(attributes);
    }
}
