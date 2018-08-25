package de.upb.crypto.clarc.acs.attributes;

import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedList;
import de.upb.crypto.math.serialization.converter.JSONConverter;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Defines the {@link AttributeNameValuePair}s an issuer can issue via corresponding {@link AttributeDefinition}s.
 * <p>
 * To uniquely determine the order of {@link AttributeNameValuePair} in an issued
 * {@link de.upb.crypto.clarc.acs.user.credentials.SignatureCredential}, one can call
 * {@link AttributeSpace#getAttributeIndex} for either a given {@link AttributeDefinition} or
 * {@link AttributeNameValuePair} to retrieve an unique index.
 */
public class AttributeSpace implements StandaloneRepresentable, UniqueByteRepresentable {

    @RepresentedList(elementRestorer = @Represented)
    private List<AttributeDefinition> definitions;

    private Representation issuerPublicKey;

    public AttributeSpace(List<AttributeDefinition> definitions,
                          Representation issuerPublicKey) {
        this.issuerPublicKey = issuerPublicKey;
        this.definitions = new ArrayList<>(definitions);
    }

    public AttributeSpace(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
        this.issuerPublicKey = representation.obj().get("issuerPublicKey");
    }

    /**
     * @param attribute {@link AttributeNameValuePair} containing the non-prefixed name of the definition to find
     * @return the unique index of the corresponding attribute definition
     */
    public int getAttributeIndex(AttributeNameValuePair attribute) {
        return getAttributeIndex(attribute.getAttributeNameWithoutSuffix());
    }

    /**
     * @param attributeName non-prefixed name of the definition to find
     * @return the unique index of the corresponding attribute definition
     */
    public int getAttributeIndex(String attributeName) {
        AttributeDefinition definition =
                definitions.stream()
                        .filter(def -> def.getAttributeName().equals(attributeName))
                        .findFirst()
                        .orElseGet(() -> new StringAttributeDefinition("", ""));

        return definitions.indexOf(definition);
    }

    /**
     * @param definition {@link AttributeDefinition} to determine the index of
     * @return the unique index of the corresponding attribute definition
     */
    public int getAttributeIndex(AttributeDefinition definition) {
        return definitions.indexOf(definition);
    }

    /**
     * Gets the {@link AttributeDefinition} for the given attribute name or null if none is present
     *
     * @param attributeName The name of the attribute
     * @return The {@link AttributeDefinition} if the attribute exists or null if not
     */
    public AttributeDefinition get(String attributeName) {
        return definitions.stream()
                .filter(definition -> definition.getAttributeName().equals(attributeName))
                .findFirst()
                .orElse(null);
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation representation = AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
        representation.put("issuerPublicKey", issuerPublicKey);
        return representation;
    }

    public List<AttributeDefinition> getDefinitions() {
        return new ArrayList<>(definitions);
    }

    public Representation getIssuerPublicKey() {
        return issuerPublicKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AttributeSpace that = (AttributeSpace) o;
        return Objects.equals(definitions, that.definitions) &&
                Objects.equals(issuerPublicKey, that.issuerPublicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(definitions, issuerPublicKey);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        JSONConverter converter = new JSONConverter();
        byteAccumulator.escapeAndSeparate(converter.serialize(issuerPublicKey));
        definitions.forEach(byteAccumulator::escapeAndSeparate);
        return byteAccumulator;
    }
}
