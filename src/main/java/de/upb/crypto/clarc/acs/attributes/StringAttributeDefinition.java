package de.upb.crypto.clarc.acs.attributes;

import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.craco.interfaces.abe.StringAttribute;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;
import java.util.regex.Pattern;

public class StringAttributeDefinition extends AttributeDefinition {
    private static final String DEFAULT_VERIFICATION_REGEX = ".*";

    @Represented
    private String verificationRegex;

    private Pattern regularExpressionPattern;

    public StringAttributeDefinition(String attributeName, String verificationRegex) {
        super(attributeName);
        if (verificationRegex == null || "".equals(verificationRegex)) {
            this.verificationRegex = DEFAULT_VERIFICATION_REGEX;
        } else {
            this.verificationRegex = verificationRegex;
        }
        this.regularExpressionPattern = Pattern.compile(this.verificationRegex);
    }

    public StringAttributeDefinition(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
        this.regularExpressionPattern = Pattern.compile(verificationRegex);
    }

    @Override
    public boolean isLegalValue(Object attributeValue) {
        if (attributeValue instanceof String) {
            String string = (String) attributeValue;
            return regularExpressionPattern.matcher(string).matches();
        }
        return false;
    }

    /**
     * Creates an {@link AttributeNameValuePair} with given value.
     *
     * @param attributeValue {@link String} to be used as value for the {@link AttributeNameValuePair}
     * @return {@link AttributeNameValuePair} with the given value
     * @throws IllegalArgumentException if {@link AttributeDefinition#isLegalValue} returns false for the given value
     */
    public AttributeNameValuePair createAttribute(String attributeValue) {
        if (!isLegalValue(attributeValue)) {
            throw new IllegalArgumentException("The given value \"" + attributeValue + "\" is not a String" +
                    " matching the pattern \"" + regularExpressionPattern.pattern() + "\"!");
        }

        Attribute value = new StringAttribute(attributeValue);

        return new AttributeNameValuePair(this.getAttributeName(), value);
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public Pattern getRegularExpressionPattern() {
        return regularExpressionPattern;
    }

    public void setRegularExpressionPattern(Pattern regularExpressionPattern) {
        this.regularExpressionPattern = regularExpressionPattern;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        StringAttributeDefinition that = (StringAttributeDefinition) o;
        return Objects.equals(verificationRegex, that.verificationRegex);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), verificationRegex, regularExpressionPattern);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        accumulator = super.updateAccumulator(accumulator);
        accumulator.escapeAndSeparate(verificationRegex);
        return accumulator;
    }
}
