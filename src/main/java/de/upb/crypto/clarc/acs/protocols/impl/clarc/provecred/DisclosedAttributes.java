package de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred;

import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedList;

import java.util.List;
import java.util.Objects;

/**
 * Data container for {@link AttributeNameValuePair} which were disclosed by the prover during a
 * {@link SigmaProtocolWithDisclosure} protocol execution. The verifier can extract these after a successful execution
 * from her protocol instance.
 */
public class DisclosedAttributes implements StandaloneRepresentable {
    @RepresentedList(elementRestorer = @Represented)
    private List<AttributeNameValuePair> attributes;
    private Representation issuerPublicKey;

    public DisclosedAttributes(Representation issuerPublicKey,
                               List<AttributeNameValuePair> attributes) {
        this.issuerPublicKey = issuerPublicKey;
        this.attributes = attributes;
    }

    public DisclosedAttributes(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
        this.issuerPublicKey = representation.obj().get("issuerPublicKey");
    }

    public List<AttributeNameValuePair> getAttributes() {
        return attributes;
    }

    public Representation getIssuerPublicKey() {
        return issuerPublicKey;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation representation = AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
        representation.put("issuerPublicKey", issuerPublicKey);
        return representation;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DisclosedAttributes that = (DisclosedAttributes) o;
        return Objects.equals(issuerPublicKey, that.issuerPublicKey) &&
                Objects.equals(attributes, that.attributes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(issuerPublicKey, attributes);
    }
}
