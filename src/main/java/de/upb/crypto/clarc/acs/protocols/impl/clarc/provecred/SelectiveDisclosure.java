package de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred;

import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.acs.attributes.AttributeSpace;
import de.upb.crypto.clarc.acs.issuer.Issuer;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedList;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * {@link SelectiveDisclosure}s are part of a {@link Policy} and describe the {@link AttributeNameValuePair}s which
 * should be disclosed during the execution of a {@link SigmaProtocolWithDisclosure}.
 * <br>
 * A {@link SelectiveDisclosure} is defined per {@link Issuer} (more specific per {@link AttributeSpace}) and contains
 * the indices of {@link AttributeNameValuePair}s to be disclosed as well as the corresponding issuer public key.
 */
public class SelectiveDisclosure implements StandaloneRepresentable {
    @RepresentedList(elementRestorer = @Represented)
    private List<Integer> attributeIndices;
    private Representation issuerPublicKey;

    public SelectiveDisclosure(Representation issuerPublicKey,
                               List<Integer> attributeIndices) {
        this.issuerPublicKey = issuerPublicKey;
        this.attributeIndices = attributeIndices;
    }

    public SelectiveDisclosure(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
        this.issuerPublicKey = representation.obj().get("issuerPublicKey");
    }

    public List<Integer> getAttributeIndices() {
        return new ArrayList<>(attributeIndices);
    }

    public Representation getIssuerPublicKey() {
        return issuerPublicKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SelectiveDisclosure that = (SelectiveDisclosure) o;
        return Objects.equals(attributeIndices, that.attributeIndices) &&
                Objects.equals(issuerPublicKey, that.issuerPublicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(attributeIndices, issuerPublicKey);
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation representation = AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
        representation.put("issuerPublicKey", issuerPublicKey);
        return representation;
    }
}
