package de.upb.crypto.clarc.acs.user.credentials;

import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;

import java.util.Arrays;
import java.util.Objects;

public abstract class SignatureCredential implements Credential, StandaloneRepresentable {
    protected Representation signatureRepresentation;
    @RepresentedArray(elementRestorer = @Represented)
    protected AttributeNameValuePair[] attributes;
    protected Representation issuerPublicKeyRepresentation;

    public SignatureCredential(Representation signatureRepresentation, AttributeNameValuePair[] attributes,
                               Representation issuerPublicKeyRepresentation) {
        this.signatureRepresentation = signatureRepresentation;
        this.issuerPublicKeyRepresentation = issuerPublicKeyRepresentation;
        this.attributes = attributes;
    }

    public SignatureCredential(Representation representation) {
        signatureRepresentation = representation.obj().get("signatureRepresentation");
        issuerPublicKeyRepresentation = representation.obj().get("issuerPublicKeyRepresentation");
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    /**
     * Only for representable
     */
    protected SignatureCredential() {
    }


    @Override
    public Representation getRepresentation() {
        final ObjectRepresentation representation = AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
        representation.put("signatureRepresentation", signatureRepresentation);
        representation.put("issuerPublicKeyRepresentation", issuerPublicKeyRepresentation);
        return representation;
    }

    public Representation getSignatureRepresentation() {
        return signatureRepresentation;
    }

    public Representation getIssuerPublicKeyRepresentation() {
        return issuerPublicKeyRepresentation;
    }

    public AttributeNameValuePair[] getAttributes() {
        return Arrays.copyOf(attributes, attributes.length);
    }

    public void setAttributes(AttributeNameValuePair[] attributes) {
        this.attributes = attributes;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SignatureCredential that = (SignatureCredential) o;
        return Objects.equals(getSignatureRepresentation(), that.getSignatureRepresentation()) &&
                Objects.equals(issuerPublicKeyRepresentation, that.issuerPublicKeyRepresentation) &&
                Arrays.equals(getAttributes(), that.getAttributes());
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(getSignatureRepresentation(), issuerPublicKeyRepresentation);
        result = 31 * result + Arrays.hashCode(getAttributes());
        return result;
    }
}
