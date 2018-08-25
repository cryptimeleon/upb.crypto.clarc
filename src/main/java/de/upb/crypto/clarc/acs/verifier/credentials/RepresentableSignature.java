package de.upb.crypto.clarc.acs.verifier.credentials;

import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

import java.util.Objects;

import static de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory.getSignatureScheme;

public class RepresentableSignature implements StandaloneRepresentable {
    private Representation signature;

    public RepresentableSignature(PSSignature signature) {
        this.signature = signature.getRepresentation();
    }

    public RepresentableSignature(Representation representation) {
        signature = representation.obj().get("signature");
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation object = new ObjectRepresentation();
        object.put("signature", signature);
        return object;
    }

    public PSSignature getSignature(PublicParameters pp) {
        PSExtendedSignatureScheme signatureScheme = getSignatureScheme(pp);
        return signatureScheme.getSignature(signature);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RepresentableSignature that = (RepresentableSignature) o;
        return Objects.equals(signature, that.signature);
    }

    @Override
    public int hashCode() {
        return Objects.hash(signature);
    }
}
