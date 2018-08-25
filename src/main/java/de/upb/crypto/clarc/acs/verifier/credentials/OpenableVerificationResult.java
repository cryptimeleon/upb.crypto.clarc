package de.upb.crypto.clarc.acs.verifier.credentials;

import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirProof;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

public class OpenableVerificationResult implements StandaloneRepresentable {
    @Represented
    private FiatShamirProof proof;
    @Represented
    private InteractiveThreeWayAoK protocol;

    public OpenableVerificationResult(FiatShamirProof proof, InteractiveThreeWayAoK protocol) {
        this.proof = proof;
        this.protocol = protocol;
    }

    public OpenableVerificationResult(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public FiatShamirProof getFiatShamirProof() {
        return proof;
    }

    public InteractiveThreeWayAoK getProtocol() {
        return protocol;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OpenableVerificationResult that = (OpenableVerificationResult) o;
        return Objects.equals(proof, that.proof) &&
                Objects.equals(protocol, that.protocol);
    }

    @Override
    public int hashCode() {
        return Objects.hash(proof, protocol);
    }
}
