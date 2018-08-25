package de.upb.crypto.clarc.acs.user;

import de.upb.crypto.clarc.acs.user.impl.clarc.UserPublicKey;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.Proof;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

public abstract class NonInteractiveJoinRequest implements StandaloneRepresentable {

    @Represented
    private Proof proof;
    private Representation tau;
    @Represented
    private UserPublicKey upk;

    public NonInteractiveJoinRequest(Proof proof, GroupElement tau, UserPublicKey upk) {
        this.proof = proof;
        this.tau = tau.getRepresentation();
        this.upk = upk;
    }

    public NonInteractiveJoinRequest(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
        this.tau = representation.obj().get("tau");
    }

    public Proof getProof() {
        return proof;
    }

    public Representation getTau() {
        return tau;
    }

    public UserPublicKey getUpk() {
        return upk;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation representation = AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
        representation.put("tau", tau);
        return representation;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NonInteractiveJoinRequest that = (NonInteractiveJoinRequest) o;
        return Objects.equals(proof, that.proof) &&
                Objects.equals(tau, that.tau);
    }

    @Override
    public int hashCode() {
        return Objects.hash(proof, tau);
    }
}
