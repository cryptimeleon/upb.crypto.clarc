package de.upb.crypto.clarc.acs.verifier.impl.clarc.credentials;

import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

public class VerifierPublicIdentity
        implements de.upb.crypto.clarc.acs.verifier.credentials.VerifierPublicIdentity, UniqueByteRepresentable {
    @Represented
    private GroupElement identity;

    public VerifierPublicIdentity(GroupElement identity) {
        this.identity = identity;
    }

    public VerifierPublicIdentity(Representation representation, PublicParameters pp) {
        identity = pp.getBilinearMap().getG1().getElement(representation.obj().get("identity"));
    }

    public GroupElement getIdentity() {
        return identity;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VerifierPublicIdentity that = (VerifierPublicIdentity) o;
        return Objects.equals(identity, that.identity);
    }

    @Override
    public int hashCode() {
        return Objects.hash(identity);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        byteAccumulator.escapeAndSeparate(identity);
        return byteAccumulator;
    }
}
