package de.upb.crypto.clarc.acs.systemmanager.impl.clarc;

import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

public class SystemManagerPublicIdentity implements de.upb.crypto.clarc.acs.systemmanager.SystemManagerPublicIdentity {
    @Represented
    private PSExtendedVerificationKey opk;
    @Represented
    private GroupElement linkabilityBasis;

    public SystemManagerPublicIdentity(PSExtendedVerificationKey opk, GroupElement linkabilityBasis) {
        this.opk = opk;
        this.linkabilityBasis = linkabilityBasis;
    }

    public SystemManagerPublicIdentity(Representation representation, PublicParameters pp) {
        final PSExtendedSignatureScheme signatureScheme = PublicParametersFactory.getSignatureScheme(pp);
        opk = signatureScheme.getVerificationKey(representation.obj().get("opk"));
        linkabilityBasis = pp.getBilinearMap().getG2().getElement(representation.obj().get("linkabilityBasis"));
    }

    public PSExtendedVerificationKey getOpk() {
        return opk;
    }

    public GroupElement getLinkabilityBasis() {
        return linkabilityBasis;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SystemManagerPublicIdentity that = (SystemManagerPublicIdentity) o;
        return Objects.equals(opk, that.opk) &&
                Objects.equals(linkabilityBasis, that.linkabilityBasis);
    }

    @Override
    public int hashCode() {
        return Objects.hash(opk, linkabilityBasis);
    }
}
