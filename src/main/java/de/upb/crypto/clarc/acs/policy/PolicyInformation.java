package de.upb.crypto.clarc.acs.policy;

import de.upb.crypto.clarc.acs.attributes.AttributeSpace;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.SelectiveDisclosure;
import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;
import de.upb.crypto.math.serialization.annotations.RepresentedList;

import java.util.List;
import java.util.Objects;

public class PolicyInformation implements StandaloneRepresentable, UniqueByteRepresentable {
    @Represented
    private PublicParameters pp;
    @Represented
    private Policy policy;
    @RepresentedList(elementRestorer = @Represented)
    private List<AttributeSpace> usedAttributeSpaces;
    @RepresentedArray(elementRestorer = @Represented)
    private SelectiveDisclosure[] requiredDisclosures;
    @Represented
    private boolean isMasterCredentialRequired;

    public PolicyInformation(PublicParameters pp, Policy policy,
                             List<AttributeSpace> usedAttributeSpaces,
                             SelectiveDisclosure[] requiredDisclosures,
                             boolean isMasterCredentialRequired) {
        this.pp = pp;
        this.policy = policy;
        this.usedAttributeSpaces = usedAttributeSpaces;
        this.requiredDisclosures = requiredDisclosures;
        this.isMasterCredentialRequired = isMasterCredentialRequired;
    }

    public PolicyInformation(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public PublicParameters getPublicParameters() {
        return pp;
    }

    public Policy getPolicy() {
        return policy;
    }

    public List<AttributeSpace> getUsedAttributeSpaces() {
        return usedAttributeSpaces;
    }

    public SelectiveDisclosure[] getRequiredDisclosures() {
        return requiredDisclosures;
    }

    public boolean isMasterCredentialRequired() {
        return isMasterCredentialRequired;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        byteAccumulator.escapeAndSeparate(policy);
        usedAttributeSpaces.forEach(byteAccumulator::escapeAndSeparate);
        byteAccumulator.escapeAndSeparate("" + isMasterCredentialRequired);
        return byteAccumulator;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PolicyInformation that = (PolicyInformation) o;
        return isMasterCredentialRequired == that.isMasterCredentialRequired &&
                Objects.equals(pp, that.pp) &&
                Objects.equals(policy, that.policy) &&
                Objects.equals(usedAttributeSpaces, that.usedAttributeSpaces);
    }

    @Override
    public int hashCode() {
        return Objects.hash(pp, policy, usedAttributeSpaces, isMasterCredentialRequired);
    }
}
