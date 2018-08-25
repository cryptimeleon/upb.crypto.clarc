package de.upb.crypto.clarc.predicategeneration.policies;

import de.upb.crypto.clarc.predicategeneration.fixedprotocols.popk.ProofOfPartialKnowledgeProtocol;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.interfaces.policy.PolicyFact;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.converter.JSONConverter;

import java.util.Collection;
import java.util.Objects;

/**
 * This class is a special {@link PolicyFact} which marks a leaf of a {@link ThresholdPolicy}. This fact encapsulates
 * another {@link ThresholdPolicy} which can only be fulfilled by a SignatureCredential which was issued by
 * the given issuer.
 * <p>
 * These so-called sub policies (the inner {@link ThresholdPolicy}) are intended to be transformed to
 * SubPolicyProvingProtocol which are then connected by a {@link ProofOfPartialKnowledgeProtocol}.
 * Therefore, as by contract of SubPolicyProvingProtocol, the sub policy has to contain
 * {@link PredicatePolicyFact} as leaves.
 * </p>
 */
public class SubPolicyPolicyFact implements PolicyFact, Policy {

    private Representation issuerPublicKeyRepresentation;
    @Represented
    private ThresholdPolicy subPolicy;

    public SubPolicyPolicyFact(Representation issuerPublicKeyRepresentation, Policy subPolicy) {
        this.issuerPublicKeyRepresentation = issuerPublicKeyRepresentation;
        if (subPolicy instanceof ThresholdPolicy) {
            this.subPolicy = (ThresholdPolicy) subPolicy;
        } else if (subPolicy instanceof PredicatePolicyFact) {
            this.subPolicy = new ThresholdPolicy(1, subPolicy);
        } else {
            throw new IllegalArgumentException("Unsupported policy type: " + subPolicy.getClass().getName());
        }
    }

    public SubPolicyPolicyFact(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
        issuerPublicKeyRepresentation = representation.obj().get("issuerPublicKeyRepresentation");
    }

    public Representation getIssuerPublicKeyRepresentation() {
        return issuerPublicKeyRepresentation;
    }

    public ThresholdPolicy getSubPolicy() {
        return subPolicy;
    }

    @Override
    public boolean isFulfilled(Collection<? extends PolicyFact> collection) {
        return subPolicy.isFulfilled(collection);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        byteAccumulator.escapeAndSeparate(new JSONConverter().serialize(issuerPublicKeyRepresentation)); //TODO replace serialization with something unique (along the lines of implementing the UniqueByteRepresentable interface)
        byteAccumulator.escapeAndSeparate(subPolicy);
        return byteAccumulator;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation representation = AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
        representation.put("issuerPublicKeyRepresentation", issuerPublicKeyRepresentation);
        return representation;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SubPolicyPolicyFact that = (SubPolicyPolicyFact) o;
        return Objects.equals(issuerPublicKeyRepresentation, that.issuerPublicKeyRepresentation) &&
                Objects.equals(subPolicy, that.subPolicy);
    }

    @Override
    public int hashCode() {
        return Objects.hash(issuerPublicKeyRepresentation, subPolicy);
    }
}
