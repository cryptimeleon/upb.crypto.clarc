package de.upb.crypto.clarc.predicategeneration.policies;

import de.upb.crypto.clarc.predicategeneration.PredicatePublicParameters;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.PredicateTypePrimitive;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.interfaces.policy.PolicyFact;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Collection;
import java.util.Objects;

/**
 * This class is a special {@link PolicyFact} which marks a leaf of a {@link ThresholdPolicy} which encapsulates
 * all information needed for de.upb.crypto.clarc.acs.PredicateToSigmaProtocolTransformation to build a {@link SigmaProtocol} for the
 * given
 * {@link PredicateTypePrimitive}.
 */
public class PredicatePolicyFact implements PolicyFact, Policy {
    @Represented
    protected PredicatePublicParameters publicParameters;
    @Represented
    protected PredicateTypePrimitive proofType;

    public PredicatePolicyFact(PredicatePublicParameters publicParameters, PredicateTypePrimitive proofType) {
        this.publicParameters = publicParameters;
        this.proofType = proofType;
    }

    public PredicatePolicyFact(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    @Override
    public boolean isFulfilled(Collection<? extends PolicyFact> facts) {
        return false;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        accumulator.escapeAndSeparate(publicParameters);
        accumulator.escapeAndAppend(proofType.name());
        return accumulator;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public PredicatePublicParameters getPublicParameters() {
        return publicParameters;
    }

    public void setPublicParameters(PredicatePublicParameters publicParameters) {
        this.publicParameters = publicParameters;
    }

    public PredicateTypePrimitive getProofType() {
        return proofType;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PredicatePolicyFact that = (PredicatePolicyFact) o;
        return Objects.equals(publicParameters, that.publicParameters) &&
                proofType == that.proofType;
    }

    @Override
    public int hashCode() {
        return Objects.hash(publicParameters, proofType);
    }
}
