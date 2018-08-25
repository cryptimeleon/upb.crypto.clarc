package de.upb.crypto.clarc.predicategeneration.policies;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.interfaces.policy.PolicyFact;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.converter.JSONConverter;

import java.util.Collection;
import java.util.Objects;

/**
 * This class is a special {@link PolicyFact} which marks a leaf of a {@link ThresholdPolicy} which encapsulates
 * a {@link SigmaProtocol} to be executed/simulated during the proof of partial knowledge.
 */
public class SigmaProtocolPolicyFact implements Policy, PolicyFact {

    @Represented
    private SigmaProtocol protocol;
    @Represented
    private int protocolId;

    public SigmaProtocolPolicyFact(SigmaProtocol protocol, int protocolId) {
        this.protocol = protocol;
        this.protocolId = protocolId;
    }

    public SigmaProtocolPolicyFact(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }


    @Override
    public boolean isFulfilled(Collection<? extends PolicyFact> facts) {
        return protocol.isFulfilled();
    }


    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        accumulator.escapeAndSeparate(new JSONConverter().serialize(protocol.getRepresentation())); //TODO replace serialization with something unique (along the lines of implementing the UniqueByteRepresentable interface)
        accumulator.append(protocolId);
        return accumulator;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public SigmaProtocol getProtocol() {
        return protocol;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SigmaProtocolPolicyFact that = (SigmaProtocolPolicyFact) o;
        return protocolId == that.protocolId &&
                Objects.equals(protocol, that.protocol);
    }

    @Override
    public int hashCode() {
        return Objects.hash(protocol, protocolId);
    }
}
