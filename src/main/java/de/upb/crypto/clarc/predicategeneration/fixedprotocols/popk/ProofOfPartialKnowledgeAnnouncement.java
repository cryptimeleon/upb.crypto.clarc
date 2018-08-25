package de.upb.crypto.clarc.predicategeneration.fixedprotocols.popk;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * {@link Announcement} for the {@link ProofOfPartialKnowledgeProtocol} which contains the {@link Announcement}
 * associated with a {@link SigmaProtocol} in a leaf of the {@link ThresholdPolicy} to be proven.
 */
public class ProofOfPartialKnowledgeAnnouncement implements Announcement {
    private SigmaProtocol protocol;

    @UniqueByteRepresented
    @Represented
    private BigInteger protocolId;

    @UniqueByteRepresented
    @RepresentedArray(elementRestorer = @Represented(structure = "protocol", recoveryMethod = Announcement
            .RECOVERY_METHOD))
    private Announcement[] announcements;

    public ProofOfPartialKnowledgeAnnouncement(int protocolId, Announcement[] announcements) {
        this.protocolId = BigInteger.valueOf(protocolId);
        this.announcements = announcements;
    }

    public ProofOfPartialKnowledgeAnnouncement(Representation representation, SigmaProtocol protocol) {
        this.protocol = protocol;
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public Announcement[] getAnnouncements() {
        return announcements;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ProofOfPartialKnowledgeAnnouncement that = (ProofOfPartialKnowledgeAnnouncement) o;
        return Objects.equals(protocolId, that.protocolId) &&
                Arrays.equals(announcements, that.announcements);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(protocolId);
        result = 31 * result + Arrays.hashCode(announcements);
        return result;
    }
}
