package de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.util.Arrays;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * A class storing the a announcements of the inner protocol within the rangeProof
 * The values of W_JHat ,used in the protocols (c.f. construction 5.7 + 5.9), are stored in
 * randomizedAccWitnesses and sent alongside with the announcement to the verifier
 */
public class ZeroToUPowLRangeProofAnnouncement implements Announcement {

    @UniqueByteRepresented
    private GroupElement[] randomizedAccWitnesses;

    @UniqueByteRepresented
    private Announcement[] announcementsOfInnerProtocol;


    /**
     * @param representation
     * @param group
     * @param innerProtocolGenerator a function that, given randomizedAccWitnesses, creates the inner protocol
     */
    public ZeroToUPowLRangeProofAnnouncement(Representation representation, Group group,
                                             Function<GroupElement[], SigmaProtocol> innerProtocolGenerator) {
        randomizedAccWitnesses = representation.obj().get("randomizedAccWitnesses").list()
                .stream().map(group::getElement).toArray(GroupElement[]::new);

        SigmaProtocol innerProtocol = innerProtocolGenerator.apply(randomizedAccWitnesses);

        announcementsOfInnerProtocol = representation.obj().get("announcementsOfInnerProtocol").list()
                .stream().map(innerProtocol::recreateAnnouncement).toArray(Announcement[]::new);
    }

    public ZeroToUPowLRangeProofAnnouncement(Announcement[] announcementsOfInnerProtocol,
                                             GroupElement[] randomizedAccWitnesses) {
        this.randomizedAccWitnesses = randomizedAccWitnesses;
        this.announcementsOfInnerProtocol = announcementsOfInnerProtocol;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

    @Override
    public Representation getRepresentation() {
        ListRepresentation accWitnesses = new ListRepresentation(Arrays.stream(randomizedAccWitnesses)
                .map(GroupElement::getRepresentation)
                .collect(Collectors.toList()));
        ListRepresentation innerAnnouncements = new ListRepresentation(Arrays.stream(announcementsOfInnerProtocol)
                .map(Announcement::getRepresentation)
                .collect(Collectors.toList()));
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("randomizedAccWitnesses", accWitnesses);
        repr.put("announcementsOfInnerProtocol", innerAnnouncements);

        return repr;
    }

    public GroupElement[] getRandomizedAccWitnesses() {
        return randomizedAccWitnesses;
    }

    public Announcement[] getAnnouncementsOfInnerProtocol() {
        return announcementsOfInnerProtocol;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ZeroToUPowLRangeProofAnnouncement
                that = (ZeroToUPowLRangeProofAnnouncement) o;
        return Arrays.equals(getRandomizedAccWitnesses(), that.getRandomizedAccWitnesses()) &&
                Arrays.equals(getAnnouncementsOfInnerProtocol(), that.getAnnouncementsOfInnerProtocol());
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(getRandomizedAccWitnesses());
        result = 31 * result + Arrays.hashCode(getAnnouncementsOfInnerProtocol());
        return result;
    }
}