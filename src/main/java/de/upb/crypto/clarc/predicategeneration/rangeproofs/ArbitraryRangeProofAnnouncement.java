package de.upb.crypto.clarc.predicategeneration.rangeproofs;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;

import java.util.Arrays;

/**
 * A class storing the two announcements of the lower and upper bound protocol within the rangeProof
 * The values of W_JHat ,used in the protocols (c.f. construction 5.7 + 5.9) , are stored in
 * lowerBoundRandomizedAccWitnesses and upperBoundRandomizedAccWitnesses and sent alongside with the announcements to
 * the verifier
 */
public class ArbitraryRangeProofAnnouncement implements Announcement {
    @UniqueByteRepresented
    @RepresentedArray(elementRestorer =
    @Represented(structure = "lowerBoundProtocol", recoveryMethod = Announcement.RECOVERY_METHOD))
    private Announcement[] announcementsOfLowerBoundProtocol;
    @UniqueByteRepresented
    @RepresentedArray(elementRestorer =
    @Represented(structure = "upperBoundProtocol", recoveryMethod = Announcement.RECOVERY_METHOD))
    private Announcement[] announcementsOfUpperBoundProtocol;

    // Used for recreation
    private Group group;
    private SigmaProtocol lowerBoundProtocol;
    private SigmaProtocol upperBoundProtocol;

    public ArbitraryRangeProofAnnouncement(Representation representation, Group group,
                                           SigmaProtocol lowerBoundProtocol,
                                           SigmaProtocol upperBoundProtocol) {
        this.group = group;
        this.lowerBoundProtocol = lowerBoundProtocol;
        this.upperBoundProtocol = upperBoundProtocol;

        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public ArbitraryRangeProofAnnouncement(Announcement[] announcementsOfLowerBoundProtocol,
                                           Announcement[] announcementsOfUpperBoundProtocol) {
        this.announcementsOfLowerBoundProtocol = announcementsOfLowerBoundProtocol;
        this.announcementsOfUpperBoundProtocol = announcementsOfUpperBoundProtocol;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public Announcement[] getAnnouncementsOfLowerBoundProtocol() {
        return announcementsOfLowerBoundProtocol;
    }

    public Announcement[] getAnnouncementsOfUpperBoundProtocol() {
        return announcementsOfUpperBoundProtocol;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ArbitraryRangeProofAnnouncement that = (ArbitraryRangeProofAnnouncement) o;
        return Arrays.equals(getAnnouncementsOfLowerBoundProtocol(), that.getAnnouncementsOfLowerBoundProtocol()) &&
                Arrays.equals(getAnnouncementsOfUpperBoundProtocol(), that.getAnnouncementsOfUpperBoundProtocol());
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(getAnnouncementsOfLowerBoundProtocol());
        result = 31 * result + Arrays.hashCode(getAnnouncementsOfUpperBoundProtocol());
        return result;
    }
}