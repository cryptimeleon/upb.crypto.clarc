package de.upb.crypto.clarc.predicategeneration.setmembershipproofs;

import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;

import java.util.Arrays;
import java.util.Objects;

/**
 * Announcement of the SetMembership proof protocol.
 * Contains the announcement of the underlying GenSchnorrProtocol and the value of W, that is computed by the prover
 * and send to the verifier in the Announcement phase
 */
public class SetMembershipAnnouncement implements Announcement {

    @UniqueByteRepresented
    @Represented(structure = "group", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement w;

    private Group group;

    @UniqueByteRepresented
    @RepresentedArray(elementRestorer =
    @Represented(structure = "protocol", recoveryMethod = Announcement.RECOVERY_METHOD))
    private Announcement[] announcements;

    private GeneralizedSchnorrProtocol protocol;

    public SetMembershipAnnouncement(Announcement[] announcements, GroupElement w) {
        this.announcements = announcements;
        this.w = w;
    }

    public SetMembershipAnnouncement(Representation representation, Group group, GeneralizedSchnorrProtocol protocol) {
        this.group = group;
        this.protocol = protocol;
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
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
        SetMembershipAnnouncement that = (SetMembershipAnnouncement) o;
        return Objects.equals(getW(), that.getW()) &&
                Arrays.equals(getAnnouncements(), that.getAnnouncements());
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(getW());
        result = 31 * result + Arrays.hashCode(getAnnouncements());
        return result;
    }

    public GroupElement getW() {
        return w;
    }

    public Announcement[] getAnnouncements() {
        return announcements;
    }
}
