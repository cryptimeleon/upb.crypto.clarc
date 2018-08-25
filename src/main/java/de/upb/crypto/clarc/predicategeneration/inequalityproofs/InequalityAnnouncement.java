package de.upb.crypto.clarc.predicategeneration.inequalityproofs;

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

public class InequalityAnnouncement implements Announcement {

    @UniqueByteRepresented
    @Represented(structure = "group", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement w;

    private Group group;

    @UniqueByteRepresented
    @RepresentedArray(elementRestorer = @Represented(structure = "protocol", recoveryMethod = Announcement
            .RECOVERY_METHOD))
    private Announcement[] announcements;

    private GeneralizedSchnorrProtocol protocol;

    public InequalityAnnouncement(Announcement[] announcements, GroupElement w) {
        this.announcements = announcements;
        this.w = w;
    }

    public InequalityAnnouncement(Representation representation, Group group, GeneralizedSchnorrProtocol protocol) {
        this.group = group;
        this.protocol = protocol;
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }


    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

    /**
     * The representation of this object. Used for serialization
     *
     * @return a Representation or null if the representedTypeName suffices to instantiate an equal object again
     * @see Representation
     */
    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        InequalityAnnouncement that = (InequalityAnnouncement) o;
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

    public void setW(GroupElement w) {
        this.w = w;
    }

    public Announcement[] getAnnouncements() {
        return announcements;
    }

    public void setAnnouncements(Announcement[] announcements) {
        this.announcements = announcements;
    }
}
