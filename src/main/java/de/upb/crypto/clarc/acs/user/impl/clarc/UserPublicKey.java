package de.upb.crypto.clarc.acs.user.impl.clarc;

import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.util.Objects;

public class UserPublicKey implements de.upb.crypto.clarc.acs.user.UserPublicKey {

    private Representation upk;

    UserPublicKey(GroupElement upk) {
        this.upk = upk.getRepresentation();
    }

    @SuppressWarnings("unused")
    public UserPublicKey(Representation representation) {
        upk = representation.obj().get("upk");
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation object = new ObjectRepresentation();
        object.put("upk", upk);
        return object;
    }

    public Representation getUpk() {
        return upk;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserPublicKey that = (UserPublicKey) o;
        return Objects.equals(upk, that.upk);
    }

    @Override
    public int hashCode() {
        return Objects.hash(upk);
    }
}
