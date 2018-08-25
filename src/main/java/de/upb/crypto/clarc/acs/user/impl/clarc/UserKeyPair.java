package de.upb.crypto.clarc.acs.user.impl.clarc;

import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

public class UserKeyPair implements de.upb.crypto.clarc.acs.user.UserKeyPair {

    @Represented
    private UserPublicKey userPublicKey;
    @Represented
    private UserSecret userSecret;

    public UserKeyPair(UserPublicKey upk, UserSecret usk) {
        this.userPublicKey = upk;
        this.userSecret = usk;
    }

    public UserKeyPair(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public UserPublicKey getUserPublicKey() {
        return userPublicKey;
    }

    public UserSecret getUserSecret() {
        return userSecret;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserKeyPair that = (UserKeyPair) o;
        return Objects.equals(userPublicKey, that.userPublicKey) &&
                Objects.equals(userSecret, that.userSecret);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userPublicKey, userSecret);
    }
}
