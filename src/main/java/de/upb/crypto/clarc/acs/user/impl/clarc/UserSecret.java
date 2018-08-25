package de.upb.crypto.clarc.acs.user.impl.clarc;

import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Objects;

/**
 * Our implementation of the user secret using Zp elements
 */
public class UserSecret implements de.upb.crypto.clarc.acs.user.UserSecret {
    @Represented
    Zp zp;
    @Represented(structure = "zp", recoveryMethod = Zp.ZpElement.RECOVERY_METHOD)
    Zp.ZpElement usk;

    /**
     * Initializes the user secret as Zp element
     *
     * @param usk user secret
     */
    public UserSecret(Zp.ZpElement usk) {
        this.usk = usk;
        this.zp = usk.getStructure();
    }

    public UserSecret(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public UserPublicKey computeUserIdentity(Zp.ZpElement usk, PSExtendedVerificationKey psVerificationKey) {
        return new UserPublicKey(psVerificationKey.getGroup1ElementG()
                .pow(usk));
    }

    public Zp.ZpElement getUsk() {
        return usk;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserSecret that = (UserSecret) o;
        return Objects.equals(getUsk(), that.getUsk()) &&
                Objects.equals(zp, that.zp);
    }

    @Override
    public int hashCode() {

        return Objects.hash(getUsk(), zp);
    }
}
