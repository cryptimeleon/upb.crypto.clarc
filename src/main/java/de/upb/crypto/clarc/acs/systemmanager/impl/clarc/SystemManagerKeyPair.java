package de.upb.crypto.clarc.acs.systemmanager.impl.clarc;

import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.craco.sig.ps.PSSigningKey;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.util.Objects;

public class SystemManagerKeyPair extends de.upb.crypto.clarc.acs.systemmanager.SystemManagerKeyPair {

    private PSSigningKey osk;
    private SystemManagerPublicIdentity publicIdentity;

    public SystemManagerKeyPair(PSSigningKey osk, SystemManagerPublicIdentity publicIdentity) {
        this.osk = osk;
        this.publicIdentity = publicIdentity;
    }

    public SystemManagerKeyPair(Representation representation, PublicParameters pp) {
        osk = new PSSigningKey(representation.obj().get("osk"), pp.getZp());
        publicIdentity = new SystemManagerPublicIdentity(representation.obj().get("publicIdentity"), pp);
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation representation = new ObjectRepresentation();
        representation.put("osk", osk.getRepresentation());
        representation.put("publicIdentity", publicIdentity.getRepresentation());
        return representation;
    }

    public PSSigningKey getSystemManagerSecretKey() {
        return osk;
    }

    public SystemManagerPublicIdentity getPublicIdentity() {
        return publicIdentity;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SystemManagerKeyPair that = (SystemManagerKeyPair) o;
        return Objects.equals(osk, that.osk) &&
                Objects.equals(publicIdentity, that.publicIdentity);
    }

    @Override
    public int hashCode() {
        return Objects.hash(osk, publicIdentity);
    }
}
