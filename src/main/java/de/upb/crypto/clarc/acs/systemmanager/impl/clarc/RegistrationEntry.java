package de.upb.crypto.clarc.acs.systemmanager.impl.clarc;

import de.upb.crypto.clarc.acs.user.impl.clarc.UserPublicKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

public class RegistrationEntry implements StandaloneRepresentable {
    @Represented
    private UserPublicKey clarcUserPublicKey;
    private Representation psSignature;
    private Representation tau;

    public RegistrationEntry(UserPublicKey clarcUserPublicKey, PSSignature psSignature, GroupElement tau) {
        this.clarcUserPublicKey = clarcUserPublicKey;
        this.psSignature = psSignature.getRepresentation();
        this.tau = tau.getRepresentation();
    }

    @SuppressWarnings("unused")
    public RegistrationEntry(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
        final ObjectRepresentation obj = representation.obj();
        psSignature = obj.get("psSignature");
        tau = obj.get("tau");
    }

    public UserPublicKey getUserPublicKey() {
        return clarcUserPublicKey;
    }

    public Representation getSignature() {
        return psSignature;
    }

    public Representation getTau() {
        return tau;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation object = AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
        object.put("psSignature", psSignature);
        object.put("tau", tau);
        return object;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RegistrationEntry that = (RegistrationEntry) o;
        return Objects.equals(clarcUserPublicKey, that.clarcUserPublicKey) &&
                Objects.equals(psSignature, that.psSignature) &&
                Objects.equals(tau, that.tau);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clarcUserPublicKey, psSignature, tau);
    }
}
