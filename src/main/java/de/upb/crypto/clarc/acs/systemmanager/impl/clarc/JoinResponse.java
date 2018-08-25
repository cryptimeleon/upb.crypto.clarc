package de.upb.crypto.clarc.acs.systemmanager.impl.clarc;

import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.util.Objects;

public class JoinResponse implements de.upb.crypto.clarc.acs.systemmanager.JoinResponse {

    private Representation registrationSignature;

    public JoinResponse(PSSignature registrationSignature) {
        this.registrationSignature = registrationSignature.getRepresentation();
    }

    public JoinResponse(Representation representation) {
        this.registrationSignature = representation.obj().get("registrationSignature");
    }

    @Override
    public Representation getRegistrationSignature() {
        return registrationSignature;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation representation = new ObjectRepresentation();
        representation.put("registrationSignature", registrationSignature);
        return representation;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        JoinResponse that = (JoinResponse) o;
        return Objects.equals(registrationSignature, that.registrationSignature);
    }

    @Override
    public int hashCode() {
        return Objects.hash(registrationSignature);
    }
}
