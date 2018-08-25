package de.upb.crypto.clarc.acs.systemmanager.impl.clarc;

import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.util.Objects;

public class RegistrationInformation implements de.upb.crypto.clarc.acs.systemmanager.RegistrationInformation {
    private Representation tau;

    public RegistrationInformation(GroupElement tau) {
        this.tau = tau.getRepresentation();
    }

    @SuppressWarnings("unused")
    public RegistrationInformation(Representation representation) {
        tau = representation.obj().get("tau");
    }

    public Representation getTau() {
        return tau;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation object = new ObjectRepresentation();
        object.put("tau", tau);
        return object;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RegistrationInformation that = (RegistrationInformation) o;
        return Objects.equals(tau, that.tau);
    }

    @Override
    public int hashCode() {
        return Objects.hash(tau);
    }
}
