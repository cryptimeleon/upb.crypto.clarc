package de.upb.crypto.clarc.acs.systemmanager;

import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

public interface JoinResponse extends StandaloneRepresentable {
    Representation getRegistrationSignature();
}
