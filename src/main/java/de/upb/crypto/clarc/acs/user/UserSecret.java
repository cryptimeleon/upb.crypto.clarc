package de.upb.crypto.clarc.acs.user;

import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * Abstract class of the user secret with only a representable user secret. This can be extended to any data type
 * needed for the acs (in our case this will be a Zp element).
 */
public interface UserSecret extends StandaloneRepresentable {
    Representable getUsk();
}
