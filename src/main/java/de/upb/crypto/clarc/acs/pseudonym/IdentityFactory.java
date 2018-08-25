package de.upb.crypto.clarc.acs.pseudonym;

import de.upb.crypto.clarc.acs.user.UserSecret;
import de.upb.crypto.craco.interfaces.PublicParameters;

public interface IdentityFactory {
    Identity create(PublicParameters pp, UserSecret usk);
}
