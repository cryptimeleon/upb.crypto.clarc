package de.upb.crypto.clarc.acs.user;

import de.upb.crypto.clarc.acs.systemmanager.SystemManagerPublicIdentity;
import de.upb.crypto.craco.interfaces.PublicParameters;

public interface UserFactory {
    UserKeyPair create(PublicParameters pp, SystemManagerPublicIdentity systemManagerPublicKey);
}
