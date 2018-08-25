package de.upb.crypto.clarc.acs.user;

import de.upb.crypto.math.serialization.StandaloneRepresentable;

public interface UserKeyPair extends StandaloneRepresentable {
    UserPublicKey getUserPublicKey();

    UserSecret getUserSecret();
}
