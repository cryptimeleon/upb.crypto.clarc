package de.upb.crypto.clarc.acs.user.impl.clarc;

import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.systemmanager.SystemManager;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.SystemManagerPublicIdentity;
import de.upb.crypto.clarc.acs.user.UserFactory;

public class UserKeyPairFactory implements UserFactory {
    /**
     * Uses the public parameters and the included size to choose a uniformly random element from the size.
     *
     * @param pp                          ACS public parameters
     * @param systemManagerPublicIdentity the public identity of the {@link SystemManager}
     * @return A user secret as Zp element
     */
    @Override
    public UserKeyPair create(de.upb.crypto.craco.interfaces.PublicParameters pp, de.upb.crypto.clarc.acs.systemmanager.SystemManagerPublicIdentity systemManagerPublicIdentity) {
        PublicParameters clarcPP = (PublicParameters) pp;
        SystemManagerPublicIdentity clarcSystemManagerPublicIdentity =
                (SystemManagerPublicIdentity) systemManagerPublicIdentity;

        final UserSecret usk = new UserSecret(clarcPP.getZp().getUniformlyRandomElement());
        final UserPublicKey upk = new UserPublicKey(
                clarcSystemManagerPublicIdentity.getOpk().getGroup1ElementG().pow(usk.getUsk())
        );
        return new UserKeyPair(upk, usk);
    }
}
