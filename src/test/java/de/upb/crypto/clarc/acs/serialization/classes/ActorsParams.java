package de.upb.crypto.clarc.acs.serialization.classes;

import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssuer;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssuerPublicIdentity;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Identity;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Pseudonym;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.RegistrationEntry;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.RegistrationInformation;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.SystemManager;
import de.upb.crypto.clarc.acs.testdataprovider.IssuerTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.ParameterTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.UserAndSystemManagerTestdataProvider;
import de.upb.crypto.clarc.acs.user.impl.clarc.User;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserKeyPair;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserPublicKey;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserSecret;
import de.upb.crypto.clarc.utils.StandaloneTestParams;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;

import java.util.ArrayList;
import java.util.Collection;

public class ActorsParams {
    public static Collection<StandaloneTestParams> get() {

        ParameterTestdataProvider clarcProvider = new ParameterTestdataProvider();
        UserAndSystemManagerTestdataProvider userProvider =
                new UserAndSystemManagerTestdataProvider(clarcProvider.getPublicParameters());
        IssuerTestdataProvider issuerProvider = new IssuerTestdataProvider(clarcProvider.getPublicParameters(),
                clarcProvider.getSignatureScheme(), userProvider.getUserSecret());

        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();

        toReturn.add(new StandaloneTestParams(UserSecret.class, userProvider.getUserSecret()));
        toReturn.add(new StandaloneTestParams(UserPublicKey.class, userProvider.getFixedUpk()));
        toReturn.add(new StandaloneTestParams(UserKeyPair.class, userProvider.getFixedUserKeyPair()));
        toReturn.add(new StandaloneTestParams(User.class, userProvider.getUser()));
        toReturn.add(new StandaloneTestParams(Identity.class, userProvider.getIdentity()));
        toReturn.add(new StandaloneTestParams(Pseudonym.class, userProvider.getIdentity().getPseudonym()));

        toReturn.add(new StandaloneTestParams(RegistrationInformation.class,
                userProvider.getRegistrationInformation()));
        toReturn.add(new StandaloneTestParams(SystemManager.class,
                userProvider.getSystemManager()));
        final BilinearMap map = clarcProvider.getPP().getBilinearMap();
        toReturn.add(new StandaloneTestParams(RegistrationEntry.class, new RegistrationEntry(
                        userProvider.getFixedUpk(),
                        new PSSignature(map.getG1().getNeutralElement(), map.getG1().getNeutralElement()),
                        map.getG2().getNeutralElement())
                )
        );
        CredentialIssuer issuer = issuerProvider.getIssuer();
        toReturn.add(new StandaloneTestParams(CredentialIssuer.class, issuer));
        toReturn.add(new StandaloneTestParams(CredentialIssuerPublicIdentity.class, issuer.getPublicIdentity()));
        return toReturn;
    }
}
