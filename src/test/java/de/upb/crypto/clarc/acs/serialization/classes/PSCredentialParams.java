package de.upb.crypto.clarc.acs.serialization.classes;

import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.utils.StandaloneTestParams;

import java.util.ArrayList;
import java.util.Collection;

public class PSCredentialParams {

    public static Collection<StandaloneTestParams> get() {

        BuildingBlocksTestdataProvider provider = new BuildingBlocksTestdataProvider();

        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();
        toReturn.add(new StandaloneTestParams(PSCredential.class, provider.getCredential()));
        return toReturn;
    }
}
