package de.upb.crypto.clarc.acs.serialization.classes;

import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.testdataprovider.ParameterTestdataProvider;
import de.upb.crypto.clarc.utils.StandaloneTestParams;

import java.util.ArrayList;
import java.util.Collection;

public class Params {

    public static Collection<StandaloneTestParams> get() {

        ParameterTestdataProvider clarcProvider = new ParameterTestdataProvider();

        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();
        toReturn.add(new StandaloneTestParams(PublicParameters.class, clarcProvider.getPP()));
        return toReturn;
    }
}
