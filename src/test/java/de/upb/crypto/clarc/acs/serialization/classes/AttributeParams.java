package de.upb.crypto.clarc.acs.serialization.classes;

import de.upb.crypto.clarc.acs.attributes.*;
import de.upb.crypto.clarc.utils.StandaloneTestParams;

import java.util.ArrayList;
import java.util.Collection;

public class AttributeParams {
    public static Collection<StandaloneTestParams> get() {

        BuildingBlocksTestdataProvider provider = new BuildingBlocksTestdataProvider();

        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();

        toReturn.add(new StandaloneTestParams(AttributeNameValuePair.class, provider.generateRandomAttribute()));

        toReturn.add(new StandaloneTestParams(StringAttributeDefinition.class, provider
                .generateRandomStringAttributeDefinition()));
        toReturn.add(new StandaloneTestParams(BigIntegerAttributeDefinition.class, provider
                .generateRandomBigIntAttributeDefinition()));
        toReturn.add(new StandaloneTestParams(RingElementAttributeDefinition.class, provider
                .generateRandomRingElemenAttributeDefinition()));
        toReturn.add(new StandaloneTestParams(AttributeSpace.class, provider.getIssuerAttributeSpace()));
        return toReturn;
    }
}
