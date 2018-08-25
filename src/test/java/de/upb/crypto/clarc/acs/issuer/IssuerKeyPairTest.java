package de.upb.crypto.clarc.acs.issuer;

import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerKeyPair;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSigningKey;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.interfaces.structures.RingAdditiveGroup;
import de.upb.crypto.math.serialization.converter.JSONConverter;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class IssuerKeyPairTest {
    private final String serializedKeyPair = "{\"signingKey\":{\"exponentX\":\"<BigInteger>1\"," +
            "\"exponentsYi\":[\"<BigInteger>0\"]},\"verificationKey\":{\"group1ElementG\":\"<BigInteger>0\"," +
            "\"group1ElementsYi\":[\"<BigInteger>0\"],\"group2ElementTildeG\":\"<BigInteger>0\"," +
            "\"group2ElementTildeX\":\"<BigInteger>0\",\"group2ElementsTildeYi\":[\"<BigInteger>0\"]}}";


    @Test
    void clarcIssuerKeyPairSerializationTest() {
        final JSONConverter converter = new JSONConverter();

        Zp zp = new Zp(BigInteger.valueOf(2));
        Group group = zp.asAdditiveGroup();

        final PSSigningKey signingKey = new PSSigningKey();
        signingKey.setExponentX(zp.getOneElement());
        signingKey.setExponentsYi(new Zp.ZpElement[]{zp.getZeroElement()});

        final PSExtendedVerificationKey verificationKey = new PSExtendedVerificationKey(group.getNeutralElement(),
                new GroupElement[]{group.getNeutralElement()}, group.getNeutralElement(), group.getNeutralElement(),
                new GroupElement[]{group.getNeutralElement()});


        IssuerKeyPair keyPair = new IssuerKeyPair(signingKey, verificationKey);
        assertEquals(serializedKeyPair, converter.serialize(keyPair.getRepresentation()));
    }

    @Test
    void deserializationTest() {
        final JSONConverter converter = new JSONConverter();

        Zp zp = new Zp(BigInteger.valueOf(2));
        final RingAdditiveGroup group = zp.asAdditiveGroup();
        IssuerKeyPair keyPair = new IssuerKeyPair(converter.deserialize(serializedKeyPair), zp, group, group);
        assertNotNull(keyPair.getSigningKey(), "signing key must not be null");
        assertNotNull(keyPair.getVerificationKey(), "verification key must not be null");
    }
}
