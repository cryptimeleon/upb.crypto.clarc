package de.upb.crypto.clarc.acs.user.impl.clarc;

import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.converter.JSONConverter;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.easymock.EasyMock.*;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

class UserSecretTest {
    private final String serializedUsk = "{\"usk\":\"<BigInteger>1\",\"zp\":{\"thisIsRepresentableRepresentation" +
            "\":true,\"representableTypeName\":\"de.upb.crypto.math.structures.zn.Zp\"," +
            "\"representation\":\"<BigInteger>2\"}}";

    @Test
    void uskSerializationTest() {
        Zp zp = new Zp(BigInteger.valueOf(2));
        Zp.ZpElement secret = zp.getOneElement();
        de.upb.crypto.clarc.acs.user.UserSecret usk = new UserSecret(secret);

        JSONConverter converter = new JSONConverter();
        assertEquals(serializedUsk, converter.serialize(usk.getRepresentation()));
    }

    @Test
    void uskDeserializationTest() {
        JSONConverter converter = new JSONConverter();

        PublicParameters pp = mock(PublicParameters.class);
        expect(pp.getZp()).andReturn(new Zp(BigInteger.valueOf(2)));
        replay(pp);

        final Representation representation = converter.deserialize(serializedUsk);
        de.upb.crypto.clarc.acs.user.UserSecret usk = new UserSecret(representation);
        assertNotNull(usk.getUsk(), "expected usk");
    }
}