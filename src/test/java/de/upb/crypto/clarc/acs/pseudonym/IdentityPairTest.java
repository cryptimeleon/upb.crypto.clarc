package de.upb.crypto.clarc.acs.pseudonym;

import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Identity;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.commitment.pedersen.PedersenOpenValue;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.serialization.converter.JSONConverter;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class IdentityPairTest {

    private final String expectedSerializedIdentity = "{\"commitment\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.craco.commitment.pedersen" +
            ".PedersenCommitmentPair\",\"representation\":{\"commitmentValue\":{\"thisIsRepresentableRepresentation" +
            "\":true,\"representableTypeName\":\"de.upb.crypto.craco.commitment.pedersen" +
            ".PedersenCommitmentValue\",\"representation\":{\"commitmentElement\":\"<BigInteger>0\"," +
            "\"group\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto.math" +
            ".interfaces.structures.RingAdditiveGroup\",\"representation\":{\"ringRepresentation\":\"<BigInteger>3\"," +
            "\"ringTypeName\":\"de.upb.crypto.math.structures.zn.Zp\"}}}}," +
            "\"openValue\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto" +
            ".craco.commitment.pedersen.PedersenOpenValue\"," +
            "\"representation\":{\"messages\":[\"<BigInteger>1\"],\"randomness\":\"<BigInteger>1\"," +
            "\"zp\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto.math" +
            ".structures.zn.Zp\",\"representation\":\"<BigInteger>3\"}}}}}," +
            "\"pseudonym\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto" +
            ".clarc.acs.pseudonym.impl.clarc.Pseudonym\"," +
            "\"representation\":{\"commitmentValue\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.craco.commitment.pedersen" +
            ".PedersenCommitmentValue\",\"representation\":{\"commitmentElement\":\"<BigInteger>0\"," +
            "\"group\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto.math" +
            ".interfaces.structures.RingAdditiveGroup\",\"representation\":{\"ringRepresentation\":\"<BigInteger>3\"," +
            "\"ringTypeName\":\"de.upb.crypto.math.structures.zn.Zp\"}}}}}}}";

    @Test
    void serializationTest() {
        final JSONConverter converter = new JSONConverter();

        final Zp zp = new Zp(BigInteger.valueOf(3));
        final Group group = zp.asAdditiveGroup();

        final PedersenCommitmentValue commitmentValue = new PedersenCommitmentValue(group.getNeutralElement());
        final PedersenOpenValue openValue =
                new PedersenOpenValue(new Zp.ZpElement[]{zp.getOneElement()}, zp.getOneElement());

        Identity clarcIdentity = new Identity(new PedersenCommitmentPair(commitmentValue, openValue));
        final String serializedIdentity = converter.serialize(clarcIdentity.getRepresentation());

        assertEquals(expectedSerializedIdentity, serializedIdentity);
    }

    @Test
    void deserializationTest() {
        final JSONConverter converter = new JSONConverter();

        final Identity clarcIdentity = new Identity(converter.deserialize(expectedSerializedIdentity));
        assertNotNull(clarcIdentity.getPseudonym(), "pseudonym must not be null");
        assertNotNull(clarcIdentity.getPseudonymSecret(), "pseudonym secret must not be null");
    }
}