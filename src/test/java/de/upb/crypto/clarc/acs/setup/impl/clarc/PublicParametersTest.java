package de.upb.crypto.clarc.acs.setup.impl.clarc;

import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParameters;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.math.hash.impl.VariableOutputLengthHashFunction;
import de.upb.crypto.math.interfaces.hash.HashFunction;
import de.upb.crypto.math.interfaces.hash.HashIntoStructure;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.converter.JSONConverter;
import de.upb.crypto.math.structures.zn.HashIntoZnAdditiveGroup;
import de.upb.crypto.math.structures.zn.HashIntoZp;
import de.upb.crypto.math.structures.zn.RingMultiplication;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class PublicParametersTest {

    private final String serializedBilinearMap = "{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.structures.zn.RingMultiplication\"," +
            "\"representation\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto" +
            ".math.structures.zn.Zp\",\"representation\":\"<BigInteger>101\"}}";

    private final String serializedHashIntoZp = "{\"hashIntoZn\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.hash.impl.VariableOutputLengthHashFunction\"," +
            "\"representation\":{\"innerFunction\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.hash.impl.SHA256HashFunction\",\"representation\":null}," +
            "\"outputLength\":1}},\"structure\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.structures.zn.Zp\"," +
            "\"representation\":\"<BigInteger>101\"}}";


    private final String serializedHashfunction = "{\"innerFunction\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.hash.impl.SHA256HashFunction\",\"representation\":null}," +
            "\"outputLength\":1}";

    private final String serializedCommitmentSchemeParameters = "{\"g\":\"<BigInteger>0\"," +
            "\"group\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto.math" +
            ".interfaces.structures.RingAdditiveGroup\"," +
            "\"representation\":{\"ringRepresentation\":\"<BigInteger>101\",\"ringTypeName\":\"de.upb.crypto.math" +
            ".structures.zn.Zp\"}},\"h\":[\"<BigInteger>0\"]}";

    private final String serializedNguyenAccumulatorPublicParameters = "{\"bilinearMap" +
            "\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto.math.structures" +
            ".zn.RingMultiplication\",\"representation\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.structures.zn.Zp\"," +
            "\"representation\":\"<BigInteger>101\"}},\"g\":\"<BigInteger>e6\"," +
            "\"g1\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto.math" +
            ".interfaces.structures.RingAdditiveGroup\"," +
            "\"representation\":{\"ringRepresentation\":\"<BigInteger>101\",\"ringTypeName\":\"de.upb.crypto.math" +
            ".structures.zn.Zp\"}},\"g2\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de" +
            ".upb.crypto.math.interfaces.structures.RingAdditiveGroup\"," +
            "\"representation\":{\"ringRepresentation\":\"<BigInteger>101\",\"ringTypeName\":\"de.upb.crypto.math" +
            ".structures.zn.Zp\"}},\"g_Tilde\":\"<BigInteger>bd\",\"g_Tilde_Power_S\":\"<BigInteger>82\"," +
            "\"p\":\"<BigInteger>101\",\"t\":[\"<BigInteger>e6\",\"<BigInteger>a5\",\"<BigInteger>bf\"," +
            "\"<BigInteger>e8\",\"<BigInteger>a\",\"<BigInteger>fd\",\"<BigInteger>35\",\"<BigInteger>85\"," +
            "\"<BigInteger>65\",\"<BigInteger>b\",\"<BigInteger>2f\",\"<BigInteger>54\",\"<BigInteger>ac\"," +
            "\"<BigInteger>22\",\"<BigInteger>c0\",\"<BigInteger>1a\",\"<BigInteger>29\",\"<BigInteger>23\"," +
            "\"<BigInteger>f3\",\"<BigInteger>39\",\"<BigInteger>50\",\"<BigInteger>e1\",\"<BigInteger>a7\"," +
            "\"<BigInteger>24\",\"<BigInteger>25\",\"<BigInteger>58\",\"<BigInteger>77\",\"<BigInteger>9e\"," +
            "\"<BigInteger>5b\",\"<BigInteger>f\",\"<BigInteger>fb\",\"<BigInteger>d0\",\"<BigInteger>47\"," +
            "\"<BigInteger>17\",\"<BigInteger>91\",\"<BigInteger>c7\",\"<BigInteger>7e\",\"<BigInteger>1\"," +
            "\"<BigInteger>33\",\"<BigInteger>1f\",\"<BigInteger>27\",\"<BigInteger>be\",\"<BigInteger>b5\"," +
            "\"<BigInteger>ec\",\"<BigInteger>d6\",\"<BigInteger>78\",\"<BigInteger>d1\",\"<BigInteger>7a\"," +
            "\"<BigInteger>36\",\"<BigInteger>b8\",\"<BigInteger>84\"]," +
            "\"universe\":[{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto" +
            ".craco.accumulators.nguyen.NguyenAccumulatorIdentity\"," +
            "\"representation\":{\"identity\":\"<BigInteger>1f\",\"zp\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.structures.zn.Zp\"," +
            "\"representation\":\"<BigInteger>101\"}}}]}";

    private final String serializedPP = "{\"bilinearMap\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.structures.zn.RingMultiplication\"," +
            "\"representation\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto" +
            ".math.structures.zn.Zp\",\"representation\":\"<BigInteger>101\"}}," +
            "\"hashFunction\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto" +
            ".math.hash.impl.VariableOutputLengthHashFunction\"," +
            "\"representation\":{\"innerFunction\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.hash.impl.SHA256HashFunction\",\"representation\":null}," +
            "\"outputLength\":1}},\"hashIntoGroup1\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.structures.zn.HashIntoZnAdditiveGroup\"," +
            "\"representation\":{\"hashIntoZn\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.hash.impl.VariableOutputLengthHashFunction\"," +
            "\"representation\":{\"innerFunction\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.hash.impl.SHA256HashFunction\",\"representation\":null}," +
            "\"outputLength\":24}},\"structure\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.structures.zn.Zn\"," +
            "\"representation\":\"<BigInteger>d92cd81645f08d1643a25cc8595fe50c8df6f651afd1837c5b\"}}}," +
            "\"hashIntoZp\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto" +
            ".math.structures.zn.HashIntoZp\",\"representation\":{\"hashIntoZn\":{\"thisIsRepresentableRepresentation" +
            "\":true,\"representableTypeName\":\"de.upb.crypto.math.hash.impl.VariableOutputLengthHashFunction\"," +
            "\"representation\":{\"innerFunction\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.hash.impl.SHA256HashFunction\",\"representation\":null}," +
            "\"outputLength\":1}},\"structure\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.structures.zn.Zp\"," +
            "\"representation\":\"<BigInteger>101\"}}}," +
            "\"nguyenAccumulatorPP\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb" +
            ".crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParameters\"," +
            "\"representation\":{\"bilinearMap\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.structures.zn.RingMultiplication\"," +
            "\"representation\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto" +
            ".math.structures.zn.Zp\",\"representation\":\"<BigInteger>101\"}},\"g\":\"<BigInteger>e6\"," +
            "\"g1\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto.math" +
            ".interfaces.structures.RingAdditiveGroup\"," +
            "\"representation\":{\"ringRepresentation\":\"<BigInteger>101\",\"ringTypeName\":\"de.upb.crypto.math" +
            ".structures.zn.Zp\"}},\"g2\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de" +
            ".upb.crypto.math.interfaces.structures.RingAdditiveGroup\"," +
            "\"representation\":{\"ringRepresentation\":\"<BigInteger>101\",\"ringTypeName\":\"de.upb.crypto.math" +
            ".structures.zn.Zp\"}},\"g_Tilde\":\"<BigInteger>bd\",\"g_Tilde_Power_S\":\"<BigInteger>82\"," +
            "\"p\":\"<BigInteger>101\",\"t\":[\"<BigInteger>e6\",\"<BigInteger>a5\",\"<BigInteger>bf\"," +
            "\"<BigInteger>e8\",\"<BigInteger>a\",\"<BigInteger>fd\",\"<BigInteger>35\",\"<BigInteger>85\"," +
            "\"<BigInteger>65\",\"<BigInteger>b\",\"<BigInteger>2f\",\"<BigInteger>54\",\"<BigInteger>ac\"," +
            "\"<BigInteger>22\",\"<BigInteger>c0\",\"<BigInteger>1a\",\"<BigInteger>29\",\"<BigInteger>23\"," +
            "\"<BigInteger>f3\",\"<BigInteger>39\",\"<BigInteger>50\",\"<BigInteger>e1\",\"<BigInteger>a7\"," +
            "\"<BigInteger>24\",\"<BigInteger>25\",\"<BigInteger>58\",\"<BigInteger>77\",\"<BigInteger>9e\"," +
            "\"<BigInteger>5b\",\"<BigInteger>f\",\"<BigInteger>fb\",\"<BigInteger>d0\",\"<BigInteger>47\"," +
            "\"<BigInteger>17\",\"<BigInteger>91\",\"<BigInteger>c7\",\"<BigInteger>7e\",\"<BigInteger>1\"," +
            "\"<BigInteger>33\",\"<BigInteger>1f\",\"<BigInteger>27\",\"<BigInteger>be\",\"<BigInteger>b5\"," +
            "\"<BigInteger>ec\",\"<BigInteger>d6\",\"<BigInteger>78\",\"<BigInteger>d1\",\"<BigInteger>7a\"," +
            "\"<BigInteger>36\",\"<BigInteger>b8\",\"<BigInteger>84\"]," +
            "\"universe\":[{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto" +
            ".craco.accumulators.nguyen.NguyenAccumulatorIdentity\"," +
            "\"representation\":{\"identity\":\"<BigInteger>1f\",\"zp\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.structures.zn.Zp\"," +
            "\"representation\":\"<BigInteger>101\"}}}]}}," +
            "\"singleMessageCommitmentPublicParameters\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":" +
            "\"de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters\"," +
            "\"representation\":{\"g\":\"<BigInteger>0\",\"group\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.interfaces.structures.RingAdditiveGroup\"," +
            "\"representation\":{\"ringRepresentation\":\"<BigInteger>101\",\"ringTypeName\":\"de.upb.crypto.math" +
            ".structures.zn.Zp\"}},\"h\":[\"<BigInteger>0\"]}},\"zp\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.structures.zn.Zp\"," +
            "\"representation\":\"<BigInteger>101\"}}";

    private final String serializedHashIntoGroup1 = "{\"hashIntoZn\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.hash.impl.VariableOutputLengthHashFunction\",\"representation\":{\"" +
            "innerFunction\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"" +
            "de.upb.crypto.math.hash.impl.SHA256HashFunction\",\"representation\":null},\"outputLength\":24}},\"" +
            "structure\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"" +
            "de.upb.crypto.math.structures.zn.Zn\",\"representation\":\"<BigInteger>d92cd81645f08d1643a25cc8595" +
            "fe50c8df6f651afd1837c5b\"}}";


    @Test
    void createSerializationTest() {
        final JSONConverter converter = new JSONConverter();

        //Need a prime larger 2^8, otherwise VariableOutputLengthHashFunction's internal SHA256 can not be created
        Zp zp = new Zp(BigInteger.valueOf(257));
        Group group = zp.asAdditiveGroup();
        BilinearMap bilinearMap = new RingMultiplication(zp);
        PedersenPublicParameters singleMessageCommitmentPP = new PedersenPublicParameters(
                group.getNeutralElement(), new GroupElement[]{group.getNeutralElement()}, group);

        HashIntoZp hashIntoZp = new HashIntoZp(zp);
        HashFunction hashFunction = new VariableOutputLengthHashFunction(((zp.getCharacteristic().bitLength() - 1) / 8));

        NguyenAccumulatorPublicParameters nguyenAccumulatorPP = new NguyenAccumulatorPublicParameters(converter
                .deserialize(serializedNguyenAccumulatorPublicParameters));

        HashIntoStructure hashIntoGroup1 = new HashIntoZnAdditiveGroup(converter.deserialize(serializedHashIntoGroup1));

        PublicParameters pp = new PublicParameters(bilinearMap, singleMessageCommitmentPP,
                hashIntoZp, hashFunction, hashIntoGroup1, nguyenAccumulatorPP);

        System.out.println("-- pp --");
        System.out.println(converter.serialize(pp.getRepresentation()));
        System.out.println("-- BilinearMap --");
        System.out.println(converter.serialize(pp.getBilinearMap().getRepresentation()));
        System.out.println("-- commitmentSchemePP --");
        System.out.println(converter.serialize(pp.getSingleMessageCommitmentPublicParameters().getRepresentation()));
        System.out.println("-- hashIntoZp --");
        System.out.println(converter.serialize(pp.getHashIntoZp().getRepresentation()));
        System.out.println("-- hashFunction --");
        System.out.println(converter.serialize(pp.getHashFunction().getRepresentation()));
        System.out.println("-- hashIntoGroup1 --");
        System.out.println(converter.serialize(pp.getHashIntoGroup1().getRepresentation()));
        System.out.println("-- nguyenAccumulatorPP --");
        System.out.println(converter.serialize(pp.getNguyenAccumulatorPP().getRepresentation()));

    }


    @Test
    void serializationTest() {
        final JSONConverter converter = new JSONConverter();
        final Representation bilinearMapRepresentation = converter.deserialize(serializedBilinearMap);
        final BilinearMap bilinearMap = (BilinearMap) bilinearMapRepresentation.repr().recreateRepresentable();

        final PedersenPublicParameters commitmentSchemePublicParameters = new PedersenPublicParameters(
                converter.deserialize(serializedCommitmentSchemeParameters));

        final PedersenPublicParameters singleMessageCommitmentPP = new PedersenPublicParameters(
                commitmentSchemePublicParameters.getG(),
                commitmentSchemePublicParameters.getH(),
                commitmentSchemePublicParameters.getGroup());

        final HashIntoZp hashIntoZp = new HashIntoZp(converter.deserialize(serializedHashIntoZp));
        final HashFunction hashFunction = new VariableOutputLengthHashFunction(converter.deserialize(serializedHashfunction));
        final HashIntoStructure hashIntoG1 = new HashIntoZnAdditiveGroup(converter.deserialize(serializedHashIntoGroup1));

        final NguyenAccumulatorPublicParameters nguyenAccumulatorPP = new NguyenAccumulatorPublicParameters(converter
                .deserialize(serializedNguyenAccumulatorPublicParameters));


        PublicParameters pp = new PublicParameters(bilinearMap, singleMessageCommitmentPP,
                hashIntoZp, hashFunction, hashIntoG1, nguyenAccumulatorPP);


        final String serialization = converter.serialize(pp.getRepresentation());

        assertEquals(serializedPP, serialization);
    }

    @Test
    void deserializationTest() {
        final JSONConverter converter = new JSONConverter();
        final PublicParameters publicParameters = new PublicParameters(converter.deserialize(serializedPP));
        assertNotNull(publicParameters.getBilinearMap());
        assertNotNull(publicParameters.getSingleMessageCommitmentPublicParameters());
        assertNotNull(publicParameters.getZp());
        assertNotNull(publicParameters.getHashFunction());
        assertNotNull(publicParameters.getHashIntoZp());
    }

}
