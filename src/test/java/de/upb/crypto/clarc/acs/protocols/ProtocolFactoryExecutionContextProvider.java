package de.upb.crypto.clarc.acs.protocols;

import de.upb.crypto.clarc.acs.attributes.AttributeSpace;
import de.upb.crypto.clarc.acs.issuer.credentials.CredentialIssuerPublicIdentity;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssuer;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.ProtocolParameters;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.ProverProtocolFactory;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.VerifierProtocolFactory;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Identity;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserKeyPair;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserSecret;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.SecretSharingSchemeProviders;
import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.math.serialization.converter.JSONConverter;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestTemplateInvocationContext;
import org.junit.jupiter.api.extension.TestTemplateInvocationContextProvider;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * This class is responsible for creating the {@link ProtocolFactoryExecutionContext} objects which are injected in
 * the generic test-methods of the {@link ProtocolFactoryTest}. The protocols in the resulting set of
 * {@link ProtocolFactoryExecutionContext}s correspond to proving/verifying fulfillment of a {@link Policy}
 * <p>
 * It collects the {@link ProtocolFactoryExecutionParams} for which the contexts shall be executed and generates the
 * corresponding protocols to be tested.
 */
public class ProtocolFactoryExecutionContextProvider implements TestTemplateInvocationContextProvider {


    private final String serializedClarcPP = "{\"bilinearMap\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.structures.zn.RingMultiplication\"," +
            "\"representation\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto" +
            ".math.structures.zn.Zn\"," +
            "\"representation\":\"<BigInteger>b19828f61fd711c7c054d283632b4f0fb5e9b949928fe8f57c275dbf5d515a4cb\"}}," +
            "\"hashFunction\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto" +
            ".math.hash.impl.VariableOutputLengthHashFunction\"," +
            "\"representation\":{\"innerFunction\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.hash.impl.SHA256HashFunction\",\"representation\":null}," +
            "\"outputLength\":32}},\"hashIntoGroup1\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.structures.zn.HashIntoZnAdditiveGroup\"," +
            "\"representation\":{\"hashIntoZn\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.hash.impl.VariableOutputLengthHashFunction\"," +
            "\"representation\":{\"innerFunction\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.hash.impl.SHA256HashFunction\",\"representation\":null}," +
            "\"outputLength\":32}},\"structure\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.structures.zn.Zn\"," +
            "\"representation\":\"<BigInteger>b19828f61fd711c7c054d283632b4f0fb5e9b949928fe8f57c275dbf5d515a4cb\"}}}," +
            "\"hashIntoZp\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto" +
            ".math.structures.zn.HashIntoZp\",\"representation\":{\"hashIntoZn\":{\"thisIsRepresentableRepresentation" +
            "\":true,\"representableTypeName\":\"de.upb.crypto.math.hash.impl.VariableOutputLengthHashFunction\"," +
            "\"representation\":{\"innerFunction\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.hash.impl.SHA256HashFunction\",\"representation\":null}," +
            "\"outputLength\":32}},\"structure\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.structures.zn.Zp\"," +
            "\"representation\":\"<BigInteger>b19828f61fd711c7c054d283632b4f0fb5e9b949928fe8f57c275dbf5d515a4cb\"}}}," +
            "\"nguyenAccumulatorPP\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb" +
            ".crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParameters\"," +
            "\"representation\":{\"bilinearMap\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.structures.zn.RingMultiplication\"," +
            "\"representation\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto" +
            ".math.structures.zn.Zn\"," +
            "\"representation\":\"<BigInteger>b19828f61fd711c7c054d283632b4f0fb5e9b949928fe8f57c275dbf5d515a4cb\"}}," +
            "\"g\":\"<BigInteger>61b616915a7fce3e812ad89e6a17ab52ad4880a0e1595dc5d23caee849d765422\"," +
            "\"g1\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto.math" +
            ".interfaces.structures.RingAdditiveGroup\"," +
            "\"representation\":{\"ringRepresentation\":\"<BigInteger" +
            ">b19828f61fd711c7c054d283632b4f0fb5e9b949928fe8f57c275dbf5d515a4cb\",\"ringTypeName\":\"de.upb.crypto" +
            ".math.structures.zn.Zn\"}},\"g2\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.math.interfaces.structures.RingAdditiveGroup\"," +
            "\"representation\":{\"ringRepresentation\":\"<BigInteger" +
            ">b19828f61fd711c7c054d283632b4f0fb5e9b949928fe8f57c275dbf5d515a4cb\",\"ringTypeName\":\"de.upb.crypto" +
            ".math.structures.zn.Zn\"}}," +
            "\"g_Tilde\":\"<BigInteger>671466fd6d2cb24f3ee66390ca9fe54ab15eca3c7aba7f10ad13aa20b5d99f97d\"," +
            "\"g_Tilde_Power_S\":\"<BigInteger>909e441680c11c402fb199e40df4772adef90dc1152ef9f30005a30a3fc0e6946\"," +
            "\"p\":\"<BigInteger>b19828f61fd711c7c054d283632b4f0fb5e9b949928fe8f57c275dbf5d515a4cb\"," +
            "\"t\":[\"<BigInteger>61b616915a7fce3e812ad89e6a17ab52ad4880a0e1595dc5d23caee849d765422\"," +
            "\"<BigInteger>a31c7763a71bbc8d7e2c3bc3eb00c5c15ca3970f9d1ba272d6ac596611e2b79b3\"," +
            "\"<BigInteger>25c58f6ad17c1358373e8dc9e20dfc7318966f3842238e50feea79d47923e9965\"," +
            "\"<BigInteger>6729ad48e5c3a71b38738d19fc9f719bf33cf3ecbf0d9b300d3e8447e1d8a29ac\"," +
            "\"<BigInteger>6a93d58fce3eda471318d6be1c0fe27976cd09e9d0dfb829857de37551f421052\"," +
            "\"<BigInteger>982e466ed42d9d53133e6c2608c6c30a366901f6163cfbf510cd6a2ceee6e4ef3\"," +
            "\"<BigInteger>5b9f99c7eaded4a29476f90d8b1f672d6e5cd16f86e6bf2eb1bfb49b7e64992a9\"," +
            "\"<BigInteger>f7b238017df2b556830a0a7df692b4d5141396cf283feec083bdb72a699d3556\"," +
            "\"<BigInteger>127b4bce45f791e63db3948dbb6f31ae31aa497f69c4070f68edfeb7b71762e8d\"," +
            "\"<BigInteger>45a2ed880e8802ae57bdb337c9058417c2fbe3553a094cb7e9505830730323a21\"," +
            "\"<BigInteger>9f9adb41df3cf4a9eb40e5fee1ce78bf3072cb16bb519d7692aa00772cd40f52\"," +
            "\"<BigInteger>3d6cacb94897a6ba1aa4a03746abf2106b6c213e99a9d5658a5a7a95a2c5aec07\"," +
            "\"<BigInteger>a0d5a54aa0a8c510f76956de681af5b24c808ed53d1e37c11f7a612a9cb1d6ee0\"," +
            "\"<BigInteger>626c645e27cba144e1f71ae91c72da588970886b5923a4e5e834ca7cf0e3129e7\"," +
            "\"<BigInteger>4d7bb03ecbc85f4d6cb8da5779f62efeba4c30d210a9970ce48866e16af3af1c8\"," +
            "\"<BigInteger>a519a411706a0769f4c83d2737e5ebfe2fc7bd0bd900b503914bd69cebcfc4cd7\"," +
            "\"<BigInteger>a27b49a70c483d03c4604e95fd356d7acc891397ee2d2b7669785542f1c299930\"," +
            "\"<BigInteger>10d9d56ffba8875c6bfcc2db372f64f77156991a84d442624aaaf7bc75ea88a60\"," +
            "\"<BigInteger>46771c8c42b6e6e24461109532b6973c066e62e49bf2913c22792c3dab530804c\"," +
            "\"<BigInteger>1409e5d20e387d095d3bd158c0f590f40c4497dc504a9a629cfad3f4958332e38\"," +
            "\"<BigInteger>73379a8def097e3ecd1e76867ca4fa056a0f34992bc0dfae1797073b44ba7ac38\"," +
            "\"<BigInteger>53155cda726ab5a7bb36eb01e2926c1cc3d4a96f72649ecbf603b17ad1a8241e8\"," +
            "\"<BigInteger>537307a040a0e8ac831a8b4a97ac565cec6070ecf227defb05c0e84b9382c50f0\"," +
            "\"<BigInteger>35be87bc00b37c35cfe74398f1c4aa90f511de6dba02e574f96fe3fe628f1cd35\"," +
            "\"<BigInteger>4e6fed3c602b15d481d56776456edcaf5650df7884dc863f8e3eabb72608ecd12\"," +
            "\"<BigInteger>2a3c36ae961e78be72d19efab62020a6918904caf8fb2b46d33baae7e36579409\"," +
            "\"<BigInteger>a0da1f2aeb65242eb35f1bb57d2acf8ce01cab0e1dc4f16a06125d55c7edab6a\"," +
            "\"<BigInteger>1edc86775a9a8134d57296411796fdd39205c35d59080392c326105e32d12aea8\"," +
            "\"<BigInteger>42f630b7bf59480e6faa44887dae8281694d18991dfca602e983191aa7d6bb9cf\"," +
            "\"<BigInteger>6a0369aa71bbb5da80f437668483b015b519e2427f9b99c58a5c6052728c9b469\"," +
            "\"<BigInteger>6582ed4500d4efd3007a039b4e34f84b2dc742577b2b6524022504c0340bf48ef\"," +
            "\"<BigInteger>206345f98034ac1cde975cd84824bcdcd99aab051cd019e6d92888727a1351f4d\"," +
            "\"<BigInteger>527d6e6818a3ee060a915d13ff092718a99539b2eced67a7d502d16bde38c63c5\"," +
            "\"<BigInteger>2590b543bc65faf10b9d0372d4ab4fe56596c67774d9ae64cf47a8f4df271eb83\"," +
            "\"<BigInteger>aa65ef22eee94d0c3b517d8cf310d31b8e5f456b58820ef567820b88c5b728ad9\"," +
            "\"<BigInteger>93eb472bc498c016a02dca50254e895d16347b63b1dfdfbddfe76046b025ad089\"," +
            "\"<BigInteger>9e6c1c724bfcae2b40eb75cbae5631606f417dd875159d32686cc9e5c31bb5d67\"," +
            "\"<BigInteger>a96f7521df3addfbe917623b363a82d3072cb5005ca56e6f0f9a051575ed877d6\"," +
            "\"<BigInteger>4247112e97ee53f32896cec6c8bdf184208979133f3182e72c398fa859713339b\"," +
            "\"<BigInteger>27c21987c00abefdd4207429db304c1cbcd7cbc2d7531afdb24f1f30c4dba1aa7\"," +
            "\"<BigInteger>94e1849c736b6d97310614532f0812a3340aff2291d422bdb3faaf8c8dbbed6ce\"," +
            "\"<BigInteger>2fe92baaaf75e8f2a1444bbf28a8b5a436afb2b0dc68b1a54812588a2269816d8\"," +
            "\"<BigInteger>ad599b2c7f645ff9e2aecf35104c6beb6f275027011bf093e147f711f3b7476a1\"," +
            "\"<BigInteger>261e99d6fddd546a3a7818339febeac7a296096af96e17881636693c8a0893e6c\"," +
            "\"<BigInteger>7150e6e217f91836f1d4f48e219332452bf32b0a7aa37e953ce2f67b6d5eef6a8\"," +
            "\"<BigInteger>3a205f5585ea7ee1e94f5351209cd4c592a12d8e68a7e18adc64dde811f392608\"," +
            "\"<BigInteger>7856c38c551a65f0606fdff56d75457e985348a6266458184128f12da83694234\"," +
            "\"<BigInteger>adc4da481c83b3b048af5e92b9fdd8a9351e2884e6d95509927ee7cc741b8f06c\"," +
            "\"<BigInteger>281109d68e710c28648be3271c5ec37df380b66eea6871432f0c847ccad5fbe28\"," +
            "\"<BigInteger>7a18d66f82b693319d66130ae69c996317d6eb39dabd00af9600a06b4a5e0a85a\"," +
            "\"<BigInteger>53cea261bf2c3a161470e51e9a9a28f184777a59d234011169a24cec464c4634\"]," +
            "\"universe\":[{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto" +
            ".craco.accumulators.nguyen.NguyenAccumulatorIdentity\"," +
            "\"representation\":{\"identity\":\"<BigInteger" +
            ">7b54535f4c9eaf062d4e9e5ee705ee6b6fe730957b77a8cb60a7f4d293f83364\"," +
            "\"zp\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto.math" +
            ".structures.zn.Zp\"," +
            "\"representation\":\"<BigInteger>b19828f61fd711c7c054d283632b4f0fb5e9b949928fe8f57c275dbf5d515a4cb" +
            "\"}}}]}},\"singleMessageCommitmentPublicParameters\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.craco.commitment.pedersen" +
            ".PedersenPublicParameters\"," +
            "\"representation\":{\"g\":\"<BigInteger" +
            ">44aa279608f8d1826039f7e162e00233704990f836efb1f580717408e1c43cdad\"," +
            "\"group\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto.math" +
            ".interfaces.structures.RingAdditiveGroup\"," +
            "\"representation\":{\"ringRepresentation\":\"<BigInteger" +
            ">b19828f61fd711c7c054d283632b4f0fb5e9b949928fe8f57c275dbf5d515a4cb\",\"ringTypeName\":\"de.upb.crypto" +
            ".math.structures.zn.Zn\"}}," +
            "\"h\":[\"<BigInteger>38930d77d0d729ae6d8a220a3a4b19568c2036ac633930503f775c8e61339a598\"]}}," +
            "\"zp\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto.math" +
            ".structures.zn.Zp\"," +
            "\"representation\":\"<BigInteger>b19828f61fd711c7c054d283632b4f0fb5e9b949928fe8f57c275dbf5d515a4cb\"}}";

    private final String serializedUserKeyPair = "{\"userPublicKey\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.clarc.acs.user.impl.clarc.UserPublicKey\"," +
            "\"representation\":{\"upk\":\"<BigInteger" +
            ">a1f1b29ddb373b83f1511a5efa151881dd6189fe358e25ac2cf3cf4e4d171a0ac\"}}," +
            "\"userSecret\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto" +
            ".clarc.acs.user.impl.clarc.UserSecret\"," +
            "\"representation\":{\"usk\":\"<BigInteger" +
            ">9f1ce9d86004ea1131bd29b18a896c26df7945f444670c02b2da453ebad568a6f\"," +
            "\"zp\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto.math" +
            ".structures.zn.Zp\"," +
            "\"representation\":\"<BigInteger>b19828f61fd711c7c054d283632b4f0fb5e9b949928fe8f57c275dbf5d515a4cb\"}}}}";

    private final String serializedIdentity = "{\"commitment\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.craco.commitment.pedersen" +
            ".PedersenCommitmentPair\",\"representation\":{\"commitmentValue\":{\"thisIsRepresentableRepresentation" +
            "\":true,\"representableTypeName\":\"de.upb.crypto.craco.commitment.pedersen" +
            ".PedersenCommitmentValue\"," +
            "\"representation\":{\"commitmentElement\":\"<BigInteger" +
            ">7e811020ab06a9d50c5195035f15d2a98fbca34b9a576e5ccf35a2e8a5e9edc21\"," +
            "\"group\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto.math" +
            ".interfaces.structures.RingAdditiveGroup\"," +
            "\"representation\":{\"ringRepresentation\":\"<BigInteger" +
            ">b19828f61fd711c7c054d283632b4f0fb5e9b949928fe8f57c275dbf5d515a4cb\",\"ringTypeName\":\"de.upb.crypto" +
            ".math.structures.zn.Zn\"}}}},\"openValue\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.craco.commitment.pedersen.PedersenOpenValue\"," +
            "\"representation\":{\"messages\":[\"<BigInteger" +
            ">9f1ce9d86004ea1131bd29b18a896c26df7945f444670c02b2da453ebad568a6f\"]," +
            "\"randomness\":\"<BigInteger>300841a8e697ab11211845bb36faaed6a72f867e5ad2794fe8464bda0683d9adf\"," +
            "\"zp\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto.math" +
            ".structures.zn.Zp\"," +
            "\"representation\":\"<BigInteger>b19828f61fd711c7c054d283632b4f0fb5e9b949928fe8f57c275dbf5d515a4cb" +
            "\"}}}}},\"pseudonym\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb" +
            ".crypto.clarc.acs.pseudonym.impl.clarc.Pseudonym\"," +
            "\"representation\":{\"commitmentValue\":{\"thisIsRepresentableRepresentation\":true," +
            "\"representableTypeName\":\"de.upb.crypto.craco.commitment.pedersen" +
            ".PedersenCommitmentValue\"," +
            "\"representation\":{\"commitmentElement\":\"<BigInteger" +
            ">7e811020ab06a9d50c5195035f15d2a98fbca34b9a576e5ccf35a2e8a5e9edc21\"," +
            "\"group\":{\"thisIsRepresentableRepresentation\":true,\"representableTypeName\":\"de.upb.crypto.math" +
            ".interfaces.structures.RingAdditiveGroup\"," +
            "\"representation\":{\"ringRepresentation\":\"<BigInteger" +
            ">b19828f61fd711c7c054d283632b4f0fb5e9b949928fe8f57c275dbf5d515a4cb\",\"ringTypeName\":\"de.upb.crypto" +
            ".math.structures.zn.Zn\"}}}}}}}";

    private final Collection<ProtocolFactoryExecutionParams> executionParams;

    protected final PublicParameters clarcPP;
    protected final UserKeyPair userKeyPair;
    protected final Identity identity;

    ProtocolFactoryExecutionContextProvider() {
        JSONConverter converter = new JSONConverter();
        clarcPP = new PublicParameters(converter.deserialize(serializedClarcPP));
        userKeyPair = new UserKeyPair(converter.deserialize(serializedUserKeyPair));
        identity = new Identity(converter.deserialize(serializedIdentity));
        executionParams = generateExecutionParams(clarcPP, userKeyPair.getUserSecret(), identity);
    }

    private Collection<ProtocolFactoryExecutionParams> generateExecutionParams(
            PublicParameters clarcPP, UserSecret usk,
            Identity identity) {
        List<ProtocolFactoryExecutionParams> executionParams = new ArrayList<>();
        executionParams.addAll(InequalityPolicies.get(clarcPP, usk));
        executionParams.add(SetMembershipPolicies.getSimpleSetMembershipProofParams(clarcPP, usk));
        executionParams.add(RangeProofPolicies.getSimpleRangeProofParams(clarcPP, usk));
        return executionParams;
    }

    @Override
    public boolean supportsTestTemplate(ExtensionContext extensionContext) {
        return true;
    }

    @Override
    public Stream<TestTemplateInvocationContext> provideTestTemplateInvocationContexts(
            ExtensionContext extensionContext) {
        return executionParams.stream().map(this::transformParamToContext);
    }

    protected ProtocolFactoryExecutionContext transformParamToContext(ProtocolFactoryExecutionParams params) {
        ProtocolParameters protocolParameters =
                new ProtocolParameters(identity.getPseudonym(), SecretSharingSchemeProviders.SHAMIR);

        List<AttributeSpace> attributeSpaces = Arrays.stream(params.issuers)
                .map(issuer -> issuer.getPublicIdentity().getAttributeSpace())
                .collect(Collectors.toList());

        ProverProtocolFactory proverProtocolFactory =
                new ProverProtocolFactory(protocolParameters, clarcPP, attributeSpaces,
                        params.fulfillingCredentials, userKeyPair.getUserSecret(),
                        identity.getPseudonymSecret(), params.policy, params.disclosures);

        InteractiveThreeWayAoK fulfillingProtocolProver = proverProtocolFactory.getProtocol();
        InteractiveThreeWayAoK anotherFulfillingProtocolProver;
        do {
            anotherFulfillingProtocolProver = proverProtocolFactory.getProtocol();
        } while (fulfillingProtocolProver.equals(anotherFulfillingProtocolProver));

        proverProtocolFactory =
                new ProverProtocolFactory(protocolParameters, clarcPP, attributeSpaces,
                        new PSCredential[params.fulfillingCredentials.length], userKeyPair.getUserSecret(),
                        identity.getPseudonymSecret(), params.policy, params.disclosures);
        InteractiveThreeWayAoK nonFulfillingProtocolProver = proverProtocolFactory.getProtocol();

        VerifierProtocolFactory verifierProtocolFactory =
                new VerifierProtocolFactory(protocolParameters, clarcPP, attributeSpaces, params.policy,
                        params.disclosures);

        InteractiveThreeWayAoK protocolVerifier = verifierProtocolFactory.getProtocol();

        List<CredentialIssuerPublicIdentity> publicIdentities = Arrays.stream(params.issuers)
                .map(CredentialIssuer::getPublicIdentity)
                .collect(Collectors.toList());

        return new ProtocolFactoryExecutionContext(fulfillingProtocolProver, anotherFulfillingProtocolProver,
                nonFulfillingProtocolProver, protocolVerifier, params.disclosures, publicIdentities);
    }
}
