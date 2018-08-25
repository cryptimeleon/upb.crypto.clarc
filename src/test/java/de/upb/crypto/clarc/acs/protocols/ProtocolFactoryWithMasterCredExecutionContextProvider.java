package de.upb.crypto.clarc.acs.protocols;

import de.upb.crypto.clarc.acs.attributes.AttributeSpace;
import de.upb.crypto.clarc.acs.issuer.credentials.CredentialIssuerPublicIdentity;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssuer;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.ProtocolParameters;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.ProverIncludingMasterProtocolFactory;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.VerifierIncludingMasterProtocolFactory;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.SystemManagerKeyPair;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.SecretSharingSchemeProviders;
import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.converter.JSONConverter;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * This class is responsible for creating the {@link ProtocolFactoryExecutionContext} objects which are injected in
 * the generic test-methods of the {@link ProtocolFactoryTest}. The protocols in the resulting set of
 * {@link ProtocolFactoryExecutionContext}s correspond to proving/verifying fulfillment of a {@link Policy} as well
 * as possession of a valid master credentia.
 * <p>
 * It collects the {@link ProtocolFactoryExecutionParams} for which the contexts shall be executed and generates the
 * corresponding protocols to be tested.
 */
public class ProtocolFactoryWithMasterCredExecutionContextProvider extends ProtocolFactoryExecutionContextProvider {

    private final String serializedsystemManagerKeyPair = "{\"osk\":{\"exponentX\":\"<BigInteger" +
            ">1c570982d6cdd3f58f49b8740da6ecd84c65f1b8916755588a0857a1c08d35bfa\"," +
            "\"exponentsYi\":[\"<BigInteger>4264f675ae30bde296bbae27971449e92907397c2ca284b3235cc5c48413bdab6\"]}," +
            "\"publicIdentity\":{\"linkabilityBasis\":\"<BigInteger" +
            ">1835433faf84f874d8818e8c6568a0b844ad1b262f4ff7747e779b9efe5892e0e\"," +
            "\"opk\":{\"group1ElementG\":\"<BigInteger" +
            ">58087719cb4a15a403ffc21cb6b2a1867923cece2175e097d0d4392ca537da916\"," +
            "\"group1ElementsYi\":[\"<BigInteger>1e0b0d5b27369ac91e9596c4a3defc7b0fd0c8a4746385782bea975f540c4f042" +
            "\"],\"group2ElementTildeG\":\"<BigInteger" +
            ">b162ea127b32d0b9c62c6ba8abc7f9676254e4e01343ebbad78e1e2a6fa61653c\"," +
            "\"group2ElementTildeX\":\"<BigInteger>11e7ae25e3d852c23ffa7b07fe832cc91a738fa68f9728ede050ec9df060de913" +
            "\",\"group2ElementsTildeYi\":[\"<BigInteger" +
            ">6a2eb936affb210cd04cce524bc36d96950b6493b660a0413cb5ae5d8f0bb6bbe\"]}}}";

    private final SystemManagerKeyPair systemManagerKeyPair;

    ProtocolFactoryWithMasterCredExecutionContextProvider() {
        super();
        JSONConverter converter = new JSONConverter();
        systemManagerKeyPair =
                new SystemManagerKeyPair(converter.deserialize(serializedsystemManagerKeyPair), clarcPP);
    }

    @Override
    protected ProtocolFactoryWithMasterCredExecutionContext transformParamToContext(
            ProtocolFactoryExecutionParams params) {
        ProtocolParameters protocolParameters =
                new ProtocolParameters(identity.getPseudonym(), SecretSharingSchemeProviders.SHAMIR);

        List<AttributeSpace> attributeSpaces = Arrays.stream(params.issuers)
                .map(issuer -> issuer.getPublicIdentity().getAttributeSpace())
                .collect(Collectors.toList());

        final GroupElement upk = clarcPP.getBilinearMap().getG1().getElement(userKeyPair.getUserPublicKey().getUpk());

        final PSExtendedVerificationKey systemManagerPublicKey = systemManagerKeyPair.getPublicIdentity().getOpk();
        // Generate a UPK for another USK
        // the user will not be able to proof validity of the resulting master credential
        final GroupElement anotherUpk =
                systemManagerPublicKey.getGroup1ElementG()
                        .pow(userKeyPair.getUserSecret().getUsk().add(clarcPP.getZp().getOneElement()));

        PSSignature masterCredential =
                computeMasterCredential(clarcPP, systemManagerKeyPair, upk);
        PSSignature invalidMasterCredential =
                computeMasterCredential(clarcPP, systemManagerKeyPair, anotherUpk);

        ProverIncludingMasterProtocolFactory proverProtocolFactory =
                new ProverIncludingMasterProtocolFactory(protocolParameters, clarcPP, attributeSpaces,
                        params.fulfillingCredentials, userKeyPair.getUserSecret(),
                        identity.getPseudonymSecret(), params.policy, params.disclosures,
                        systemManagerPublicKey, masterCredential);


        InteractiveThreeWayAoK fulfillingProver = proverProtocolFactory.getProtocol();

        InteractiveThreeWayAoK anotherFulfillingProver;
        do {
            anotherFulfillingProver = proverProtocolFactory.getProtocol();
        } while (fulfillingProver.equals(anotherFulfillingProver));

        proverProtocolFactory =
                new ProverIncludingMasterProtocolFactory(protocolParameters, clarcPP, attributeSpaces,
                        new PSCredential[params.fulfillingCredentials.length], userKeyPair.getUserSecret(),
                        identity.getPseudonymSecret(), params.policy, params.disclosures,
                        systemManagerPublicKey, masterCredential);

        InteractiveThreeWayAoK nonFulfillingPolicyProver = proverProtocolFactory.getProtocol();

        VerifierIncludingMasterProtocolFactory verifierFactory =
                new VerifierIncludingMasterProtocolFactory(protocolParameters, clarcPP, attributeSpaces,
                        params.policy, params.disclosures, systemManagerPublicKey, masterCredential);

        InteractiveThreeWayAoK protocolVerifier = verifierFactory.getProtocol();

        proverProtocolFactory =
                new ProverIncludingMasterProtocolFactory(protocolParameters, clarcPP, attributeSpaces,
                        params.fulfillingCredentials, userKeyPair.getUserSecret(),
                        identity.getPseudonymSecret(), params.policy, params.disclosures,
                        systemManagerPublicKey, invalidMasterCredential);

        InteractiveThreeWayAoK invalidMasterCredentialProver = proverProtocolFactory.getProtocol();

        verifierFactory =
                new VerifierIncludingMasterProtocolFactory(protocolParameters, clarcPP, attributeSpaces,
                        params.policy, params.disclosures, systemManagerPublicKey,
                        invalidMasterCredential);


        InteractiveThreeWayAoK invalidMasterCredentialVerifier = verifierFactory.getProtocol();

        List<CredentialIssuerPublicIdentity> publicIdentities = Arrays.stream(params.issuers)
                .map(CredentialIssuer::getPublicIdentity)
                .collect(Collectors.toList());

        return new ProtocolFactoryWithMasterCredExecutionContext(fulfillingProver, anotherFulfillingProver,
                nonFulfillingPolicyProver, protocolVerifier, params.disclosures, publicIdentities,
                invalidMasterCredentialProver, invalidMasterCredentialVerifier);
    }


    /**
     * Generate a master credential in the same way as the joining process, but forgo the randomness involved
     *
     * @param pp                        public parameters of the system
     * @param clarcSystemManagerKeyPair key pair of the SystemManager
     * @param userPublicKey             public key of the user
     * @return a valid master credential for the given upk and systemManagerPublicKey
     */
    static PSSignature computeMasterCredential(PublicParameters pp,
                                               SystemManagerKeyPair clarcSystemManagerKeyPair,
                                               GroupElement userPublicKey) {
        GroupElement g = clarcSystemManagerKeyPair.getPublicIdentity().getOpk().getGroup1ElementG();
        Zp zp = pp.getZp();
        //We want as few random values in our tests as possible
        Zp.ZpElement u = zp.getOneElement();
        GroupElement g_u = g.pow(u);
        Zp.ZpElement x = clarcSystemManagerKeyPair.getSystemManagerSecretKey().getExponentX();
        Zp.ZpElement y = clarcSystemManagerKeyPair.getSystemManagerSecretKey().getExponentsYi()[0];
        GroupElement g_pow_x = g.pow(x);
        GroupElement upk_pow_y = userPublicKey.pow(y);
        return new PSSignature(g_u, (g_pow_x.op(upk_pow_y)).pow(u));
    }

}
