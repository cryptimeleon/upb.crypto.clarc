package de.upb.crypto.clarc.acs.serialization.classes;

import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.ProtocolParameters;
import de.upb.crypto.clarc.acs.subpolicyproving.SubPolicyProvingProtocol;
import de.upb.crypto.clarc.acs.subpolicyproving.SubPolicyProvingProtocolPublicParameters;
import de.upb.crypto.clarc.acs.subpolicyproving.SubPolicyProvingProtocolWitness;
import de.upb.crypto.clarc.acs.testdataprovider.ExtendetProveCredTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.IssuerTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.ParameterTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.UserAndSystemManagerTestdataProvider;
import de.upb.crypto.clarc.acs.verifier.credentials.OpenableVerificationResult;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.SecretSharingSchemeProviders;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.popk.ProofOfPartialKnowledgeProtocol;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.popk.ProofOfPartialKnowledgePublicParameters;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirProof;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.clarc.utils.StandaloneTestParams;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;

import java.util.ArrayList;
import java.util.Collection;

public class FixedProtocolsParams {

    public static Collection<StandaloneTestParams> get() {

        ParameterTestdataProvider clarcProvider = new ParameterTestdataProvider();
        UserAndSystemManagerTestdataProvider userProvider =
                new UserAndSystemManagerTestdataProvider(clarcProvider.getPublicParameters());
        IssuerTestdataProvider issuerProvider = new IssuerTestdataProvider(clarcProvider.getPublicParameters(),
                clarcProvider.getSignatureScheme(), userProvider.getUserSecret());
        ExtendetProveCredTestdataProvider protocolProvider =
                new ExtendetProveCredTestdataProvider(clarcProvider.getPublicParameters(),
                        userProvider.getIdentity(), issuerProvider.getIssuer(),
                        IssuerTestdataProvider.AGE, IssuerTestdataProvider.GENDER,
                        issuerProvider.getCredentialWitfDefaultAttributeSpace(), clarcProvider
                        .getSignatureScheme(), clarcProvider
                        .getPedersenCommitmentScheme());

        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();

        Announcement[] announcements = protocolProvider.getSubPolAnnouncement();
        Response[] responses = protocolProvider.getSubPolResponse();
        ByteArrayImplementation[] byteArray = new ByteArrayImplementation[]{new ByteArrayImplementation("123".getBytes())};
        FiatShamirProof proof = new FiatShamirProof(announcements, byteArray, responses);

        toReturn.add(new StandaloneTestParams(ProtocolParameters.class,
                protocolProvider.getProtocolParameters()));

        toReturn.add(new StandaloneTestParams(SubPolicyProvingProtocolPublicParameters.class,
                protocolProvider.getSubPolicyProvingProtocol().getPublicParameters()));
        toReturn.add(new StandaloneTestParams(SubPolicyProvingProtocol.class,
                protocolProvider.getSubPolicyProvingProtocol()));
        toReturn.add(new StandaloneTestParams(SubPolicyProvingProtocolWitness.class,
                protocolProvider.getSubPolWitness()[0]));

        toReturn.add(new StandaloneTestParams(ProofOfPartialKnowledgeProtocol.class,
                protocolProvider.getPoPKProtocol()));
        toReturn.add(new StandaloneTestParams(ProofOfPartialKnowledgePublicParameters.class,
                new ProofOfPartialKnowledgePublicParameters(SecretSharingSchemeProviders.SHAMIR,
                        clarcProvider.getPP().getZp())));
        toReturn.add(new StandaloneTestParams(OpenableVerificationResult.class,
                new OpenableVerificationResult(proof, protocolProvider.getProtocol())));
        return toReturn;
    }
}
