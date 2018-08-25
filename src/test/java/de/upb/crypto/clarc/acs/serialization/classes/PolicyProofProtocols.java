package de.upb.crypto.clarc.acs.serialization.classes;

import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.*;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.testdataprovider.ExtendetProveCredTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.IssuerTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.ParameterTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.UserAndSystemManagerTestdataProvider;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.predicategeneration.policies.SubPolicyPolicyFact;
import de.upb.crypto.clarc.utils.StandaloneTestParams;
import de.upb.crypto.craco.sig.ps.PSSignature;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

public class PolicyProofProtocols {

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

        ProtocolParameters protocolParameters =
                new ProtocolParameters(userProvider.getIdentity().getPseudonym());

        PSCredential credential = issuerProvider.getCredentialWitfDefaultAttributeSpace();

        SelectiveDisclosure disclosure = new SelectiveDisclosure(credential.getIssuerPublicKeyRepresentation(),
                Collections.singletonList(0));
        SelectiveDisclosure[] selectiveDisclosures = new SelectiveDisclosure[]{disclosure};

        PublicParameters pp = clarcProvider.getPublicParameters();
        PSSignature signature = new PSSignature(pp.getBilinearMap().getG1().getUniformlyRandomElement(),
                pp.getBilinearMap().getG1().getUniformlyRandomElement());


        SubPolicyPolicyFact subPolicyPolicyFact =
                new SubPolicyPolicyFact(issuerProvider.getIssuerPublicKey().getRepresentation(),
                        protocolProvider.getSubpolicy());

        ProverProtocolFactory proverProtocolFactory =
                new ProverProtocolFactory(protocolParameters, clarcProvider.getPublicParameters(),
                        issuerProvider.currentAttributeSpaces(),
                        new PSCredential[]{credential},
                        userProvider.getUserSecret(),
                        userProvider.getIdentity().getPseudonymSecret(),
                        subPolicyPolicyFact, selectiveDisclosures);

        ProverIncludingMasterProtocolFactory proverWithMasterCredProtocolFactory =
                new ProverIncludingMasterProtocolFactory(protocolParameters, clarcProvider
                        .getPublicParameters(),
                        issuerProvider.currentAttributeSpaces(),
                        new PSCredential[]{credential},
                        userProvider.getUserSecret(),
                        userProvider.getIdentity().getPseudonymSecret(),
                        subPolicyPolicyFact, selectiveDisclosures,
                        userProvider.getSystemManager().getPublicIdentity().getOpk(),
                        signature);


        List<StandaloneTestParams> toReturn = new ArrayList<>();
        PolicyProvingProtocol policyProvingProtocol = proverProtocolFactory.getProtocol();

        toReturn.add(new StandaloneTestParams(PolicyProvingProtocol.class, policyProvingProtocol));
        toReturn.add(new StandaloneTestParams(PolicyProvingWithMasterCredProtocol.class,
                proverWithMasterCredProtocolFactory.getProtocol()));
        toReturn.add(new StandaloneTestParams(DisclosedAttributes.class,
                policyProvingProtocol.getDisclosedAttributes().get(0)));
        toReturn.add(new StandaloneTestParams(SelectiveDisclosure.class, disclosure));

        return toReturn;
    }
}
