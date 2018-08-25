package de.upb.crypto.clarc.acs.serialization.classes;


import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.JoinResponse;
import de.upb.crypto.clarc.acs.testdataprovider.*;
import de.upb.crypto.clarc.acs.user.impl.clarc.NonInteractiveJoinRequest;
import de.upb.crypto.clarc.acs.user.impl.clarc.NonInteractivePolicyProof;
import de.upb.crypto.clarc.acs.user.impl.clarc.credentials.NonInteractiveCredentialRequest;
import de.upb.crypto.clarc.acs.user.impl.clarc.reviewtoken.NonInteractiveReviewTokenRequest;
import de.upb.crypto.clarc.utils.StandaloneTestParams;

import java.util.ArrayList;
import java.util.Collection;

public class NonInteractiveParams {

    public static Collection<StandaloneTestParams> get() {

        ParameterTestdataProvider clarcProvider = new ParameterTestdataProvider();
        UserAndSystemManagerTestdataProvider userProvider =
                new UserAndSystemManagerTestdataProvider(clarcProvider.getPublicParameters());
        IssuerTestdataProvider issuerProvider = new IssuerTestdataProvider(clarcProvider.getPublicParameters(),
                clarcProvider.getSignatureScheme(), userProvider.getUserSecret());
        ExtendetProveCredTestdataProvider protocolProvider =
                new ExtendetProveCredTestdataProvider(clarcProvider.getPublicParameters(), userProvider
                        .getIdentity(), issuerProvider.getIssuer(),
                        IssuerTestdataProvider.AGE, IssuerTestdataProvider.GENDER, issuerProvider
                        .getCredentialWitfDefaultAttributeSpace(), clarcProvider.getSignatureScheme(), clarcProvider
                        .getPedersenCommitmentScheme());
        NonInteractiveTestdataProvider nonIteractiveProvider =
                new NonInteractiveTestdataProvider(clarcProvider.getPP(), userProvider.getUser(), userProvider
                        .getIdentity(), issuerProvider.getIssuer(), issuerProvider
                        .getReviewTokenIssuer(), userProvider
                        .getSystemManager(), protocolProvider.getProtocol(), protocolProvider
                        .getProtocolParameters());
        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();


        toReturn.add(new StandaloneTestParams(NonInteractivePolicyProof.class,
                nonIteractiveProvider.getNonInteractivePolicyProof()));
        toReturn.add(new StandaloneTestParams(NonInteractiveCredentialRequest.class,
                nonIteractiveProvider.getNonInteractiveCredentialRequest().getRequest()));
        toReturn.add(new StandaloneTestParams(NonInteractiveReviewTokenRequest.class,
                nonIteractiveProvider.getNonInteractiveReviewTokenRequest().getRequest()));
        toReturn.add(new StandaloneTestParams(NonInteractiveJoinRequest.class,
                nonIteractiveProvider.getNonInteractiveJoinRequest()));
        toReturn.add(new StandaloneTestParams(JoinResponse.class,
                nonIteractiveProvider.getNonInteractiveJoinResponse()));
        return toReturn;
    }
}
