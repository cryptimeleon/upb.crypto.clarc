package de.upb.crypto.clarc.acs.testdataprovider;

import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;

/**
 * Setup the {@link PublicParameters} and {@link PedersenCommitmentScheme} generated from the
 * clarcPublicParameters as well as the {@link PSExtendedSignatureScheme}
 */
public class ParameterTestdataProvider {

    private final PublicParameters clarcPublicParameters;
    private final PedersenCommitmentScheme pedersenCommitmentScheme;
    private final PSExtendedSignatureScheme signatureScheme;


    public ParameterTestdataProvider() {
        PublicParametersFactory publicParametersFactory = new PublicParametersFactory();
        publicParametersFactory.setDebugMode(true);
        clarcPublicParameters = publicParametersFactory.create();

        this.pedersenCommitmentScheme =
                new PedersenCommitmentScheme(clarcPublicParameters.getSingleMessageCommitmentPublicParameters());
        this.signatureScheme = PublicParametersFactory.getSignatureScheme(clarcPublicParameters);
    }

    public PublicParameters getPublicParameters() {
        return clarcPublicParameters;
    }

    public PedersenCommitmentScheme getPedersenCommitmentScheme() {
        return pedersenCommitmentScheme;
    }

    public PSExtendedSignatureScheme getSignatureScheme() {
        return signatureScheme;
    }

    public PublicParameters getPP() {
        return clarcPublicParameters;
    }
}
