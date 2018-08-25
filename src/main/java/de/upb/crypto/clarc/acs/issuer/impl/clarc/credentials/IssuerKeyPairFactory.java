package de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials;

import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.craco.interfaces.signature.SignatureKeyPair;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSigningKey;
import de.upb.crypto.math.interfaces.structures.GroupElement;

public class IssuerKeyPairFactory implements de.upb.crypto.clarc.acs.issuer.credentials.IssuerKeyPairFactory {

    /**
     * Helper method to get {@link PedersenPublicParameters} just from the issuer verification key and the
     * public parameters.
     *
     * @param pp                    public parameters of the ACS
     * @param issuerVerificationKey public verification key of the issuer
     * @return {@link PedersenPublicParameters} needed to recreate the signature scheme used for the issuing
     */
    public static PedersenPublicParameters getPedersenPPForSingleValueFromIssuerPK(
            PublicParameters pp, PSExtendedVerificationKey issuerVerificationKey) {
        return new PedersenPublicParameters(
                issuerVerificationKey.getGroup1ElementG(),
                new GroupElement[]{issuerVerificationKey.getGroup1ElementsYi()[0]},
                pp.getBilinearMap().getG1()
        );
    }

    /**
     * Creates key pair dependant on the number of attributes that the issuer can provide credentials for.
     *
     * @param pp                 public parameters of acs
     * @param numberOfAttributes number of attributes the issuer has within his attribute space
     * @return issuer key pair (signing key + verification key) for issuing
     */
    @Override
    public IssuerKeyPair create(de.upb.crypto.craco.interfaces.PublicParameters pp, int numberOfAttributes) {
        if (!(pp instanceof PublicParameters)) {
            throw new IllegalArgumentException("Invalid type of public parameters.");
        }
        PublicParameters clarcPublicParameters = (PublicParameters) pp;
        SignatureKeyPair<? extends PSExtendedVerificationKey, ? extends PSSigningKey> psKeyPair =
                PublicParametersFactory.getSignatureScheme(clarcPublicParameters)
                        .generateKeyPair(numberOfAttributes + 1);
        return new IssuerKeyPair(psKeyPair.getSigningKey(), psKeyPair.getVerificationKey());
    }
}
