package de.upb.crypto.clarc.acs.systemmanager.impl.clarc;

import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.craco.interfaces.signature.SignatureKeyPair;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSigningKey;
import de.upb.crypto.math.interfaces.structures.GroupElement;

import static de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory.getSignatureScheme;


public class SystemManagerKeyPairFactory implements de.upb.crypto.clarc.acs.systemmanager.SystemManagerKeyPairFactory {

    @Override
    public SystemManagerKeyPair create(de.upb.crypto.craco.interfaces.PublicParameters pp) {
        PublicParameters clarcPP = (PublicParameters) pp;

        SignatureKeyPair<? extends PSExtendedVerificationKey, ? extends PSSigningKey> psKeyPair =
                getSignatureScheme((PublicParameters) pp).generateKeyPair(1);
        GroupElement linkabilityBasis = clarcPP.getBilinearMap().getG2().getUniformlyRandomElement();

        SystemManagerPublicIdentity publicIdentity = new SystemManagerPublicIdentity(
                psKeyPair.getVerificationKey(),
                linkabilityBasis
        );
        return new SystemManagerKeyPair(psKeyPair.getSigningKey(), publicIdentity);
    }

}
