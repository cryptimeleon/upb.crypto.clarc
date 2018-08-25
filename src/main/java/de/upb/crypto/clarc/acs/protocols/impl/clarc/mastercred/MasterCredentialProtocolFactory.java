package de.upb.crypto.clarc.acs.protocols.impl.clarc.mastercred;

import de.upb.crypto.clarc.acs.protocols.ProtocolFactory;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.systemmanager.SystemManager;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;

/**
 * A {@link ProtocolFactory} which generates protocols to prove/verify the possession of a valid master credential
 */
public abstract class MasterCredentialProtocolFactory implements ProtocolFactory {

    protected final PublicParameters pp;
    protected final PSExtendedVerificationKey systemManagerPublicKey;
    protected final PSSignature masterCredential;

    /**
     * Creates a factory which is able to generate protocols for proving/verifying possession of a valid master
     * credential.
     *
     * @param pp                     the system's public parameters
     * @param systemManagerPublicKey public key of the {@link SystemManager}
     * @param masterCredential       the prover's master credential to be verified
     */
    public MasterCredentialProtocolFactory(PublicParameters pp,
                                           PSExtendedVerificationKey systemManagerPublicKey,
                                           PSSignature masterCredential) {
        this.pp = pp;
        this.systemManagerPublicKey = systemManagerPublicKey;
        this.masterCredential = masterCredential;
    }
}
