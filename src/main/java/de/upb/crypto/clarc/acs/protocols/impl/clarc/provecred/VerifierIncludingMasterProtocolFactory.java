package de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred;

import de.upb.crypto.clarc.acs.attributes.AttributeSpace;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.mastercred.MasterCredentialVerifierProtocolFactory;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.systemmanager.SystemManager;
import de.upb.crypto.clarc.acs.verifier.credentials.RepresentableSignature;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.popk.ProofOfPartialKnowledgeProtocol;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;

import java.util.ArrayList;
import java.util.List;

/**
 * {@link de.upb.crypto.clarc.acs.protocols.ProtocolFactory} which generates verifier protocol to verify the fulfillment of a {@link Policy}  as well as
 * verifying possession of a valid master credential obtained during the join process.
 * <p>
 * This factory combines the protocols created by {@link VerifierProtocolFactory} and
 * {@link MasterCredentialVerifierProtocolFactory} using a {@link ProofOfPartialKnowledgeProtocol}.
 */
public class VerifierIncludingMasterProtocolFactory extends ProtocolFactory {

    private final PSExtendedVerificationKey systemManagerPublicKey;
    private final PSSignature masterCredential;

    /**
     * Instantiates a ProtocolFactory with given public and protocol parameters.
     * The currently available attribute spaces are needed to correctly parse the policy to be fulfilled.
     *
     * @param protocolParameters     shared input for all protocol instances (prover and verifier)
     * @param publicParameters       the system's public parameters
     * @param attributeSpaces        currently available attribute spaces
     * @param policy                 the policy which fulfillment is to be proven
     * @param systemManagerPublicKey public key of the {@link SystemManager}
     * @param masterCredential       master credential of the user
     */
    public VerifierIncludingMasterProtocolFactory(
            ProtocolParameters protocolParameters,
            PublicParameters publicParameters,
            List<AttributeSpace> attributeSpaces,
            Policy policy,
            PSExtendedVerificationKey systemManagerPublicKey, PSSignature masterCredential) {
        this(protocolParameters, publicParameters, attributeSpaces, policy, null, systemManagerPublicKey,
                masterCredential);
    }

    /**
     * Instantiates a ProtocolFactory with given public and protocol parameters.
     * The currently available attribute spaces are needed to correctly parse the policy to be fulfilled.     *
     * <p>
     * The order of the given {@link SelectiveDisclosure} must match the order of
     * {@link ProtocolFactory#getSubPolicies} associated with the same issuer. If there is no
     * {@link SelectiveDisclosure} available for a certain sub policy, null is expected at the corresponding position
     * in the array.
     * </p>
     *
     * @param protocolParameters     shared input for all protocol instances (prover and verifier)
     * @param publicParameters       the system's public parameters
     * @param attributeSpaces        currently available attribute spaces
     * @param policy                 the policy which fulfillment is to be proven
     * @param systemManagerPublicKey public key of the {@link SystemManager}
     * @param masterCredential       master credential of the user
     * @param disclosures            attributes to be disclosed
     */
    public VerifierIncludingMasterProtocolFactory(
            ProtocolParameters protocolParameters,
            PublicParameters publicParameters,
            List<AttributeSpace> attributeSpaces,
            Policy policy, SelectiveDisclosure[] disclosures,
            PSExtendedVerificationKey systemManagerPublicKey, PSSignature masterCredential) {
        super(protocolParameters, publicParameters, attributeSpaces, policy, disclosures);
        this.systemManagerPublicKey = systemManagerPublicKey;
        this.masterCredential = masterCredential;
    }


    @Override
    public PolicyProvingWithMasterCredProtocol getProtocol() {
        VerifierProtocolFactory clarcVerifierProtocolFactory =
                new VerifierProtocolFactory(protocolParameters, publicParameters,
                        new ArrayList<>(attributespaceMapping.values()), policy);

        MasterCredentialVerifierProtocolFactory credentialVerifierProtocolFactory =
                new MasterCredentialVerifierProtocolFactory(publicParameters, systemManagerPublicKey,
                        masterCredential);

        GeneralizedSchnorrProtocol masterCredentialProofProtocol = credentialVerifierProtocolFactory.getProtocol();
        PolicyProvingProtocol policyProofProtocol = clarcVerifierProtocolFactory.getProtocol();

        return new PolicyProvingWithMasterCredProtocol(publicParameters.getZp(), policyProofProtocol,
                masterCredentialProofProtocol, new RepresentableSignature(masterCredential));
    }
}
