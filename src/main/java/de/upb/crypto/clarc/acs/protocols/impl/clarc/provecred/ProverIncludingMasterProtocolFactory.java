package de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred;

import de.upb.crypto.clarc.acs.attributes.AttributeSpace;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.mastercred.MasterCredentialProverProtocolFactory;
import de.upb.crypto.clarc.acs.pseudonym.Pseudonym;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.systemmanager.SystemManager;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserSecret;
import de.upb.crypto.clarc.acs.verifier.credentials.RepresentableSignature;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.popk.ProofOfPartialKnowledgeProtocol;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.craco.commitment.pedersen.PedersenOpenValue;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;

import java.util.ArrayList;
import java.util.List;

/**
 * {@link de.upb.crypto.clarc.acs.protocols.ProtocolFactory} which generates prover protocol to prove the fulfillment of a {@link Policy} utilizing the
 * owned {@link PSCredential} as well as possession of a valid master credential obtained during the join process.
 * <p>
 * This factory combines the protocols created by {@link ProverProtocolFactory} and
 * {@link MasterCredentialProverProtocolFactory} using a {@link ProofOfPartialKnowledgeProtocol}.
 */
public class ProverIncludingMasterProtocolFactory extends ProtocolFactory {
    private final PSCredential[] credentials;
    private final PedersenOpenValue pseudonymSecret;
    private final UserSecret usk;

    private final PSExtendedVerificationKey systemManagerPublicKey;
    private final PSSignature masterCredential;

    /**
     * Instantiates a {@link de.upb.crypto.clarc.acs.protocols.ProtocolFactory} with given public and protocol parameters.
     * It is able to generate a protocol to prove the fulfillment of a {@link Policy} as well as the possession of a
     * valid master credential.
     * The currently available attribute spaces are needed to correctly parse the policy to be fulfilled.
     * <p>
     * The order of the given {@link PSCredential} must match the order of
     * {@link ProtocolFactory#getSubPolicies} they should be used to prove fulfillment of.
     * If there is no {@link PSCredential} available for a certain sub policy
     * null is expected at the corresponding position in the array.
     * </p>
     *
     * @param protocolParameters     shared input for all protocol instances (prover and verifier)
     * @param publicParameters       the system's public parameters
     * @param attributeSpaces        currently available attribute spaces
     * @param credentials            the credentials which are available for proving.
     * @param usk                    the user secret
     * @param pseudonymSecret        the secret value of the {@link Pseudonym} used during the interaction with
     *                               the verifier
     * @param policy                 the policy of which the fulfillment is to be proven
     * @param systemManagerPublicKey public key of the {@link SystemManager}
     * @param masterCredential       master credential of the user
     */
    public ProverIncludingMasterProtocolFactory(
            ProtocolParameters protocolParameters,
            PublicParameters publicParameters,
            List<AttributeSpace> attributeSpaces, PSCredential[] credentials,
            UserSecret usk, PedersenOpenValue pseudonymSecret, Policy policy,
            PSExtendedVerificationKey systemManagerPublicKey, PSSignature masterCredential) {
        this(protocolParameters, publicParameters, attributeSpaces, credentials, usk, pseudonymSecret, policy, null,
                systemManagerPublicKey, masterCredential);
    }

    /**
     * Instantiates a {@link de.upb.crypto.clarc.acs.protocols.ProtocolFactory} with given public and protocol parameters.
     * It is able to generate a protocol to prove the fulfillment of a {@link Policy} as well as the possession of a
     * valid master credential.
     * The currently available attribute spaces are needed to correctly parse the policy to be fulfilled.
     * <p>
     * The order of the given {@link PSCredential} and {@link SelectiveDisclosure} must match the order of
     * {@link ProtocolFactory#getSubPolicies} associated with the same issuer.
     * If there is no {@link PSCredential} or {@link SelectiveDisclosure} available for a certain sub policy
     * null is expected at the corresponding position in the arrays.
     * </p>
     *
     * @param protocolParameters     shared input for all protocol instances (prover and verifier)
     * @param publicParameters       the system's public parameters
     * @param attributeSpaces        currently available attribute spaces
     * @param credentials            the credentials which are available for proving.
     * @param usk                    the user secret
     * @param pseudonymSecret        the secret value of the {@link Pseudonym} used during the interaction with
     *                               the verifier
     * @param policy                 the policy of which the fulfillment is to be proven
     * @param systemManagerPublicKey public key of the {@link SystemManager}
     * @param masterCredential       master credential of the user
     * @param disclosures            attributes to be disclosed
     */
    public ProverIncludingMasterProtocolFactory(
            ProtocolParameters protocolParameters,
            PublicParameters publicParameters,
            List<AttributeSpace> attributeSpaces, PSCredential[] credentials,
            UserSecret usk, PedersenOpenValue pseudonymSecret, Policy policy, SelectiveDisclosure[] disclosures,
            PSExtendedVerificationKey systemManagerPublicKey, PSSignature masterCredential) {
        super(protocolParameters, publicParameters, attributeSpaces, policy, disclosures);
        this.credentials = credentials;
        this.usk = usk;
        this.pseudonymSecret = pseudonymSecret;
        this.systemManagerPublicKey = systemManagerPublicKey;
        this.masterCredential = masterCredential;
    }

    @Override
    public SigmaProtocol getProtocol() {
        ProverProtocolFactory clarcProverProtocolFactory =
                new ProverProtocolFactory(protocolParameters, publicParameters,
                        new ArrayList<>(attributespaceMapping.values()),
                        credentials, usk, pseudonymSecret, policy, disclosures);

        MasterCredentialProverProtocolFactory masterCredentialProverProtocolFactory =
                new MasterCredentialProverProtocolFactory(publicParameters, systemManagerPublicKey,
                        masterCredential, usk);

        GeneralizedSchnorrProtocol masterCredentialProofProtocol = masterCredentialProverProtocolFactory.getProtocol();
        PolicyProvingProtocol policyProofProtocol = clarcProverProtocolFactory.getProtocol();

        return new PolicyProvingWithMasterCredProtocol(publicParameters.getZp(), policyProofProtocol,
                masterCredentialProofProtocol, new RepresentableSignature(masterCredential));
    }
}
