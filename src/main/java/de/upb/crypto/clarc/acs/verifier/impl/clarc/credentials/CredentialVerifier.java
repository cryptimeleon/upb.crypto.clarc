package de.upb.crypto.clarc.acs.verifier.impl.clarc.credentials;

import de.upb.crypto.clarc.acs.policy.PolicyInformation;
import de.upb.crypto.clarc.acs.protocols.ProtocolFactory;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.mastercred.MasterCredentialVerifierProtocolFactory;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.ProtocolParameters;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.VerifierIncludingMasterProtocolFactory;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.VerifierProtocolFactory;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Pseudonym;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.SystemManagerPublicIdentity;
import de.upb.crypto.clarc.acs.user.impl.clarc.NonInteractivePolicyProof;
import de.upb.crypto.clarc.acs.verifier.credentials.InteractiveVerificationProcess;
import de.upb.crypto.clarc.acs.verifier.credentials.RepresentableSignature;
import de.upb.crypto.clarc.acs.verifier.credentials.VerificationResult;
import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.FiatShamirHeuristic;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.interfaces.signature.Signature;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

/**
 * Clarc specific implementation of the Verifier interface
 */
public class CredentialVerifier
        implements de.upb.crypto.clarc.acs.verifier.credentials.CredentialVerifier, Representable {
    private final PublicParameters pp;
    private final SystemManagerPublicIdentity systemManagerPublicIdentity;
    @Represented
    private final VerifierPublicIdentity identity;

    /**
     * Constructs a new verifier for the given credential system parameters, policy and attributes
     *
     * @param pp The public parameters of the credential system in use
     */
    public CredentialVerifier(PublicParameters pp,
                              SystemManagerPublicIdentity systemManagerPublicIdentity) {
        this.pp = pp;
        this.systemManagerPublicIdentity = systemManagerPublicIdentity;
        identity = new VerifierPublicIdentity(pp.getBilinearMap().getG1().getUniformlyRandomElement());
    }

    @SuppressWarnings("unused")
    public CredentialVerifier(Representation representation,
                              PublicParameters pp,
                              SystemManagerPublicIdentity systemManagerPublicIdentity) {
        this.pp = pp;
        this.systemManagerPublicIdentity = systemManagerPublicIdentity;
        identity = new VerifierPublicIdentity(representation.obj().get("identity"), pp);
    }

    @Override
    public InteractiveVerificationProcess initInteractiveVerificationProcess(
            de.upb.crypto.clarc.acs.protocols.ProtocolParameters protocolParameters,
            Announcement[] announcements,
            PolicyInformation policyInformation,
            Signature masterCredential
    ) {
        if (policyInformation == null) {
            throw new IllegalArgumentException("There was no policy given to verify against.");
        }

        ProtocolParameters clarcProtocolParameters = (ProtocolParameters) protocolParameters;
        if (policyInformation.isMasterCredentialRequired()) {
            if (masterCredential == null) {
                throw new IllegalArgumentException("Master credential should be provided in this case");
            }
            ProtocolFactory factory = new VerifierIncludingMasterProtocolFactory(
                    clarcProtocolParameters,
                    pp,
                    policyInformation.getUsedAttributeSpaces(),
                    policyInformation.getPolicy(),
                    policyInformation.getRequiredDisclosures(),
                    systemManagerPublicIdentity.getOpk(),
                    (PSSignature) masterCredential
            );
            final InteractiveThreeWayAoK protocol = factory.getProtocol();
            return new InteractiveVerificationProcess(protocol, announcements);
        } else {
            ProtocolFactory factory =
                    new VerifierProtocolFactory(clarcProtocolParameters, pp, policyInformation
                            .getUsedAttributeSpaces(),
                            policyInformation.getPolicy(),
                            policyInformation.getRequiredDisclosures());
            final InteractiveThreeWayAoK protocol = factory.getProtocol();
            return new InteractiveVerificationProcess(protocol, announcements);
        }
    }

    @Override
    public VerificationResult verifyNonInteractiveProof(de.upb.crypto.clarc.acs.user.NonInteractivePolicyProof proof,
                                                        PolicyInformation policyInformation) {
        if (!(proof instanceof NonInteractivePolicyProof)) {
            throw new IllegalArgumentException("expected 'proof' object of the type 'NonInteractivePolicyProof'");
        }
        final NonInteractivePolicyProof clarcProof = (NonInteractivePolicyProof) proof;
        InteractiveThreeWayAoK protocol;
        if (policyInformation.isMasterCredentialRequired()) {
            if (clarcProof.getMasterCredential() == null || clarcProof.getMasterCredential().getSignature(pp) == null) {
                throw new IllegalArgumentException("Master credential should be provided in this case");
            }
            PSSignature masterCredential = clarcProof.getMasterCredential().getSignature(pp);
            ProtocolFactory factory =
                    new VerifierIncludingMasterProtocolFactory(clarcProof.getProtocolParameters(), pp,
                            policyInformation.getUsedAttributeSpaces(), policyInformation.getPolicy(),
                            policyInformation.getRequiredDisclosures(),
                            systemManagerPublicIdentity.getOpk(), masterCredential);
            protocol = factory.getProtocol();
        } else {
            ProtocolFactory factory =
                    new VerifierProtocolFactory(clarcProof.getProtocolParameters(), pp,
                            policyInformation.getUsedAttributeSpaces(), policyInformation.getPolicy());
            protocol = factory.getProtocol();
        }
        FiatShamirHeuristic fiatShamirHeuristic = new FiatShamirHeuristic(protocol, new SHA256HashFunction());
        RepresentableSignature signature = clarcProof.getMasterCredential();
        ByteArrayImplementation identityBytes = new ByteArrayImplementation(identity.getUniqueByteRepresentation());
        if (clarcProof.getProof().getAuxData().length > 1 && !clarcProof.getProof().getAuxData()[1].equals(identityBytes)) {
            throw new IllegalArgumentException("Aux Data of proof should contain the public identity");
        }
        return new VerificationResult(fiatShamirHeuristic.verify(clarcProof.getProof()),
                clarcProof.getProof(), policyInformation, (Pseudonym) proof.getProtocolParameters().getPseudonym(), signature);
    }

    public SigmaProtocol createMasterCredVerifierProtocol(PSSignature masterCred,
                                                          PSExtendedVerificationKey systemManagerPublicKey) {
        final MasterCredentialVerifierProtocolFactory verifyMasterCredFactory =
                new MasterCredentialVerifierProtocolFactory(pp, systemManagerPublicKey, masterCred);

        return verifyMasterCredFactory.getProtocol();
    }

    public VerifierPublicIdentity getIdentity() {
        return identity;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }
}
