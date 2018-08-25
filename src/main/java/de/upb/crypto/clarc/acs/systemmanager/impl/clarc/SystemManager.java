package de.upb.crypto.clarc.acs.systemmanager.impl.clarc;

import de.upb.crypto.clarc.acs.policy.PolicyInformation;
import de.upb.crypto.clarc.acs.protocols.ProtocolFactory;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.JoinVerifyProtocolFactory;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.ProtocolParameters;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.VerifierIncludingMasterProtocolFactory;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.user.impl.clarc.NonInteractiveJoinRequest;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserPublicKey;
import de.upb.crypto.clarc.acs.verifier.credentials.VerificationResult;
import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.FiatShamirHeuristic;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirProof;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedList;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class SystemManager implements de.upb.crypto.clarc.acs.systemmanager.SystemManager {

    @Represented
    private PublicParameters pp;
    private SystemManagerKeyPair clarcSystemManagerKeyPair;
    @RepresentedList(elementRestorer = @Represented)
    private List<RegistrationEntry> registry = new ArrayList<>();

    public SystemManager(PublicParameters pp) {
        this.pp = pp;
        SystemManagerKeyPairFactory factory = new SystemManagerKeyPairFactory();
        this.clarcSystemManagerKeyPair = factory.create(pp);
    }

    @SuppressWarnings("unused")
    public SystemManager(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
        clarcSystemManagerKeyPair =
                new SystemManagerKeyPair(representation.obj().get("clarcSystemManagerKeyPair"), pp);
    }

    public UserPublicKey retrievePublicKey(VerificationResult verificationResult) {
        FiatShamirProof proof = verificationResult.getFiatShamirProof();
        PolicyInformation policyInformation = verificationResult.getPolicyInformation();
        PSSignature signature = verificationResult.getBlindedMasterCredential().getSignature(
                (PublicParameters) policyInformation.getPublicParameters());

        de.upb.crypto.clarc.acs.protocols.ProtocolParameters
                protocolParameters = new ProtocolParameters(verificationResult.getPseudonym());
        ProtocolFactory factory = new VerifierIncludingMasterProtocolFactory(
                (ProtocolParameters) protocolParameters,
                (PublicParameters) policyInformation.getPublicParameters(),
                policyInformation.getUsedAttributeSpaces(),
                policyInformation.getPolicy(),
                clarcSystemManagerKeyPair.getPublicIdentity().getOpk(),
                signature);

        InteractiveThreeWayAoK protocol = factory.getProtocol();

        FiatShamirHeuristic fiatShamirHeuristic = new FiatShamirHeuristic(protocol, new SHA256HashFunction());
        ByteArrayImplementation hashOfPolicy =
                new ByteArrayImplementation(policyInformation.getUniqueByteRepresentation());
        // Testing if the proof is valid AND if the policy used in the proof is the same that was given by the verifier
        if (!fiatShamirHeuristic.verify(proof) ||
                (proof.getAuxData().length > 0 && !proof.getAuxData()[0].equals(hashOfPolicy))) {
            throw new IllegalArgumentException("Proof is expected to be valid");
        }

        final PSExtendedVerificationKey verificationKey = clarcSystemManagerKeyPair.getPublicIdentity().getOpk();
        for (RegistrationEntry entry : registry) {
            BilinearMap map = pp.getBilinearMap();
            GroupElement firstValue =
                    map.apply(signature.getGroup1ElementSigma2(),
                            verificationKey.getGroup2ElementTildeG());
            GroupElement secondValue =
                    map.apply(signature.getGroup1ElementSigma1(),
                            verificationKey.getGroup2ElementTildeX()).inv();
            GroupElement tau = pp.getBilinearMap().getG2().getElement(entry.getTau());
            GroupElement expectedResult = map.apply(signature.getGroup1ElementSigma1(), tau);
            if (firstValue.op(secondValue).equals(expectedResult)) {
                return entry.getUserPublicKey();
            }
        }
        throw new IllegalArgumentException("No user public key found!");
    }

    public SystemManagerPublicIdentity getPublicIdentity() {
        return clarcSystemManagerKeyPair.getPublicIdentity();
    }

    @Override
    public InteractiveJoinVerifyProcess initInteractiveJoinVerifyProcess(UserPublicKey userPublicKey,
                                                                         Announcement[] announcements,
                                                                         de.upb.crypto.clarc.acs.systemmanager.RegistrationInformation registration) {
        return new InteractiveJoinVerifyProcess(pp, userPublicKey,
                clarcSystemManagerKeyPair, announcements, registry, (RegistrationInformation) registration);
    }

    public JoinResponse nonInteractiveJoinVerification(
            de.upb.crypto.clarc.acs.user.NonInteractiveJoinRequest nonInteractiveJoinRequest) {
        NonInteractiveJoinRequest joinRequest =
                (NonInteractiveJoinRequest) nonInteractiveJoinRequest;
        JoinVerifyProtocolFactory protocolFactory = new JoinVerifyProtocolFactory(
                pp,
                nonInteractiveJoinRequest.getUpk(),
                clarcSystemManagerKeyPair.getPublicIdentity().getOpk()
        );
        GeneralizedSchnorrProtocol protocol = protocolFactory.getProtocol();
        FiatShamirHeuristic fiatShamirHeuristic = new FiatShamirHeuristic(protocol, new SHA256HashFunction());
        if (!fiatShamirHeuristic.verify(joinRequest.getProof())) {
            return null;
        }
        Representation tau = joinRequest.getTau();
        PSSignature signature =
                CreateSignatureHelper
                        .computeSignature(registry, joinRequest.getUpk(), pp, clarcSystemManagerKeyPair, tau);
        return new JoinResponse(signature);
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation object = AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
        object.put("clarcSystemManagerKeyPair", clarcSystemManagerKeyPair.getRepresentation());
        return object;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SystemManager that = (SystemManager) o;
        return Objects.equals(pp, that.pp) &&
                Objects.equals(clarcSystemManagerKeyPair, that.clarcSystemManagerKeyPair) &&
                Objects.equals(registry, that.registry);
    }

    @Override
    public int hashCode() {
        return Objects.hash(pp, clarcSystemManagerKeyPair, registry);
    }
}
