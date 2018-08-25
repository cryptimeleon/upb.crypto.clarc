package de.upb.crypto.clarc.acs.user.impl.clarc;

import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.acs.attributes.AttributeSpace;
import de.upb.crypto.clarc.acs.issuer.IssueResponse;
import de.upb.crypto.clarc.acs.issuer.credentials.Attributes;
import de.upb.crypto.clarc.acs.issuer.credentials.CredentialIssuerPublicIdentity;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerKeyPairFactory;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerPublicIdentity;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.RepresentableReviewToken;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.ReviewToken;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.HashOfItem;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.ReviewTokenIssuerPublicIdentity;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.impl.clarc.HashOfItemHelper;
import de.upb.crypto.clarc.acs.policy.PolicyInformation;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.JoinProtocolFactory;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.RateProtocolFactory;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.RequestCredentialProtocolFactory;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.mastercred.MasterCredentialProverProtocolFactory;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.ProtocolFactory;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.ProtocolParameters;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.ProverIncludingMasterProtocolFactory;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.ProverProtocolFactory;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Identity;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.IdentityFactory;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Pseudonym;
import de.upb.crypto.clarc.acs.review.impl.clarc.Review;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.clarc.acs.systemmanager.JoinResponse;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.SystemManagerPublicIdentity;
import de.upb.crypto.clarc.acs.user.InteractiveJoinProcess;
import de.upb.crypto.clarc.acs.user.InteractiveProvingProcess;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.acs.user.impl.clarc.credentials.CredentialNonInteractiveResponseHandler;
import de.upb.crypto.clarc.acs.user.impl.clarc.credentials.CredentialReceiver;
import de.upb.crypto.clarc.acs.user.impl.clarc.credentials.InteractiveRequestCredentialProcess;
import de.upb.crypto.clarc.acs.user.impl.clarc.credentials.NonInteractiveCredentialRequest;
import de.upb.crypto.clarc.acs.user.impl.clarc.reviewtoken.InteractiveRequestReviewTokenProcess;
import de.upb.crypto.clarc.acs.user.impl.clarc.reviewtoken.NonInteractiveReviewTokenReceiver;
import de.upb.crypto.clarc.acs.user.impl.clarc.reviewtoken.NonInteractiveReviewTokenRequest;
import de.upb.crypto.clarc.acs.user.impl.clarc.reviewtoken.ReviewTokenNonInteractiveResponseHandler;
import de.upb.crypto.clarc.acs.user.reviewtokens.ReviewTokeIssueanceState;
import de.upb.crypto.clarc.acs.verifier.credentials.RepresentableSignature;
import de.upb.crypto.clarc.acs.verifier.impl.clarc.credentials.VerifierPublicIdentity;
import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.FiatShamirHeuristic;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.FiatShamirSignatureScheme;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirProof;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirSignature;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirSigningKey;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocolProvider;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.MapRepresentation;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedList;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static de.upb.crypto.clarc.acs.protocols.impl.clarc.ComputeRatingPublicKeyAndItemHashHelper.getHashedRatingPublicKeyAndItem;
import static de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory.getSignatureScheme;

/**
 * Implementation of the Clarc specific user
 * <p>
 * The class provides a simple API to allow an user to interact with the credential system without needing to manually
 * deal with constructing all the necessary objects. For the standard use cases this class should provide all the
 * functionality of the credential system from the user perspective.
 * </p>
 */
public class User implements de.upb.crypto.clarc.acs.user.User<PSCredential, RepresentableReviewToken> {
    private class ProtocolInformation {
        final ProtocolParameters parameters;
        final InteractiveThreeWayAoK protocol;

        public ProtocolInformation(ProtocolParameters parameters, InteractiveThreeWayAoK protocol) {
            this.parameters = parameters;
            this.protocol = protocol;
        }
    }


    @Represented
    private PublicParameters pp;
    @Represented
    private UserKeyPair clarcUserKeyPair;


    private Map<Representation, PSCredential> credentials = new HashMap<>();
    @RepresentedList(elementRestorer = @Represented)
    private List<RepresentableReviewToken> reviewTokens = new ArrayList<>();
    @RepresentedList(elementRestorer = @Represented)
    private List<Identity> identities = new ArrayList<>();

    private PSSignature registrationSignature;
    private SystemManagerPublicIdentity systemManagerPublicIdentity;

    /**
     * Constructs a new user for a credential system with the given parameters
     *
     * @param pp The public parameters of the credential system
     */
    public User(PublicParameters pp) {
        this.pp = pp;
    }


    public User(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
        final PSExtendedSignatureScheme signatureScheme = getSignatureScheme(pp);
        final Representation registrationSignature = representation.obj().get("registrationSignature");
        this.registrationSignature =
                registrationSignature == null ? null : signatureScheme.getSignature(registrationSignature);
        final Representation systemManagerPublicIdentity = representation.obj().get("systemManagerPublicIdentity");
        this.systemManagerPublicIdentity =
                systemManagerPublicIdentity == null
                        ? null
                        : new SystemManagerPublicIdentity(systemManagerPublicIdentity, pp);

        final MapRepresentation credentialMap = representation.obj().get("credentials").map();
        this.credentials =
                credentialMap.stream()
                        .collect(Collectors.toMap(
                                Map.Entry::getKey,
                                entry -> (PSCredential) entry.getValue().repr().recreateRepresentable()
                        ));
    }

    private void createKeys(SystemManagerPublicIdentity systemManagerPublicIdentity) {
        this.systemManagerPublicIdentity = systemManagerPublicIdentity;
        final UserKeyPairFactory uskFactory = new UserKeyPairFactory();
        clarcUserKeyPair = uskFactory.create(pp, systemManagerPublicIdentity);
    }

    protected void checkForKeys() {
        if (clarcUserKeyPair == null) {
            throw new IllegalStateException("join operation not performed yet!");
        }
    }

    private ProtocolInformation createProveProtocol(Identity clarcIdentity,
                                                    PolicyInformation policyInformation,
                                                    PSSignature blindedRegistrationSignature) {
        checkForKeys();
        final PSCredential[] credentialArray = new PSCredential[policyInformation.getUsedAttributeSpaces().size()];
        for (int i = 0; i < credentialArray.length; i++) {
            AttributeSpace space = policyInformation.getUsedAttributeSpaces().get(i);
            credentialArray[i] = this.credentials.get(space.getIssuerPublicKey());
        }

        final Pseudonym clarcPseudonym = clarcIdentity.getPseudonym();
        final ProtocolParameters parameters = new ProtocolParameters(clarcPseudonym);
        InteractiveThreeWayAoK protocol;
        if (policyInformation.isMasterCredentialRequired()) {
            final ProtocolFactory protocolFactory =
                    new ProverIncludingMasterProtocolFactory(parameters, pp, policyInformation.getUsedAttributeSpaces(),
                            credentialArray, clarcUserKeyPair.getUserSecret(),
                            clarcIdentity.getPseudonymSecret(), policyInformation.getPolicy(),
                            policyInformation.getRequiredDisclosures(),
                            systemManagerPublicIdentity.getOpk(), blindedRegistrationSignature);
            protocol = protocolFactory.getProtocol();
        } else {
            final ProtocolFactory protocolFactory =
                    new ProverProtocolFactory(parameters, pp, policyInformation.getUsedAttributeSpaces(),
                            credentialArray, clarcUserKeyPair.getUserSecret(),
                            clarcIdentity.getPseudonymSecret(), policyInformation.getPolicy(),
                            policyInformation.getRequiredDisclosures());
            protocol = protocolFactory.getProtocol();
        }

        if (!protocol.isFulfilled()) {
            throw new IllegalStateException("The given policy can not be fulfilled with the user's credentials.");
        }

        return new ProtocolInformation(parameters, protocol);
    }

    @Override
    public InteractiveProvingProcess initInteractiveProvingProcess(de.upb.crypto.clarc.acs.pseudonym.Identity identity,
                                                                   PolicyInformation information) {
        if (!(identity instanceof Identity)) {
            throw new IllegalArgumentException("Unsupported identity type");
        }
        final Identity clarcIdentity = (Identity) identity;

        ProtocolInformation protocolInfo;
        PSSignature blindedRegistrationSignature;
        if (information.isMasterCredentialRequired()) {
            blindedRegistrationSignature = getBlindedRegistrationSignature();
        } else {
            blindedRegistrationSignature = null;
        }
        protocolInfo = createProveProtocol(clarcIdentity, information, blindedRegistrationSignature);
        return new InteractiveProvingProcess(
                protocolInfo.protocol,
                protocolInfo.parameters,
                blindedRegistrationSignature);
    }

    public InteractiveJoinProcess initInteractiveJoinProcess(SystemManagerPublicIdentity systemManagerPublicIdentity) {
        createKeys(systemManagerPublicIdentity);
        return new InteractiveJoinProcess(pp, this.clarcUserKeyPair, systemManagerPublicIdentity);
    }

    /**
     * Creates a new {@link Identity} for the user and safes it in his list of identities.
     *
     * @return The created new identity
     */
    @Override
    public Identity createIdentity() {
        checkForKeys();
        IdentityFactory clarcPseudonymFactory = new IdentityFactory();
        final Identity newIdentity = clarcPseudonymFactory.create(pp, clarcUserKeyPair.getUserSecret());
        identities.add(newIdentity);
        return newIdentity;
    }

    private IssuingContext createIssuingContext(de.upb.crypto.clarc.acs.issuer.IssuerPublicIdentity issuerPublicIdentity,
                                                de.upb.crypto.clarc.acs.pseudonym.Identity identity, boolean interactive) {
        if (!(identity instanceof Identity)) {
            throw new IllegalArgumentException("Unsupported identity type");
        }
        if (!(issuerPublicIdentity instanceof IssuerPublicIdentity)) {
            throw new IllegalArgumentException("Unsupported issuer identity");
        }
        checkForKeys();
        final Identity clarcIdentity = (Identity) identity;
        final IssuerPublicIdentity clarcReviewTokenIssuerPublicIdentity =
                (IssuerPublicIdentity) issuerPublicIdentity;
        PSExtendedSignatureScheme signatureScheme = PublicParametersFactory.getSignatureScheme(pp);
        final PSExtendedVerificationKey verificationKey =
                signatureScheme.getVerificationKey(clarcReviewTokenIssuerPublicIdentity.getIssuerPublicKey());
        final PedersenPublicParameters pedersenPublicParameters =
                IssuerKeyPairFactory.getPedersenPPForSingleValueFromIssuerPK(pp, verificationKey);
        UserSecret usk = clarcUserKeyPair.getUserSecret();
        PedersenCommitmentScheme commitmentScheme = new PedersenCommitmentScheme(pedersenPublicParameters);
        final PedersenCommitmentPair commitment = commitmentScheme.commit(new RingElementPlainText(usk.getUsk()));

        if (interactive) {
            return new IssuingContext(pp, pedersenPublicParameters, clarcReviewTokenIssuerPublicIdentity, usk,
                    clarcIdentity,
                    commitment);
        }

        final RequestCredentialProtocolFactory protocolFactory =
                new RequestCredentialProtocolFactory(pedersenPublicParameters, clarcIdentity, commitment, pp,
                        usk);
        final InteractiveThreeWayAoK protocol = protocolFactory.getProtocol();
        FiatShamirHeuristic fiatShamirHeuristic = new FiatShamirHeuristic(protocol, new SHA256HashFunction());
        final FiatShamirProof proof = fiatShamirHeuristic.prove();

        return new NonInteractiveIssuingContext(pp, pedersenPublicParameters, clarcReviewTokenIssuerPublicIdentity,
                usk, clarcIdentity, commitment, proof);

    }

    private Attributes suffixAttributesForIssuer(CredentialIssuerPublicIdentity issuerPublicIdentity,
                                                 Attributes attributes) {
        PSExtendedSignatureScheme signatureScheme = PublicParametersFactory.getSignatureScheme(pp);
        final PSExtendedVerificationKey verificationKey =
                signatureScheme.getVerificationKey(issuerPublicIdentity.getIssuerPublicKey());
        return new Attributes(
                Arrays.stream(attributes.getAttributes(issuerPublicIdentity.getAttributeSpace()))
                        .map(a -> AttributeNameValuePair.getAttributeForIssuer(verificationKey, a))
                        .toArray(AttributeNameValuePair[]::new)
        );
    }

    @Override
    public InteractiveRequestCredentialProcess createInteractiveIssueCredentialRequest(
            CredentialIssuerPublicIdentity issuerPublicIdentity, de.upb.crypto.clarc.acs.pseudonym.Identity identity, Attributes issuable) {
        checkForKeys();
        issuable = suffixAttributesForIssuer(issuerPublicIdentity, issuable);
        IssuingContext issuanceData = createIssuingContext(issuerPublicIdentity, identity, true);

        return new InteractiveRequestCredentialProcess(issuanceData, issuable);
    }

    @Override
    public CredentialNonInteractiveResponseHandler createNonInteractiveIssueCredentialRequest(
            CredentialIssuerPublicIdentity issuerPublicIdentity,
            de.upb.crypto.clarc.acs.pseudonym.Identity identity,
            Attributes issuable) {
        checkForKeys();
        issuable = suffixAttributesForIssuer(issuerPublicIdentity, issuable);
        NonInteractiveIssuingContext issuanceData =
                (NonInteractiveIssuingContext) createIssuingContext(issuerPublicIdentity, identity, false);


        final NonInteractiveCredentialRequest issueRequest =
                new NonInteractiveCredentialRequest(
                        issuanceData.getUskCommitPair().getCommitmentValue(),
                        issuanceData.getIdentity().getPseudonym(),
                        issuable,
                        issuanceData.getProof()
                );

        final CredentialReceiver receiver = new CredentialReceiver(issuable, issuanceData);

        return new CredentialNonInteractiveResponseHandler(issueRequest, receiver);
    }

    @Override
    public InteractiveRequestReviewTokenProcess createInteractiveIssueReviewTokenRequest(
            ReviewTokenIssuerPublicIdentity issuerPublicIdentity, de.upb.crypto.clarc.acs.pseudonym.Identity identity, byte... reviewSubject) {
        checkForKeys();
        IssuingContext issuanceData = createIssuingContext(issuerPublicIdentity, identity, true);
        final HashOfItem hashOfItem = HashOfItemHelper.getHashOfItemFromBytes(pp, reviewSubject);
        return new InteractiveRequestReviewTokenProcess(issuanceData, hashOfItem);
    }

    @Override
    public ReviewTokenNonInteractiveResponseHandler createNonInteractiveIssueReviewTokenRequest(
            ReviewTokenIssuerPublicIdentity reviewTokenIssuerPublicIdentity,
            de.upb.crypto.clarc.acs.pseudonym.Identity identity,
            byte... reviewSubject) {
        checkForKeys();
        NonInteractiveIssuingContext issuanceData =
                (NonInteractiveIssuingContext) createIssuingContext(reviewTokenIssuerPublicIdentity, identity, false);

        final HashOfItem hashOfItem = HashOfItemHelper.getHashOfItemFromBytes(pp, reviewSubject);
        final NonInteractiveReviewTokenRequest issueRequest =
                new NonInteractiveReviewTokenRequest(
                        issuanceData.getUskCommitPair().getCommitmentValue(),
                        issuanceData.getIdentity().getPseudonym(),
                        hashOfItem,
                        issuanceData.getProof()
                );

        final NonInteractiveReviewTokenReceiver receiver =
                new NonInteractiveReviewTokenReceiver(hashOfItem, issuanceData);

        return new ReviewTokenNonInteractiveResponseHandler(issueRequest, receiver);
    }

    @Override
    public void receiveCredentialInteractively(
            de.upb.crypto.clarc.acs.user.credentials.InteractiveRequestCredentialProcess issuanceProcess,
            IssueResponse<PSCredential> issueResponse) {
        if (issueResponse == null) {
            throw new IllegalStateException("Interactive issuing failed, unable to receive credential");
        }
        if (!(issuanceProcess instanceof InteractiveRequestCredentialProcess)) {
            throw new IllegalArgumentException("Unsupported process type");
        }
        PSCredential credential = ((InteractiveRequestCredentialProcess) issuanceProcess).receive(issueResponse);
        this.credentials.put(credential.getIssuerPublicKeyRepresentation(), credential);
    }

    @Override
    public void receiveCredentialNonInteractively(
            de.upb.crypto.clarc.acs.user.credentials.CredentialNonInteractiveResponseHandler responseHandler,
            IssueResponse<PSCredential> issueResponse) {
        if (issueResponse == null) {
            throw new IllegalStateException("Non-interactive issuing failed, unable to receive credential");
        }
        if (!(responseHandler instanceof CredentialNonInteractiveResponseHandler)) {
            throw new IllegalArgumentException("Unsupported process type");
        }
        PSCredential credential =
                ((CredentialNonInteractiveResponseHandler) responseHandler).getReceiver().receive(issueResponse);
        this.credentials.put(credential.getIssuerPublicKeyRepresentation(), credential);
    }

    @Override
    public void receiveReviewTokenInteractively(
            de.upb.crypto.clarc.acs.user.reviewtokens.InteractiveRequestReviewTokenProcess requestReviewTokenProcess,
            IssueResponse<RepresentableReviewToken> issueResponse) {
        if (issueResponse == null) {
            throw new IllegalStateException("Interactive issuing failed, unable to receive review token");
        }
        if (!(requestReviewTokenProcess instanceof InteractiveRequestReviewTokenProcess)) {
            throw new IllegalArgumentException("Unsupported process type");
        }
        RepresentableReviewToken token =
                ((InteractiveRequestReviewTokenProcess) requestReviewTokenProcess).receive(issueResponse);
        this.reviewTokens.add(token);
    }

    @Override
    public void receiveReviewTokenNonInteractively(ReviewTokeIssueanceState request,
                                                   IssueResponse<RepresentableReviewToken> issueResponse) {
        if (issueResponse == null) {
            throw new IllegalStateException("Non-interactive issuing failed, unable to receive review token");
        }
        if (!(request instanceof ReviewTokenNonInteractiveResponseHandler)) {
            throw new IllegalArgumentException("Unsupported process type");
        }
        RepresentableReviewToken token =
                ((ReviewTokenNonInteractiveResponseHandler) request).getReceiver().receive(issueResponse);
        this.reviewTokens.add(token);

    }

    public SigmaProtocol createMasterCredProverProtocol() {
        checkForKeys();
        final MasterCredentialProverProtocolFactory proveMasterCredFactory =
                new MasterCredentialProverProtocolFactory(pp, systemManagerPublicIdentity.getOpk(),
                        registrationSignature, clarcUserKeyPair.getUserSecret());
        return proveMasterCredFactory.getProtocol();
    }

    @Override
    public NonInteractivePolicyProof createNonInteractivePolicyProof(de.upb.crypto.clarc.acs.pseudonym.Identity identity,
                                                                     PolicyInformation information,
                                                                     de.upb.crypto.clarc.acs.verifier.credentials.VerifierPublicIdentity verifierIdentity) {
        if (!(identity instanceof Identity)) {
            throw new IllegalArgumentException("Unsupported identity type");
        }
        if (!(verifierIdentity instanceof VerifierPublicIdentity)) {
            throw new IllegalArgumentException("Unsupported verifier identity type");
        }
        final Identity clarcIdentity = (Identity) identity;

        PSSignature blindedRegistrationSignature = null;
        RepresentableSignature representableRegistrationSignature = null;
        if (information.isMasterCredentialRequired()) {
            blindedRegistrationSignature = getBlindedRegistrationSignature();
            representableRegistrationSignature = new RepresentableSignature(blindedRegistrationSignature);
        }

        final ProtocolInformation protocolInfo = createProveProtocol(clarcIdentity, information, blindedRegistrationSignature);
        FiatShamirHeuristic fiatShamirHeuristic =
                new FiatShamirHeuristic(protocolInfo.protocol, new SHA256HashFunction());
        final FiatShamirProof proof = fiatShamirHeuristic.prove(information, (VerifierPublicIdentity) verifierIdentity);

        return new NonInteractivePolicyProof(protocolInfo.parameters, proof, representableRegistrationSignature);
    }

    public NonInteractiveJoinRequest createNonInteractiveJoinRequest(
            SystemManagerPublicIdentity systemManagerPublicIdentity) {
        createKeys(systemManagerPublicIdentity);
        Zp.ZpElement usk = clarcUserKeyPair.getUserSecret().getUsk();
        final GroupElement tau = systemManagerPublicIdentity.getOpk().getGroup2ElementsTildeYi()[0].pow(usk);

        JoinProtocolFactory factory = new JoinProtocolFactory(pp,
                clarcUserKeyPair, systemManagerPublicIdentity.getOpk());
        InteractiveThreeWayAoK protocol = factory.getProtocol();
        FiatShamirHeuristic fiatShamirHeuristic = new FiatShamirHeuristic(protocol,
                new SHA256HashFunction());
        FiatShamirProof proof = fiatShamirHeuristic.prove();
        return new NonInteractiveJoinRequest(
                proof, tau, clarcUserKeyPair.getUserPublicKey());
    }

    public void finishRegistration(JoinResponse joinResponse) {
        if (this.registrationSignature != null) {
            throw new IllegalStateException("registration already seems to be finished");
        }
        final Representation registrationSignature = joinResponse.getRegistrationSignature();
        final PSExtendedSignatureScheme signatureScheme = getSignatureScheme(pp);
        this.registrationSignature = signatureScheme.getSignature(registrationSignature);
    }

    @Override
    public Review createReview(byte[] message,
                               ReviewTokenIssuerPublicIdentity reviewTokenIssuerPublicIdentity,
                               byte[] reviewSubject) {
        final ReviewToken token =
                Stream.of(getReviewTokens(reviewTokenIssuerPublicIdentity, reviewSubject))
                        .findFirst()
                        .orElseThrow(() -> new IllegalStateException("unable to find matching review token"));
        return createReview(message, token);
    }

    @Override
    public Review createReview(byte[] message, de.upb.crypto.clarc.acs.issuer.reviewtokens.ReviewToken token) {
        if (!(token instanceof ReviewToken)) {
            throw new IllegalArgumentException("Expected 'ReviewToken'");
        }
        ReviewToken clarcToken = (ReviewToken) token;

        Zp.ZpElement zeta = pp.getZp().getUniformlyRandomElement();

        // Blinding the registration signature
        Zp.ZpElement s = pp.getZp().getUniformlyRandomUnit();
        PSSignature blindedRegistrationSignature = getBlindedRegistrationSignature();

        // Blinding the token signature
        Zp.ZpElement u = pp.getZp().getUniformlyRandomUnit();
        Zp.ZpElement r = pp.getZp().getUniformlyRandomElement();
        GroupElement tokenSigma1 = clarcToken.getSignature().getGroup1ElementSigma1();
        GroupElement tokenSigma2 = clarcToken.getSignature().getGroup1ElementSigma2();
        PSSignature blindedTokenSignature =
                new PSSignature(tokenSigma1.pow(u), tokenSigma2.op(tokenSigma1.pow(r)).pow(u));
        ReviewToken blindedToken =
                new ReviewToken(blindedTokenSignature, clarcToken.getItem(), clarcToken
                        .getRatingIssuerPublicKey());
        final PSExtendedVerificationKey systemManagerPublicKey = systemManagerPublicIdentity.getOpk();
        final GroupElement linkabilityBasis = systemManagerPublicIdentity.getLinkabilityBasis();

        // Prepare hash values and review values
        GroupElement hash = getHashedRatingPublicKeyAndItem(blindedToken, pp);
        GroupElement L1 = hash.pow(zeta).op(hash.pow(clarcUserKeyPair.getUserSecret().getUsk()));
        GroupElement L2 = linkabilityBasis.pow(zeta);

        // Use factory for FiatShamirSignatureScheme
        RateProtocolFactory factory = new RateProtocolFactory(pp, blindedRegistrationSignature,
                systemManagerPublicKey, linkabilityBasis, blindedToken, L1, L2,
                clarcUserKeyPair.getUserSecret(), zeta, r);
        GeneralizedSchnorrProtocolProvider protocolProvider = new GeneralizedSchnorrProtocolProvider(pp.getZp());
        FiatShamirSignatureScheme signatureScheme =
                new FiatShamirSignatureScheme(protocolProvider, new SHA256HashFunction());

        // Signing of the message with FiatShamirSignatureScheme
        GeneralizedSchnorrProtocol protocol = factory.getProtocol();
        FiatShamirSigningKey fiatShamirSigningKey = new FiatShamirSigningKey(protocol.getProblems(),
                protocol.getWitnesses());
        final ByteArrayImplementation messageArray = new ByteArrayImplementation(message);
        FiatShamirSignature fiatShamirSignature = signatureScheme.sign(messageArray, fiatShamirSigningKey);

        return new Review(
                messageArray,
                clarcToken.getItem(),
                systemManagerPublicKey,
                linkabilityBasis,
                clarcToken.getRatingIssuerPublicKey(),
                blindedRegistrationSignature,
                blindedTokenSignature,
                fiatShamirSignature,
                L1, L2);
    }

    @Override
    public UserPublicKey getPublicKey() {
        checkForKeys();
        return clarcUserKeyPair.getUserPublicKey();
    }

    /**
     * This method blinds the master credential such that the user can do multiple proofs without someone
     * being able to know that it was done by the same user.
     *
     * @return the blinded master credential
     */
    private PSSignature getBlindedRegistrationSignature() {
        Zp.ZpElement s = pp.getZp().getUniformlyRandomUnit();
        return new PSSignature(registrationSignature.getGroup1ElementSigma1().pow(s),
                registrationSignature.getGroup1ElementSigma2().pow(s));
    }

    @Override
    public List<Identity> getIdentities() {
        return identities;
    }

    @Override
    public PSCredential getCredential(CredentialIssuerPublicIdentity issuerPublicIdentity) {
        return credentials.get(issuerPublicIdentity.getIssuerPublicKey());
    }

    public ReviewToken[] getReviewTokens(ReviewTokenIssuerPublicIdentity issuerIdentity,
                                         byte[] reviewSubject) {
        PSExtendedSignatureScheme signatureScheme = getSignatureScheme(pp);
        final PSExtendedVerificationKey verificationKey =
                signatureScheme.getVerificationKey(issuerIdentity.getIssuerPublicKey());
        return reviewTokens.stream()
                .map(token -> token.getReviewToken(pp))
                .filter(token -> token.getRatingIssuerPublicKey().equals(verificationKey))
                .filter(token -> token.getItem().getData()
                        .equals(new ByteArrayImplementation(reviewSubject)))
                .toArray(ReviewToken[]::new);
    }

    @Override
    public Representation getRepresentation() {
        final ObjectRepresentation object = AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
        object.put("registrationSignature",
                registrationSignature == null ? null : registrationSignature.getRepresentation());
        object.put("systemManagerPublicIdentity",
                systemManagerPublicIdentity == null ? null : systemManagerPublicIdentity.getRepresentation());

        MapRepresentation credentialMap = new MapRepresentation();
        for (Map.Entry<Representation, PSCredential> credentialEntry : this.credentials.entrySet()) {
            credentialMap.put(credentialEntry.getKey(),
                    new RepresentableRepresentation(credentialEntry.getValue()));
        }
        object.put("credentials", credentialMap);
        return object;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User clarcUser = (User) o;
        return Objects.equals(pp, clarcUser.pp) &&
                Objects.equals(clarcUserKeyPair, clarcUser.clarcUserKeyPair) &&
                Objects.equals(credentials, clarcUser.credentials) &&
                Objects.equals(identities, clarcUser.identities) &&
                Objects.equals(registrationSignature, clarcUser.registrationSignature) &&
                Objects.equals(systemManagerPublicIdentity, clarcUser.systemManagerPublicIdentity);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                pp,
                clarcUserKeyPair,
                credentials,
                identities,
                registrationSignature,
                systemManagerPublicIdentity);
    }
}
