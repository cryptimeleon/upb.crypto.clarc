package de.upb.crypto.clarc.acs.testdataprovider;

import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.acs.attributes.BigIntegerAttributeDefinition;
import de.upb.crypto.clarc.acs.attributes.StringAttributeDefinition;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssuer;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.ProtocolFactory;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.ProtocolParameters;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.ProverProtocolFactory;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Identity;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.subpolicyproving.*;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserSecret;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.PredicateTypePrimitive;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.popk.ProofOfPartialKnowledgeProtocol;
import de.upb.crypto.clarc.predicategeneration.inequalityproofs.InequalityPublicParameters;
import de.upb.crypto.clarc.predicategeneration.parametergeneration.InequalityParameterGen;
import de.upb.crypto.clarc.predicategeneration.policies.PredicatePolicyFact;
import de.upb.crypto.clarc.predicategeneration.policies.SubPolicyPolicyFact;
import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.clarc.protocols.parameters.Witness;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;

public class ExtendetProveCredTestdataProvider {


    private final SubPolicyProvingProtocolPublicParameters subPolicyProvingProtocolPublicParameters;
    private final SubPolicyProvingProtocol subPolicyProvingProtocol;
    private final SubPolicyProvingProtocolFactory subPolicyProvingProtocolFactory;
    private final Witness[] subPolWitness;
    private final Announcement[] subPolAnnouncement;
    private final Challenge subPolChallenge;
    private final Response[] subPolResponse;

    private final ProofOfPartialKnowledgeProtocol poPKProtocol;
    private final Witness[] popkWitness;
    private final Response[] popkResponse;
    private final Announcement[] popkAnnouncement;
    private final ProtocolParameters protocolParameters;
    private final InteractiveThreeWayAoK protocol;

    private final ThresholdPolicy subpolicy;

    public ExtendetProveCredTestdataProvider(PublicParameters clarcPublicParameters, Identity identity,
                                             CredentialIssuer issuer, BigIntegerAttributeDefinition age,
                                             StringAttributeDefinition gender, PSCredential credential,
                                             PSExtendedSignatureScheme signatureScheme,
                                             PedersenCommitmentScheme pedersenCommitmentScheme) {
        // Setup setupClarcProtocolFactory
        subpolicy = this.computeThresholdPolicyWithPredicateLeaves(clarcPublicParameters, age, gender);
        SubPolicyPolicyFact subPolicyPolicyFact =
                new SubPolicyPolicyFact(issuer.getPublicIdentity().getIssuerPublicKey(), subpolicy);

        ThresholdPolicy policy = new ThresholdPolicy(1, subPolicyPolicyFact);

        protocolParameters = new ProtocolParameters(identity.getPseudonym());

        UserSecret usk =
                UserAndSystemManagerTestdataProvider.extractUserSecretFromIdentity(clarcPublicParameters, identity);
        final ProtocolFactory protocolFactory =
                new ProverProtocolFactory(protocolParameters, clarcPublicParameters,
                        new ArrayList<>(Collections.singletonList(issuer.getPublicIdentity().getAttributeSpace())),
                        new PSCredential[]{credential}, usk, identity.getPseudonymSecret(), policy);
        protocol = protocolFactory.getProtocol();

        // Setup setupProveCred

        subPolicyProvingProtocolFactory =
                new SubPolicyProvingProtocolFactory(pedersenCommitmentScheme, signatureScheme,
                        identity.getPseudonym().getCommitmentValue(),
                        issuer.getPublicIdentity().getAttributeSpace(), new HashMap<>(), subpolicy,
                        clarcPublicParameters.getHashIntoZp(), clarcPublicParameters.getBilinearMap());
        Zp.ZpElement nymRandom = identity.getPseudonymSecret().getRandomValue();
        this.subPolicyProvingProtocol =
                subPolicyProvingProtocolFactory.getProverProtocol(credential, usk.getUsk(), nymRandom);

        subPolAnnouncement = subPolicyProvingProtocol.generateAnnouncements();
        subPolicyProvingProtocolPublicParameters =
                (SubPolicyProvingProtocolPublicParameters) subPolicyProvingProtocol.getPublicParameters();
        subPolWitness = subPolicyProvingProtocol.getWitnesses();
        subPolChallenge = subPolicyProvingProtocol.chooseChallenge();


        subPolResponse = subPolicyProvingProtocol.generateResponses(subPolChallenge);


        poPKProtocol = subPolicyProvingProtocol.getPredicateProvingProtocol();
        popkAnnouncement = ((SubPolicyProvingProtocolAnnouncement) subPolAnnouncement[0])
                .getAnnouncementsOfPredicateProvingProtocol();
        popkWitness = poPKProtocol.getWitnesses();
        popkResponse = ((SubPolicyProvingProtocolResponse) subPolResponse[0]).getResponsesPoPKProtocol();

    }

    private ThresholdPolicy computeThresholdPolicyWithPredicateLeaves(PublicParameters clarcPublicParameters,
                                                                      BigIntegerAttributeDefinition age,
                                                                      StringAttributeDefinition gender) {
        AttributeNameValuePair attribute1 = age.createAttribute(BigInteger.valueOf(20));
        AttributeNameValuePair attribute2 = gender.createAttribute("m");

        InequalityPublicParameters ageInequalityPP =
                InequalityParameterGen.createInequalityPP(
                        clarcPublicParameters.getSingleMessageCommitmentPublicParameters(),
                        clarcPublicParameters.getBilinearMap(),
                        0, attribute1.getZpRepresentation(clarcPublicParameters.getHashIntoZp()), clarcPublicParameters.getHashIntoZp().getTargetStructure()
                );
        InequalityPublicParameters genderInequalityPP =
                InequalityParameterGen.createInequalityPP(
                        clarcPublicParameters.getSingleMessageCommitmentPublicParameters(),
                        clarcPublicParameters.getBilinearMap(),
                        1, attribute2.getZpRepresentation(clarcPublicParameters.getHashIntoZp()), clarcPublicParameters.getHashIntoZp().getTargetStructure()
                );
        PredicatePolicyFact inequalAge = new PredicatePolicyFact(
                ageInequalityPP, PredicateTypePrimitive.INEQUALITY_PUBLIC_VALUE
        );
        PredicatePolicyFact inequalGender = new PredicatePolicyFact(
                genderInequalityPP, PredicateTypePrimitive.INEQUALITY_PUBLIC_VALUE
        );

        return new ThresholdPolicy(2, inequalAge, inequalGender);
    }

    public Announcement[] getSubPolAnnouncement() {
        return subPolAnnouncement;
    }

    public SubPolicyProvingProtocolPublicParameters getSubPolicyProvingProtocolPublicParameters() {
        return subPolicyProvingProtocolPublicParameters;
    }

    public SubPolicyProvingProtocol getSubPolicyProvingProtocol() {
        return subPolicyProvingProtocol;
    }

    public SubPolicyProvingProtocolFactory getSubPolicyProvingProtocolFactory() {
        return subPolicyProvingProtocolFactory;
    }

    public Witness[] getSubPolWitness() {
        return subPolWitness;
    }

    public Challenge getSubPolChallenge() {
        return subPolChallenge;
    }

    public Response[] getSubPolResponse() {
        return subPolResponse;
    }

    public ProofOfPartialKnowledgeProtocol getPoPKProtocol() {
        return poPKProtocol;
    }

    public Witness[] getPopkWitness() {
        return popkWitness;
    }

    public Response[] getPopkResponse() {
        return popkResponse;
    }

    public Announcement[] getPopkAnnouncement() {
        return popkAnnouncement;
    }

    public ThresholdPolicy getSubpolicy() {
        return subpolicy;
    }

    public ProtocolParameters getProtocolParameters() {
        return protocolParameters;
    }

    public InteractiveThreeWayAoK getProtocol() {
        return protocol;
    }
}
