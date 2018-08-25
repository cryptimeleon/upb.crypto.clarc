package de.upb.crypto.clarc.predicategeneration.pssignatureschnorrprotocol;

import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssuer;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Identity;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Pseudonym;
import de.upb.crypto.clarc.acs.pssignatureschnorrprotocol.PSSignatureSchnorrProtocolFactory;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserSecret;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.HashIntoZp;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

class GenSchnorrTestdataProvider {

    private PublicParameters clarcPublicParameters;
    private PSCredential credential;
    private CredentialIssuer issuer;
    private Identity identity;
    private UserSecret userSecret;
    private Zp.ZpElement signatureRandom;

    public GenSchnorrTestdataProvider(PublicParameters clarcPublicParameters, PSCredential credential,
                                      CredentialIssuer issuer,
                                      Identity identity, UserSecret userSecret) {
        this.clarcPublicParameters = clarcPublicParameters;
        this.credential = credential;
        this.issuer = issuer;
        this.identity = identity;
        this.userSecret = userSecret;

        signatureRandom = clarcPublicParameters.getZp().getUniformlyRandomElement();
    }


    public Group[] generateGenSchnorrGroups() {
        Group[] groups = new Group[2];

        BilinearMap bilinearMap = clarcPublicParameters.getBilinearMap();
        groups[0] = bilinearMap.getG1();
        groups[1] = bilinearMap.getG2();
        return groups;
    }


    public Zp generateGenSchnorrZPGroup(Group G1) {
        return new Zp(G1.size());
    }


    private GroupElement[][] getGenerators(int m, int n, Group[] groups) {


        GroupElement[][] generators = new GroupElement[m][n];
        for (int j = 0; j < m; j++) {
            for (int i = 0; i < n; i++) {
                generators[j][i] = groups[j].getUniformlyRandomNonNeutral();
            }
        }
        return generators;
    }

    public GeneralizedSchnorrProtocol getPSSigSchnorrSigma() {
        return createProtcol(false);


    }

    private GeneralizedSchnorrProtocol createProtcol(boolean useElementDisclosure) {


        Zp.ZpElement signatureRandom = clarcPublicParameters.getZp().getUniformlyRandomElement();

        int i = new Zp(BigInteger.valueOf(credential.getAttributes().length)).getUniformlyRandomElement().getInteger
                ().intValue();
        Map<Integer, AttributeNameValuePair> disclosedElements = new HashMap<>();
        if (useElementDisclosure) {
            disclosedElements.put(i, credential.getAttributes()[i]);
        }

        Pseudonym nym = identity.getPseudonym();
        PSPublicParameters psPublicParameter = new PSPublicParameters(clarcPublicParameters.getBilinearMap());
        PSExtendedSignatureScheme psSignatureScheme = new PSExtendedSignatureScheme(psPublicParameter);
        final PSSignature signature = psSignatureScheme.getSignature(credential
                .getSignatureRepresentation());
        final PSSignature randomizedSignature =
                psSignatureScheme.randomizeExistingSignature(signature, signatureRandom);

        PedersenCommitmentScheme pedersenCommitmentScheme =
                PublicParametersFactory.getSingleMessageCommitmentScheme(clarcPublicParameters);

        List<PedersenCommitmentPair> commitmentOnAttributes = getPedersenCommitmentPairs(pedersenCommitmentScheme,
                clarcPublicParameters.getHashIntoZp(), credential);
        List<PedersenCommitmentValue> valuesOfCommitments = commitmentOnAttributes.stream().
                map(PedersenCommitmentPair::getCommitmentValue).collect(Collectors.toList());

        PSSignatureSchnorrProtocolFactory factory = new PSSignatureSchnorrProtocolFactory(nym.getCommitmentValue(),
                randomizedSignature, psSignatureScheme, clarcPublicParameters.getHashIntoZp(),
                disclosedElements, issuer.getPublicIdentity().getAttributeSpace(), valuesOfCommitments,
                clarcPublicParameters.getBilinearMap(), pedersenCommitmentScheme.getPp());

        return factory
                .getProverProtocol(credential, userSecret.getUsk(), identity.getPseudonymSecret().getRandomValue(),
                        signatureRandom, commitmentOnAttributes);
    }

    private List<PedersenCommitmentPair> getPedersenCommitmentPairs(PedersenCommitmentScheme pedersenCommitmentScheme,
                                                                    HashIntoZp hashIntoZp,
                                                                    PSCredential credential) {
        return Arrays.stream(credential.getAttributes())
                .map(attr -> attr.getZpRepresentation(hashIntoZp))
                .map(zp -> pedersenCommitmentScheme.commit(new RingElementPlainText(zp)))
                .collect(Collectors.toList());
    }

    public GeneralizedSchnorrProtocol getPSSigSchnorrSigmaWithDisclosure() {
        return createProtcol(true);

    }
}
