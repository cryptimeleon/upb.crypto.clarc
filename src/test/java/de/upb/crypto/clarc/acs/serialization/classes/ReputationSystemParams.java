package de.upb.crypto.clarc.acs.serialization.classes;

import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.acs.issuer.credentials.Attributes;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssueResponse;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.*;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.HashOfItem;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.Item;
import de.upb.crypto.clarc.acs.review.impl.clarc.RepresentableReview;
import de.upb.crypto.clarc.acs.review.impl.clarc.Review;
import de.upb.crypto.clarc.acs.testdataprovider.IssuerTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.ParameterTestdataProvider;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.acs.verifier.credentials.RepresentableSignature;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.FiatShamirSignatureScheme;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.ProtocolProvider;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirSignature;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirSigningKey;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GenSchnorrTestdataProvider;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocolProvider;
import de.upb.crypto.clarc.utils.StandaloneTestParams;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.interfaces.signature.SignatureKeyPair;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.craco.sig.ps.PSSigningKey;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;

public class ReputationSystemParams {
    public static Collection<StandaloneTestParams> get() {
        ParameterTestdataProvider clarcProvider = new ParameterTestdataProvider();
        final SignatureKeyPair<? extends PSExtendedVerificationKey, ? extends PSSigningKey> signatureKeyPair =
                clarcProvider.getSignatureScheme().generateKeyPair(1);

        byte[] bytes = "only-for-test-purposes".getBytes();
        ByteArrayImplementation byteArray = new ByteArrayImplementation(bytes);
        Item item = new Item(byteArray);
        GroupElement testElement = clarcProvider.getPublicParameters().getBilinearMap().getG1().getNeutralElement();
        PSSignature signature = new PSSignature(testElement, testElement);

        GenSchnorrTestdataProvider provider = new GenSchnorrTestdataProvider();
        Group[] groups = provider.generateGenSchnorrGroups();
        Zp zp = provider.generateGenSchnorrZPGroup(groups[0]);
        GeneralizedSchnorrProtocol protocolForProver = provider.getGenSchorrProtocol(2, 3, groups);
        ProtocolProvider instanteProvider =
                new GeneralizedSchnorrProtocolProvider(zp);
        FiatShamirSignatureScheme signatureScheme =
                new FiatShamirSignatureScheme(instanteProvider, new SHA256HashFunction());
        FiatShamirSigningKey signingKey = new FiatShamirSigningKey(protocolForProver.getProblems(), protocolForProver.getWitnesses());
        RingElementPlainText[] messages = new RingElementPlainText[5];
        for (int i = 0; i < messages.length; i++) {
            messages[i] = new RingElementPlainText(zp.getUniformlyRandomElement());
        }
        MessageBlock msg = new MessageBlock(messages);
        FiatShamirSignature fssignature = signatureScheme.sign(msg, signingKey);

        return new ArrayList<StandaloneTestParams>() {{
            add(new StandaloneTestParams(
                    ReviewTokenIssuer.class,
                    new ReviewTokenIssuer(clarcProvider.getPP())
            ));
            add(new StandaloneTestParams(
                    RepresentableReviewToken.class,
                    new RepresentableReviewToken(new ReviewToken(signature,
                            item, signatureKeyPair.getVerificationKey()))
            ));
            add(new StandaloneTestParams(
                    ReviewTokenIssuerPublicIdentity.class,
                    new ReviewTokenIssuerPublicIdentity(signatureKeyPair.getVerificationKey())
            ));
            add(new StandaloneTestParams(
                    RepresentableReview.class,
                    new RepresentableReview(new Review(byteArray, item,
                            signatureKeyPair.getVerificationKey(), testElement, signatureKeyPair.getVerificationKey(),
                            signature, signature, fssignature, testElement, testElement))
            ));
            add(new StandaloneTestParams(
                    HashOfItem.class,
                    new HashOfItem(zp.getUniformlyRandomElement(), item)
            ));
            add(new StandaloneTestParams(
                    Attributes.class,
                    new Attributes(new AttributeNameValuePair[]{
                            IssuerTestdataProvider.AGE.createAttribute(BigInteger.valueOf(18)),
                            IssuerTestdataProvider.GENDER.createAttribute("m"),
                    })
            ));
            add(new StandaloneTestParams(
                    CredentialIssueResponse.class,
                    new CredentialIssueResponse(new PSCredential(signature.getRepresentation(),
                            new AttributeNameValuePair[]{
                                    IssuerTestdataProvider.AGE.createAttribute(BigInteger.valueOf(18)),
                                    IssuerTestdataProvider.GENDER.createAttribute("m"),
                            }, signatureKeyPair.getVerificationKey().getRepresentation()))
            ));
            add(new StandaloneTestParams(
                    ReviewTokenIssueResponse.class,
                    new ReviewTokenIssueResponse(new RepresentableReviewToken(new ReviewToken(signature,
                            item, signatureKeyPair.getVerificationKey())))
            ));
            add(new StandaloneTestParams(
                    Item.class,
                    new Item(byteArray)
            ));
            add(new StandaloneTestParams(
                    RepresentableSignature.class,
                    new RepresentableSignature(signature)
            ));
        }};
    }
}
