package de.upb.crypto.clarc.acs.user.impl.clarc.credentials;

import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.acs.issuer.IssueResponse;
import de.upb.crypto.clarc.acs.issuer.credentials.Attributes;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssuerPublicIdentity;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserSecret;
import de.upb.crypto.craco.commitment.pedersen.PedersenOpenValue;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.interfaces.signature.VerificationKey;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSSignature;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.stream.Collectors;

public class ReceiveCredentialHelper {
    public static PSCredential unblindCredential(PublicParameters pp,
                                                 IssueResponse<PSCredential> issueResponse,
                                                 PedersenOpenValue openValue,
                                                 Attributes issuable,
                                                 UserSecret usk,
                                                 CredentialIssuerPublicIdentity issuerPublicIdentity) {
        PSCredential credential = issueResponse.getIssuedObject();
        final PSExtendedSignatureScheme signatureScheme = PublicParametersFactory.getSignatureScheme(pp);
        PSSignature psSignature = signatureScheme.getSignature(credential.getSignatureRepresentation());

        final PSSignature unblindedSignature =
                signatureScheme.unblindSignature(psSignature, openValue.getRandomValue());
        PSCredential unblindedCredential = new PSCredential(
                unblindedSignature.getRepresentation(),
                credential.getAttributes(),
                issuerPublicIdentity.getIssuerPublicKey()
        );

        AttributeNameValuePair[] attributes = issuable.getAttributes(issuerPublicIdentity.getAttributeSpace());

        VerificationKey issuerPK = signatureScheme.getVerificationKey(issuerPublicIdentity.getIssuerPublicKey());

        final ArrayList<RingElementPlainText> plainText = new ArrayList<>();
        plainText.add(new RingElementPlainText(usk.getUsk()));
        Arrays.stream(attributes)
                .map(attr -> attr.getZpRepresentation(pp.getHashIntoZp()))
                .map(RingElementPlainText::new)
                .collect(Collectors.toCollection(() -> plainText));
        if (!signatureScheme.verify(new MessageBlock(plainText), unblindedSignature, issuerPK)) {
            throw new IllegalStateException("received non-matching signature on credential");
        }
        return unblindedCredential;
    }
}
