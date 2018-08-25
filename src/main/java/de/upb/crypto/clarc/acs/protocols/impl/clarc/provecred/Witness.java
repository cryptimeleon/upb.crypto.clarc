package de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred;

import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserSecret;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedMap;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * A {@link de.upb.crypto.clarc.protocols.parameters.Witness} for the fulfillment of a sub policy during execution of a {@link SigmaProtocolWithDisclosure}.
 */
public class Witness implements de.upb.crypto.clarc.protocols.parameters.Witness {

    @Represented
    private PSCredential credential;
    @Represented
    private Zp.ZpElement nymRandom;
    @Represented
    private UserSecret usk;
    @Represented
    private String name;
    @RepresentedMap(keyRestorer = @Represented, valueRestorer = @Represented)
    private Map<Integer, AttributeNameValuePair> disclosedElements;

    private Representation issuerPublicKey;


    Witness(PSCredential credential, Zp.ZpElement nymRandom,
            UserSecret usk, int subPolicyId, SelectiveDisclosure disclosure) {
        this.credential = credential;
        this.nymRandom = nymRandom;
        this.usk = usk;
        this.name = Integer.toString(subPolicyId);
        disclosedElements = new HashMap<>(disclosure.getAttributeIndices().size());
        if (credential != null) {
            for (int index : disclosure.getAttributeIndices()) {
                disclosedElements.put(index, credential.getAttributes()[index]);
            }
        }
        this.issuerPublicKey = disclosure.getIssuerPublicKey();
    }

    public Witness(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
        this.issuerPublicKey = representation.obj().get("issuerPublicKey");
    }

    public PSCredential getCredential() {
        return credential;
    }

    public Zp.ZpElement getNymRandom() {
        return nymRandom;
    }

    public UserSecret getUsk() {
        return usk;
    }

    public Map<Integer, AttributeNameValuePair> getDisclosedElements() {
        return new HashMap<>(disclosedElements);
    }

    public Representation getIssuerPublicKey() {
        return issuerPublicKey;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation representation = AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
        representation.put("issuerPublicKey", issuerPublicKey);
        return representation;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Witness that = (Witness) o;
        return Objects.equals(credential, that.credential) &&
                Objects.equals(nymRandom, that.nymRandom) &&
                Objects.equals(usk, that.usk) &&
                Objects.equals(name, that.name) &&
                Objects.equals(disclosedElements, that.disclosedElements) &&
                Objects.equals(issuerPublicKey, that.issuerPublicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(credential, nymRandom, usk, name, disclosedElements, issuerPublicKey);
    }
}
