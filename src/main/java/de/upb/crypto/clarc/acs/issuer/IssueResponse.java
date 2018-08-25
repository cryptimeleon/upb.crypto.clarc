package de.upb.crypto.clarc.acs.issuer;

import de.upb.crypto.clarc.acs.user.NonInteractiveIssuableRequest;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

/**
 * A {@link IssueResponse} is used to answer an {@link InteractiveIssueIssuableProcess} or
 * {@link NonInteractiveIssuableRequest} with the actual issued object.
 * The received objects can then be processed by the {@link de.upb.crypto.clarc.acs.user.User} using
 * {@link de.upb.crypto.clarc.acs.user.IssueanceReceiver#receive}.
 */
public abstract class IssueResponse<IssuedObject extends StandaloneRepresentable> implements StandaloneRepresentable {

    @Represented
    private IssuedObject issuedObject;

    public IssueResponse(IssuedObject issuedObject) {
        this.issuedObject = issuedObject;
    }

    public IssueResponse(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public IssuedObject getIssuedObject() {
        return issuedObject;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IssueResponse that = (IssueResponse) o;
        return Objects.equals(issuedObject, that.issuedObject);
    }

    @Override
    public int hashCode() {
        return Objects.hash(issuedObject);
    }
}
