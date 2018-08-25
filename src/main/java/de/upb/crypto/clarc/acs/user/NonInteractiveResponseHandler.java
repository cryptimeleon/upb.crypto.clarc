package de.upb.crypto.clarc.acs.user;

import de.upb.crypto.clarc.acs.issuer.Issuable;
import de.upb.crypto.clarc.acs.issuer.IssueResponse;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * Container for keeping the necessary state in order to be able to unwrap the {@link IssueResponse}
 * of an issuer
 * <p>
 * The {@link NonInteractiveResponseHandler#getRequest} method exposes the
 * {@link NonInteractiveIssuableRequest} which needs to be forwarded to the issuer.
 * <p>
 * The {@link NonInteractiveResponseHandler#getReceiver} exposes the {@link IssueanceReceiver} which
 * allows the unwrapping of a {@link IssueResponse} once it is received from the issuer.
 */
public abstract class NonInteractiveResponseHandler<IssuableType extends Issuable,
        IssuedObject extends StandaloneRepresentable> {

    private final NonInteractiveIssuableRequest<IssuableType> request;
    private final IssueanceReceiver<IssuableType, IssuedObject> receiver;

    protected NonInteractiveResponseHandler(
            NonInteractiveIssuableRequest<IssuableType> request,
            IssueanceReceiver<IssuableType, IssuedObject> receiver) {
        this.request = request;
        this.receiver = receiver;
    }

    /**
     * Getter for the {@link NonInteractiveIssuableRequest}
     *
     * @return The {@link NonInteractiveIssuableRequest} object which needs to be forwarded to the issuer
     */
    public final NonInteractiveIssuableRequest<IssuableType> getRequest() {
        return request;
    }

    /**
     * Returns the {@link IssueanceReceiver} which is able to process the {@link IssueResponse} for the given
     * {@link NonInteractiveIssuableRequest}
     *
     * @return The {@link IssueanceReceiver} which is able to process the issuer's {@link IssueResponse}
     */
    public final IssueanceReceiver<IssuableType, IssuedObject> getReceiver() {
        return receiver;
    }
}
