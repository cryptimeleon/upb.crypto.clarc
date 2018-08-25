package de.upb.crypto.clarc.acs.user;

import de.upb.crypto.clarc.acs.issuer.Issuable;
import de.upb.crypto.clarc.acs.issuer.IssueResponse;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

public abstract class IssueanceReceiver<IssuableType extends Issuable, IssuedObject extends StandaloneRepresentable> {

    protected final IssuingContext issuanceData;
    protected final IssuableType issuable;

    protected IssueanceReceiver(IssuableType issuable, IssuingContext issuanceData) {
        this.issuable = issuable;
        this.issuanceData = issuanceData;
    }

    /**
     * Process the received object und unwrap it according to some secret known only to the requesting
     * {@link User} as needed.
     *
     * @param response response send by {@link de.upb.crypto.clarc.acs.issuer.Issuer}
     * @return the processed (e.g. unblinded) object issued to the {@link User}
     */
    public abstract IssuedObject receive(IssueResponse<IssuedObject> response);
}
