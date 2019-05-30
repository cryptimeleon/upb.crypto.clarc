package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

public abstract class CPreComProofInstance {
    // internal state
    Zp.ZpElement eskusr;
    Zp.ZpElement dsrnd0;
    Zp.ZpElement dsrnd1;
    Zp.ZpElement z;
    Zp.ZpElement t;
    Zp.ZpElement u;
    Zp.ZpElement eskisr;
    MessageBlock cPre;
    GroupElement bCom;
    Zp.ZpElement open;
    // common input
    IncentiveSystemPublicParameters pp;
    IncentiveProviderPublicKey pk;
    IncentiveUserKeyPair usrKeypair;
    SigmaProtocol protocol;

    public CPreComProofInstance(IncentiveSystemPublicParameters pp, IncentiveProviderPublicKey pk, IncentiveUserKeyPair keyPair, IncentiveUser.CPreComProofValues cPreComProofValues) {
        this.eskusr = cPreComProofValues.eskusr;
        this.dsrnd0 = cPreComProofValues.dsrnd0;
        this.dsrnd1 = cPreComProofValues.dsrnd1;
        this.z = cPreComProofValues.z;
        this.t = cPreComProofValues.t;
        this.u = cPreComProofValues.u;
        this.cPre = cPreComProofValues.cPre;
        this.pp = pp;
        this.pk = pk;
        this.usrKeypair = keyPair;
    }


    public MessageBlock getCommitment() {
        return cPre;
    }

    public SigmaProtocol getProtocol() {
        return protocol;
    }

    /**
     * @return
     *      announcements of {@link #protocol} sent in the second move of Receive.
     */
    public Announcement[] generateAnnoucements() {
        return protocol.generateAnnouncements();
    }

    /**
     *
     * @param ch
     *          challenge received by the issuer
     * @return
     *          responses sent in the third move of Receive
     */
    public Response[] computeResponses(Challenge ch) {
        return protocol.generateResponses(ch);
    }
}
