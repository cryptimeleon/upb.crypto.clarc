package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSignature;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSignatureScheme;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

/**
 * A prover instance of the provider secret key proof protocol
 *
 */
public class ProverSecretKeyProtocolInstance {

	//Zp.ZpElement dsid;
	//PedersenCommitmentValue c;
	IncentiveSystemPublicParameters pp;
	IncentiveProviderKeyPair providerKeyPair;
	SigmaProtocol protocol;


	public ProverSecretKeyProtocolInstance(IncentiveSystemPublicParameters pp, IncentiveProviderKeyPair providerKeyPair) {
		this.pp = pp;
		this.providerKeyPair = providerKeyPair;
	}

	/** Initializes the ZKAK protocol after receiving the eskisr of the issuer.
	 *
	 */
	public void initProtocol() {
		Group groupG1 = pp.group.getG1();
		Zp zp = new Zp(groupG1.size());

		this.protocol = ZKAKProvider.getSecretKeyProverProtocol(pp, zp, this);
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

	/**
	 * Computes the final output of Join.
	 * <p>
	 *
	 * @param spseqSignature
	 *              blinded signature computed by the issuer
	 * @return
	 *      Incentive spseqSignature , ...
	 */
	public TokenDoubleSpendIdPair endProverSecretKeyProtocol(SPSEQSignature spseqSignature) {
		return null;
	}
}
