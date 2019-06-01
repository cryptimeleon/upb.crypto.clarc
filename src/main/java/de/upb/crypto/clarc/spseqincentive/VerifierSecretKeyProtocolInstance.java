package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSignature;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSignatureScheme;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

/**
 * Verifier (in this case user) side of the provider protocol to proof its secret key
 * <p>
 * It is set up with the common input, the verifier's private input, the verifier instance of the {@link SigmaProtocol}
 * ran during the protocol execution and the announcement sent by the prover as the first message. After setup this instance
 * can be used to generate every message sent from the verifier to the prover.
 * The correct (temporal) order of method invocation is:
 *  1. {@link #chooseChallenge()}
 *  2. {@link #issue(Response[])}
 */
public class VerifierSecretKeyProtocolInstance {

	IncentiveSystemPublicParameters pp;
	IncentiveUserPublicKey userPublicKey;

	IncentiveProviderPublicKey providerPublicKey;

	PedersenCommitmentValue c;
	SigmaProtocol protocol;
	Announcement[] announcements;
	Challenge ch;

	public VerifierSecretKeyProtocolInstance(IncentiveSystemPublicParameters pp, IncentiveProviderPublicKey providerPublicKey, IncentiveUserPublicKey userPublicKey) {
		this.pp = pp;
		this.providerPublicKey = providerPublicKey;
		this.userPublicKey = userPublicKey;
	}

	/**
	 * Initializes the verfierer protocol of Issue/Receive.
	 *
	 * In particular, this sets up the ZKAK protocol instance, and stores the announcements for the verification in {@link #issue(Response[])}.
	 *
	 *          commitment computed by the receiver that should be signed blindly
	 * @param announcements
	 *          Receiver's announcement
	 */
	public void initProtocol(Announcement[] announcements) {
		this.protocol = ZKAKProvider.getSecretKeyVerifierProtocol(pp, new Zp(pp.group.getG1().size()), providerPublicKey);
		this.announcements = announcements;
	}

	public Challenge chooseChallenge() {
		this.ch = protocol.chooseChallenge();
		return this.ch;
	}

	public boolean endProt(Response[] responses) {
		if (this.ch == null) {
			throw new IllegalStateException("Please run the ZKAK to completion first.");
		}
		if(!protocol.verify(announcements, ch, responses)) {
			throw new IllegalStateException("Proof does not accept! Issue aborted...");
		}


		return true;
	}



}
