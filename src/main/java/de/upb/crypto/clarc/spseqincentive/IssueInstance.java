package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.sig.sps.eq.*;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

/**
 * A verifier instance of the Receive <-> Issue protocol.
 * <p>
 * It is set up with the common input, the verifier's private input, the verifier instance of the {@link SigmaProtocol}
 * ran during the protocol execution and the annoucement sent by the prover as the first message. After setup this instance
 * can be used to generate every message sent from the verifier to the prover.
 * The correct (temporal) order of method invocation is:
 *  1. {@link #chooseChallenge()}
 *  2. {@link #issue(Response[])}
 */
public class IssueInstance {

	IncentiveSystemPublicParameters pp;
	IncentiveUserPublicKey userPublicKey;

	IncentiveProviderKeyPair providerKeyPair;

	Zp.ZpElement eskisr;
	MessageBlock cPre;

	PedersenCommitmentValue c;
	SigmaProtocol protocol;
	Announcement[] announcements;
	Challenge ch;

	public IssueInstance(IncentiveSystemPublicParameters pp, IncentiveProviderKeyPair providerKeyPair, IncentiveUserPublicKey userPublicKey, Zp.ZpElement eskisr, MessageBlock cPre) {
		this.pp = pp;
		this.providerKeyPair = providerKeyPair;
		this.userPublicKey = userPublicKey;
		this.eskisr = eskisr;
		this.cPre = cPre;
	}

	/**
	 * Initializes the verfierer protocol of Issue/Receive.
	 *
	 * In particular, this sets up the ZKAK protocol instance, and stores the announcements for the verification in {@link #issue(Response[])}.
	 *
	 * @param c
	 *          commitment computed by the receiver that should be signed blindly
	 * @param announcements
	 *          Receiver's announcement
	 */
	public void initProtocol(MessageBlock cPre, GroupElement bCom, Announcement[] announcements) {
		this.protocol = ZKAKProvider.getIssueJoinVerifierProtocol(pp, new Zp(pp.group.getG1().size()), userPublicKey, providerKeyPair.providerPublicKey, cPre, bCom);
		this.announcements = announcements;
	}

	public Challenge chooseChallenge() {
		this.ch = protocol.chooseChallenge();
		return this.ch;
	}

	public SPSEQSignature issue(Response[] responses) {
		if (this.ch == null) {
			throw new IllegalStateException("Please run the ZKAK to completion first.");
		}
		if(!protocol.verify(announcements, ch, responses)) {
			throw new IllegalStateException("Proof does not accept! Issue aborted...");
		}

		// generate signature
		GroupElement cPre0 = ((GroupElementPlainText) cPre.get(0)).get();
		GroupElement cPre1 = ((GroupElementPlainText) cPre.get(1)).get();
		Zp.ZpElement test = eskisr;

		Zp.ZpElement exp = providerKeyPair.q[1].mul(eskisr);
		GroupElement cPost0 = cPre0.op(cPre1.pow(exp));

		MessageBlock cPost = new MessageBlock();
		cPost.add(new GroupElementPlainText(cPost0));
		cPost.add(new GroupElementPlainText(cPre1));



		SPSEQSignatureScheme spseqSignatureScheme = new SPSEQSignatureScheme(providerKeyPair.providerPublicKey.spseqPublicParameters);
		SPSEQSignature signature = (SPSEQSignature) spseqSignatureScheme.sign(cPost, providerKeyPair.spseqSigningKey);

		return signature;
	}



}
