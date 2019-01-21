package de.upb.crypto.clarc.incentive;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalCipherText;
import de.upb.crypto.craco.sig.ps.*;
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
	PSExtendedVerificationKey pk;
	PSSigningKey sk;
	IncentiveUserPublicKey userPublicKey;

	Zp.ZpElement dsidIsr;
	ElgamalCipherText cDsid;

	PedersenCommitmentValue c;
	SigmaProtocol protocol;
	Announcement[] announcements;
	Challenge ch;

	public IssueInstance(IncentiveSystemPublicParameters pp, PSExtendedVerificationKey pk, PSSigningKey sk, IncentiveUserPublicKey userPublicKey, Zp.ZpElement dsidIsr, ElgamalCipherText cDsid) {
		this.pp = pp;
		this.pk = pk;
		this.sk = sk;
		this.userPublicKey = userPublicKey;
		this.dsidIsr = dsidIsr;
		this.cDsid = cDsid;
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
	public void initProtocol(PedersenCommitmentValue c, Announcement[] announcements) {
		this.c = c;
		this.protocol = ZKAKProvider.getIssueReceiveVerifierProtocol(pp, new Zp(pp.group.getG1().size()), userPublicKey, pk, c, cDsid);
		this.announcements = announcements;
	}

	public Challenge chooseChallenge() {
		this.ch = protocol.chooseChallenge();
		return this.ch;
	}

	public PSSignature issue(Response[] responses) {
		if (this.ch == null) {
			throw new IllegalStateException("Please run the ZKAK to completion first.");
		}
		if(!protocol.verify(announcements, ch, responses)) {
			throw new IllegalStateException("Proof does not accept! Issue aborted...");
		}

		// generate blinded signature
		GroupElement g = pk.getGroup1ElementG();
		Zp zp = new Zp(pp.group.getG1().size());
		Zp.ZpElement rPrime = zp.getUniformlyRandomUnit();

		return new PSSignature(
				// g^r'
				g.asPowProductExpression().pow(rPrime).evaluate(),
				// (c * g^x)^r'
				c.getCommitmentElement().asPowProductExpression().op(g,sk.getExponentX()).pow(rPrime).evaluate()
		);
	}



}
