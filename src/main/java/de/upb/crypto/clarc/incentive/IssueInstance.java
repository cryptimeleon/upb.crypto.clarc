package de.upb.crypto.clarc.incentive;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.sig.ps.*;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

public class IssueInstance {
	IncentiveSystemPublicParameters pp;
	PSExtendedVerificationKey pk;
	PSSigningKey sk;
	IncentiveUserPublicKey userPublicKey;

	PedersenCommitmentValue c;
	SigmaProtocol protocol;
	Announcement[] announcements;
	Challenge ch;


	public IssueInstance(IncentiveSystemPublicParameters pp, PSExtendedVerificationKey pk, PSSigningKey sk, IncentiveUserPublicKey userPublicKey, PedersenCommitmentValue c, SigmaProtocol protocol, Announcement[] announcements) {
		this.pp = pp;
		this.pk = pk;
		this.sk = sk;
		this.userPublicKey = userPublicKey;
		this.c = c;
		this.protocol = protocol;
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
