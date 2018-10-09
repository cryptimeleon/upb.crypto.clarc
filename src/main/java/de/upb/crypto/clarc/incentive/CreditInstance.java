package de.upb.crypto.clarc.incentive;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.craco.sig.ps.PSSigningKey;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

public class CreditInstance {
	IncentiveSystemPublicParameters pp;
	PSExtendedVerificationKey pk;
	PSSigningKey sk;
	Zp.ZpElement k;

	PSSignature randToken;
	SigmaProtocol protocol;
	Announcement[] announcements;
	Challenge ch;

	public CreditInstance(IncentiveSystemPublicParameters pp, PSExtendedVerificationKey pk, PSSigningKey sk, Zp.ZpElement k, PSSignature randToken, SigmaProtocol protocol, Announcement[] announcements) {
		this.pp = pp;
		this.pk = pk;
		this.sk = sk;
		this.k = k;
		this.randToken = randToken;
		this.protocol = protocol;
		this.announcements = announcements;
	}

	public Challenge chooseChallenge() {
		this.ch = protocol.chooseChallenge();
		return this.ch;
	}

	public PSSignature credit(Response[] responses) {
		if (this.ch == null) {
			throw new IllegalStateException("Please run the ZKAK to completion first.");
		}
		if(!protocol.verify(announcements, ch, responses)) {
			throw new IllegalStateException("Proof does not accept! Issue aborted...");
		}

		Zp zp = new Zp(pp.group.getG1().size());
		Zp.ZpElement rPrimePrime = zp.getUniformlyRandomUnit();

		GroupElement sigma0 = randToken.getGroup1ElementSigma1();
		GroupElement sigma1 = randToken.getGroup1ElementSigma2();

		return new PSSignature(
				sigma0.asPowProductExpression().pow(rPrimePrime).evaluate(),
				// (sigma1 * sigma0^{y4 * k})^r''
				sigma1.asPowProductExpression().op( sigma0, sk.getExponentsYi()[3].mul(k)).pow(rPrimePrime).evaluate()
		);
	}
}
