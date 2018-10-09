package de.upb.crypto.clarc.incentive;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalCipherText;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.craco.sig.ps.PSSigningKey;
import de.upb.crypto.math.interfaces.mappings.PairingProductExpression;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.interfaces.structures.PowProductExpression;
import de.upb.crypto.math.structures.zn.Zp;

public class DeductInstance {
	IncentiveSystemPublicParameters pp;
	PSExtendedVerificationKey pk;
	PSSigningKey sk;
	Zp.ZpElement k;
	GroupElement dsid;

	Zp.ZpElement gamma;

	PedersenCommitmentValue commitment;
	PedersenCommitmentValue commitmentOnV;
	Zp.ZpElement c;
	ElgamalCipherText ctrace;
	PSSignature randToken;

	SigmaProtocol protocol;
	Announcement[] announcements;
	Challenge ch;

	public DeductInstance(IncentiveSystemPublicParameters pp, PSExtendedVerificationKey pk, PSSigningKey sk, Zp.ZpElement k, GroupElement dsid, Zp.ZpElement gamma) {
		this.pp = pp;
		this.pk = pk;
		this.sk = sk;
		this.k = k;
		this.dsid = dsid;
		this.gamma = gamma;
	}

	public void initProtocol(PedersenCommitmentValue commitment, PedersenCommitmentValue commitmentOnV, Zp.ZpElement c, ElgamalCipherText ctrace, PSSignature randToken, Announcement[] announcements) {
		this.commitment = commitment;
		this.commitmentOnV = commitmentOnV;
		this.c = c;
		this.ctrace = ctrace;
		this.randToken = randToken;
		this.announcements = announcements;

		// set up protocol
		this.protocol = ZKAKProvider.getSpendDeductVerifierProtocol(pp, c, gamma, pk, randToken, k, ctrace, commitment, commitmentOnV);
	}

	public Challenge chooseChallenge() {
		if(protocol == null) {
			throw new IllegalStateException("Please initialize the protocol first!");
		}
		this.ch = protocol.chooseChallenge();
		return this.ch;
	}

	public DeductOutput deduct(Response[] responses) {
		if(protocol == null) {
			throw new IllegalStateException("Please initialize the protocol first!");
		}
		if (this.ch == null) {
			throw new IllegalStateException("Please run the ZKAK to completion first.");
		}
		if(!protocol.verify(announcements, ch, responses)) {
			throw new IllegalStateException("Proof does not accept! Issue aborted...");
		}

		Zp zp = new Zp(pp.group.getG1().size());
		Zp.ZpElement r4Prime = zp.getUniformlyRandomUnit();

		GroupElement g = pk.getGroup1ElementG();
		PSSignature blindedSig = new PSSignature(
				// g^r''''
				g.asPowProductExpression().pow(r4Prime).evaluate(),
				// (C * g^x)^r''''
				commitment.getCommitmentElement().asPowProductExpression().op(g,sk.getExponentX()).pow(r4Prime).evaluate()
		);

		DoubleSpendTag dstag = new DoubleSpendTag(c, gamma, ctrace);
		return new DeductOutput(blindedSig, true, dstag);
	}

}
