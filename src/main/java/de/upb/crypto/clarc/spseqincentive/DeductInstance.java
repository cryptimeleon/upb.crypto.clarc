package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofPublicParameters;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalCipherText;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.craco.sig.ps.PSSigningKey;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

/**
 * A verifier instance of the Spend <-> Deduct protocol.
 * <p>
 * It is set up with the common input and the verifier's private input. After setup this instance can be used to generate every message sent from the verifier to the prover.
 * The correct (temporal) order of method invocation is:
 *  1. {@link #initProtocol(PedersenCommitmentValue, PedersenCommitmentValue, Zp.ZpElement, ElgamalCipherText, PSSignature, Announcement[], ZeroToUPowLRangeProofPublicParameters, Announcement[])}
 *  2. {@link #chooseChallenge()}
 *  3. {@link #deduct(Response[], Response[])}
 */
public class DeductInstance {
	IncentiveSystemPublicParameters pp;
	PSExtendedVerificationKey pk;
	PSSigningKey sk;
	Zp.ZpElement k;

	Zp.ZpElement dsid;
	Zp.ZpElement dsidIsrStar;
	ElgamalCipherText cDsidStar;
	Zp.ZpElement gamma;

	PedersenCommitmentValue commitment;
	PedersenCommitmentValue commitmentOnV;
	Zp.ZpElement c;
	ElgamalCipherText ctrace;
	PSSignature randToken;

	SigmaProtocol schnorrProtocol;
	Announcement[] schnorrAnnouncements;
	Challenge schnorrChallenge;
	SigmaProtocol rangeProtocol;
	Announcement[] rangeAnnouncements;
	Challenge rangeChallenge;

	public DeductInstance(IncentiveSystemPublicParameters pp, PSExtendedVerificationKey pk, PSSigningKey sk, Zp.ZpElement k, Zp.ZpElement dsid, Zp.ZpElement dsidIsrStar, Zp.ZpElement gamma, ElgamalCipherText cDsidStar) {
		this.pp = pp;
		this.pk = pk;
		this.sk = sk;
		this.k = k;
		this.dsid = dsid;
		this.dsidIsrStar = dsidIsrStar;
		this.gamma = gamma;
		this.cDsidStar = cDsidStar;
	}

	/**
	 * This method is required as the verifier needs to set up the same protocol instance as the prover. Therefore, the prover needs to send over the {@link ZeroToUPowLRangeProofPublicParameters} of the protocol set up in the {@link SpendPhase1Instance}.
	 * @param commitment
	 *              commitment on usk, dldsidStar, dsrndStar, and v-k
	 * @param commitmentOnV
	 *              commitment on v
	 * @param c
	 *              linking value usk * gamma + dsrnd
	 * @param ctrace
	 *              elgamal encryption of dsidInGroupStar
	 * @param randToken
	 *              randomized version of the spseqSignature the points are spent from
	 * @param schnorrAnnouncements
	 *              announcement of the Schnoor protocol
	 * @param rangePP
	 *              pp of the ZeroToURangeProof
	 * @param rangeAnnouncements
	 *              annoucement of the ZeroToURangeProof
	 */
	public void initProtocol(PedersenCommitmentValue commitment, PedersenCommitmentValue commitmentOnV, Zp.ZpElement c, ElgamalCipherText ctrace, PSSignature randToken, Announcement[] schnorrAnnouncements, ZeroToUPowLRangeProofPublicParameters rangePP, Announcement[] rangeAnnouncements) {
		this.commitment = commitment;
		this.commitmentOnV = commitmentOnV;
		this.c = c;
		this.ctrace = ctrace;
		this.randToken = randToken;
		this.schnorrAnnouncements = schnorrAnnouncements;
		this.rangeAnnouncements = rangeAnnouncements;

		// set up protocol
		this.schnorrProtocol = ZKAKProvider.getSpendDeductSchnorrVerifierProtocol(pp, c, gamma, pk, randToken, k, ctrace, commitment, commitmentOnV, dsid, cDsidStar);
	}

	public Challenge chooseChallenge() {
		if(schnorrProtocol == null || rangeProtocol == null) {
			throw new IllegalStateException("Please initialize the protocol first!");
		}
		this.schnorrChallenge = schnorrProtocol.chooseChallenge();
	}

	public DeductOutput deduct(Response[] schnorrResponses) {
		if(schnorrProtocol == null || rangeProtocol == null) {
			throw new IllegalStateException("Please initialize the protocol first!");
		}
		if (this.schnorrChallenge == null || this.rangeChallenge == null) {
			throw new IllegalStateException("Please run the ZKAK to completion first.");
		}
		if(!schnorrProtocol.verify(schnorrAnnouncements, schnorrChallenge, schnorrResponses)) {
			throw new IllegalStateException("Schnorr Proof does not accept! Issue aborted...");
		}
		if(!rangeProtocol.verify(rangeAnnouncements, rangeChallenge, rangeResponses)) {
			throw new IllegalStateException("Range Proof does not accept! Issue aborted...");
		}

		Zp zp = new Zp(pp.group.getG1().size());
		Zp.ZpElement r4Prime = zp.getUniformlyRandomUnit();

		GroupElement g = pk.getGroup1ElementG();
		PSSignature blindedSig = new PSSignature(
				// g1^r''''
				g.asPowProductExpression().pow(r4Prime).evaluate(),
				// (C * g1^x)^r''''
				commitment.getCommitmentElement().asPowProductExpression().op(g,sk.getExponentX()).pow(r4Prime).evaluate()
		);

		DoubleSpendTag dstag = new DoubleSpendTag(c, gamma, ctrace);
		return new DeductOutput(blindedSig, true, dstag);
	}

}
