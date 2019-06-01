package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofPublicParameters;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalCipherText;
import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.craco.sig.ps.PSSigningKey;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSignature;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSignatureScheme;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSigningKey;
import de.upb.crypto.craco.sig.sps.eq.SPSEQVerificationKey;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

/**
 * A verifier instance of the Spend <-> Deduct protocol.
 */
public class DeductInstance {
	IncentiveSystemPublicParameters pp;
	IncentiveProviderPublicKey pk;
	IncentiveProviderSecretKey sk;
	Zp.ZpElement k;

	SPSEQSignature oldSig;
	GroupElement commitmentC;
	Zp.ZpElement eskisr;
	GroupElement cPre0, cPre1;
	StuffThatsSentOverBeforeSpend stuff;

	SigmaProtocol schnorrProtocol;
	Announcement[] schnorrAnnouncements;
	Challenge schnorrChallenge;

	public DeductInstance(IncentiveSystemPublicParameters pp, IncentiveProviderPublicKey pk, IncentiveProviderSecretKey sk, Zp.ZpElement eskisr, StuffThatsSentOverBeforeSpend stuff, SPSEQSignature oldSig) {
		this.pp = pp;
		this.pk = pk;
		this.sk = sk;
		this.oldSig = oldSig;
		this.eskisr = eskisr;
		this.stuff = stuff;
		cPre0 = stuff.Cpre0powU;
		cPre1 = stuff.Cpre1PowU;
		this.commitmentC = stuff.commitmentC0;
	}

	public void initProtocol(Announcement[] schnorrAnnouncements) {
		this.schnorrAnnouncements = schnorrAnnouncements;

		// set up protocol
		this.schnorrProtocol = ZKAKProvider.getSpendDeductSchnorrVerifierProtocol(pp, pk, stuff.dsid, stuff.ctraceRandomness, stuff.ctraceCiphertexts, stuff.k, stuff.gamma, stuff.rho, stuff.blindedSigmaViStar, stuff.hViStar, stuff.blindedSigmaEskiStar, stuff.hEskiStar, stuff.commitmentC0, stuff.c0, stuff.c1, stuff.Cpre0blinded /*Cpre0 * h6^Cpre0blinderVar*/, stuff.Cpre0powU, stuff.Cpre1PowU, stuff.eskIsr);
	}

	public Challenge chooseChallenge() {
		if(schnorrProtocol == null) {
			throw new IllegalStateException("Please initialize the protocol first!");
		}
		this.schnorrChallenge = schnorrProtocol.chooseChallenge();
		return schnorrChallenge;
	}

	public DeductOutput deduct(Response[] schnorrResponses) {
		if(schnorrProtocol == null) {
			throw new IllegalStateException("Please initialize the protocol first!");
		}
		if (this.schnorrChallenge == null) {
			throw new IllegalStateException("Please run the ZKAK to completion first.");
		}
		if(!schnorrProtocol.verify(schnorrAnnouncements, schnorrChallenge, schnorrResponses)) {
			throw new IllegalStateException("Schnorr Proof does not accept! Issue aborted...");
		}

		//Check SPSEQ
		SPSEQSignatureScheme spseqSignatureScheme = new SPSEQSignatureScheme(pk.spseqPublicParameters);
		PlainText pt = new MessageBlock(new GroupElementPlainText(commitmentC), new GroupElementPlainText(pp.g1));
		spseqSignatureScheme.verify(pt, oldSig, pk.spseqVerificationKey);

		//Sign next commitment
		PlainText newPt = new MessageBlock(new GroupElementPlainText(cPre0.op(cPre1.pow(sk.q[1].mul(eskisr)))), new GroupElementPlainText(cPre1));
		SPSEQSignature sig = (SPSEQSignature) spseqSignatureScheme.sign(newPt, sk.spseqSigningKey);

		//DoubleSpendTag dstag = new DoubleSpendTag(c, gamma, ctrace); //TODO
		return new DeductOutput(sig, true, null);
	}

}
