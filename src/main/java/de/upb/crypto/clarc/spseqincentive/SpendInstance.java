package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalCipherText;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalEncryption;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalPlainText;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalPublicKey;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * A prover instance of the Spend <-> Deduct protocol.
 * <p>
 * It is set up with the common input, the prover's private input, and the prover instance of the {@link de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol} and of {@link de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofProtocol} ran during the protocol execution. After setup this instance can be used to generate every message sent from the prover to the verifier.
 * The correct (temporal) order of method invocation is:
 *  1. {@link #generateSchnorrAnnoucements()}
 *  2. {@link #generateRangeAnnoucements()}
 *  3. {@link #generateSchnorrResponses(Challenge)}
 *  4. {@link #generateRangeAnnoucements()}
 *  3. {@link #spend(PSSignature)} (PSSignature)}
 * After {@link #spend(PSSignature)} was run, the prover should have obtained an updated token for a new double-spend id.
 */
public class SpendInstance {
	IncentiveSystemPublicParameters pp;
	PSExtendedVerificationKey pk;
	Zp.ZpElement k;
	Zp.ZpElement dsid;
	GroupElement upk;
	Zp.ZpElement usk;
	IncentiveToken token;

	// 1st move
	Zp.ZpElement dsidUsrStar;
	Zp.ZpElement openStar;
	ElgamalCipherText cUsrStar;

	// 2nd move
	Zp.ZpElement dsidStar;
	Zp.ZpElement gamma;
	ElgamalCipherText cDsidStar;

	Zp.ZpElement dsrndStar;
	GroupElement dsidInGroupStar;
	Zp.ZpElement rC;


	SigmaProtocol schnorrProtocol;
	SigmaProtocol rangeProtocol;
	PedersenCommitmentValue commitment;
	Zp.ZpElement c;
	PedersenCommitmentValue commitmentOnValue;
	PSSignature randToken;
	ElgamalCipherText ctrace;

	public SpendInstance(IncentiveSystemPublicParameters pp, PSExtendedVerificationKey pk, Zp.ZpElement k, Zp.ZpElement dsid, GroupElement upk, Zp.ZpElement usk, IncentiveToken token, Zp.ZpElement dsidUsrStar, Zp.ZpElement openStar, ElgamalCipherText cUsrStar) {
		this.pp = pp;
		this.pk = pk;
		this.k = k;
		this.dsid = dsid;
		this.upk = upk;
		this.usk = usk;
		this.token = token;
		this.dsidUsrStar = dsidUsrStar;
		this.openStar = openStar;
		this.cUsrStar = cUsrStar;
	}

	/**
	 * Initializes the ZKAK protocol after receiving dsid_isr*.
	 * And prepares the second move of the spend algorithm.
	 *
	 * @param dsidIsrStar
	 *          issuer double-spend id for the new token
	 * @param gamma
	 *          value used to enable linking
	 */
	public void initProtocol(Zp.ZpElement dsidIsrStar, Zp.ZpElement gamma) {
		Group g1 = pp.group.getG1();
		Zp zp = new Zp(g1.size());

		this.dsidStar = dsidUsrStar.add(dsidIsrStar);
		this.cDsidStar = new ElgamalCipherText(cUsrStar.getC1(), cUsrStar.getC2().op(pp.g1.pow(dsidIsrStar)));
		this.gamma = gamma;


		// double spend stuff
		this.dsrndStar = zp.getUniformlyRandomElement();
		this.dsidInGroupStar = pp.w.pow(dsidStar);

		// commitment C using randomness rC
		MessageBlock msg = new MessageBlock();
		Stream.of(usk, dsidStar, dsrndStar, token.value.sub(k)).map(RingElementPlainText::new).collect(Collectors.toCollection(() -> msg));
		PedersenPublicParameters pedersenPP = new PedersenPublicParameters(pk.getGroup1ElementG(), pk.getGroup1ElementsYi(), g1);

		PedersenCommitmentScheme pedersen = new PedersenCommitmentScheme(pedersenPP);
		PedersenCommitmentPair commitmentPair = pedersen.commit(msg);
		this.commitment = commitmentPair.getCommitmentValue();
		this.rC = commitmentPair.getOpenValue().getRandomValue();

		// linking value c
		this.c = usk.mul(gamma).add(token.dsrnd);

		// encryption ctrace of dsidInGroup*
		ElgamalPublicKey encKey = new ElgamalPublicKey(g1, pp.w, upk);
		ElgamalEncryption elgamal = new ElgamalEncryption(g1);
		Zp.ZpElement r = zp.getUniformlyRandomElement();
		this.ctrace = (ElgamalCipherText) elgamal.encrypt(new ElgamalPlainText(dsidInGroupStar), encKey, r.getInteger());

		// randomize token signature sigma -> sigma'
		Zp.ZpElement r2Prime = zp.getUniformlyRandomUnit();
		Zp.ZpElement rPrime = zp.getUniformlyRandomElement();
		GroupElement sigma0 = token.token.getGroup1ElementSigma1();
		GroupElement sigma1 = token.token.getGroup1ElementSigma2();
		this.randToken = new PSSignature(
				sigma0.asPowProductExpression().pow(r2Prime).evaluate(),
				sigma1.asPowProductExpression().op(sigma0, rPrime).pow(r2Prime).evaluate()
		);

		// commitment on value v for range proof using randomness rV
		// C = h7^{v} * g1^{rV} for rV in open value
		PedersenPublicParameters pedersenPP2 = new PedersenPublicParameters(
				pp.g1,
				new GroupElement[]{pp.h7},
				g1
		);
		PedersenCommitmentScheme pedersen2 = new PedersenCommitmentScheme(pedersenPP2);
		PedersenCommitmentPair commitmentTokenValue = pedersen2.commit(new RingElementPlainText(token.value));
		this.commitmentOnValue = commitmentTokenValue.getCommitmentValue();
		Zp.ZpElement rV = commitmentTokenValue.getOpenValue().getRandomValue();
		PedersenCommitmentValue commitmentVSubK = new PedersenCommitmentValue(commitmentOnValue.getCommitmentElement().op(pedersenPP2.getH()[0].pow(k.neg())));

		// protocol
		this.schnorrProtocol = ZKAKProvider.getSpendDeductSchnorrProverProtocol(pp, c, gamma, pk, randToken, k, ctrace, commitment, commitmentTokenValue, usk, dsid, token.dsrnd, dsidStar, dsrndStar, r, rC, rPrime, token.value, openStar, cDsidStar);

		this.rangeProtocol = ZKAKProvider.getSpendDeductRangeProverProtocol(pp, commitmentVSubK, rV, (Zp.ZpElement) token.value.sub(k));
	}

	public Announcement[] generateSchnorrAnnoucements() {
		return schnorrProtocol.generateAnnouncements();
	}

	public Response[] generateSchnorrResponses(Challenge ch) {
		return schnorrProtocol.generateResponses(ch);
	}

	public Announcement[] generateRangeAnnoucements() {
		return rangeProtocol.generateAnnouncements();
	}

	public Response[] generateRangeResponses(Challenge ch) {
		return rangeProtocol.generateResponses(ch);
	}

	/**
	 * Prepares the final output of Spend. If the signature computed with is valid, it outputs a token with v-k points.
	 *
	 * @param blindedSig
	 *          blinded updated token issued by the provider running Deduct
	 * @return
	 *      updated token with value v-k, Dsid*
	 */
	public TokenDoubleSpendIdPair spend(PSSignature blindedSig) {
		PSExtendedSignatureScheme psScheme = new PSExtendedSignatureScheme(new PSPublicParameters(pp.group.getBilinearMap()));
		// unblind
		PSSignature unblindedSig = psScheme.unblindSignature(blindedSig, rC);
		// verify
		MessageBlock messages = new MessageBlock();
		Stream.of(
				usk,
				dsidStar, dsrndStar,
				token.value.sub(k)
		).map(RingElementPlainText::new).collect(Collectors.toCollection(() -> messages));

		if (!psScheme.verify(messages, unblindedSig, pk)) {
			throw new IllegalStateException("Not a valid signature!");
		}
		// output token
		return new TokenDoubleSpendIdPair(new IncentiveToken(dsidStar, dsrndStar, (Zp.ZpElement) token.value.sub(k), unblindedSig), dsidInGroupStar);
	}
}
