package de.upb.crypto.clarc.incentive;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalCipherText;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
import de.upb.crypto.craco.sig.ps.PSSignature;
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
	GroupElement dsid;
	Zp.ZpElement usk;
	IncentiveToken token;

	Zp.ZpElement gamma;

	Zp.ZpElement dldsidStar;
	Zp.ZpElement dsrndStar;
	GroupElement dsidStar;
	PedersenCommitmentValue commitment;
	Zp.ZpElement rC;
	Zp.ZpElement c;
	ElgamalCipherText ctrace;

	Zp.ZpElement rPrime;
	PSSignature randToken;
	PedersenCommitmentPair commitmentOnValue;

	SigmaProtocol schnorrProtocol;
	SigmaProtocol rangeProtocol;

	public SpendInstance(IncentiveSystemPublicParameters pp, PSExtendedVerificationKey pk, Zp.ZpElement k, GroupElement dsid, Zp.ZpElement usk, IncentiveToken token, Zp.ZpElement gamma, Zp.ZpElement dldsidStar, Zp.ZpElement dsrndStar, GroupElement dsidStar, PedersenCommitmentValue commitment, Zp.ZpElement rC, Zp.ZpElement c, ElgamalCipherText ctrace, Zp.ZpElement rPrime, PSSignature randToken, PedersenCommitmentPair commitmentOnValue, SigmaProtocol schnorrProtocol, SigmaProtocol rangeProtocol) {
		this.pp = pp;
		this.pk = pk;
		this.k = k;
		this.dsid = dsid;
		this.usk = usk;
		this.token = token;
		this.gamma = gamma;
		this.dldsidStar = dldsidStar;
		this.dsrndStar = dsrndStar;
		this.dsidStar = dsidStar;
		this.commitment = commitment;
		this.rC = rC;
		this.c = c;
		this.ctrace = ctrace;
		this.rPrime = rPrime;
		this.randToken = randToken;
		this.commitmentOnValue = commitmentOnValue;
		this.schnorrProtocol = schnorrProtocol;
		this.rangeProtocol = rangeProtocol;
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

	public TokenDoubleSpendIdPair spend(PSSignature blindedSig) {
		PSExtendedSignatureScheme psScheme = new PSExtendedSignatureScheme(new PSPublicParameters(pp.group.getBilinearMap()));
		// unblind
		PSSignature unblindedSig = psScheme.unblindSignature(blindedSig, rC);
		// verify
		MessageBlock messages = new MessageBlock();
		Stream.of(
				usk,
				dldsidStar, dsrndStar,
				token.value.sub(k)
		).map(RingElementPlainText::new).collect(Collectors.toCollection(() -> messages));

		if (!psScheme.verify(messages, unblindedSig, pk)) {
			throw new IllegalStateException("Not a valid signature!");
		}
		// output token
		return new TokenDoubleSpendIdPair(new IncentiveToken(dldsidStar, dsrndStar, (Zp.ZpElement) token.value.sub(k), unblindedSig), dsidStar);
	}
}
