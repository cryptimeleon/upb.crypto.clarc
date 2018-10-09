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

	SigmaProtocol protocol;

	public SpendInstance(IncentiveSystemPublicParameters pp, PSExtendedVerificationKey pk, Zp.ZpElement k, GroupElement dsid, Zp.ZpElement usk, IncentiveToken token, Zp.ZpElement gamma, Zp.ZpElement dldsidStar, Zp.ZpElement dsrndStar, GroupElement dsidStar, PedersenCommitmentValue commitment, Zp.ZpElement rC, Zp.ZpElement c, ElgamalCipherText ctrace, Zp.ZpElement rPrime, PSSignature randToken, PedersenCommitmentPair commitmentOnValue, SigmaProtocol protocol) {
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
		this.protocol = protocol;
	}

	public Announcement[] generateAnnoucements() {
		return protocol.generateAnnouncements();
	}

	public Response[] generateResponses(Challenge ch) {
		return protocol.generateResponses(ch);
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
