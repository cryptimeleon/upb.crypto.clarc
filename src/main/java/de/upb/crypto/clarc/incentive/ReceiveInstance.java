package de.upb.crypto.clarc.incentive;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ReceiveInstance {
	// common input
	IncentiveSystemPublicParameters pp;
	PSExtendedVerificationKey pk;
	IncentiveUserKeyPair usrKeypair;

	// state
	Zp.ZpElement dldsid;
	Zp.ZpElement dsrnd;
	Zp.ZpElement r;
	PedersenCommitmentValue c;

	SigmaProtocol protocol;

	public ReceiveInstance(IncentiveSystemPublicParameters pp, PSExtendedVerificationKey pk, IncentiveUserKeyPair usrKeypair, Zp.ZpElement dldsid, Zp.ZpElement dsrnd, Zp.ZpElement r, PedersenCommitmentValue c, SigmaProtocol protocol) {
		this.pp = pp;
		this.pk = pk;
		this.usrKeypair = usrKeypair;
		this.dldsid = dldsid;
		this.dsrnd = dsrnd;
		this.r = r;
		this.c = c;
		this.protocol = protocol;
	}

	public PedersenCommitmentValue getCommitment() {
		return c;
	}

	public SigmaProtocol getProtocol() {
		return protocol;
	}

	public Announcement[] generateAnnoucements() {
		return protocol.generateAnnouncements();
	}

	public Response[] computeResponses(Challenge ch) {
		return protocol.generateResponses(ch);
	}

	public TokenDoubleSpendIdPair receive(PSSignature blindedSig) {
		PSExtendedSignatureScheme psScheme = new PSExtendedSignatureScheme(new PSPublicParameters(pp.group.getBilinearMap()));
		// unblind
		PSSignature unblindedSig = psScheme.unblindSignature(blindedSig, r);
		// verify
		MessageBlock messages = new MessageBlock();
		Zp.ZpElement zeroElement = new Zp(pp.group.getG1().size()).getZeroElement();
		Stream.of(
				usrKeypair.userSecretKey.usk,
				dldsid, dsrnd,
				zeroElement
		).map(RingElementPlainText::new).collect(Collectors.toCollection(() ->	messages));

		if (!psScheme.verify(messages, unblindedSig, pk)) {
			throw new IllegalStateException("Not a valid signature!");
		}
		// output token
		return new TokenDoubleSpendIdPair(new IncentiveToken(dldsid, dsrnd, zeroElement, unblindedSig), pp.w.pow(dldsid));
	}
}
