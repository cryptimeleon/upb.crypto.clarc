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
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * A prover instance of the Receive <-> Issue protocol.
 * <p>
 * It is set up with the common input, the prover's private input and the prover instance of the {@link SigmaProtocol}
 * ran during the protocol execution. After setup this instance can be used to generate every message sent from the prover
 * to the verifier. The correct (temporal) order of method invocation is:
 *  1. {@link #initProtocol(Zp.ZpElement)}
 *  2. {@link #generateAnnoucements()}
 *  3. {@link #computeResponses(Challenge)}
 *  4. {@link #join(PSSignature)}
 * After {@link #join(PSSignature)} was run, the prover should have obtained an token and a double-spend ID.
 */
public class JoinInstance {
	// internal state
	Zp.ZpElement eskusr;
	Zp.ZpElement dsrnd0;
	Zp.ZpElement dsrnd1;
	Zp.ZpElement z;
	Zp.ZpElement t;
	Zp.ZpElement u;
	MessageBlock cPre;
	// common input
	IncentiveSystemPublicParameters pp;
	IncentiveProviderPublicKey pk;
	IncentiveUserKeyPair usrKeypair;

	Zp.ZpElement dsid;
	PedersenCommitmentValue c;

	SigmaProtocol protocol;

	public JoinInstance(IncentiveSystemPublicParameters pp, IncentiveProviderPublicKey pk, IncentiveUserKeyPair keyPair, Zp.ZpElement eskusr, Zp.ZpElement dsrnd0, Zp.ZpElement dsrnd1, Zp.ZpElement z, Zp.ZpElement t, Zp.ZpElement u, MessageBlock cPre) {
		this.pp = pp;
		this.pk = pk;
		this.usrKeypair = keyPair;
		this.eskusr = eskusr;
		this.dsrnd0 = dsrnd0;
		this.dsrnd1 = dsrnd1;
		this.z = z;
		this.t = t;
		this.u = u;
		this.cPre = cPre;
	}

	/** Initializes the ZKAK protocol after receiving the eskIsr of the issuer.
	 *
	 * @param eskIsr
	 *          issuer's (random) esk share
	 */
	public void initProtocol(Zp.ZpElement eskIsr) {
		Group g1 = pp.group.getG1();
		Zp zp = new Zp(g1.size());

		this.dsid = this.dsisUsr.add(dsidIsr);
		this.cDsid = new ElgamalCipherText(cUsr.getC1(), cUsr.getC2().op(pp.g1.pow(dsidIsr)));

		this.dsrnd = zp.getUniformlyRandomElement();

		// remove the last group element for the proof
		// value v = 0 => always 1 for every g1
		GroupElement[] groupElements = new GroupElement[] {pk.getGroup1ElementsYi()[0],pk.getGroup1ElementsYi()[1], pk.getGroup1ElementsYi()[2]};
		PedersenPublicParameters pedersenPP = new PedersenPublicParameters(pk.getGroup1ElementG(), groupElements, g1);
		PedersenCommitmentScheme pedersen = new PedersenCommitmentScheme(pedersenPP);
		MessageBlock messages = new MessageBlock();
		Stream.of(usrKeypair.userSecretKey.usk, dsid, dsrnd).map(RingElementPlainText::new).collect(Collectors.toCollection(() -> messages));
		PedersenCommitmentPair commitmentPair = pedersen.commit(messages);
		this.c = commitmentPair.getCommitmentValue();
		this.t = commitmentPair.getOpenValue().getRandomValue();

		this.protocol = ZKAKProvider.getIssueReceiveProverProtocol(pp, zp, usrKeypair.userPublicKey, pk, c, cDsid, usrKeypair.userSecretKey.usk, dsid, dsrnd, r, open);
	}

	public PedersenCommitmentValue getCommitment() {
		return c;
	}

	public SigmaProtocol getProtocol() {
		return protocol;
	}

	/**
	 * @return
	 *      announcements of {@link #protocol} sent in the second move of Receive.
	 */
	public Announcement[] generateAnnoucements() {
		return protocol.generateAnnouncements();
	}

	/**
	 *
	 * @param ch
	 *          challenge received by the issuer
	 * @return
	 *          responses sent in the third move of Receive
	 */
	public Response[] computeResponses(Challenge ch) {
		return protocol.generateResponses(ch);
	}

	/**
	 * Computes the final output of Join.
	 * <p>
	 *
	 * @param blindedSig
	 *              blinded signature computed by the issuer
	 * @return
	 *      Incentive token , ...
	 */
	public TokenDoubleSpendIdPair join(PSSignature blindedSig) {
		PSExtendedSignatureScheme psScheme = new PSExtendedSignatureScheme(new PSPublicParameters(pp.group.getBilinearMap()));
		// unblind
		PSSignature unblindedSig = psScheme.unblindSignature(blindedSig, r);
		// verify
		MessageBlock messages = new MessageBlock();
		Zp.ZpElement zeroElement = new Zp(pp.group.getG1().size()).getZeroElement();
		Stream.of(
				usrKeypair.userSecretKey.usk,
				dsid, dsrnd,
				zeroElement
		).map(RingElementPlainText::new).collect(Collectors.toCollection(() ->	messages));

		if (!psScheme.verify(messages, unblindedSig, pk)) {
			throw new IllegalStateException("Not a valid signature!");
		}
		// output token
		return new TokenDoubleSpendIdPair(new IncentiveToken(dsid, dsrnd, zeroElement, unblindedSig), pp.w.pow(dsid));
	}
}
