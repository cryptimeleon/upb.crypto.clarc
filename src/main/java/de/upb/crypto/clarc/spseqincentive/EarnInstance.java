package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * A prover instance of the Earn <-> Credit protocol.
 * <p>
 * It is set up with the common input, the prover's private input and the prover instance of the {@link SigmaProtocol}
 * ran during the protocol execution. After setup this instance can be used to generate every message sent from the prover
 * to the verifier. The correct (temporal) order of method invocation is:
 *  1. {@link #generateAnnoucements()}
 *  2. {@link #generateAnnoucements()}
 *  3. {@link #earn(PSSignature)}
 * After {@link #earn(PSSignature)} was run, the prover should have obtained an updated token for the same double-spend ID
 * credited with the negotiated amount of 'points'.
 */
public class EarnInstance {

	IncentiveSystemPublicParameters pp;
	PSExtendedVerificationKey pk;
	Zp.ZpElement k;
	IncentiveUserSecretKey userSecretKey;
	IncentiveToken token;

	Zp.ZpElement rPrime;

	PSSignature randToken;

	SigmaProtocol protocol;

	public EarnInstance(IncentiveSystemPublicParameters pp, PSExtendedVerificationKey pk, Zp.ZpElement k, IncentiveUserSecretKey userSecretKey, IncentiveToken token,  Zp.ZpElement rPrime, PSSignature randToken, SigmaProtocol protocol) {
		this.pp = pp;
		this.pk = pk;
		this.k = k;
		this.userSecretKey = userSecretKey;
		this.token = token;
		this.rPrime = rPrime;
		this.randToken = randToken;
		this.protocol = protocol;
	}

	public Announcement[] generateAnnoucements() {
		return protocol.generateAnnouncements();
	}

	public Response[] generateResponses(Challenge challenge) {
		return protocol.generateResponses(challenge);
	}

	/**
	 * Computes the final output of earn. This includes unblinding the updated token and verifying its validity.
	 *
	 * @param blindedSig
	 *          blinded, updated incentive token
	 * @return
	 *          unblinded updated token
	 *
	 */
	public IncentiveToken earn(PSSignature blindedSig) {
		PSExtendedSignatureScheme signatureScheme = new PSExtendedSignatureScheme(new PSPublicParameters(pp.group.getBilinearMap()));

		PSSignature unblindedSig = signatureScheme.unblindSignature(blindedSig, rPrime);

		MessageBlock msg = new MessageBlock();
		Stream.of(userSecretKey.usk, token.dsid, token.dsrnd, token.value.add(k))
				.map(RingElementPlainText::new)
				.collect(Collectors.toCollection(() -> msg));

		if (!signatureScheme.verify(msg, unblindedSig, pk)) {
			throw new IllegalStateException("Not a valid signature!");
		}

		return new IncentiveToken(token.dsid, token.dsrnd, token.value.add(k), unblindedSig);
	}
}
