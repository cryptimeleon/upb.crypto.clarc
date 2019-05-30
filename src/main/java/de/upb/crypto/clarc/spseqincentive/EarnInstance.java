package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.craco.sig.sps.eq.SPSEQPublicParameters;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSignature;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSignatureScheme;
import de.upb.crypto.craco.sig.sps.eq.SPSEQVerificationKey;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;
import org.apache.logging.log4j.message.Message;

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
 * After {@link #earn(PSSignature)} was run, the prover should have obtained an updated spseqSignature for the same double-spend ID
 * credited with the negotiated amount of 'points'.
 */
public class EarnInstance {

	IncentiveSystemPublicParameters pp;
	IncentiveProviderPublicKey pk;
	Zp.ZpElement k;
	IncentiveUserSecretKey userSecretKey;
	IncentiveToken token;
	MessageBlock cPrime;

	Zp.ZpElement s;

	SPSEQSignature spseqSignature;

	SigmaProtocol protocol;

	public EarnInstance(IncentiveSystemPublicParameters pp, IncentiveProviderPublicKey pk, Zp.ZpElement k, IncentiveUserSecretKey userSecretKey, IncentiveToken token, Zp.ZpElement s, SPSEQSignature spseqSignature, MessageBlock cPrime, SigmaProtocol protocol) {
		this.pp = pp;
		this.pk = pk;
		this.k = k;
		this.userSecretKey = userSecretKey;
		this.token = token;
		this.s = s;
		this.spseqSignature = spseqSignature;
		this.cPrime = cPrime;
		this.protocol = protocol;
	}

	public Announcement[] generateAnnoucements() {
		return protocol.generateAnnouncements();
	}

	public Response[] generateResponses(Challenge challenge) {
		return protocol.generateResponses(challenge);
	}

	/**
	 * Computes the final output of earn. This includes unblinding the updated spseqSignature and verifying its validity.
	 *
	 * @param spseqSignature
	 *          blinded, updated incentive spseqSignature
	 * @return
	 *          unblinded updated spseqSignature
	 *
	 */
	public IncentiveToken earn(SPSEQSignature spseqSignature) {
		SPSEQSignatureScheme spseqSignatureScheme = new SPSEQSignatureScheme(pk.spseqPublicParameters);


		Zp.ZpElement updatedValue = token.value.add(k);

		MessageBlock cPre = token.M;

		// compute cPost with k added
		GroupElement cPre0 = ((GroupElementPlainText) cPre.get(0)).get();
		cPre0 = cPre0.pow(s);
		GroupElement cPre1 = ((GroupElementPlainText) cPre.get(1)).get();
		cPre1 = cPre1.pow(s);
		GroupElement cPost0 = cPre0.op(pk.h1to6[4].pow(s.mul(k)));



		MessageBlock cPost = new MessageBlock();
		cPost.add(new GroupElementPlainText(cPost0));
		cPost.add(new GroupElementPlainText(cPre1));



		// unblinding of signature and message
		SPSEQSignature spseqSignatureFinal = (SPSEQSignature) spseqSignatureScheme.chgRepWithVerify(cPost,spseqSignature,s.inv(),pk.spseqVerificationKey);

		MessageBlock cPostFinal = (MessageBlock) spseqSignatureScheme.chgRepMessage(cPost,s.inv());

		return new IncentiveToken(cPostFinal, token.esk, token.dsrnd0, token.dsrnd1, token.z, token.t, updatedValue, spseqSignatureFinal);
	}
}
