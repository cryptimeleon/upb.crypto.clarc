package de.upb.crypto.clarc.incentive;

import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofProtocol;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofProtocolFactory;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParameters;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParametersGen;
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
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class IncentiveUser {
	IncentiveSystemPublicParameters pp;
	IncentiveUserKeyPair keyPair;

	public IncentiveUser(IncentiveSystemPublicParameters pp) {
		this.pp = pp;
		IncentiveUserSetup usrSetup = new IncentiveUserSetup();
		this.keyPair = usrSetup.generateUserKeys(this.pp);
	}

	public ReceiveInstance initReceive(PSExtendedVerificationKey pk) {
		Group g1 = pp.group.getG1();
		Zp zp = new Zp(g1.size());

		Zp.ZpElement dldsid = zp.getUniformlyRandomElement();
		Zp.ZpElement dsrnd = zp.getUniformlyRandomElement();

		// remove the last group element for the proof
		// value v = 0 => always 1 for every g
		GroupElement[] groupElements = new GroupElement[] {pk.getGroup1ElementsYi()[0],pk.getGroup1ElementsYi()[1], pk.getGroup1ElementsYi()[2]};
		PedersenPublicParameters pedersenPP = new PedersenPublicParameters(pk.getGroup1ElementG(), groupElements, g1);
		PedersenCommitmentScheme pedersen = new PedersenCommitmentScheme(pedersenPP);
		MessageBlock messages = new MessageBlock();
		Stream.of(keyPair.userSecretKey.usk, dldsid, dsrnd).map(RingElementPlainText::new).collect(Collectors.toCollection(() -> messages));
		PedersenCommitmentPair commitmentPair = pedersen.commit(messages);
		PedersenCommitmentValue c = commitmentPair.getCommitmentValue();
		Zp.ZpElement r = commitmentPair.getOpenValue().getRandomValue();

		SigmaProtocol protocol = ZKAKProvider.getIssueReceiveProverProtocol(pp, zp, keyPair.userPublicKey, pk, c, keyPair.userSecretKey.usk, dldsid, dsrnd, r);

		return new ReceiveInstance(pp, pk, keyPair, dldsid, dsrnd, r, c, protocol);
	}

	public EarnInstance initEarn(PSExtendedVerificationKey pk, Zp.ZpElement k, IncentiveToken token) {
		Zp zp = new Zp(pp.group.getG1().size());

		PSSignature signature = token.token;
		GroupElement sigma0 = signature.getGroup1ElementSigma1();
		GroupElement sigma1 = signature.getGroup1ElementSigma2();
		Zp.ZpElement r = zp.getUniformlyRandomUnit();
		Zp.ZpElement rPrime = zp.getUniformlyRandomElement();
		GroupElement sigma0Prime = sigma0.pow(r);
		GroupElement sigma1Prime = (sigma1.op(sigma0.pow(rPrime))).pow(r);
		PSSignature blindedSig = new PSSignature(sigma0Prime, sigma1Prime);


		return new EarnInstance(pp, pk, k, keyPair.userSecretKey, token, rPrime, blindedSig, ZKAKProvider.getCreditEarnProverProtocol(pp, blindedSig, pk, keyPair.userSecretKey.usk, token.dldsid, token.dsrnd, token.value, rPrime));
	}

	public SpendInstance initSpend(PSExtendedVerificationKey pk, Zp.ZpElement k, GroupElement dsid, Zp.ZpElement gamma, IncentiveToken token) {
		Group g1 = pp.group.getG1();
		Zp zp = new Zp(g1.size());
		Zp.ZpElement usk = keyPair.userSecretKey.usk;

		// double spend stuff
		Zp.ZpElement dldsidStar = zp.getUniformlyRandomElement();
		Zp.ZpElement dsrndStar = zp.getUniformlyRandomElement();
		GroupElement dsidStar = pp.w.pow(dldsidStar);

		// commitment C using randomness rC
		MessageBlock msg = new MessageBlock();
		Stream.of(usk, dldsidStar, dsrndStar, token.value.sub(k)).map(RingElementPlainText::new).collect(Collectors.toCollection(() -> msg));
		PedersenPublicParameters pedersenPP = new PedersenPublicParameters(pk.getGroup1ElementG(), pk.getGroup1ElementsYi(), g1);

		PedersenCommitmentScheme pedersen = new PedersenCommitmentScheme(pedersenPP);
		PedersenCommitmentPair commitmentPair = pedersen.commit(msg);
		PedersenCommitmentValue commitment = commitmentPair.getCommitmentValue();
		Zp.ZpElement rC = commitmentPair.getOpenValue().getRandomValue();

		// linking value c
		Zp.ZpElement c = usk.mul(gamma).add(token.dsrnd);

		// encryption ctrace of dsid*
		ElgamalPublicKey encKey = new ElgamalPublicKey(g1, pp.w, keyPair.userPublicKey.upk);
		ElgamalEncryption elgamal = new ElgamalEncryption(g1);
		Zp.ZpElement r = zp.getUniformlyRandomElement();
		ElgamalCipherText ctrace = (ElgamalCipherText) elgamal.encrypt(new ElgamalPlainText(dsidStar), encKey, r.getInteger());

		// randomize token signature sigma -> sigma'
		Zp.ZpElement r2Prime = zp.getUniformlyRandomUnit();
		Zp.ZpElement rPrime = zp.getUniformlyRandomElement();
		GroupElement sigma0 = token.token.getGroup1ElementSigma1();
		GroupElement sigma1 = token.token.getGroup1ElementSigma2();
		PSSignature randToken = new PSSignature(
									sigma0.asPowProductExpression().pow(r2Prime).evaluate(),
									sigma1.asPowProductExpression().op(sigma0, rPrime).pow(r2Prime).evaluate()
								);

		// commitment on value v for range proof using randomness rV
		// C = g^{y_1 * v} * g^{rV} for rV in open value
		PedersenPublicParameters pedersenPP2 = new PedersenPublicParameters(
				pk.getGroup1ElementG(),
				new GroupElement[]{pk.getGroup1ElementsYi()[0]},
				g1
		);
		PedersenCommitmentScheme pedersen2 = new PedersenCommitmentScheme(pedersenPP2);
		PedersenCommitmentPair commitmentTokenValue = pedersen2.commit(new RingElementPlainText(token.value));
		PedersenCommitmentValue commitmentV = commitmentTokenValue.getCommitmentValue();
		Zp.ZpElement rV = commitmentTokenValue.getOpenValue().getRandomValue();
		PedersenCommitmentValue commitmentVSubK = new PedersenCommitmentValue(commitmentV.getCommitmentElement().op(pedersenPP2.getH()[0].pow(k.neg())));

		// protocol
		SigmaProtocol protocol = ZKAKProvider.getSpendDeductSchnorrProverProtocol(
										this.pp, c, gamma, pk, randToken, k, ctrace, commitment, commitmentTokenValue,
										usk, token.dldsid, token.dsrnd, dldsidStar, dsrndStar, r, rC, rPrime,
										token.value
								);

		ZeroToUPowLRangeProofProtocol rangeProtocol = ZKAKProvider.getSpendDeductRangeProverProtocol(pp, pk, commitmentVSubK, rV, (Zp.ZpElement) token.value.sub(k));

		return new SpendInstance(this.pp, pk, k, dsid, usk, token, gamma, dldsidStar, dsrndStar, dsidStar, commitment, rC, c, ctrace, rPrime, randToken, commitmentTokenValue, protocol, rangeProtocol);
	}
}
