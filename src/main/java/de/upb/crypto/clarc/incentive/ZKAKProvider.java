package de.upb.crypto.clarc.incentive;

import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofProtocol;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofProtocolFactory;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofPublicParameters;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.expressions.arith.*;
import de.upb.crypto.clarc.protocols.expressions.comparison.ArithComparisonExpression;
import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.protocolfactory.GeneralizedSchnorrProtocolFactory;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParameters;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParametersGen;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalCipherText;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.mappings.PairingProductExpression;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.interfaces.structures.PowProductExpression;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class ZKAKProvider {

	/* Defines the factory for the ZKAK ran in the Issue/Receive protocol */
	private static GeneralizedSchnorrProtocolFactory getIssueReceiveProtocolFactory(IncentiveSystemPublicParameters pp, Zp zp, IncentiveUserPublicKey userPublicKey, PSExtendedVerificationKey pk, PedersenCommitmentValue c, ElgamalCipherText cDsid) {

		ZnVariable uskVar = new ZnVariable("usk");
		ZnVariable dsid = new ZnVariable("dsidInGroup");
		ZnVariable dsrndVar = new ZnVariable("dsrnd");
		ZnVariable rVar = new ZnVariable("r");
		ZnVariable openVar = new ZnVariable("open");

		// problem 1: c = {g^{y_1}}^usk {g^{y_2}}^dsid {g^{y_3}}^dsrnd g^r
		ArithGroupElementExpression cExpr = new NumberGroupElementLiteral(c.getCommitmentElement());
		ArithGroupElementExpression gY1Expr = new NumberGroupElementLiteral(pk.getGroup1ElementsYi()[0]);
		ArithGroupElementExpression gY2Expr = new NumberGroupElementLiteral(pk.getGroup1ElementsYi()[1]);
		ArithGroupElementExpression gY3Expr = new NumberGroupElementLiteral(pk.getGroup1ElementsYi()[2]);
		ArithGroupElementExpression gPSExpr = new NumberGroupElementLiteral(pk.getGroup1ElementG());

		ArithGroupElementExpression gY1UskExpr = new PowerGroupElementExpression(gY1Expr, uskVar);
		ArithGroupElementExpression gY2DsidExpr = new PowerGroupElementExpression(gY2Expr, dsid);
		ArithGroupElementExpression gY3DsrndExpr = new PowerGroupElementExpression(gY3Expr, dsrndVar);
		ArithGroupElementExpression gRExpr = new PowerGroupElementExpression(gPSExpr, rVar);

		ArithGroupElementExpression rhsExpr = new ProductGroupElementExpression(gY1UskExpr, gY2DsidExpr, gY3DsrndExpr, gRExpr);
		GroupElementEqualityExpression problem1 = new GroupElementEqualityExpression(cExpr, rhsExpr);

		// problem 2: upk = w^usk
		ArithGroupElementExpression upkExpr = new NumberGroupElementLiteral(userPublicKey.upk);
		NumberGroupElementLiteral wExpr = new NumberGroupElementLiteral(pp.w);
		PowerGroupElementExpression wUskExpr = new PowerGroupElementExpression(wExpr, uskVar);

		GroupElementEqualityExpression problem2 = new GroupElementEqualityExpression(upkExpr, new ProductGroupElementExpression(wUskExpr));

		// problem 3: C_{dsid} = (g^open, g^{dsid} * h^open)
		ArithGroupElementExpression gPPExpr = new NumberGroupElementLiteral(pp.g);
		ArithGroupElementExpression hExpr = new NumberGroupElementLiteral(pp.h);



		// 1st component
		GroupElementEqualityExpression problem3a = getElgamalProblemA(cDsid.getC1(), gPPExpr, openVar);

		// 2nd component
		GroupElementEqualityExpression problem3b = getElgamalProblemB(cDsid.getC2(), gPPExpr, dsid, hExpr, openVar);


		return new GeneralizedSchnorrProtocolFactory(new GroupElementEqualityExpression[]{problem1, problem2, problem3a, problem3b}, zp);
	}

	/* Returns the prover protocol of the ZKAK ran in Issue/Receive */
	static SigmaProtocol getIssueReceiveProverProtocol(IncentiveSystemPublicParameters pp, Zp zp, IncentiveUserPublicKey userPublicKey, PSExtendedVerificationKey pk, PedersenCommitmentValue c, ElgamalCipherText cDsid, Zp.ZpElement usk, Zp.ZpElement dsid, Zp.ZpElement dsrnd, Zp.ZpElement r, Zp.ZpElement open) {

		HashMap<String, Zp.ZpElement> witnessMapping = new HashMap<>();
		witnessMapping.put("usk", usk);
		witnessMapping.put("dsidInGroup", dsid);
		witnessMapping.put("dsrnd", dsrnd);
		witnessMapping.put("r", r);
		witnessMapping.put("open", open);

		return getIssueReceiveProtocolFactory(pp, zp, userPublicKey, pk, c, cDsid).createProverGeneralizedSchnorrProtocol(witnessMapping);
	}

	static SigmaProtocol getIssueReceiveVerifierProtocol(IncentiveSystemPublicParameters pp, Zp zp, IncentiveUserPublicKey userPublicKey, PSExtendedVerificationKey pk, PedersenCommitmentValue c, ElgamalCipherText cDsid) {
		return getIssueReceiveProtocolFactory(pp, zp, userPublicKey, pk, c, cDsid).createVerifierGeneralizedSchnorrProtocol();
	}

	private static GeneralizedSchnorrProtocolFactory getPSVerifyProtocolFactory(IncentiveSystemPublicParameters pp, PSSignature randtoken, PSExtendedVerificationKey pk) {
		GroupElementEqualityExpression problem = getPSVerifyProtocolProblem(pp, randtoken, pk);
		return new GeneralizedSchnorrProtocolFactory(new GroupElementEqualityExpression[]{problem}, new Zp(pp.group.getG1().size()));
	}

	private static GroupElementEqualityExpression getPSVerifyProtocolProblem(IncentiveSystemPublicParameters pp, PSSignature randtoken, PSExtendedVerificationKey pk) {
		ZnVariable uskVar = new ZnVariable("usk");
		ZnVariable dsidVar = new ZnVariable("dsid");
		ZnVariable dsrndVar = new ZnVariable("dsrnd");
		ZnVariable vVar = new ZnVariable("v");
		ZnVariable rPrimeVar = new ZnVariable("rPrime");

		BilinearMap e = pp.group.getBilinearMap();

		GroupElement sigma0 = randtoken.getGroup1ElementSigma1();
		GroupElement sigma1 = randtoken.getGroup1ElementSigma2();

		GroupElement tildeX = pk.getGroup2ElementTildeX();
		GroupElement tildeG = pk.getGroup2ElementTildeG();
		GroupElement lhs = (e.apply(sigma0, tildeX).inv()).op(e.apply(sigma1, tildeG));
		ArithGroupElementExpression lhsExpr = new NumberGroupElementLiteral(lhs);

		ArithGroupElementExpression sigma0Expr = new NumberGroupElementLiteral(sigma0);
		ArithGroupElementExpression tildeGExpr = new NumberGroupElementLiteral(tildeG);
		ArithGroupElementExpression tildeY1Expr = new NumberGroupElementLiteral(pk.getGroup2ElementsTildeYi()[0]);
		ArithGroupElementExpression tildeY2Expr = new NumberGroupElementLiteral(pk.getGroup2ElementsTildeYi()[1]);
		ArithGroupElementExpression tildeY3Expr = new NumberGroupElementLiteral(pk.getGroup2ElementsTildeYi()[2]);
		ArithGroupElementExpression tildeY4Expr = new NumberGroupElementLiteral(pk.getGroup2ElementsTildeYi()[3]);

		List<ArithGroupElementExpression> factorsRHS = Arrays.asList(
				// e( sigma0, g~)^r'
				new PowerGroupElementExpression(new PairingGroupElementExpression(e, sigma0Expr, tildeGExpr), rPrimeVar),
				// e(sigma0, Y1~)^usk
				new PowerGroupElementExpression(new PairingGroupElementExpression(e, sigma0Expr, tildeY1Expr), uskVar),
				// e(sigma0, Y2~)^dsidInGroup
				new PowerGroupElementExpression(new PairingGroupElementExpression(e, sigma0Expr, tildeY2Expr), dsidVar),
				// e(sigma0, Y3~)^dsrnd
				new PowerGroupElementExpression(new PairingGroupElementExpression(e, sigma0Expr, tildeY3Expr), dsrndVar),
				// e(sigma0, Y4~)^v
				new PowerGroupElementExpression(new PairingGroupElementExpression(e, sigma0Expr, tildeY4Expr), vVar)
		);

		return new GroupElementEqualityExpression(lhsExpr, new ProductGroupElementExpression(factorsRHS));
	}

	static GeneralizedSchnorrProtocol getCreditEarnProverProtocol(IncentiveSystemPublicParameters pp, PSSignature randtoken, PSExtendedVerificationKey pk, Zp.ZpElement usk, Zp.ZpElement dsid, Zp.ZpElement dsrnd, Zp.ZpElement v, Zp.ZpElement rPrime) {
		HashMap<String, Zp.ZpElement> witnessMapping = new HashMap<>();
		witnessMapping.put("usk", usk);
		witnessMapping.put("dsid", dsid);
		witnessMapping.put("dsrnd", dsrnd);
		witnessMapping.put("v", v);
		witnessMapping.put("rPrime", rPrime);

		return getPSVerifyProtocolFactory(pp, randtoken, pk).createProverGeneralizedSchnorrProtocol(witnessMapping);
	}

	static GeneralizedSchnorrProtocol getCreditEarnVerifierProtocol(IncentiveSystemPublicParameters pp, PSSignature randtoken, PSExtendedVerificationKey pk) {
		return getPSVerifyProtocolFactory(pp, randtoken, pk).createVerifierGeneralizedSchnorrProtocol();
	}

	private static GeneralizedSchnorrProtocolFactory getSpendDeductSchnoorProtocolFactory(IncentiveSystemPublicParameters pp, Zp.ZpElement dsid, Zp.ZpElement c, PSExtendedVerificationKey pk, PSSignature blindedSig, PedersenCommitmentValue commitmentOfValue, ElgamalCipherText ctrace, Zp.ZpElement k, PedersenCommitmentValue commitment, ElgamalCipherText cDsidStar, Zp.ZpElement gamma) {

		ZnVariable uskVar = new ZnVariable("usk");
		ZnVariable dsrndVar = new ZnVariable("dsrnd");
		ZnVariable vVar = new ZnVariable("v");
		ZnVariable dsidStarVar = new ZnVariable("dsidStar");
		ZnVariable dsrndStarVar = new ZnVariable("dsrndStar");
		ZnVariable rPrimeVar = new ZnVariable("rPrime");
		ZnVariable rVar = new ZnVariable("r");
		ZnVariable rCVar = new ZnVariable("rC");
		ZnVariable openStarVar = new ZnVariable("openStar");
		ZnVariable rVVar = new ZnVariable("rV");

		ArithGroupElementExpression wExpr = new NumberGroupElementLiteral(pp.w);

		// problem 1: c = usk * gamma + dsrnd <=> w^c = (w^{gamma})^usk * w^dsrnd
		NumberGroupElementLiteral lhs1 = new NumberGroupElementLiteral(pp.w.pow(c));

		PowerGroupElementExpression factor1 = new PowerGroupElementExpression(new NumberGroupElementLiteral(pp.w.pow(gamma)), uskVar);
		PowerGroupElementExpression factor2 = new PowerGroupElementExpression(wExpr, dsrndVar);

		ArithComparisonExpression problem1 = new GroupElementEqualityExpression(lhs1, new ProductGroupElementExpression(factor1, factor2));

		// problem 2: Vrfy randomized token
		// Note that the second msg signed by the token (dsid) is publicly known. Thus, we pull it on the LHS of the expression.

		BilinearMap e = pp.group.getBilinearMap();

		GroupElement sigma0 = blindedSig.getGroup1ElementSigma1();
		GroupElement sigma1 = blindedSig.getGroup1ElementSigma2();

		GroupElement tildeX = pk.getGroup2ElementTildeX();
		GroupElement tildeG = pk.getGroup2ElementTildeG();

		// lhs2 = e(sigma1, g~) / [e(sigma0, X~)] (usual lhs of the expression)
		PairingProductExpression lhs2 = e.pairingProductExpression();
		lhs2.op(sigma0, tildeX).inv().op(sigma1, tildeG);
		// lhs2 *= 1 / [e(sigma0, Y2~)^dsid] (added due to the fact that dsid is common input)
		lhs2.op(e.pairingProductExpression().op(sigma0, pk.getGroup2ElementsTildeYi()[1], dsid).inv());
		ArithGroupElementExpression lhsExpr = new NumberGroupElementLiteral(lhs2.evaluate());

		ArithGroupElementExpression sigma0Expr = new NumberGroupElementLiteral(sigma0);
		ArithGroupElementExpression tildeGExpr = new NumberGroupElementLiteral(tildeG);
		ArithGroupElementExpression tildeY1Expr = new NumberGroupElementLiteral(pk.getGroup2ElementsTildeYi()[0]);
		ArithGroupElementExpression tildeY3Expr = new NumberGroupElementLiteral(pk.getGroup2ElementsTildeYi()[2]);
		ArithGroupElementExpression tildeY4Expr = new NumberGroupElementLiteral(pk.getGroup2ElementsTildeYi()[3]);

		List<ArithGroupElementExpression> factorsRHS = Arrays.asList(
				// e( sigma0, g~)^r'
				new PowerGroupElementExpression(new PairingGroupElementExpression(e, sigma0Expr, tildeGExpr), rPrimeVar),
				// e(sigma0, Y1~)^usk
				new PowerGroupElementExpression(new PairingGroupElementExpression(e, sigma0Expr, tildeY1Expr), uskVar),
				// e(sigma0, Y3~)^dsrnd
				new PowerGroupElementExpression(new PairingGroupElementExpression(e, sigma0Expr, tildeY3Expr), dsrndVar),
				// e(sigma0, Y4~)^v
				new PowerGroupElementExpression(new PairingGroupElementExpression(e, sigma0Expr, tildeY4Expr), vVar)
		);

		GroupElementEqualityExpression problem2 = new GroupElementEqualityExpression(lhsExpr, new ProductGroupElementExpression(factorsRHS));

		// problem 4: ctrace = (c1, c2) :: (a) c1 = w^r AND (b) c2 = (c1)^usk * w^{dsid*}
		ArithGroupElementExpression c1Expr = new NumberGroupElementLiteral(ctrace.getC1());
		ArithGroupElementExpression c2Expr = new NumberGroupElementLiteral(ctrace.getC2());

		ArithComparisonExpression problem4a = getElgamalProblemA(ctrace.getC1(), wExpr, rVar);
		ArithComparisonExpression problem4b = getElgamalProblemB(ctrace.getC2(), c1Expr, uskVar, wExpr, dsidStarVar);

		// problem 5: {g^{y_1}}^usk {g^{y_2}}^dsid* {g^{y_3}}^dsrnd* {g_{y_3}}^{v-k}  g^rC
		ArithGroupElementExpression gY1Expr = new NumberGroupElementLiteral(pk.getGroup1ElementsYi()[0]);
		ArithGroupElementExpression gY2Expr = new NumberGroupElementLiteral(pk.getGroup1ElementsYi()[1]);
		ArithGroupElementExpression gY3Expr = new NumberGroupElementLiteral(pk.getGroup1ElementsYi()[2]);
		ArithGroupElementExpression gY4Expr = new NumberGroupElementLiteral(pk.getGroup1ElementsYi()[3]);
		ArithGroupElementExpression gExpr = new NumberGroupElementLiteral(pk.getGroup1ElementG());

		// C * (g^{y4})^k (due to the fact that k is public)
		PowProductExpression lhs5 = commitment.getCommitmentElement()
										.asPowProductExpression()
										.op(pk.getGroup1ElementsYi()[3], k);
		NumberGroupElementLiteral problem5Lhs = new NumberGroupElementLiteral(lhs5.evaluate());

		List<ArithGroupElementExpression> problem5RhsFactors = Arrays.asList(
				new PowerGroupElementExpression(gY1Expr, uskVar),
				new PowerGroupElementExpression(gY2Expr, dsidStarVar),
				new PowerGroupElementExpression(gY3Expr, dsrndStarVar),
				new PowerGroupElementExpression(gY4Expr, vVar),
				new PowerGroupElementExpression(gExpr, rCVar)
		);
		ArithComparisonExpression problem5 = new GroupElementEqualityExpression(problem5Lhs, new ProductGroupElementExpression(problem5RhsFactors));

		// problem 6: C_dsid* = (c1, c2) = (g^(open*), g^dsid* h^(open*)) :: (a) c1 = g^(open*) AND (b) c2 = g^dsid* h^(open*)
		ArithGroupElementExpression gPPExpr = new NumberGroupElementLiteral(pp.g);
		ArithGroupElementExpression hExpr = new NumberGroupElementLiteral(pp.h);

		// 1st component
		GroupElementEqualityExpression problem6a = getElgamalProblemA(cDsidStar.getC1(), gPPExpr, openStarVar);
		// 2nd component
		GroupElementEqualityExpression problem6b = getElgamalProblemB(cDsidStar.getC2(), gPPExpr, dsidStarVar, hExpr, openStarVar);

		// problem 3: commitment on value is valid for v, needed for the range proof.
		// cV = (g^{y1})^v * g^{rV}
		ArithGroupElementExpression cVExpr = new NumberGroupElementLiteral(commitmentOfValue.getCommitmentElement());
		ProductGroupElementExpression rhs = new ProductGroupElementExpression(new PowerGroupElementExpression(gY1Expr, vVar), new PowerGroupElementExpression(gExpr, rVVar));
		GroupElementEqualityExpression problem3 = new GroupElementEqualityExpression(cVExpr, rhs);

		return new GeneralizedSchnorrProtocolFactory(
				new ArithComparisonExpression[]{problem1, problem2, problem3, problem4a, problem4b, problem5, problem6a, problem6b},
				new Zp(pp.group.getG1().size())
		);
	}

	static GeneralizedSchnorrProtocol getSpendDeductSchnorrProverProtocol(IncentiveSystemPublicParameters pp, Zp.ZpElement c, Zp.ZpElement gamma, PSExtendedVerificationKey pk, PSSignature blindedSig, Zp.ZpElement k, ElgamalCipherText ctrace, PedersenCommitmentValue commitment, PedersenCommitmentPair commitmentOfValue, Zp.ZpElement usk, Zp.ZpElement dsid, Zp.ZpElement dsrnd, Zp.ZpElement dsidStar, Zp.ZpElement dsrndStar, Zp.ZpElement r, Zp.ZpElement rC, Zp.ZpElement rPrime, Zp.ZpElement v, Zp.ZpElement openStar, ElgamalCipherText cDsidStar) {

		GeneralizedSchnorrProtocolFactory schnorrFac = getSpendDeductSchnoorProtocolFactory(pp, dsid, c, pk, blindedSig, commitmentOfValue.getCommitmentValue(), ctrace, k, commitment, cDsidStar, gamma);

		HashMap<String, Zp.ZpElement> witnessMapping = new HashMap<>();
		witnessMapping.put("usk", usk);
		witnessMapping.put("dsid", dsid);
		witnessMapping.put("dsrnd", dsrnd);
		witnessMapping.put("v", v);
		witnessMapping.put("dsidStar", dsidStar);
		witnessMapping.put("dsrndStar", dsrndStar);
		witnessMapping.put("rPrime", rPrime);
		witnessMapping.put("r", r);
		witnessMapping.put("rC", rC);
		witnessMapping.put("openStar", openStar);
		witnessMapping.put("rV", commitmentOfValue.getOpenValue().getRandomValue());

		return schnorrFac.createProverGeneralizedSchnorrProtocol(witnessMapping);
	}

	static GeneralizedSchnorrProtocol getSpendDeductSchnorrVerifierProtocol(IncentiveSystemPublicParameters pp, Zp.ZpElement c, Zp.ZpElement gamma, PSExtendedVerificationKey pk, PSSignature blindedSig, Zp.ZpElement k, ElgamalCipherText ctrace, PedersenCommitmentValue commitment, PedersenCommitmentValue commitmentOnV, Zp.ZpElement dsid, ElgamalCipherText cDsidStar) {
		GeneralizedSchnorrProtocolFactory schnorrFac = getSpendDeductSchnoorProtocolFactory(pp, dsid, c, pk, blindedSig, commitmentOnV, ctrace, k, commitment, cDsidStar, gamma);
		return schnorrFac.createVerifierGeneralizedSchnorrProtocol();
	}


	/* Note that prover and verifier need to ne generated from the **same** factory. Therefore, this factory should only be set up by either the prover or the
	 * verifier, and the parameters generated in that way should be sent to the other party. In this application, the user/prover generates the protocol and sends
     * the parameters to the verifier
	 */
	static ZeroToUPowLRangeProofProtocolFactory getSpendDeductRangeProofProtocolFactory(IncentiveSystemPublicParameters pp, PSExtendedVerificationKey pk, PedersenCommitmentValue commitment) {
		PedersenPublicParameters pedersenPP = new PedersenPublicParameters(pk.getGroup1ElementG(), new GroupElement[] { pk.getGroup1ElementsYi()[0] }, pp.group.getG1());
		Zp zp = new Zp(pp.group.getG1().size());

		return new ZeroToUPowLRangeProofProtocolFactory(commitment, pedersenPP, BigInteger.valueOf(16), ((int) Math.log(Integer.MAX_VALUE)) / ((int) Math.log(16)),0, zp, pp.nguyenPP, "Spend/Deduct");
	}

	static ZeroToUPowLRangeProofProtocol getSpendDeductRangeProverProtocol(IncentiveSystemPublicParameters pp, PSExtendedVerificationKey pk, PedersenCommitmentValue commitment, Zp.ZpElement commitmentRandomness, Zp.ZpElement committedValue) {
		ZeroToUPowLRangeProofProtocolFactory rangeFac = getSpendDeductRangeProofProtocolFactory(pp, pk, commitment);

		return rangeFac.getProverProtocol(commitmentRandomness, committedValue);
	}
	static ZeroToUPowLRangeProofProtocol getSpendDeductRangeVerifierProtocol(ZeroToUPowLRangeProofPublicParameters rangePP) {
		ZeroToUPowLRangeProofProtocolFactory rangeFac = new ZeroToUPowLRangeProofProtocolFactory(rangePP, "Spend/Deduct");
		return rangeFac.getVerifierProtocol();
	}

	/** Problem for expression c1 = baseExpr^expVar */
	private static GroupElementEqualityExpression getElgamalProblemA(GroupElement c1, ArithGroupElementExpression baseExpr, ZnVariable expVar) {
		return new GroupElementEqualityExpression(
				new NumberGroupElementLiteral(c1),
				new ProductGroupElementExpression(new PowerGroupElementExpression(baseExpr, expVar))
		);
	}

	/** Problem for expression c2 = gExpr^aVar * hExpr^bVar */
	private static GroupElementEqualityExpression getElgamalProblemB(GroupElement c2, ArithGroupElementExpression gExpr, ZnVariable aVar, ArithGroupElementExpression hExpr, ZnVariable bVar) {
		ProductGroupElementExpression rhs3bExpr = new ProductGroupElementExpression(
				new PowerGroupElementExpression(gExpr, aVar),
				new PowerGroupElementExpression(hExpr, bVar)
		);
		return new GroupElementEqualityExpression(new NumberGroupElementLiteral(c2), rhs3bExpr);
	}

	/* Prover and Verifier protocols using PoPK */

//	static SigmaProtocol getSpendDeductProverProtocol(IncentiveSystemPublicParameters pp, Zp.ZpElement c, Zp.ZpElement gamma, PSExtendedVerificationKey pk, PSSignature blindedSig, Zp.ZpElement k, ElgamalCipherText ctrace, PedersenCommitmentValue commitment, PedersenCommitmentPair commitmentOfValue, Zp.ZpElement usk, Zp.ZpElement dldsid, Zp.ZpElement dsrnd, Zp.ZpElement dldsidStar, Zp.ZpElement dsrndStar, Zp.ZpElement r, Zp.ZpElement rC, Zp.ZpElement rPrime, Zp.ZpElement v, PedersenCommitmentValue rangeCommitment, Zp.ZpElement rangeRandomness) {
//		GeneralizedSchnorrProtocol schnorr = getSpendDeductSchnorrProverProtocol(pp, c, gamma, pk, blindedSig, k, ctrace, commitment, commitmentOfValue, usk, dldsid, dsrnd, dldsidStar, dsrndStar, r, rC, rPrime, v, , );
//		SigmaProtocolPolicyFact schnorrPolicyFact = new SigmaProtocolPolicyFact(schnorr, 1);
//
//		ZeroToUPowLRangeProofProtocol rangeProof = getSpendDeductRangeProverProtocol(pp, pk, rangeCommitment, rangeRandomness, (Zp.ZpElement) v.sub(k));
//		SigmaProtocolPolicyFact rangePolicyFact = new SigmaProtocolPolicyFact(rangeProof, 2);
//
//		ThresholdPolicy policy = new ThresholdPolicy(2, schnorrPolicyFact, rangePolicyFact);
//
//		return new ProofOfPartialKnowledgeProtocol(
//				new ProofOfPartialKnowledgePublicParameters(
//						new ShamirSecretSharingSchemeProvider(),
//						new Zp(pp.group.getG1().size())
//				), policy
//		);
//	}
//
//	static SigmaProtocol getSpendDeductVerifierProtocol(IncentiveSystemPublicParameters pp, Zp.ZpElement c, Zp.ZpElement gamma, PSExtendedVerificationKey pk, PSSignature blindedSig, Zp.ZpElement k, ElgamalCipherText ctrace, PedersenCommitmentValue commitment, PedersenCommitmentValue commitmentOnV, ArbitraryRangeProofPublicParameters rangePP) {
//		GeneralizedSchnorrProtocol schnorr = getSpendDeductSchnorrVerifierProtocol(pp, c, gamma, pk, blindedSig, k, ctrace, commitment, commitmentOnV);
//		SigmaProtocolPolicyFact schnorrPolicyFact = new SigmaProtocolPolicyFact(schnorr, 1);
//
//		ZeroToUPowLRangeProofProtocol rangeProof = getSpendDeductRangeVerifierProtocol(rangePP);
//		SigmaProtocolPolicyFact rangePolicyFact = new SigmaProtocolPolicyFact(rangeProof, 2);
//
//		ThresholdPolicy policy = new ThresholdPolicy(2, schnorrPolicyFact, rangePolicyFact);
//
//		return new ProofOfPartialKnowledgeProtocol(
//				new ProofOfPartialKnowledgePublicParameters(
//						new ShamirSecretSharingSchemeProvider(),
//						new Zp(pp.group.getG1().size())
//				), policy
//		);
//	}
}
