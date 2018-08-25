package de.upb.crypto.clarc.acs.protocols.impl.clarc;

import de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.ReviewToken;
import de.upb.crypto.clarc.acs.protocols.ProtocolFactory;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserSecret;
import de.upb.crypto.clarc.protocols.expressions.arith.*;
import de.upb.crypto.clarc.protocols.expressions.comparison.ArithComparisonExpression;
import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.protocolfactory.GeneralizedSchnorrProtocolFactory;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.HashIntoZp;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static de.upb.crypto.clarc.acs.protocols.impl.clarc.ComputeRatingPublicKeyAndItemHashHelper.getHashedRatingPublicKeyAndItem;

public class RateProtocolFactory implements ProtocolFactory {

    private PublicParameters pp;
    private PSSignature blindedRegistrationInformation;
    private PSExtendedVerificationKey openPublicKey;
    private GroupElement linkabilityBasis;
    private ReviewToken blindedToken;
    private GroupElement L1;
    private GroupElement L2;
    private UserSecret usk;
    private Zp.ZpElement zeta;
    private Zp.ZpElement r;


    public RateProtocolFactory(PublicParameters pp,
                               PSSignature blindedRegistrationInformation,
                               PSExtendedVerificationKey openPublicKey,
                               GroupElement linkabilityBasis,
                               ReviewToken blindedToken,
                               GroupElement L1,
                               GroupElement L2,
                               UserSecret usk,
                               Zp.ZpElement zeta,
                               Zp.ZpElement r) {
        this.pp = pp;
        this.blindedRegistrationInformation = blindedRegistrationInformation;
        this.openPublicKey = openPublicKey;
        this.linkabilityBasis = linkabilityBasis;
        this.blindedToken = blindedToken;
        this.L1 = L1;
        this.L2 = L2;
        this.usk = usk;
        this.zeta = zeta;
        this.r = r;
    }

    @Override
    public GeneralizedSchnorrProtocol getProtocol() {
        BilinearMap map = pp.getBilinearMap();
        Zp zp = pp.getZp();

        GroupElement hash = getHashedRatingPublicKeyAndItem(blindedToken, pp);
        ArithGroupElementExpression hashExpr = new NumberGroupElementLiteral(hash);

        ArithZnElementExpression userSecret = new ZnVariable("usk");
        ArithZnElementExpression zetaExpr = new ZnVariable("zeta");
        ArithZnElementExpression rExpr = new ZnVariable("r");

        // first equation
        GroupElement leftSide1 = map.apply(blindedRegistrationInformation.getGroup1ElementSigma1(),
                openPublicKey.getGroup2ElementsTildeYi()[0]);
        GroupElement rightSideTop1 = map.apply(blindedRegistrationInformation.getGroup1ElementSigma2(),
                openPublicKey.getGroup2ElementTildeG());
        GroupElement rightSideBottom1 = map.apply(blindedRegistrationInformation.getGroup1ElementSigma1(),
                openPublicKey.getGroup2ElementTildeX());
        GroupElement rightSide1 = rightSideTop1.op(rightSideBottom1.inv());

        ArithGroupElementExpression rightSide1Expr = new NumberGroupElementLiteral(rightSide1);
        ArithGroupElementExpression leftSide1WithoutUsk = new NumberGroupElementLiteral(leftSide1);
        ArithGroupElementExpression leftSide1Expr = new PowerGroupElementExpression(leftSide1WithoutUsk, userSecret);
        List<ArithGroupElementExpression> leftSide1List = new ArrayList<>();
        leftSide1List.add(leftSide1Expr);
        ArithGroupElementExpression leftSide1Final = new ProductGroupElementExpression(leftSide1List);
        ArithComparisonExpression equality1 = new GroupElementEqualityExpression(rightSide1Expr, leftSide1Final);

        // second equation
        ArithGroupElementExpression leftSide2Expr = new NumberGroupElementLiteral(L1);
        ArithGroupElementExpression rightSide2First = new PowerGroupElementExpression(hashExpr, zetaExpr);
        ArithGroupElementExpression rightSide2Second = new PowerGroupElementExpression(hashExpr, userSecret);
        List<ArithGroupElementExpression> rightSide2 = new ArrayList<>();
        rightSide2.add(rightSide2First);
        rightSide2.add(rightSide2Second);
        ArithGroupElementExpression rightSide2Expr = new ProductGroupElementExpression(rightSide2);
        ArithComparisonExpression equality2 = new GroupElementEqualityExpression(leftSide2Expr, rightSide2Expr);

        // third equation
        ArithGroupElementExpression leftSide3Expr = new NumberGroupElementLiteral(L2);
        ArithGroupElementExpression bExpr = new NumberGroupElementLiteral(linkabilityBasis);
        ArithGroupElementExpression rightSide3Expr = new PowerGroupElementExpression(bExpr, zetaExpr);
        List<ArithGroupElementExpression> rightSide3List = new ArrayList<>();
        rightSide3List.add(rightSide3Expr);
        ArithGroupElementExpression rightSide3Final = new ProductGroupElementExpression(rightSide3List);
        ArithComparisonExpression equality3 = new GroupElementEqualityExpression(leftSide3Expr, rightSide3Final);

        // fourth equation
        HashIntoZp hashIntoZp = new HashIntoZp(zp);
        GroupElement leftSide4First = map.apply(blindedToken.getSignature().getGroup1ElementSigma1(),
                blindedToken.getRatingIssuerPublicKey().getGroup2ElementTildeG());
        ArithGroupElementExpression leftSide4FirstWithoutR = new NumberGroupElementLiteral(leftSide4First);
        ArithGroupElementExpression leftSide4FirstExpr = new PowerGroupElementExpression(leftSide4FirstWithoutR, rExpr);
        GroupElement leftSide4Second = map.apply(blindedToken.getSignature().getGroup1ElementSigma1(),
                blindedToken.getRatingIssuerPublicKey().getGroup2ElementsTildeYi()[0]);
        ArithGroupElementExpression leftSide4SecondWithoutUsk = new NumberGroupElementLiteral(leftSide4Second);
        ArithGroupElementExpression leftSide4SecondExpr =
                new PowerGroupElementExpression(leftSide4SecondWithoutUsk, userSecret);
        List<ArithGroupElementExpression> leftSide4 = new ArrayList<>();
        leftSide4.add(leftSide4FirstExpr);
        leftSide4.add(leftSide4SecondExpr);
        ArithGroupElementExpression leftSide4Expr = new ProductGroupElementExpression(leftSide4);

        GroupElement rightSide4Top = map.apply(blindedToken.getSignature().getGroup1ElementSigma2(),
                blindedToken.getRatingIssuerPublicKey().getGroup2ElementTildeG());
        GroupElement rightSide4BottomFirstPart = map.apply(blindedToken.getSignature().getGroup1ElementSigma1(),
                blindedToken.getRatingIssuerPublicKey().getGroup2ElementTildeX());
        GroupElement rightSide4BottomSecondPart = map.apply(blindedToken.getSignature().getGroup1ElementSigma1(),
                blindedToken.getRatingIssuerPublicKey()
                        .getGroup2ElementsTildeYi()[1]).pow(hashIntoZp.hashIntoStructure
                (blindedToken.getItem().getData().getUniqueByteRepresentation()));
        GroupElement rightSide4Bottom = rightSide4BottomFirstPart.op(rightSide4BottomSecondPart);
        GroupElement rightSide4 = rightSide4Top.op(rightSide4Bottom.inv());
        ArithGroupElementExpression rightSide4Expr = new NumberGroupElementLiteral(rightSide4);
        ArithComparisonExpression equality4 = new GroupElementEqualityExpression(rightSide4Expr, leftSide4Expr);

        ArithComparisonExpression[] listOfProblems = {equality1, equality2, equality3, equality4};
        GeneralizedSchnorrProtocolFactory generalizedSchnorrProtocolFactory = new GeneralizedSchnorrProtocolFactory
                (listOfProblems, pp.getZp());

        HashMap<String, Zp.ZpElement> witnessMapping = new HashMap<>();
        witnessMapping.put("usk", usk.getUsk());
        witnessMapping.put("zeta", zeta);
        witnessMapping.put("r", r);

        return generalizedSchnorrProtocolFactory.createProverGeneralizedSchnorrProtocol(witnessMapping);
    }
}
