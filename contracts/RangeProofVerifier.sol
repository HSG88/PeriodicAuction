pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;
import "./alt_bn128.sol";
import {EfficientInnerProductVerifier} from "./EfficientInnerProductVerifier.sol";
import {PublicParameters} from "./PublicParameters.sol";

contract RangeProofVerifier {
    bool public val;
    using alt_bn128 for uint256;
    using alt_bn128 for alt_bn128.G1Point;

    uint256 public constant m = 16;
    uint256 public constant n = 4;

    PublicParameters public publicParameters;
    EfficientInnerProductVerifier public ipVerifier;

    constructor (address _publicParameters, address _ipVerifier) public {
        publicParameters = PublicParameters(_publicParameters);
        ipVerifier = EfficientInnerProductVerifier(_ipVerifier);
    }

    /*function verify(
        uint256[10] memory coords, // [input_x, input_y, A_x, A_y, S_x, S_y, commits[0]_x, commits[0]_y, commits[1]_x, commits[1]_y]
        uint256[5] memory scalars, // [tauX, mu, t, a, b]
        uint256[2*n] memory ls_coords, // 2 * n
        uint256[2*n] memory rs_coords  // 2 * n
    ) public
    returns (bool) {
        RangeProof memory rangeProof;
        alt_bn128.G1Point memory input = alt_bn128.G1Point(coords[0], coords[1]);
        rangeProof.A = alt_bn128.G1Point(coords[2], coords[3]);
        rangeProof.S = alt_bn128.G1Point(coords[4], coords[5]);
        rangeProof.commits = [alt_bn128.G1Point(coords[6], coords[7]), alt_bn128.G1Point(coords[8], coords[9])];
        rangeProof.tauX = scalars[0];
        rangeProof.mu = scalars[1];
        rangeProof.t = scalars[2];
        InnerProductProof memory ipProof;
        rangeProof.ipProof = ipProof;
        ipProof.ls = ls_coords;
        ipProof.rs = rs_coords;
        ipProof.a = scalars[3];
        ipProof.b = scalars[4];
        val = verifyInternal(input, rangeProof);
        return val;
    }*/
    function Verify(
        uint[2] memory commitment,
        uint[29] memory proof
        )
       public
    returns (bool) {
        RangeProof memory rangeProof;
        alt_bn128.G1Point memory input = alt_bn128.G1Point(commitment[0], commitment[1]);
        rangeProof.A = alt_bn128.G1Point(proof[0], proof[1]);
        rangeProof.S = alt_bn128.G1Point(proof[2], proof[3]);
        rangeProof.commits = [alt_bn128.G1Point(proof[4], proof[5]), alt_bn128.G1Point(proof[6], proof[7])];
        rangeProof.tauX = proof[8];
        rangeProof.mu = proof[9];
        rangeProof.t = proof[10];
        InnerProductProof memory ipProof;
        rangeProof.ipProof = ipProof;
        ipProof.ls = [proof[13],proof[14],proof[15],proof[16],proof[17],proof[18],proof[19],proof[20]];
        ipProof.rs = [proof[21],proof[22],proof[23],proof[24],proof[25],proof[26],proof[27],proof[28]];
        ipProof.a = proof[11];
        ipProof.b = proof[12];
        val = verifyInternal(input, rangeProof);
        return val;
    }

    struct RangeProof {
        alt_bn128.G1Point A;
        alt_bn128.G1Point S;
        alt_bn128.G1Point[2] commits;
        uint256 tauX;
        uint256 mu;
        uint256 t;
        InnerProductProof ipProof;
    }

    struct InnerProductProof {
        uint256[2*n] ls;
        uint256[2*n] rs;
        uint256 a;
        uint256 b;
    }
    struct Board {
        uint256 y;
        uint256[m] ys;
        uint256 z;
        uint256 zSquared;
        uint256 zCubed;
        uint256[m] twoTimesZSquared;
        uint256 x;
        alt_bn128.G1Point lhs;
        uint256 k;
        alt_bn128.G1Point rhs;
        uint256 uChallenge;
        alt_bn128.G1Point u;
        alt_bn128.G1Point P;
    }

    function verifyInternal(alt_bn128.G1Point memory input, RangeProof memory proof) internal view returns (bool) {
        alt_bn128.G1Point memory G = publicParameters.G();
        alt_bn128.G1Point memory H = publicParameters.H();
        alt_bn128.G1Point[m] memory gs = publicParameters.gs();
        alt_bn128.G1Point[m] memory hs = publicParameters.hs();
        Board memory b;
        b.y = uint256(keccak256(abi.encodePacked(input.X, input.Y, proof.A.X, proof.A.Y, proof.S.X, proof.S.Y))).mod();
        b.ys = powers(b.y);
        b.z = uint256(keccak256(abi.encodePacked(b.y))).mod();
        b.zSquared = b.z.mul(b.z);
        b.zCubed = b.zSquared.mul(b.z);
        b.twoTimesZSquared = times(powers(2), b.zSquared);
        b.x = uint256(keccak256(abi.encodePacked(proof.commits[0].X, proof.commits[0].Y, proof.commits[1].X, proof.commits[1].Y))).mod();
        b.lhs = G.mul(proof.t).add(H.mul(proof.tauX));
        b.k = sumScalars(b.ys).mul(b.z.sub(b.zSquared)).sub(b.zCubed.mul(2 ** m).sub(b.zCubed));
        b.rhs = proof.commits[0].mul(b.x).add(proof.commits[1].mul(b.x.mul(b.x)));
        b.rhs = b.rhs.add(input.mul(b.zSquared));
        b.rhs = b.rhs.add(G.mul(b.k));
        if (!b.rhs.eq(b.lhs)) {
            return false;
        }
        b.uChallenge = uint256(keccak256(abi.encodePacked(proof.tauX, proof.mu, proof.t))).mod();
        b.u = G.mul(b.uChallenge);
        alt_bn128.G1Point[m] memory hPrimes = haddamard(hs, powers(b.y.inv())); // the most expensive, roughly 64*40000 gas
        uint256[m] memory hExp = addVectors(times(b.ys, b.z), b.twoTimesZSquared);
        b.P = proof.A.add(proof.S.mul(b.x));
        b.P = b.P.add(sumPoints(gs).mul(b.z.neg()));
        b.P = b.P.add(commit(hPrimes, hExp)); // the most expensive, 64*40000
        b.P = b.P.add(H.mul(proof.mu).neg());
        b.P = b.P.add(b.u.mul(proof.t));
        return ipVerifier.verifyWithCustomParams(b.P, proof.ipProof.ls, proof.ipProof.rs, proof.ipProof.a, proof.ipProof.b, gs, hPrimes, b.u);
    }

    function addVectors(uint256[m] memory a, uint256[m] memory b) internal pure returns (uint256[m] memory result) {
        for (uint256 i = 0; i < m; i++) {
            result[i] = a[i].add(b[i]);
        }
    }

    function haddamard(alt_bn128.G1Point[m] memory ps, uint256[m] memory ss) internal view returns (alt_bn128.G1Point[m] memory result) {
        for (uint256 i = 0; i < m; i++) {
            result[i] = ps[i].mul(ss[i]);
        }
    }

    function sumScalars(uint256[m] memory ys) internal pure returns (uint256 result) {
        for (uint256 i = 0; i < m; i++) {
            result = result.add(ys[i]);
        }
    }

    function sumPoints(alt_bn128.G1Point[m] memory ps) internal view returns (alt_bn128.G1Point memory sum) {
        sum = ps[0];
        for (uint256 i = 1; i < m; i++) {
            sum = sum.add(ps[i]);
        }
    }

    function commit(alt_bn128.G1Point[m] memory ps, uint256[m] memory ss) internal view returns (alt_bn128.G1Point memory _commit) {
        _commit = ps[0].mul(ss[0]);
        for (uint256 i = 1; i < m; i++) {
            _commit = _commit.add(ps[i].mul(ss[i]));
        }
    }

    function powers(uint256 base) internal pure returns (uint256[m] memory _powers) {
        _powers[0] = 1;
        _powers[1] = base;
        for (uint256 i = 2; i < m; i++) {
            _powers[i] = _powers[i-1].mul(base);
        }
    }

    function powers(uint256 base, uint256 firstPower, uint256 numberOfPowers) internal pure returns (uint256[] memory) {
        uint256[] memory pwrs = new uint256[](numberOfPowers);
        pwrs[0] = 1;
        uint256 i = 0;
        if (firstPower != 0) {
            for (i = 0; i < firstPower; i++) {
                pwrs[0] = pwrs[0].mul(base);
            }
        }
        for (i = 1; i < numberOfPowers; i++) {
            pwrs[i] = pwrs[i-1].mul(base);
        }
        return pwrs;
    }

    function times(uint256[m] memory v, uint256 x) internal pure returns (uint256[m] memory result) {
        for (uint256 i = 0; i < m; i++) {
            result[i] = v[i].mul(x);
        }
    }
}
