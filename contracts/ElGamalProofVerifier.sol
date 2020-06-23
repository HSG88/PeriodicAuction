pragma solidity ^0.5.0;
import './alt_bn128.sol';

contract ElGamalProofVerifier {
    using alt_bn128 for uint256;
    using alt_bn128 for alt_bn128.G1Point;

    alt_bn128.G1Point public y;
    alt_bn128.G1Point public g2;
    alt_bn128.G1Point public g;
    alt_bn128.G1Point public h;
    constructor(uint[2] memory _g, uint[2] memory _h, uint[2] memory _g2,uint[2] memory _y) public {
        y = alt_bn128.G1Point(_y[0],_y[1]);
        g = alt_bn128.G1Point(_g[0],_g[1]);
        g2 = alt_bn128.G1Point(_g2[0],_g2[1]);
        h = alt_bn128.G1Point(_h[0],_h[1]);
    }
    function Verify(uint[2] memory _C, uint[2] memory _c1, uint[2] memory _c2, uint[8] memory proof) public returns(bool) {
        bool flag = true;
        uint e = uint(keccak256(abi.encodePacked(_C,_c1, _c2,proof[0],proof[1],proof[2],proof[3],proof[4],proof[5]))).mod();
        alt_bn128.G1Point memory C = alt_bn128.G1Point(_C[0],_C[1]);
        alt_bn128.G1Point memory c1 = alt_bn128.G1Point(_c1[0],_c1[1]);
        alt_bn128.G1Point memory c2 = alt_bn128.G1Point(_c2[0],_c2[1]);
        alt_bn128.G1Point memory a1 = alt_bn128.G1Point(proof[0],proof[1]);
        alt_bn128.G1Point memory a2 = alt_bn128.G1Point(proof[2],proof[3]);
        alt_bn128.G1Point memory a3 = alt_bn128.G1Point(proof[4],proof[5]);
        uint z1 = proof[6];
        uint z2 = proof[7];
        /*require(g2.mul(z1).add(y.mul(z2)).eq(a1.add(c2.mul(e))),"First condition error");
        require(g2.mul(z2).eq(a2.add(c1.mul(e))),"Second condition error");
        require(g.mul(z1).add(h.mul(z2)).eq(a3.add(C.mul(e))),"Third condition error");*/
        flag = flag && (g2.mul(z1).add(y.mul(z2)).eq(a1.add(c2.mul(e))));
        flag = flag && (g2.mul(z2).eq(a2.add(c1.mul(e))));
        flag = flag && (g.mul(z1).add(h.mul(z2)).eq(a3.add(C.mul(e))));
        return flag;
    }
}