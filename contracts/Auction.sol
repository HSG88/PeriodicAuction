pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;
import "./RangeProofVerifier.sol";
import "./ElGamalProofVerifier.sol";
import "./alt_bn128.sol";

contract Auction {
    using alt_bn128 for alt_bn128.G1Point;
    alt_bn128.G1Point public g;
    struct Order {
        bytes32 Price;
        bytes32 PriceProof;
        bytes32 Quantity;
        bytes32 QuantityProof;
        bytes32 PriceElGamalProof;
        bytes32 QuantityElGamalProof;
    }
    struct Interval{
        uint Submit;
        uint Reveal;
        uint Clear;
        uint Dispute;
    }
    event orderCreated(address indexed trader, bool indexed isBuyOrder, uint[2] price, uint[29] priceProof,
     uint[2] quantity, uint[29] quantityProof);
    event orderRevealed(address indexed trader, bool indexed isBuyOrder, uint[2] priceC1, uint[2] priceC2, uint[8] priceProof,
     uint[2] quantityC1, uint[2] quantityC2, uint[8] quantityProof);

    mapping(address=>Order) BuyOrders;
    mapping(address=>Order) SellOrders;
    address[] public Buyers;
    address[] public Sellers;
    bytes32[] public BuyProofs;
    bytes32[] public SellProofs;
    Interval public IntervalsEnd;
    uint constant public DEPOSIT = 1 ether;
    address public operator;

    RangeProofVerifier public bulletProofVerifier;
    ElGamalProofVerifier public elgamalProofVerifier;

    uint public marketPrice;
    bool public invalidMarketPrice;

    constructor (address _bulletProofverifier, address _elgamalProofVerifier, uint[4] memory _timeIntervals, uint[2] memory _g) public payable {
        require(msg.value == DEPOSIT,"not valid deposit");
        bulletProofVerifier = RangeProofVerifier(_bulletProofverifier);
        elgamalProofVerifier = ElGamalProofVerifier(_elgamalProofVerifier);
        IntervalsEnd = Interval(_timeIntervals[0] + block.number,_timeIntervals[1] + _timeIntervals[0] + block.number,
        _timeIntervals[2] + _timeIntervals[1] + _timeIntervals[0] + block.number,_timeIntervals[3]);
        g = alt_bn128.G1Point(_g[0],_g[1]);
        operator = msg.sender;
    }

    function FindOrder(address owner) private view returns (Order storage) {
        Order storage order = BuyOrders[owner];
        if(order.Price==0)
            order = SellOrders[owner];
        return order;
    }

    function RemoveOrder(address owner) public { //it is public for test unit only, otherwise it must be private
        if(BuyOrders[owner].Price!=0) {
            delete BuyOrders[owner];
            for(uint i = 0; i<Buyers.length; i++)
                if(Buyers[i] == owner) {
                    for(uint j = i ; j<Buyers.length-1;j++)
                        Buyers[j] = Buyers[j+1];
                    Buyers.length = Buyers.length-1;
                    break;
                }
        }
        if(SellOrders[owner].Price!=0) {
            delete SellOrders[owner];
            for(uint i = 0; i < Sellers.length; i++)
                if(Sellers[i] == owner) {
                    for(uint j = i; j<Sellers.length-1; j++)
                        Sellers[j] = Sellers[j+1];
                    Sellers.length = Sellers.length-1;
                    break;
                }
        }
    }
    function SubmitOrder(bool direction, uint[2] memory price, uint[29] memory priceProof,
    uint[2] memory quantity, uint[29] memory quantityProof) public payable {
        require(block.number < IntervalsEnd.Submit,"Invalid bidding phase");
        require(msg.value == DEPOSIT,"Invalid deposit");
        emit orderCreated(msg.sender, direction, price, priceProof, quantity, quantityProof);
        Order memory order = Order(keccak256(abi.encodePacked(price)),keccak256(abi.encodePacked(price,priceProof)),
        keccak256(abi.encodePacked(quantity)),keccak256(abi.encodePacked(quantityProof)),0,0);
        if(direction) {
            BuyOrders[msg.sender] = order;
            Buyers.push(msg.sender);
        } else {
            SellOrders[msg.sender] = order;
            Sellers.push(msg.sender);
        }
    }

    function DisputeSubmitOrder(address owner, uint[2] memory commitment, uint[29] memory proof) public {
        require(block.number > IntervalsEnd.Submit && block.number < IntervalsEnd.Submit + IntervalsEnd.Dispute,
        "Invalid dispute submit order phase");
        bytes32 hash = keccak256(abi.encodePacked(commitment,proof));
        Order storage order = FindOrder(owner);
        require((hash == order.PriceProof) || (hash == order.QuantityProof),"Inconsistant input");
        require(bulletProofVerifier.Verify(commitment, proof)==false, "The proof is already valid");
        RemoveOrder(owner);
        msg.sender.transfer(DEPOSIT);
    }

    function RevealOrder(bool isBuyOrder, uint[2] memory priceC1, uint[2] memory priceC2, uint[8] memory priceProof,
     uint[2] memory quantityC1, uint[2] memory quantityC2, uint[8] memory quantityProof) public {
         IntervalsEnd.Submit = IntervalsEnd.Submit+1;
        require(block.number > IntervalsEnd.Submit+IntervalsEnd.Dispute && block.number < IntervalsEnd.Reveal,"Invalid reveal phase");
        emit orderRevealed(msg.sender, isBuyOrder, priceC1, priceC2, priceProof, quantityC1, quantityC2, quantityProof);
        Order storage order = FindOrder(msg.sender);
        order.PriceElGamalProof = keccak256(abi.encodePacked(priceC1,priceC2,priceProof));
        order.QuantityElGamalProof = keccak256(abi.encodePacked(quantityC1,quantityC2,quantityProof));
    }

    function DisputeRevealOrder(address owner, uint[2] memory commitment, uint[2] memory c1, uint[2] memory c2, uint[8] memory proof) public {
        require(block.number > IntervalsEnd.Reveal && block.number < IntervalsEnd.Reveal + IntervalsEnd.Dispute,
        "Invalid dispute reveal order phase");
        Order storage order = FindOrder(owner);
        require(order.Price == keccak256(abi.encodePacked(commitment)) && order.PriceElGamalProof == keccak256(abi.encodePacked(c1,c2,proof)) ||
        order.Quantity == keccak256(abi.encodePacked(commitment)) && order.QuantityElGamalProof == keccak256(abi.encodePacked(c1,c2,proof)), "inconsistent input");
        require(elgamalProofVerifier.Verify(commitment, c1, c2, proof)==false, "The proof is already valid");
        RemoveOrder(owner);
        msg.sender.transfer(DEPOSIT);
    }

    function DisuputeUnrevealedOrder(address[] memory owners) public {
        require(block.number > IntervalsEnd.Reveal && block.number < IntervalsEnd.Reveal + IntervalsEnd.Dispute,
        "Invalid dispute reveal order phase");
        for(uint i = 0; i<owners.length; i++) {
            Order storage order = FindOrder(owners[i]);
            if(order.PriceElGamalProof == 0) {
                RemoveOrder(owners[i]);
                msg.sender.transfer(DEPOSIT);
            }
        }
    }

    function ClearMarket(uint _marketPrice, uint[] memory x, uint[] memory y, uint[29][] memory buyProofs, uint[29][] memory sellProofs) public {
        require(block.number > IntervalsEnd.Reveal+IntervalsEnd.Dispute && block.number < IntervalsEnd.Clear,
        "Invalid clear market phase");
        require(msg.sender == operator,"only the operator");
        marketPrice = _marketPrice;
        alt_bn128.G1Point memory p = g.mul(marketPrice);
        Order memory order = Order(keccak256(abi.encodePacked([p.X, p.Y])),0,0,0,0,0);
        BuyOrders[msg.sender] = order;
        SellOrders[msg.sender] = order;
        Buyers.push(msg.sender);
        Sellers.push(msg.sender);
        address[] memory newBuyers = new address[](Buyers.length);
        address[] memory newSellers = new address[](Sellers.length);
        for(uint i = 0; i<Buyers.length; i++)
            newBuyers[i] = Buyers[x[i]];
        for(uint i = 0; i<Sellers.length; i++)
            newSellers[i] = Sellers[y[i]];
        Buyers = newBuyers;
        Sellers = newSellers;

        for(uint i = 0; i<buyProofs.length;i++)
            BuyProofs.push(keccak256(abi.encodePacked(buyProofs[i])));
        for(uint i = 0; i<sellProofs.length;i++)
            SellProofs.push(keccak256(abi.encodePacked(sellProofs[i])));

    }
    function DisputeClear(bool isBuy, uint index, uint[2] memory P1, uint[2] memory P2, uint[29] memory proof) public {
        require(block.number > IntervalsEnd.Clear && block.number < IntervalsEnd.Clear+IntervalsEnd.Dispute,
        "Invalid dispute clear market phase");
        require(msg.sender!=operator,"Operator not allowed");
        require(invalidMarketPrice == false,"Already disputed");
        alt_bn128.G1Point memory p1 = alt_bn128.G1Point (P1[0],P1[1]);
        alt_bn128.G1Point memory p2 = alt_bn128.G1Point (P2[0],P2[1]);
        if(isBuy) {
            require(BuyOrders[Buyers[index]].Price == keccak256(abi.encodePacked(P1)),"Invalid P1");
            require(BuyOrders[Buyers[index+1]].Price == keccak256(abi.encodePacked(P2)),"Invalid P2");
            require(BuyProofs[index] == keccak256(abi.encodePacked(proof)),"Invalid proof");
            alt_bn128.G1Point memory D = p1.add(p2.neg());
            require(bulletProofVerifier.Verify([D.X,D.Y], proof)==false,"Proof is already valid");
            invalidMarketPrice = true;
            msg.sender.transfer(DEPOSIT);
        } else {
            require(SellOrders[Sellers[index]].Price == keccak256(abi.encodePacked(P1)),"Invalid P1");
            require(SellOrders[Sellers[index+1]].Price == keccak256(abi.encodePacked(P2)),"Invalid P2");
            require(SellProofs[index] == keccak256(abi.encodePacked(proof)),"Invalid proof");
            alt_bn128.G1Point memory D = p2.add(p1.neg());
            require(bulletProofVerifier.Verify([D.X,D.Y], proof)==false,"Proof is already valid");
            invalidMarketPrice = true;
            msg.sender.transfer(DEPOSIT);
        }
    }
}