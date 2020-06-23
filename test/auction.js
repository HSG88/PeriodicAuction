const Auction = artifacts.require("Auction.sol");
const RangeProofVerifier = artifacts.require("RangeProofVerifier.sol")
const ElGamalProofVerifier = artifacts.require("ElGamalProofVerifier.sol")
const {RangeProofProver} = require("../prover/rangeProof/rangeProofProver")
const {GeneratorParams} = require("../prover/rangeProof/generatorParams")
const Web3 = require('web3')
const web3 = new Web3(new Web3.providers.HttpProvider('http://localhost:8545'));
const {mineToBlockNumber, takeSnapshot,revertToSnapshot} = require('../helpers/truffleHelper.js')
const BN = require("bn.js")
const assert = require("assert");
const {PeddersenCommitment} = require("../prover/commitments/peddersenCommitment")
const {ECCurve} = require("../prover/curve/curve")
const {ProofUtils} = require("../prover/util/proofUtil")

function generateBulletProof(parameters, commit, witness) {
    const prover = new RangeProofProver();
    const proof = prover.generateProof(parameters, commit, witness);
    const coords = [];
        //coords.push(commit.getX()) //commitment itself
        //coords.push(commit.getY())
        coords.push(proof.getaI().getX())
        coords.push(proof.getaI().getY())
        coords.push(proof.getS().getX())
        coords.push(proof.getS().getY())
        const tCommits = proof.gettCommits();
        coords.push(tCommits.get(0).getX())
        coords.push(tCommits.get(0).getY())
        coords.push(tCommits.get(1).getX())
        coords.push(tCommits.get(1).getY())
        const ls_coords = [];
        const rs_coords = [];
        for (let i=0; i < proof.getProductProof().getL().length; i++) {
            const L = proof.getProductProof().getL()[i];
            const R = proof.getProductProof().getR()[i];
            ls_coords.push(L.getX())
            ls_coords.push(L.getY())
            rs_coords.push(R.getX())
            rs_coords.push(R.getY())
        }
        const scalars = [proof.getTauX(), proof.getMu(), proof.getT(), proof.getProductProof().getA(), proof.getProductProof().getB()]
        return coords.concat(scalars).concat(ls_coords).concat(rs_coords)
    
}
function generateElGamalCipherTextAndProof(parameters, m, r) {  
    q = parameters.group.order
    g2 = parameters.g2;
    y = parameters.y;
    c = parameters.base.commit(m,r)
    c1 = g2.mul(r)
    c2 = g2.mul(m).add(y.mul(r))
    mm = ProofUtils.randomNumber().mod(q)
    rr = ProofUtils.randomNumber().mod(q)
    
    a1 = g2.mul(mm).add(y.mul(rr))
    a2 = g2.mul(rr)
    a3 = parameters.base.commit(mm,rr)
    e = ProofUtils.computeChallenge(q ,[c,c1,c2,a1,a2,a3])
    z1 = m.mul(e).mod(q).add(mm).mod(q)
    z2 = r.mul(e).mod(q).add(rr).mod(q)
    return {C1:[c1.getX(),c1.getY()], C2:[c2.getX(),c2.getY()], Proof:[a1.getX(),a1.getY(),a2.getX(),a2.getY(),a3.getX(),a3.getY(),z1,z2],E:e}
}
function createOrders(parameters) {
    base = parameters.base;
    let buyOrders=[]
    let sellOrders=[]
    buyOrders.push({P:new PeddersenCommitment(base, new BN(10)), Q: new PeddersenCommitment(base, new BN(50))},
                    {P:new PeddersenCommitment(base, new BN(60)), Q: new PeddersenCommitment(base, new BN(20))},                     
                    {P:new PeddersenCommitment(base, new BN(40)), Q: new PeddersenCommitment(base, new BN(40))},
                    {P:new PeddersenCommitment(base, new BN(50)), Q: new PeddersenCommitment(base, new BN(30))})
    sellOrders.push({P:new PeddersenCommitment(base, new BN(10)), Q: new PeddersenCommitment(base, new BN(20))},
                    {P:new PeddersenCommitment(base, new BN(30)), Q: new PeddersenCommitment(base, new BN(40))},
                    {P:new PeddersenCommitment(base, new BN(60)), Q: new PeddersenCommitment(base, new BN(50))},
                    {P:new PeddersenCommitment(base, new BN(20)), Q: new PeddersenCommitment(base, new BN(30))})
    for(i=0;i<buyOrders.length;i++) {
        buyOrders[i].PriceProof = generateBulletProof(parameters, buyOrders[i].P.getCommitment(), buyOrders[i].P)
        buyOrders[i].QuantityProof = generateBulletProof(parameters, buyOrders[i].Q.getCommitment(), buyOrders[i].Q)
        console.time("ElGamal")
        buyOrders[i].PriceCiphertextAndProof = generateElGamalCipherTextAndProof(parameters, buyOrders[i].P.getX(), buyOrders[i].P.getR());
        console.timeEnd("ElGamal")
        buyOrders[i].QuantityCiphertextAndProof = generateElGamalCipherTextAndProof(parameters, buyOrders[i].Q.getX(), buyOrders[i].Q.getR());
        buyOrders[i].Index = i;
    }
    for(i=0; i<sellOrders.length;i++) {
        sellOrders[i].PriceProof = generateBulletProof(parameters, sellOrders[i].P.getCommitment(), sellOrders[i].P)
        sellOrders[i].QuantityProof = generateBulletProof(parameters, sellOrders[i].Q.getCommitment(), sellOrders[i].Q)
        sellOrders[i].PriceCiphertextAndProof = generateElGamalCipherTextAndProof(parameters, sellOrders[i].P.getX(), sellOrders[i].P.getR());
        sellOrders[i].QuantityCiphertextAndProof = generateElGamalCipherTextAndProof(parameters, sellOrders[i].Q.getX(), sellOrders[i].Q.getR());
        sellOrders[i].Index = i;
    }
    return [buyOrders,sellOrders];
}
contract('Auction', async (accounts) => {
    M=16 //16-bits    
    log=''
    const group = new ECCurve("bn256");    
    const parameters = GeneratorParams.generateParams(M, group); 
    orders = createOrders(parameters);
    buyOrders = orders[0];
    sellOrders = orders[1];
    buyProofs = []
    sellProofs = []
    marketPrice = 35
    const operator = accounts[0];
    var IntervalsEnd;
    it('Deploy the auction', async()=>{    
        rangeProofVerifier = await RangeProofVerifier.deployed(); 
        elgamalProofVerifier = await ElGamalProofVerifier.new([parameters.g.getX(),parameters.g.getY()], [parameters.h.getX(),parameters.h.getY()], [parameters.g2.getX(), parameters.g2.getY()], [parameters.y.getX(), parameters.y.getY()])
        auction = await Auction.new(rangeProofVerifier.address, elgamalProofVerifier.address, [20,50,80,10], [parameters.g.getX(),parameters.g.getY()], {from:operator, value:web3.utils.toWei("1","ether")});
        var receipt = await web3.eth.getTransactionReceipt(auction.transactionHash)
        log+=`DeployAuction: ${receipt.gasUsed}\n`
    })
    it('Submit Order',async ()=> {
        j = 1;
        for(i = 0; i<buyOrders.length; i++) {
            P = [buyOrders[i].P.getCommitment().getX(),buyOrders[i].P.getCommitment().getY()]
            Q = [buyOrders[i].Q.getCommitment().getX(),buyOrders[i].Q.getCommitment().getY()]
            tx = await auction.SubmitOrder(true, P, buyOrders[i].PriceProof, Q, buyOrders[i].QuantityProof,{from:accounts[j++], value:web3.utils.toWei("1","ether")});
            //console.log(`SubmitOrder(Buyer):${accounts[j++]}, GasUsed:${tx.receipt.gasUsed}`)
        }
        for(i = 0; i<sellOrders.length; i++) {
            P = [sellOrders[i].P.getCommitment().getX(),sellOrders[i].P.getCommitment().getY()]
            Q = [sellOrders[i].Q.getCommitment().getX(),sellOrders[i].Q.getCommitment().getY()]
            tx = await auction.SubmitOrder(false, P, sellOrders[i].PriceProof, Q, sellOrders[i].QuantityProof,{from:accounts[j++], value:web3.utils.toWei("1","ether")});
            //console.log(`SubmitOrder(Seller):${accounts[j++]}, GasUsed:${tx.receipt.gasUsed}`)
        }   
        log+=`SubmitOrder:${tx.receipt.gasUsed}\n`
       // console.log(tx.logs[0].args.buyer)      
    })
   it('Dispute Order', async ()=> {
        snapShot = await takeSnapshot()
        snapshotId = snapShot['result']

        //submitting invalid commitment proof  (i.e. quantityproof with price)
        P = [buyOrders[0].P.getCommitment().getX(),buyOrders[0].P.getCommitment().getY()]
        Q = [buyOrders[0].Q.getCommitment().getX(),buyOrders[0].Q.getCommitment().getY()]
        await auction.SubmitOrder(true, P, buyOrders[0].QuantityProof, Q, buyOrders[0].QuantityProof,{from:accounts[accounts.length-1], value:web3.utils.toWei("1","ether")});
   
        var submitEnd = (await auction.IntervalsEnd.call()).Submit.toNumber()
        await mineToBlockNumber(submitEnd+1)
        try{    
        tx = await auction.DisputeSubmitOrder(accounts[accounts.length-1],P, buyOrders[0].QuantityProof)
        log+=`DisputeSubmit:${tx.receipt.gasUsed}\n`
        }catch(err) {
            
            console.log(String(err))
        }
        await revertToSnapshot(snapshotId)
        //needed for dispute reveal
        await auction.SubmitOrder(true, P, buyOrders[0].QuantityProof, Q, buyOrders[0].QuantityProof,{from:accounts[accounts.length-1], value:web3.utils.toWei("1","ether")});
    })
    it('Reveal Order', async ()=> {

        var submitEnd  = (await auction.IntervalsEnd.call()).Submit.toNumber()
        var submitDisputeEnd =  submitEnd + (await auction.IntervalsEnd.call()).Dispute.toNumber()
        await mineToBlockNumber(submitDisputeEnd+1)
        j = 1;
        for(i = 0; i<buyOrders.length; i++) {
            P = buyOrders[i].PriceCiphertextAndProof
            Q = buyOrders[i].QuantityCiphertextAndProof
            tx = await auction.RevealOrder(true, P.C1, P.C2, P.Proof, Q.C1, Q.C2, Q.Proof,{from:accounts[j++]});
            //console.log(`RevealOrder(Buyer):${accounts[j++]}, GasUsed:${tx.receipt.gasUsed}`)
        }
        for(i = 0; i<sellOrders.length; i++) {
            P = sellOrders[i].PriceCiphertextAndProof
            Q = sellOrders[i].QuantityCiphertextAndProof
            tx = await auction.RevealOrder(false, P.C1, P.C2, P.Proof, Q.C1, Q.C2, Q.Proof,{from:accounts[j++]});
            //console.log(`RevealOrder(Seller):${accounts[j++]}, GasUsed:${tx.receipt.gasUsed}`)
        }
        log+=`RevealOrder:${tx.receipt.gasUsed}\n`
    })
    it('Dispute Reveal', async ()=> {
        snapShot = await takeSnapshot()
        snapshotId = snapShot['result']    

        //submit invalid proofs (quantity proof for price)
        P = buyOrders[0].PriceCiphertextAndProof
        Q = buyOrders[0].QuantityCiphertextAndProof
        tx = await auction.RevealOrder(true, P.C1, P.C2, Q.Proof, Q.C1, Q.C2, Q.Proof,{from:accounts[accounts.length-1]});

        var revealEnd  = (await auction.IntervalsEnd.call()).Reveal.toNumber()
        await mineToBlockNumber(revealEnd+1)

        PC = [buyOrders[0].P.getCommitment().getX(),buyOrders[0].P.getCommitment().getY()]   

        try{    
        tx = await auction.DisputeRevealOrder(accounts[accounts.length-1],PC, P.C1, P.C2, Q.Proof)
        log+=`DisputeReveal:${tx.receipt.gasUsed}\n`
        }catch(err) {
            console.log(String(err))
        }
        await revertToSnapshot(snapshotId)

        //no longer needed
        await auction.RemoveOrder(accounts[accounts.length-1])
        
    })
    it('Clear Market', async()=>{
        marketPriceCommitment = new PeddersenCommitment(parameters.base, new BN(marketPrice),new BN(0))
        buyOrders.push({P:marketPriceCommitment, Index:buyOrders.length})
        sellOrders.push({P:marketPriceCommitment, Index: sellOrders.length})
        
        buyOrders.sort((a,b)=>{return a.P.getX().lte(b.P.getX())?1:-1})
        sellOrders.sort((a,b)=>{return a.P.getX().gte(b.P.getX())?1:-1})
        
        x = buyOrders.map(a=>{return a.Index})
        y = sellOrders.map(a=>{return a.Index})

        for(i=0; i<buyOrders.length-1; i++) {
            D = buyOrders[i].P.add(buyOrders[i+1].P.times(new BN(-1)))
            buyProofs.push(generateBulletProof(parameters, D.getCommitment(), D))
        }
        for(i=0; i<sellOrders.length-1; i++) {
            D = sellOrders[i+1].P.add(sellOrders[i].P.times(new BN(-1)))
            sellProofs.push(generateBulletProof(parameters, D.getCommitment(), D))
        }

        var revealEnd  = (await auction.IntervalsEnd.call()).Reveal.toNumber()
        var revealDisputeEnd =  revealEnd + (await auction.IntervalsEnd.call()).Dispute.toNumber()
        await mineToBlockNumber(revealDisputeEnd+1)

        tx = await auction.ClearMarket(marketPrice, x, y, buyProofs, sellProofs, {from:operator})
        log +=`ClearMarket: ${tx.receipt.gasUsed}\n`
        console.log(log)

    })
    it('Dispute Clear', async()=>{
        snapShot = await takeSnapshot()
        snapshotId = snapShot['result']    

        var clearEnd  = (await auction.IntervalsEnd.call()).Clear.toNumber()
        await mineToBlockNumber(clearEnd+1)
        P1 = [buyOrders[0].P.getCommitment().getX(), buyOrders[0].P.getCommitment().getY()]
        P2 = [buyOrders[1].P.getCommitment().getX(), buyOrders[1].P.getCommitment().getY()]
        Proof = buyProofs[0]
        try{
        tx = await auction.DisputeClear(true, 0, P1, P2, Proof, {from:accounts[1]})
        log +=`DisputeClear: ${tx.receipt.gasUsed}\n`
        }catch(err) {
            console.log(String(err));
        }
        console.log(log)
        await revertToSnapshot(snapshotId)        
    })
})