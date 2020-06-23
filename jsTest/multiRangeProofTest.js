const {InnerProductProofSystem} = require("../prover/innerProduct/innerProductProofSystem")
const {ECCurve} = require("../prover/curve/curve")
const secureRandom = require("secure-random")
const BN = require("bn.js")
const {FieldVector} = require("../prover/linearAlgebra/fieldVector")
const {InnerProductWitness} = require("../prover/innerProduct/innerProductWitness")
const {EfficientInnerProductVerifier} = require("../prover/innerProduct/efficientInnerProductVerifier")
const ethUtil = require("ethereumjs-util");
const assert = require("assert");
const {MultiRangeProofProver} = require("../prover/multiRangeProof/multiRangeProofProver")
const {MultiRangeProofVerifier} = require("../prover/multiRangeProof/multiRangeProofVerifier")
const {GeneratorParams} = require("../prover/rangeProof/generatorParams")
const {PeddersenCommitment} = require("../prover/commitments/peddersenCommitment")
const {GeneratorVector} = require("../prover/linearAlgebra/generatorVector")
const {ProofUtils} = require("../prover/util/proofUtil")

function testSoundness() {
    const group = new ECCurve("bn256")
    const number = new BN(7);
    const n = 128
    let comms = [], wits=[]
    const parameters = GeneratorParams.generateParams(16*n, group);
    for(let i=0; i<n;i++) {
        wits.push(new PeddersenCommitment(parameters.getBase(), number, ProofUtils.randomNumber()))
        comms.push(wits[i].getCommitment())
    }    
    const commitments = new GeneratorVector(comms, group)
    const prover = new MultiRangeProofProver();
    console.time("Proof")
    const proof = prover.generateProof(parameters, commitments, wits);
    console.timeEnd("Proof")
    const verifier = new MultiRangeProofVerifier();
    let valid = verifier.verify(parameters, commitments, proof);
    console.log("For two proofs proof size is: scalaras " + proof.numInts() + ", field elements " + proof.numElements());
    console.log("Multi range proof is " + valid + "\n");
}

testSoundness();