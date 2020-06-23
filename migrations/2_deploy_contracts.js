const PublicParameters = artifacts.require("PublicParameters.sol");
const EfficientInnerProductVerifier = artifacts.require("EfficientInnerProductVerifier.sol")
const RangeProofVerifier = artifacts.require("RangeProofVerifier.sol")

module.exports = async function(deployer,network, accounts) {
    const operator = accounts[0];

    await deployer.deploy(PublicParameters, {from: operator})
    const publicParams = await PublicParameters.deployed();
    for (let i = 0; i < 1000; i++) {
        try{
            await publicParams.createGVector()
            await publicParams.createHVector()
        } catch(err) {
            break
        }
    }

    await deployer.deploy(EfficientInnerProductVerifier, publicParams.address, {from: operator});
    const ipVerifier = await EfficientInnerProductVerifier.deployed();

    await deployer.deploy(RangeProofVerifier, publicParams.address, ipVerifier.address, {from: operator});
    const rangeProofVerifier = await RangeProofVerifier.deployed();    
    for (let i = 0; i < 100; i++) {
        try{
            await rangeProofVerifier.producePowers()
        } catch(err) {
            break
        }
    }
};
