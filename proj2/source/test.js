const MessengerClient = require("./messenger.js");
const lib = require("./lib.js")

async function runtest(){

let caKeyPair = await lib.generateECDSA();
let govKeyPair = await lib.generateEG();

let alice = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
const aliceCertificate = await alice.generateCertificate('alice');
console.log(aliceCertificate);

}

runtest();