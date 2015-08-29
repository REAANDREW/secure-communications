var https = require('https');
var fs = require('fs');

/*
var options = {
key: fs.readFileSync('../CA/server.key','utf8'),
cert: fs.readFileSync('../CA/server.pem','utf8'),
ca: fs.readFileSync('../CA/cacert.pem','utf8'),
requestCert:        true,
rejectUnauthorized: true,
honorCipherOrder: true
};
*/

(function test(){
    var fs = require("fs"),
    xmldom = require("xmldom");

    var dsig = require("xml-dsig")();

    var xml = '<docs><doc id="doc-1"/><doc id="doc-2"/></docs>',
    doc = (new xmldom.DOMParser()).parseFromString(xml);

    var node = doc.documentElement;


    var node = doc.documentElement;
    var transform = dsig.transforms["http://www.w3.org/2001/10/xml-exc-c14n#"]();
    console.log('transform', transform);
    var options = {
        transforms: [],
            references: [],
            canonicalisationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
            digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
            signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            signatureOptions: {
                privateKey: fs.readFileSync("../CA/client.key"),
                publicKey: fs.readFileSync("../CA/client.pem"),
            },
    };
    dsig.signAndInsert(node,options, function(err, signature){
        if (err !== null){
            console.log(err.stack);
            return;
        }
        console.log("");

        console.log(node.toString());
        console.log("");

        console.log(signature.toString());
        console.log("");

        console.log(dsig.verifySignature(node, signature, options));
        console.log("");
    });


})();
/*
https.createServer(options, function (req, res) {
res.writeHead(200);
res.end("hello world from node.js\n");
}).listen(8000);
*/
