var fs = require('fs');  
var https = require('https');

var options = {  
    hostname: 'chain_1.acme.com',
    port: 8000,
    path: '/',
    method: 'GET',
    key: fs.readFileSync('./client_chain_1.key'),
    cert: fs.readFileSync('./client_chain_1.crt'),
    ca: fs.readFileSync('./full_chain.crt')
};

var req = https.request(options, function(res) {  
    res.on('data', function(data) {
        process.stdout.write(data);
    });
});
req.end();

req.on('error', function(e) {  
    console.error(e);
});
