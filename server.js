
const PATH = require("path");
const FS = require("fs");
const HTTP = require("http");


var serviceUid = false;
if (FS.existsSync(PATH.join(__dirname, "service.json"))) {
    serviceUid = JSON.parse(FS.readFileSync(PATH.join(__dirname, "service.json"))).uid;
}


HTTP.createServer(function (req, res) {

	var headers = {
		'Content-Type': 'text/plain'
	};

	if (serviceUid) {
        headers["x-service-uid"] = serviceUid;
    }

	res.writeHead(200, headers);
	res.end('Hello World from identity provider server!\n');

}).listen(process.env.PORT, '127.0.0.1');


console.log('Identity server running at http://127.0.0.1:' + process.env.PORT + '/');
