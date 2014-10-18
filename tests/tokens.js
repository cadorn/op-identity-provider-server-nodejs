
const CRYPTO = require("crypto");


describe("tokens", function() {

	var INPUT = {
		tokenSecret: "kjdfkj82398jkwefkjwkjef892398welkefklewkflo234230ioewklw",
		tokenInfo: {
			service: 'facebook_v1',
			identifier: '100007572584075',
			username: 'Fbtest Fbtest',
			token: 'CAAIn2rA1gD8BAF5KP8A0k51Dw5gwZAf5uqdG3AGhXcwLQcjEIiHfDJyRXr8ITzy6stFXuOMREW1JX42gK2e0HZCULH4ZCHCXzUfM2tIYKNF1BLcsATZB7tueLYsU9ZCzlLR0KZBodu6GoGn1HJDEu4ARVlC0GRiaCPxPAtmbipWejWFEUBuaAQxdDeThrJ7vnYPG4hChuhHt9SZBlCco1ZBZC'
		}
	};


	function makeToken(tokenInfo, callback) {
        /*
        <sharedSecret> = 52+ plain text characters
        <iv> = MD5 random hash (16 bytes)
        token = hex(<iv>) + "-" + hex(AES.encrypt(sha256(<sharedSecret>), <iv>, <credentials>))
        <credentials> = JSON.stringify({
            service: <name (github|twitter|linkedin|facebook)>
            consumer_key: <OAuth consumer/api key provided by service>,
            consumer_secret: <OAuth consumer/api secret provided by service>,
            token: <OAuth access token>,
            token_secret: <OAuth access token secret>
        })
        */
        if (tokenInfo.service === "oauth") {
            tokenInfo.consumer_key = req.session.login.accountConfig.services.oauth.mergedConfiguration.oauth.clientID;
            tokenInfo.consumer_secret = req.session.login.accountConfig.services.oauth.mergedConfiguration.oauth.clientSecret;
        } else
        if (tokenInfo.service === "facebook") {
            tokenInfo.consumer_key = req.session.login.accountConfig.services.facebook.mergedConfiguration.appID;
            tokenInfo.consumer_secret = req.session.login.accountConfig.services.facebook.mergedConfiguration.appSecret;
        } else
        if (tokenInfo.service === "twitter") {
            tokenInfo.token_secret = req.session.user.accessTokenSecret;
            tokenInfo.consumer_key = req.session.login.accountConfig.services.twitter.mergedConfiguration.apiKey;
            tokenInfo.consumer_secret = req.session.login.accountConfig.services.twitter.mergedConfiguration.apiSecret;
        }
        var tokenSecret = INPUT.tokenSecret;
        return CRYPTO.randomBytes(32, function(err, buffer) {
            if (err) return callback(err);
            var token = null;
            try {
                var iv = CRYPTO.createHash("md5");
                iv.update(buffer.toString("hex"));
                iv = iv.digest();
                var secretHash = CRYPTO.createHash("sha256");
                secretHash.update(tokenSecret);
                secretHash = secretHash.digest();
                var cipher = CRYPTO.createCipheriv('aes-256-cbc', secretHash, iv);
                var encryptdata = cipher.update(JSON.stringify(tokenInfo), 'utf8', 'binary');
                encryptdata += cipher.final('binary');
                token = iv.toString('hex') + "-" + new Buffer(encryptdata, 'binary').toString('base64');
            } catch(err) {
                return callback(err);
            }
            return callback(null, token);
        });
    }


	function parseToken (token, callback) {
        /*
        <sharedSecret> = 52+ plain text characters
        <iv> = MD5 random hash (16 bytes)
        token = hex(<iv>) + "-" + hex(AES.encrypt(sha256(<sharedSecret>), <iv>, <credentials>))
        <credentials> = JSON.stringify({
            service: <name (github|twitter|linkedin|facebook)>
            consumer_key: <OAuth consumer/api key provided by service>,
            consumer_secret: <OAuth consumer/api secret provided by service>,
            token: <OAuth access token>,
            token_secret: <OAuth access token secret>
        })
        */
        var tokenInfo = null;
        try {
            var tokenSecret = INPUT.tokenSecret;
            var secretHash = CRYPTO.createHash("sha256");
            secretHash.update(tokenSecret);
            secretHash = secretHash.digest();
			var tokenParts = token.split("-");
			var iv = new Buffer(tokenParts[0], 'hex');
			var encryptdata = new Buffer(tokenParts[1], 'base64').toString('binary');
            var decipher = CRYPTO.createDecipheriv('aes-256-cbc', secretHash, iv);
            var decryptdata = decipher.update(encryptdata, 'binary', 'utf8');
            decryptdata += decipher.final('utf8');
            tokenInfo = JSON.parse(decryptdata);
        } catch (err) {
            return callback(err);
        }
        return callback(null, tokenInfo);
	}


	var token = null;

    it("/encrypt", function(done) {
        return makeToken(INPUT.tokenInfo, function(err, _token) {
            if (err) return done(err);

            token = _token;

            console.log("token", token);

            return done();
        });
    });

    it("/decrypt", function(done) {

		return parseToken(token, function (err, tokenInfo) {
            if (err) return done(err);

			console.log("tokenInfo", tokenInfo);

			if (JSON.stringify(tokenInfo) !== JSON.stringify(INPUT.tokenInfo)) {
				return done(new Error("Result does not match input!"));
			}

			return done();
		});
    });

});

