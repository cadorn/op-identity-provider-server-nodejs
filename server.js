

const ASSERT = require("assert");
const PATH = require("path");
const FS = require("fs");
const URL = require("url");
const PASSPORT = require("passport");
const PASSPORT_OAUTH2 = require("passport-oauth2");
const REQUEST = require("request");
const CRYPTO = require("crypto");


var hcsConfigBasePath = "/opt/data/config2";
var hcsIntegrationConfigPath = PATH.join(hcsConfigBasePath, "hcs-integration.json");

var integrationConfig = JSON.parse(FS.readFileSync(hcsIntegrationConfigPath));
var AUTH_CONFIG = integrationConfig.identity.oauth;


var passport = null

require("./server-prototype").for(module, __dirname, function(app, serviceConfig, HELPERS) {

	passport = new PASSPORT.Passport();
	passport.serializeUser(function(user, done) {
	    return done(null, user);
	});
	passport.deserializeUser(function(obj, done) {
	    return done(null, obj);
	});
    AUTH_CONFIG.callbackURL = serviceConfig.config.identity.oauth.callbackURL;
	var oauthStrategy = new PASSPORT_OAUTH2.Strategy(AUTH_CONFIG, function(accessToken, refreshToken, profile, done) {
	    return done(null, {
            accessToken: accessToken,
            refreshToken: refreshToken,
            id: profile.id,
            username: profile.username
	    });
	  }
	);
    oauthStrategy.userProfile = function(accessToken, callback) {
        return REQUEST.get(AUTH_CONFIG.profileURL + "?access_token=" + accessToken, function(err, res, body) {
            if (err) return callback(err);
            var profile = null;
            try {
            	profile = JSON.parse(body);
	        } catch(err) {
	        	return callback(err);
	        }
            return callback(null, profile);
        });
    };
    passport.use(oauthStrategy);

    app.use(passport.initialize());
    app.use(passport.session());

    app.use(function(req, res, next) {
    	if (req.session.authorized) {
    		res.view = {
    			authorized: true,
    			user: req.session.user
    		};
    	} else {
    		res.view = {
    			authorized: false
    		};
    	}
        res.view.hcs = {
            config: integrationConfig
        };
    	return next();
    });

	app.get('/login', function(req, res, next) {
        req.logout();
        if (req.query && req.query.returnTo) {
            req.session.returnTo = req.query.returnTo;
        }
        return next();
    }, passport.authenticate('oauth2'));

    app.get('/oauth/callback', passport.authenticate('oauth2', {
        failureRedirect: '/fail'
    }), function(req, res, next) {
        req.session.user = req.session.passport.user;
        req.session.authorized = true;
        var returnTo = null;
        if (req.session.login) {
            returnTo = req.session.login.callbackURL;
        } else
        if (req.session.returnTo) {
            returnTo = req.session.returnTo;
        }
        delete req.session.returnTo;
        return res.redirect(returnTo || '/');
    });

    app.get(/^\/logout$/, function (req, res) {
    	req.logout();
        delete req.session.user;
        delete req.session.authorized;
        res.writeHead(302, {
            "Location": "/"
        });
        return res.end();
    });


    // @see https://github.com/openpeer/hcs-system/blob/master/architecture/servers/HCS%20protocol%20-%20Identity%20Provider.md#44-social-provider-authentication-request
    app.get(/^\/login.php$/, function (req, res) {
        return FS.readFile(serviceConfig.config.loginTemplatePath, "utf8", function(err, template) {

            template = template.replace(/\{\{\s*config.HF_LOGGER_HOST\s*\}\}/g, integrationConfig.logger.host);
            template = template.replace(/\{\{\s*config.ASSET_PATH\s*\}\}/g, "/assets");
            template = template.replace(/\{\{\s*config.HF_PASSWORD1_BASEURI\s*\}\}/g, integrationConfig.hcs.password1.uri);
            template = template.replace(/\{\{\s*config.HF_PASSWORD2_BASEURI\s*\}\}/g, integrationConfig.hcs.password2.uri);
            template = template.replace(/\{\{\s*config.SESSION_identityServiceAuthenticationURL\s*\}\}/g, "");

            res.writeHead(200, {
                "Content-Type": "text/html",
                "Content-Length": template.length
            });
            return res.end(template);
        });
    });
    app.get(/^\/assets\//, function (req, res, next) {
        var path = PATH.join(PATH.dirname(serviceConfig.config.loginTemplatePath), req.url.replace(/^\/assets/, ""));
        return HELPERS.API.SEND(req, PATH.basename(path))
            .root(PATH.dirname(path))
            .on('error', next)
            .pipe(res);
    });


    app.post(/^\/api.php$/, function (req, res, next) {

        var request = req.body.request || null;
        if (!request) {
            return next(new Error("Request did not contain a 'request' property!"));
        }

        function respond (data) {
            var result = {
                "$domain": request.$domain,
                "$id": request.$id,
                "$handler": request.$handler,
                "$method": request.$method,
                "$epoch": Date.now()
            };
            for (var name in data) {
                result[name] = data[name];
            }
            var payload = JSON.stringify({
                result: result
            }, null, 4);
            res.writeHead(200, {
                "Content-Type": "application/json",
                "Content-Length": payload.length
            });
            return res.end(payload);
        }

        try {

            if (request.$handler === "identity-provider") {
                // @see https://github.com/openpeer/hcs-system/blob/master/architecture/servers/HCS%20protocol%20-%20Identity%20Provider.md#44-social-provider-authentication-request
                if (request.$method === "oauth-provider-authentication") {

                    ASSERT.equal(typeof request.clientAuthenticationToken, "string", "'request.clientAuthenticationToken' must be set!");
                    ASSERT.equal(typeof request.callbackURL, "string", "'request.callbackURL' must be set!");
                    ASSERT.equal(typeof request.identity.type, "string", "'request.identity.type' must be set!");

                    req.session.login = {
                        clientAuthenticationToken: request.clientAuthenticationToken,
                        callbackURL: request.callbackURL,
                        identity: request.identity,
                        serverAuthenticationToken: generateId(),
                        // TODO: Remove 'reloginKey' here as it should only be known to the client. [Security]
                        reloginKey: generateId()
                    };

                    return respond({
                        "providerRedirectURL": "/login",
                        "serverAuthenticationToken": req.session.login.serverAuthenticationToken
                    });
                } else
                // @see https://github.com/openpeer/hcs-system/blob/master/architecture/servers/HCS%20protocol%20-%20Identity%20Provider.md#456-example---social-login
                if (request.$method === "login") {

                    ASSERT.equal(typeof request.proof.clientAuthenticationToken, "string", "'request.proof.clientAuthenticationToken' must be set!");
                    ASSERT.equal(typeof request.proof.serverAuthenticationToken, "string", "'request.proof.serverAuthenticationToken' must be set!");
                    ASSERT.equal(typeof request.identity.type, "string", "'request.identity.type' must be set!");
                    ASSERT.equal(typeof request.identity.base, "string", "'request.identity.base' must be set!");

                    if (!req.session.login) {
                        return next(new Error("No active login session"));
                    }
                    if (req.session.login.clientAuthenticationToken !== request.proof.clientAuthenticationToken) {
                        return next(new Error("clientAuthenticationToken does not match"));
                    }
                    if (req.session.login.serverAuthenticationToken !== request.proof.serverAuthenticationToken) {
                        return next(new Error("serverAuthenticationToken does not match"));
                    }
                    if (req.session.login.identity.type !== request.identity.type) {
                        return next(new Error("identity.type does not match"));
                    }
                    if (req.session.login.identity.base !== request.identity.base) {
                        return next(new Error("identity.base does not match"));
                    }

                    return respond({
                        "identity": {
                            "accessToken": "facebook-100024352456-345345542345-dsgtyewdrq6r3rtytiuytw45yt",
                            "accessSecret": "rqy4rtyqiryqwieyrtq46tryertyqu43r6yq",
                            "accessSecretExpires": Date.now() + 60 * 60 * 24 * 1000,
                            "uri": request.identity.base + "/" + req.session.user.id,
                            "reloginKey": req.session.login.reloginKey,
                            // e.g. http://hcs-stack-cust-oauth-ia10ccf8-1.vm.opp.me:81/profile/{id}
//                            "profile": integrationConfig.identity.oauth.publicProfileURL.replace(/\{id\}/g, req.session.user.id),
                            // e.g. http://hcs-stack-cust-oauth-ia10ccf8-1.vm.opp.me:81/profile/{id}?format=vcard
//                            "vprofile": integrationConfig.identity.oauth.publicVcardProfileURL.replace(/\{id\}/g, req.session.user.id)
                        },
                        "lockbox": {
                            "reset": false,
                            // TODO: Set if available.
                            "key": null
                        }
                    });
                } else
                // TODO: Document
                if (request.$method === "lockbox-half-key-store") {
/*
        "nonce": request.nonce,
        "identity": {
            "accessToken": request.identity.accessToken,
            "accessSecretProof": request.identity.accessSecretProof,
            "accessSecretProofExpires": request.identity.accessSecretProofExpires,            
            // TODO: What is this used for?
            "type": self.session.authType,
            // TODO: What is this used for?
            "identifier": "",
            "uri": request.identity.uri
        },
        "lockbox": {
            "keyEncrypted": keyEncrypted
        }
*/

console.log("TODO: Store lockbox key:", request.lockbox.keyEncrypted);

                    return respond({});
                } else
                // @see http://docs.openpeer.org/OpenPeerProtocolSpecificationAnnexRolodex/#IdentityServiceRequestsAnnex-IdentityAccessRolodexCredentialsGetRequest
                if (request.$method === "identity-access-rolodex-credentials-get") {

console.log("TODO: Get rolodex token for:", request.identity);

                    return respond({
                        "rolodex": {
                            "serverToken": "b3ff46bae8cacd1e572ee5e158bcb04ed9297f20-9619e3bc-4cd41c9c64ab2ed2a03b45ace82c546d"
                        }
                    });
                }
            } else
            if (request.$handler === "identity") {
                // @see http://docs.openpeer.org/OpenPeerProtocolSpecification/#IdentityServiceRequests-IdentityAccessValidateRequest
                if (request.$method === "identity-access-validate") {
/*
"nonce": "ed585021eec72de8634ed1a5e24c66c2",
    "purpose": "whatever",
    "identity": {
      "accessToken": "a913c2c3314ce71aee554986204a349b",
      "accessSecretProof": "b7277a5e49b3f5ffa9a8cb1feb86125f75511988",
      "accessSecretProofExpires": 43843298934,

      "uri": "identity://domain.com/alice",
      "provider": "domain.com"
    }
*/

console.log("TODO: Validate identity");

                    return respond({});
                }
            } else
            if (request.$handler === "identity") {
                // @see http://docs.openpeer.org/OpenPeerProtocolSpecification/#IdentityServiceRequests-IdentityLookupUpdateRequest
                if (request.$method === "identity-lookup-update") {
/*
"nonce": "ed585021eec72de8634ed1a5e24c66c2",
    "lockbox": {
      "$id": "123456",
      "domain": "domain.com",
      "accessToken": "a913c2c3314ce71aee554986204a349b",
      "accessSecretProof": "b7277a5e49b3f5ffa9a8cb1feb86125f75511988",
      "accessSecretProofExpires": 43843298934
    },
    "identity": {
      "accessToken": "a913c2c3314ce71aee554986204a349b",
      "accessSecretProof": "b7277a5e49b3f5ffa9a8cb1feb86125f75511988",
      "accessSecretProofExpires": 43843298934,

      "uri": "identity://domain.com/alice",
      "provider": "domain.com",

      "stableID": "0acc990c7b6e7d5cb9a3183d432e37776fb182bf",
      "peer": {...},
      "priority": 5,
      "weight": 1,
      "contactProofBundle": {
        "contactProof": {
          "$id": "2d950c960b52c32a4766a148e8a39d0527110fee",
          "stableID": "0acc990c7b6e7d5cb9a3183d432e37776fb182bf",
          "contact": "peer://example.com/ab43bd44390dabc329192a392bef1",
          "uri": "identity://domain.com/alice",
          "created": 54593943,
          "expires": 65439343
        },
        "signature": {
          "reference": "#2d950c960b52c32a4766a148e8a39d0527110fee",
          "algorithm": "http://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1",
          "digestValue": "Wm1Sa...lptUT0=",
          "digestSigned": "ZmRh...2FzZmQ=",
          "key": { "uri": "peer://example.com/ab43bd44390dabc329192a392bef1" }
        }
      }
    }


    "nonce": "ed585021eec72de8634ed1a5e24c66c2",
    "identity": {
      "accessToken": "a913c2c3314ce71aee554986204a349b",
      "accessSecretProof": "b7277a5e49b3f5ffa9a8cb1feb86125f75511988",
      "accessSecretProofExpires": 43843298934,

      "uri": "identity://domain.com/alice",
      "provider": "domain.com"      
    }
*/

console.log("TODO: Update identity");

                    return respond({});
                }
            }

        } catch (err) {
            return next(err);
        }

        return next();
    });

});


function generateId () {
    return parseInt(CRYPTO.randomBytes(8).toString('hex'), 16).toString(36) + "-" + Date.now().toString(36);
}

