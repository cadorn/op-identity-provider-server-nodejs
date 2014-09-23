

const ASSERT = require("assert");
const PATH = require("path");
const FS = require("fs");
const URL = require("url");
const PASSPORT = require("passport");
const PASSPORT_OAUTH2 = require("passport-oauth2");
const PASSPORT_FACEBOOK = require("passport-facebook");
const PASSPORT_TWITTER = require("passport-twitter");
const REQUEST = require("request");
const CRYPTO = require("crypto");
const UTILS = require("op-primitives-server-nodejs/utils");

const MODEL_IDENTITY_LOOKUP = require("./models/identity-lookup");


var passport = null

require("op-primitives-server-nodejs/server-prototype").for(module, __dirname, function(app, serviceConfig, HELPERS) {


    function loadConfiguration(host, callback) {
        if (!host) {
            return callback(new Error("No 'host' specified!"));
        }
        var m = host.match(/^(.+?)\.identity\./);
        if (!m) {
            var err = new Error("Could not parse host");
            err.code = 404;
            return callback(err);
        }
        var domain = m[1].replace(/-{2}/g, "__DASH__").replace(/-/g, ".").replace(/__DASH__/g, "-");
        return HELPERS.API.REQUEST({
            url: "http://" + serviceConfig.config.hcs.accounts.hostname + "/apps/" + domain + "/runtime-config.json?token=" + serviceConfig.config.hcs.accounts.token,
            json: true
        }, function (err, response, body) {
            if (err) return callback(err);
            if (!body) {
                var err = new Error("Domain not found");
                err.code = 404;
                return callback(err);
            }
            return callback(null, body);
        });
    }

	passport = new PASSPORT.Passport();
	passport.serializeUser(function(user, done) {
	    return done(null, user);
	});
	passport.deserializeUser(function(obj, done) {
	    return done(null, obj);
	});

    passport.use(new PASSPORT_FACEBOOK.Strategy({
        clientID: "tmp",
        clientSecret: "tmp",
        callbackURL: serviceConfig.config.identity.oauth.callbackURL
    }, function(accessToken, refreshToken, profile, done) {
        return done(null, {
            "type": "facebook",
            "id": ""+profile.id,
            "username": profile.displayName,
            "accessToken": accessToken
        });
    }));

    passport.use(new PASSPORT_TWITTER.Strategy({
        consumerKey: "tmp",
        consumerSecret: "tmp",
        callbackURL: serviceConfig.config.identity.oauth.callbackURL
    }, function(accessToken, accessTokenSecret, profile, done) {
        return done(null, {
            "type": "twitter",
            "id": profile.id,
            "username": profile.username,
            "accessToken": accessToken,
            "accessTokenSecret": accessTokenSecret
        });
    }));

	var oauthStrategy = new PASSPORT_OAUTH2.Strategy({
        callbackURL: serviceConfig.config.identity.oauth.callbackURL,
        // NOTE: These values get set dynamically based on the request $domain upon oauth authorization.
        authorizationURL: "tmp",
        tokenURL: "tmp",
        clientID: "tmp",
        clientSecret: "tmp"
    }, function(accessToken, refreshToken, profile, done) {
	    return done(null, {
            "type": "oauth",
            "id": ""+profile.id,
            "username": profile.username,
            "accessToken": accessToken,
            "refreshToken": refreshToken
	    });
	  }
	);
    oauthStrategy.userProfile = function(accessToken, callback) {
        return REQUEST.get(passport._strategies.oauth2._profileURL + "?access_token=" + accessToken, function(err, res, body) {
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
        return next();
    });

    app.get("/test", function(req, res, next) {
        res.view.hcs = {
            config: {
                "logger": {
                    "host": "logger-v1-rel-lespaulinst2-i.hcs.io"
                },
                "hcs": {
                    "password1": {
                        "uri": "http://hfservice-v1-rel-lespaulinst2-i.hcs.io/password1"
                    },
                    "password2": {
                        "uri": "http://hfservice-v1-rel-lespaulinst2-i.hcs.io/password2"
                    }
                },
                "rolodex": {
                    "sharedSecret": "kjdfkj82398jkwefkjwkjef892398welkefklewkflo234230ioewklw"
                },
                "identity": {
                    "domain": serviceConfig.config.test.identity.domain,
                    "oauth": {
                        "logoutURL": "http://" + serviceConfig.config.test.identity.oauth.hostname + ":81/logout",
                        "authorizationURL": "http://" + serviceConfig.config.test.identity.oauth.hostname + ":81/authorize",
                        "tokenURL": "http://" + serviceConfig.config.test.identity.oauth.hostname + ":81/token",
                        "clientID": "hcs-stack-int~test.oauth.client",
                        "clientSecret": "hcs-stack-int~test.oauth.client~secret",
                        "profileURL": "http://" + serviceConfig.config.test.identity.oauth.hostname + ":81/profile",
                        "publicProfileURL": "http://" + serviceConfig.config.test.identity.oauth.hostname + ":81/profile/{id}",
                        "publicVcardProfileURL": "http://" + serviceConfig.config.test.identity.oauth.hostname + ":81/profile/{id}?format=vcard",
                        "publicFeedURL": "http://" + serviceConfig.config.test.identity.oauth.hostname + ":81/profile/{id}/feed",
                        "publicAvatarURL": "http://" + serviceConfig.config.test.identity.oauth.hostname + ":81/profile/{id}/avatar"
                    }
                },
                "contacts": {
                    "contactsURL": "http://" + serviceConfig.config.test.identity.oauth.hostname + ":82/contacts"
                }
            }
        };
    	return next();
    });


    function updateAuthConfig (req) {
        if (!req.session.login) {
            return;
        }
        var services = req.session.login.accountConfig.services;

        if (services && services.oauth) {
            passport._strategies.oauth2._oauth2._clientId = services.oauth.mergedConfiguration.oauth.clientID;
            passport._strategies.oauth2._oauth2._clientSecret = services.oauth.mergedConfiguration.oauth.clientSecret;
            passport._strategies.oauth2._oauth2._authorizeUrl = services.oauth.mergedConfiguration.oauth.authorizationURL;
            passport._strategies.oauth2._oauth2._accessTokenUrl = services.oauth.mergedConfiguration.oauth.tokenURL;
            passport._strategies.oauth2._key = "oauth2:" + URL.parse(services.oauth.mergedConfiguration.oauth.authorizationURL).hostname;
            passport._strategies.oauth2._profileURL = services.oauth.mergedConfiguration.profile.profileURL;
        } else {
            passport._strategies.oauth2._oauth2._clientId = "tmp";
            passport._strategies.oauth2._oauth2._clientSecret = "tmp";
            passport._strategies.oauth2._oauth2._authorizeUrl = "tmp";
            passport._strategies.oauth2._oauth2._accessTokenUrl = "tmp";
            passport._strategies.oauth2._key = "tmp";
            passport._strategies.oauth2._profileURL = "tmp";
        }

        // NOTE: We force auth via v1. It is important that ALL logins for this app happen
        //       using the v1 API. If an account logs in using v2 API ONLY ONCE, the facebook system
        //       will always respond using v2 API rules!
        //       See: https://github.com/hookflashco/hcs-stack-integration/issues/40#issuecomment-54231715
//        passport._strategies.facebook._oauth2._authorizeUrl = "https://www.facebook.com/dialog/oauth?type=web_server";
//        passport._strategies.facebook._oauth2._accessTokenUrl = "https://graph.facebook.com/oauth/access_token";
        if (services && services.facebook) {
            passport._strategies.facebook._oauth2._clientId = services.facebook.mergedConfiguration.appID;
            passport._strategies.facebook._oauth2._clientSecret = services.facebook.mergedConfiguration.appSecret;
        } else {
            passport._strategies.facebook._oauth2._clientId = "tmp";
            passport._strategies.facebook._oauth2._clientSecret = "tmp";
        }

        if (services && services.twitter) {
            passport._strategies.twitter._oauth._consumerKey = services.twitter.mergedConfiguration.apiKey;
            passport._strategies.twitter._oauth._consumerSecret = services.twitter.mergedConfiguration.apiSecret;
        } else {
            passport._strategies.twitter._oauth._consumerKey = "tmp";
            passport._strategies.twitter._oauth._consumerSecret = "tmp";
        }
    }


    app.get('/login/facebook', function(req, res, next) {
        updateAuthConfig(req);
        if (passport._strategies.facebook._oauth2._clientId === "tmp") {
            return next(new Error("'facebook' service not configured!"));
        }
        req.logout();
        if (req.query && req.query.returnTo) {
            req.session.returnTo = req.query.returnTo;
        }
        req.session.authType = "facebook";
        return next();
    }, passport.authenticate('facebook'/*, {
        scope: [
            // v1
            "read_friendlists"
            // v2
            //"user_friends"
        ]
    }*/));

    app.get('/login/twitter', function(req, res, next) {
        updateAuthConfig(req);
        if (passport._strategies.twitter._oauth._consumerKey === "tmp") {
            return next(new Error("'twitter' service not configured!"));
        }
        req.logout();
        if (req.query && req.query.returnTo) {
            req.session.returnTo = req.query.returnTo;
        }
        req.session.authType = "twitter";
        return next();
    }, passport.authenticate('twitter'));


	app.get('/login/oauth', function(req, res, next) {
        updateAuthConfig(req);
        if (passport._strategies.oauth2._oauth2._clientId === "tmp") {
            return next(new Error("'oauth2' service not configured!"));
        }
        req.logout();
        if (req.query && req.query.returnTo) {
            req.session.returnTo = req.query.returnTo;
        }
        req.session.authType = "oauth2";
        return next();
    }, passport.authenticate('oauth2'));

    app.get('/oauth/callback', function(req, res, next) {
        updateAuthConfig(req);
        return passport.authenticate(req.session.authType, {
            failureRedirect: '/fail'
        })(req, res, next);
    }, function(req, res, next) {
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

    app.get('/facebook_v1/callback', function(req, res, next) {
        if (!req.query.credentialsToken) {
            return next(new Error("No 'credentialsToken' set in query string!"));
        }
        function resolveToken(token, callback) {
            if (!/^https?:/.test(token)) return callback(null, token);
            return REQUEST(token, function(err, response, body) {
                if (err) return callback(err);
                if (response.statusCode !== 200) {
                    return callback(new Error("Got status " + response.statusCode + " while fetching: " + token));
                }
                return callback(null, body);
            });
        }
        return resolveToken(req.query.credentialsToken, function(err, token) {
            if (err) return next(err);

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
                    var tokenSecret = serviceConfig.config.rolodex.sharedSecret;
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

            return parseToken(token, function(err, tokenInfo) {
                if (err) return next(err);
                req.session.user = {
                    "type": "facebook_v1",
                    "id": tokenInfo.originalId,
                    "username": tokenInfo.displayName,
                    "accessToken": tokenInfo.token
                };
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
        });
    });    

    app.get(/^\/logout$/, function (req, res) {
        updateAuthConfig(req);
    	req.logout();
        delete req.session.user;
        delete req.session.authorized;
        res.writeHead(302, {
            "Location": "/"
        });
        return res.end();
    });


    // @see https://github.com/openpeer/hcs-system/blob/master/architecture/servers/HCS%20protocol%20-%20Identity%20Provider.md#44-social-provider-authentication-request
    app.get(/^\/login.html$/, function (req, res) {
        return FS.readFile(serviceConfig.config.loginTemplatePath, "utf8", function(err, template) {

            template = template.replace(/\{\{\s*config.HF_LOGGER_HOST\s*\}\}/g, serviceConfig.config.logger.host);
            template = template.replace(/\{\{\s*config.ASSET_PATH\s*\}\}/g, "/assets");
            template = template.replace(/\{\{\s*config.HF_PASSWORD1_BASEURI\s*\}\}/g, serviceConfig.config.hcs.password1.uri);
            template = template.replace(/\{\{\s*config.HF_PASSWORD2_BASEURI\s*\}\}/g, serviceConfig.config.hcs.password2.uri);
            template = template.replace(/\{\{\s*config.SESSION_identityServiceAuthenticationURL\s*\}\}/g, "");

            return loadConfiguration(req.query.domain || req.cookies['test-config-identity-domain'] || null, function(err, config) {
                if (err) {
                    console.error("Warning: Test domain not yet specified!", err.stack);
                } else {
                    var services = [];
                    if (config.services) {
                        for (var name in config.services) {
                            services.push({
                                "name": config.services[name].service,
                                "domain": config.services[name].identity.domain
                            });
                        }
                    }
                    template = template.replace(/\{\{\s*config.HF_CONFIGURED_SERVICES\s*\}\}/g, JSON.stringify(services));
                }
                res.writeHead(200, {
                    "Content-Type": "text/html",
                    "Content-Length": template.length
                });
                return res.end(template);
            });
        });
    });
    app.get(/^\/assets\//, function (req, res, next) {
        var path = PATH.join(PATH.dirname(serviceConfig.config.loginTemplatePath), req.url.replace(/^\/assets/, ""));
        return HELPERS.API.SEND(req, PATH.basename(path))
            .root(PATH.dirname(path))
            .on('error', next)
            .pipe(res);
    });


    // TODO: Store active tokens in database.
    var activeTokens = {};

    function processRequest(req, res, next) {

        var request = req.body.request || null;
        if (!request) {
            return next(new Error("Request did not contain a 'request' property!"));
        }

        console.log("Request: " + JSON.stringify(request, null, 4));

        function respond (data) {
            var result = {
                "$domain": request.$domain,
                "$id": request.$id,
                "$handler": request.$handler,
                "$method": request.$method,
                "$epoch": Math.floor(Date.now() / 1000)
            };
            for (var name in data) {
                result[name] = data[name];
            }
            console.log("Result: " + JSON.stringify(result, null, 4));
            var payload = JSON.stringify({
                result: result
            }, null, 4);
            res.writeHead(200, {
                "Content-Type": "application/json",
                "Content-Length": payload.length
            });
            return res.end(payload);
        }

        function validateAccess(request, callback) {
            if (
                req.session.credentials &&
                request.identity.accessToken === req.session.credentials.accessToken &&
                request.identity.uri === req.session.credentials.uri
            ) {
                if (request.nonce === "na") {
                    if (
                        // TODO: This needs to be fixed when we send the actual proof. [Security]
                        request.identity.accessSecretProof === req.session.credentials.accessSecret &&
                        // TODO: This needs to be fixed when we send the actual proof. [Security]
                        request.identity.accessSecretProofExpires === req.session.credentials.accessSecretExpires
                    ) {
                        console.log("validateAccess - load session by req.session.credentials");
                        return callback(null, true);
                    } else {
                        return callback(null, false);
                    }
                } else {
                    return callback(null, true);
                }
            } else
            if (
                activeTokens[request.identity.accessToken] &&
                request.identity.uri === activeTokens[request.identity.accessToken].credentials.uri
                // TODO: Verify access proof.
            ) {
                console.log("validateAccess - load session by request.identity.accessToken");
                for (var name in activeTokens[request.identity.accessToken]) {
                    req.session[name] = activeTokens[request.identity.accessToken][name];
                }
                return callback(null, true);
            }
            return callback(null, false);
        }

        try {

            if (request.$handler === "identity-provider") {
                // @see https://github.com/openpeer/hcs-system/blob/master/architecture/servers/HCS%20protocol%20-%20Identity%20Provider.md#44-social-provider-authentication-request
                if (request.$method === "oauth-provider-authentication") {

                    ASSERT.equal(typeof request.clientAuthenticationToken, "string", "'request.clientAuthenticationToken' must be set!");
                    ASSERT.equal(typeof request.callbackURL, "string", "'request.callbackURL' must be set!");
                    ASSERT.equal(typeof request.identity.type, "string", "'request.identity.type' must be set!");

console.log("request.identity.reloginKey", request.identity.reloginKey);
console.log("activeTokens", JSON.stringify(Object.keys(activeTokens), null, 4));

                    return loadConfiguration(request.$domain, function (err, accountConfig) {
                        if (err) return next(err);

                        if (
                            request.identity.reloginKey &&
                            activeTokens[request.identity.reloginKey]
                        ) {
                            console.log("Login using relogin key: " + request.identity.reloginKey);

    console.log("req.cookies.sid", req.cookies.sid);
    console.log("req.sessionID", req.sessionID);
    console.log("req.session", req.session);

                            for (var name in activeTokens[request.identity.reloginKey]) {
                                req.session[name] = activeTokens[request.identity.reloginKey][name];
                            }

                            req.session.login.clientAuthenticationToken = request.clientAuthenticationToken;
                            req.session.login.callbackURL = request.callbackURL;

    console.log("req.session2", req.session);

                            return respond({
                                "serverAuthenticationToken": req.session.login.serverAuthenticationToken
                            });
                        } else {
                            req.session.login = {
                                clientAuthenticationToken: request.clientAuthenticationToken,
                                callbackURL: request.callbackURL,
                                identity: request.identity,
                                serverAuthenticationToken: UTILS.generateId(),
                                // TODO: Remove 'reloginKey' here as it should only be known to the client. [Security]
                                reloginKey: null,   // Gets set at login below, after authenticating user, before returning to client.
                                accountConfig: accountConfig
                            };

                            var services = accountConfig.services;

                            if (!services || !services[request.identity.type] || !services[request.identity.type].enabled) {
                                return next(new Error("Identity type '" + request.identity.type + "' not configured or enabled!"));
                            }

                            var providerRedirectURL = null;
                            // TODO: Ensure `request.identity.type` is configured.
                            if (request.identity.type === "oauth") {
                                providerRedirectURL = "/login/oauth";
                            } else
                            if (request.identity.type === "facebook") {
                                providerRedirectURL = "/login/facebook";
                            } else
                            if (request.identity.type === "facebook_v1") {
                                providerRedirectURL = services[request.identity.type].mergedConfiguration.loginUrl + "?callback=" + serviceConfig.config.identity.facebook_v1.callbackURL;
                            } else
                            if (request.identity.type === "twitter") {
                                providerRedirectURL = "/login/twitter";
                            } else {
                                return next(new Error("Unknown identity type '" + request.identity.type + "'!"));
                            }

                            return respond({
                                "providerRedirectURL": providerRedirectURL,
                                "serverAuthenticationToken": req.session.login.serverAuthenticationToken
                            });
                        }
                    });
                } else
                // @see https://github.com/openpeer/hcs-system/blob/master/architecture/servers/HCS%20protocol%20-%20Identity%20Provider.md#456-example---social-login
                if (request.$method === "login") {

                    ASSERT.equal(typeof request.proof.clientAuthenticationToken, "string", "'request.proof.clientAuthenticationToken' must be set!");
                    ASSERT.equal(typeof request.proof.serverAuthenticationToken, "string", "'request.proof.serverAuthenticationToken' must be set!");
                    ASSERT.equal(typeof request.identity.type, "string", "'request.identity.type' must be set!");
                    ASSERT.equal(typeof request.identity.base, "string", "'request.identity.base' must be set!");

console.log("req.cookies.sid", req.cookies.sid);
console.log("req.sessionID", req.sessionID);
console.log("req.session", req.session);

                    if (!req.session.login) {
                        return respond({
                            error: {
                                $id: 403,
                                reason: "No active login session"
                            }
                        });
                    }
                    if (req.session.login.clientAuthenticationToken !== request.proof.clientAuthenticationToken) {
                        return respond({
                            error: {
                                $id: 403,
                                reason: "clientAuthenticationToken does not match"
                            }
                        });
                    }
                    if (req.session.login.serverAuthenticationToken !== request.proof.serverAuthenticationToken) {
                        return respond({
                            error: {
                                $id: 403,
                                reason: "serverAuthenticationToken does not match"
                            }
                        });
                    }
                    if (req.session.login.identity.type !== request.identity.type) {
                        return respond({
                            error: {
                                $id: 403,
                                reason: "identity.type does not match"
                            }
                        });
                    }

                    if (!req.session.user) {
                        return respond({
                            error: {
                                $id: 403,
                                reason: "no session found on server. reload page."
                            }
                        });
                    }

                    // TODO: Use the `serverAuthenticationToken` to auth session. Better yet, use openpeer protocol sdk
                    //       and erect a standard openeer session for idprovider.

                    // TODO: Instead of storing this on the session it should be stored in DB by access token. [Security]
                    req.session.credentials = {
                        "accessToken": UTILS.generateId(),
                        "accessSecret": UTILS.generateId(),
                        "accessSecretExpires": Math.floor(Date.now()/1000 + 60 * 60 * 24),
                        "uri": request.identity.base.replace(/\/$/, "") + "/" + req.session.user.id
                    };

                    // TODO: Remove 'reloginKey' here as it should only be known to the client. [Security]
                    req.session.login.reloginKey = UTILS.generateId();

                    activeTokens[req.session.credentials.accessToken] = JSON.parse(JSON.stringify({
                        login: req.session.login,
                        user: req.session.user,
                        authorized: req.session.authorized,
                        authType: req.session.authType,
                        credentials: {
                            uri: req.session.credentials.uri
                        },
                        passport: {}
                    }));

                    // NOTE: For now instead of resetting the login key we are going to use
                    //       the existing one if there is one
                    //req.session.login.reloginKey = req.session.credentials.accessToken;
                    if (req.session.login.reloginKey) {
                        activeTokens[req.session.login.reloginKey] = activeTokens[req.session.credentials.accessToken];
                    }

                    return respond({
                        "identity": {
                            "accessToken": req.session.credentials.accessToken,
                            "accessSecret": req.session.credentials.accessSecret,
                            "accessSecretExpires": req.session.credentials.accessSecretExpires,
                            "uri": req.session.credentials.uri,
                            // TODO: Remove 'reloginKey' here as it should only be known to the client. [Security]
                            "reloginKey": req.session.login.reloginKey
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
                    return validateAccess(request, function(err, hasAccess) {
                        if (err) return next(err);
                        if (!hasAccess) {
                            return respond({
                                "error": {
                                    "reason": "Invalid Token",
                                    "$id": 403
                                }
                            });
                        } else {

                            // TODO: Store lockbox key in DB instead of on session.
                            req.session.lockbox = request.lockbox;

                            return respond({});
                        }
                    });
                } else
                // @see http://docs.openpeer.org/OpenPeerProtocolSpecificationAnnexRolodex/#IdentityServiceRequestsAnnex-IdentityAccessRolodexCredentialsGetRequest
                if (request.$method === "identity-access-rolodex-credentials-get") {
                    return validateAccess(request, function(err, hasAccess) {
                        if (err) return next(err);
                        if (!hasAccess) {
                            return respond({
                                "error": {
                                    "reason": "Invalid Token",
                                    "$id": 403
                                }
                            });
                        } else {

                            function makeToken(callback) {

console.log("makeToken", req.session);
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
                                var tokenInfo = {
                                    service: req.session.user.type,
                                    identifier: req.session.user.id,
                                    username: req.session.user.username,
                                    token: req.session.user.accessToken
                                };
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
console.log("tokenInfo", tokenInfo);                                
                                var tokenSecret = serviceConfig.config.rolodex.sharedSecret;
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

                            return makeToken(function(err, token) {
                                if (err) return next(err);

                                return respond({
                                    "rolodex": {
                                        "serverToken": token
                                    }
                                });
                            });
                        }
                    });
                }
            } else
            if (request.$handler === "identity") {
                // @see http://docs.openpeer.org/OpenPeerProtocolSpecification/#IdentityServiceRequests-IdentityAccessValidateRequest
                if (request.$method === "identity-access-validate") {
                    return validateAccess(request, function(err, hasAccess) {
                        if (err) return next(err);

console.log("identity-access-validate - req.session", req.session);
console.log("identity-access-validate - hasAccess", hasAccess);

                        if (!hasAccess) {
                            return respond({
                                "error": {
                                    "reason": "Invalid Token",
                                    "$id": 403
                                }
                            });
                        } else {
                            // TODO: Do we need to do additional validation?
                            return respond({});
                        }
                    });
                } else
                // @see http://docs.openpeer.org/OpenPeerProtocolSpecification/#IdentityServiceRequests-IdentityLookupUpdateRequest
                if (request.$method === "identity-lookup-update") {
                    return validateAccess(request, function(err, hasAccess) {
                        if (err) return next(err);

console.log("identity-lookup-update - req.session", req.session);
console.log("identity-lookup-update - hasAccess", hasAccess);

                        if (!hasAccess) {
                            return respond({
                                "error": {
                                    "reason": "Invalid Token",
                                    "$id": 403
                                }
                            });
                        } else {
                            if (request.identity.peer) {

                                var identity = JSON.parse(JSON.stringify(request.identity));
                                delete identity.accessToken;
                                delete identity.accessSecretProof;
                                delete identity.accessSecretProofExpires;

                                identity.name = "Username: " + req.session.user.id;
                                // e.g. http://hcs-stack-cust-oauth-ia10ccf8-1.vm.opp.me:81/profile/{id}
                                identity.profile = req.session.login.accountConfig.services.oauth.mergedConfiguration.profile.publicProfileURL.replace(/\{id\}/g, req.session.user.id);
                                // e.g. http://hcs-stack-cust-oauth-ia10ccf8-1.vm.opp.me:81/profile/{id}?format=vcard
                                identity.vprofile = req.session.login.accountConfig.services.oauth.mergedConfiguration.profile.publicVcardProfileURL.replace(/\{id\}/g, req.session.user.id);
                                // e.g. http://hcs-stack-cust-oauth-ia10ccf8-1.vm.opp.me:81/profile/{id}/feed
                                identity.feed = req.session.login.accountConfig.services.oauth.mergedConfiguration.profile.publicFeedURL.replace(/\{id\}/g, req.session.user.id);
                                // e.g. http://hcs-stack-cust-oauth-ia10ccf8-1.vm.opp.me:81/profile/{id}/avatar
                                identity.avatars = {
                                    "avatar": {
                                        "url": req.session.login.accountConfig.services.oauth.mergedConfiguration.profile.publicAvatarURL.replace(/\{id\}/g, req.session.user.id)
                                    }
                                };

                                return MODEL_IDENTITY_LOOKUP.create(res.r, identity, function (err) {
                                    if (err) return next(err);
                                    return respond({});
                                });
                            } else {
                                return MODEL_IDENTITY_LOOKUP.remove(res.r, request.identity, function (err) {
                                    if (err) return next(err);
                                    return respond({});
                                });
                            }
                        }
                    });
                }
            } else
            if (request.$handler === "identity-lookup") {
                // @see http://docs.openpeer.org/OpenPeerProtocolSpecification/#IdentityLookupServiceRequests-IdentityLookupCheckRequest
                if (request.$method === "identity-lookup-check") {
                    if (!Array.isArray(request.providers.provider)) {
                        request.providers.provider = [
                            request.providers.provider
                        ];
                    }
                    return MODEL_IDENTITY_LOOKUP.check(res.r, request.providers.provider, function (err, identities) {
                        if (err) return next(err);
                        return respond({
                            "identities": {
                                "identity": identities
                            }
                        });
                    });
                } else
                // @see http://docs.openpeer.org/OpenPeerProtocolSpecification/#IdentityLookupServiceRequests-IdentityLookupRequest
                if (request.$method === "identity-lookup") {
                    if (!Array.isArray(request.providers.provider)) {
                        request.providers.provider = [
                            request.providers.provider
                        ];
                    }
                    return MODEL_IDENTITY_LOOKUP.lookup(res.r, request.providers.provider, function (err, identities) {
                        if (err) return next(err);
                        return respond({
                            "identities": {
                                "identity": identities
                            }
                        });
                    });
                }
            }
        } catch (err) {
            return next(err);
        }

        return next();
    }

    app.post(/^\/api$/, processRequest);

    app.post(/^\/oauth-provider-authentication$/, processRequest);
    app.post(/^\/login$/, processRequest);
    app.post(/^\/lockbox-half-key-store$/, processRequest);
    app.post(/^\/identity-access-rolodex-credentials-get$/, processRequest);
    app.post(/^\/identity-access-validate$/, processRequest);
    app.post(/^\/identity-lookup-update$/, processRequest);
    app.post(/^\/identity-lookup-check$/, processRequest);
    app.post(/^\/identity-lookup$/, processRequest);

});

