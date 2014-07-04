
const ASSERT = require("assert");
const PATH = require("path");
const FS = require("fs-extra");
const EXPRESS = require("express");
const EXPRESS_SESSION = require("express-session");
const REQUEST = require("request");
const DEEPMERGE = require("deepmerge");
const CONNECT_MEMCACHED = require("connect-memcached");
const MEMCACHED = require('memcached');
const COOKIE_PARSER = require("cookie-parser");
const BODY_PARSER = require("body-parser");
const MORGAN = require("morgan");
const METHOD_OVERRIDE = require("method-override");
const WAITFOR = require("waitfor");
const Q = require("q");
const DOT = require("dot");
const SEND = require("send");


var PORT = process.env.PORT || 8080;


exports.for = function(module, packagePath, preAutoRoutesHandler) {

	var exports = module.exports;

	exports.main = function(callback) {

		try {
	
		    var pioConfig = FS.readJsonSync(PATH.join(__dirname, "../.pio.json"));

		    var app = EXPRESS();

	        app.use(MORGAN());
	        app.use(COOKIE_PARSER());
	        app.use(BODY_PARSER());
	        app.use(METHOD_OVERRIDE());
			if (
				pioConfig.config["pio.service"].config &&
				pioConfig.config["pio.service"].config.memcachedHost
			) {
				var sessionStore = new (CONNECT_MEMCACHED(EXPRESS_SESSION))({
					prefix: "op-identity-provider-server-nodejs",
					hosts: [
						pioConfig.config["pio.service"].config.memcachedHost
					]
				});
				app.use(EXPRESS_SESSION({
					secret: 'session secret',
					key: 'sid',
					proxy: 'true',
					store: sessionStore
				}));
				if (!app.helpers) {
					app.helpers = {};
				}
				app.helpers.destroyAllSessions = function() {
					sessionStore.prefix = originalSessionPrefix + Date.now() + "-";
				}
			}
			
	        if (preAutoRoutesHandler) {
	        	preAutoRoutesHandler(app, pioConfig.config["pio.service"], {
	        		API: {
	        			FS: FS,
	        			EXPRESS: EXPRESS,
						DEEPMERGE: DEEPMERGE,
						WAITFOR: WAITFOR,
						Q: Q,
						REQUEST: REQUEST,
						SEND: SEND
	        		}
	        	});
	        }

	        // Default routes inserted by config.

		    app.get("/favicon.ico", function (req, res, next) {
		    	return res.end();
		    });

		    function processRequest(requestConfig, req, res, next) {

	    		var pathname = req._parsedUrl.pathname;
	    		if (pathname === "/") pathname = "/index";

	    		function formatPath(callback) {

	    			function checkExtensions(originalPath, callback) {
			    		return FS.exists(originalPath, function(exists) {
			    			if (/\/[^\/]+\.[^\.]+$/.test(pathname)) {
				    			return callback(null, originalPath, exists);
			    			}
			    			if (!exists) {
			    				var path = originalPath;
			    				if (pathname === "/index") {
			    					pathname += ".html";
			    					path += ".html";
			    				} else {
			    					pathname += ".htm";
			    					path += ".htm";
			    				}
					    		return FS.exists(path, function(exists) {
					    			return callback(null, path, exists);
					    		});
			    			}
			    			return callback(null, originalPath, true);
			    		});
	    			}

	    			return checkExtensions(PATH.join(packagePath, "www", pathname), callback);
	    		}

		    	return formatPath(function(err, path, pathExists) {
		    		if (err) return next(err);
	    			if (!pathExists) {
	    				return next();
	    			}
					return FS.readFile(path, "utf8", function(err, templateSource) {
						if (err) return callback(err);

						// TODO: Get own instance: https://github.com/olado/doT/issues/112
                        DOT.templateSettings.strip = false;
                        DOT.templateSettings.varname = "view";
                        var compiled = null;
                        try {
                            compiled = DOT.template(templateSource);
                        } catch(err) {
							console.error("templateSource", templateSource);
                        	console.error("Error compiling template: " + path);
                            return callback(err);
                        }

						var result = null;
                        try {
                            result = compiled(res.view || {});
                        } catch(err) {
                        	console.error("Error running compiled template: " + path);
                            return next(err);
                        }

                        // TODO: Send proper headers.
                        res.writeHead(200, {
                        	"Content-Type": "text/html",
                        	"Content-Length": result.length
                        });
                        return res.end(result);
					});
	    		});
		    }

		    app.post(/^\//, function(req, res, next) {
		    	if (req.headers["x-config"] === "in-body") {
					return processRequest(req.body, req, res, next);
		    	}
		    	return next();
		    });

		    app.get(/^\//, function(req, res, next) {
		    	return processRequest(false, req, res, next);
		    });


			var server = app.listen(PORT);

			console.log("Listening at: http://localhost:" + PORT);

		    return callback(null, {
		        server: server
		    });
		} catch(err) {
			return callback(err);
		}
	}

	if (require.main === module) {
		return exports.main(function(err) {
			if (err) {
				console.error(err.stack);
				process.exit(1);
			}
			// Keep server running.
		});
	}
}


exports.for(module, __dirname);

