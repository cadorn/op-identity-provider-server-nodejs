
const WAITFOR = require("waitfor");
const CRYPTO = require('crypto');

const DB_NAME = "hcs_integration";


function randomString(length) {
  return CRYPTO.randomBytes(length / 2).toString('hex');
}



function get (r, base, uri, domain, callback) {
	return r.tableEnsure(DB_NAME, "identity_lookup", "identities", function(err, identitiesTable) {
        if (err) return callback(err);
        if (uri === null) {
			return identitiesTable.filter({
	    		base: base
	    	}).run(r.conn, function (err, cursor) {
			    if (err) return callback(err);
				return cursor.toArray(function(err, results) {
				    if (err) return callback(err);
					return callback(null, results);
				});
			});
        } else {
			return identitiesTable.get(domain + "~" + uri).run(r.conn, function (err, result) {
			    if (err) return callback(err);
			    if (!result) {
					return callback(null, null);
			    }	
				return callback(null, result);
			});
		}
	});
}

function set (r, uri, data, callback) {
	return r.tableEnsure(DB_NAME, "identity_lookup", "identities", function(err, identitiesTable) {
        if (err) return callback(err);
		if (data === null) {
			return identitiesTable.get(uri).delete().run(r.conn, function (err, result) {
			    if (err) return callback(err);
				return callback(null);
			});
		} else {
			data.id = uri;
			return identitiesTable.insert(data, {
			    upsert: true
			}).run(r.conn, function (err, result) {
			    if (err) return callback(err);
				return callback(null);
			});
		}
	});
}

exports.create = function (r, identity, domain, callback) {
	console.log("create", identity.uri);
	return set(r, domain + "~" + identity.uri, {
		updatedOn: Date.now(),
		expiresOn: Date.now() + 60 * 60 * 24 * 1000,
		identity: identity,
		base: identity.uri.replace(/^(identity:\/\/[^\/]+\/).*$/, "$1"),
		domain: domain,
		uri: identity.uri
	}, callback);
}

exports.remove = function (r, identity, domain, callback) {
	return set(r, domain + "~" + identity.uri, null, callback);
}

exports.check = function (r, providers, domain, callback) {
	var identities = [];
	if (
		providers.length === 1 &&
		providers[0] &&
		providers[0].identities === "*"
	) {
		return get(r, providers[0].base, null, domain, function(err, identities) {
			if (err) return callback(err);
//			console.log("found identities", identities);
			if (identities.length > 0) {
				identities = identities.map(function (identity) {
					return {
						uri: identity.uri,
						updated: Math.floor(identity.updatedOn/1000)
					};
				});
			}
			return callback(null, identities);
		});
	}
	var waitfor = WAITFOR.parallel(function (err) {
		if (err) return callback(err);
		return callback(null, identities);
	});
	providers.forEach(function (provider) {
		return provider.identities.split(provider.separator || ",").forEach(function (identity) {
			return waitfor(provider.base.replace(/\/$/, "") + "/" + identity, function (uri, callback) {
//				console.log("check", uri);
				return get(r, provider.base, uri, domain, function(err, identity) {
					if (err) return callback(err);
//					console.log("found identity", identity);
					if (identity) {
						identities.push({
							uri: uri,
							updated: Math.floor(identity.updatedOn/1000)
						});
					}
					return callback(null);
				});
			});
		});
	});
	return waitfor();
}


exports.allForDomain = function(r, domain, callback) {
	return r.tableEnsure(DB_NAME, "identity_lookup", "identities", function(err, identitiesTable) {
        if (err) return callback(err);
		return identitiesTable.filter({
			domain: domain
		}).run(r.conn, function (err, result) {
		    if (err) return callback(err);
		    if (!result) {
				return callback(null, null);
		    }
			return result.toArray(function(err, results) {
			    if (err) return callback(err);

				return callback(null, results);
			});
		});
	});
	return waitfor();
}

exports.clearAllForDomain = function(r, domain, callback) {
	return r.tableEnsure(DB_NAME, "identity_lookup", "identities", function(err, identitiesTable) {
        if (err) return callback(err);
		return identitiesTable.filter({
			domain: domain
		}).delete().run(r.conn, function (err) {
		    if (err) return callback(err);
			return callback(null);
		});
	});
	return waitfor();
}


exports.lookup = function (r, providers, domain, callback) {
	var identities = [];
	var waitfor = WAITFOR.parallel(function (err) {
		if (err) return callback(err);
		return callback(null, identities);
	});
	if (providers) {
		providers.forEach(function (provider) {
			return provider.identities.split(provider.separator || ",").forEach(function (identity) {
				return waitfor(provider.base.replace(/\/$/, "") + "/" + identity, function (uri, callback) {
					console.log("lookup", uri);
					return get(r, provider.base, uri, domain, function(err, identity) {
						if (err) return callback(err);
						console.log("found identity", identity);
						if (identity) {

							var info = JSON.parse(JSON.stringify(identity.identity));
							info.updated = Math.floor(identity.updatedOn/1000);
							info.expires = Math.floor(identity.expiresOn/1000);

							var identityProofId = randomString(32);
							info.identityProofBundle = {
								identityProof: {
									$id: identityProofId,
									contactProofBundle: identity.contactProofBundle
								},
								signature: {
									reference: "#" + identityProofId
								}
							}
//							delete identity.contactProofBundle;

							identities.push(info);
						}
						return callback(null);
					});
				});
			});
		});
	}
	return waitfor();
}

