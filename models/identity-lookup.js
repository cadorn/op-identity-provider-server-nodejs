
const WAITFOR = require("waitfor");
const CRYPTO = require('crypto');

const DB_NAME = "hcs_integration";


function randomString(length) {
  return CRYPTO.randomBytes(length / 2).toString('hex');
}



function get (r, uri, callback) {
	return r.tableEnsure(DB_NAME, "identity_lookup", "identities", function(err, identitiesTable) {
        if (err) return callback(err);
		return identitiesTable.get(uri).run(r.conn, function (err, result) {
		    if (err) return callback(err);
		    if (!result) {
				return callback(null, null);
		    }	
			return callback(null, result.data);
		});
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
			return identitiesTable.insert({
			    id: uri,
			    data: data
			}, {
			    upsert: true
			}).run(r.conn, function (err, result) {
			    if (err) return callback(err);
				return callback(null);
			});
		}
	});
}



exports.create = function (r, identity, callback) {
	console.log("create", identity.uri);
	return set(r, identity.uri, {
		updatedOn: Date.now(),
		expiresOn: Date.now() + 60 * 60 * 24 * 1000,
		identity: identity
	}, callback);
}

exports.remove = function (r, identity, callback) {
	return set(r, identity.uri, null, callback);
}

exports.check = function (r, providers, callback) {
	var identities = [];
	var waitfor = WAITFOR.parallel(function (err) {
		if (err) return callback(err);
		return callback(null, identities);
	});
	providers.forEach(function (provider) {
		return provider.identities.split(provider.separator || ",").forEach(function (identity) {
			return waitfor(provider.base.replace(/\/$/, "") + "/" + identity, function (uri, callback) {
				console.log("check", uri);
				return get(r, uri, function(err, identity) {
					if (err) return callback(err);
					console.log("found identity", identity);
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


exports.lookup = function (r, providers, callback) {
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
					return get(r, uri, function(err, identity) {
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

