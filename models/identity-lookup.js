
const WAITFOR = require("waitfor");


// TODO: Store in DB instead of memory.

var identities = {};

function get (uri, callback) {
	return callback(null, identities[uri] || null);
}

function set (uri, data, callback) {
	if (data === null) {
		delete identities[uri];
	} else {
		identities[uri] = data;
	}
	return callback(null);	
}



exports.create = function (identity, callback) {
	return set(identity.uri, {
		updatedOn: Date.now(),
		expiresOn: Date.now() + 60 * 60 * 24 * 1000,
		identity: identity
	}, callback);
}

exports.remove = function (identity, callback) {
	return set(identity.uri, null, callback);
}

exports.check = function (providers, callback) {
	var identities = [];
	var waitfor = WAITFOR.parallel(function (err) {
		if (err) return callback(err);
		return callback(null, identities);
	});
	providers.forEach(function (provider) {
		return provider.identities.split(provider.separator || ",").forEach(function (identity) {
			return waitfor(provider.base.replace(/\/$/, "") + "/" + identity, function (uri, callback) {
				return get(uri, function(err, identity) {
					if (err) return callback(err);
					if (identity) {
						identities.push({
							uri: uri,
							updated: identity.updatedOn
						});
					}
					return callback(null);
				});
			});
		});
	});
	return waitfor();
}


exports.lookup = function (providers, callback) {
	var identities = [];
	var waitfor = WAITFOR.parallel(function (err) {
		if (err) return callback(err);
		return callback(null, identities);
	});
	providers.forEach(function (provider) {
		return provider.identities.split(provider.separator || ",").forEach(function (identity) {
			return waitfor(provider.base.replace(/\/$/, "") + "/" + identity, function (uri, callback) {
				return get(uri, function(err, identity) {
					if (err) return callback(err);
					if (identity) {

						var info = JSON.parse(JSON.stringify(identity.identity));
						info.updated = identity.updatedOn;
						info.expires = identity.expiresOn;

						info.identityProofBundle = {
							identityProof: {
								$id: "id",
								contactProofBundle: identity.contactProofBundle
							},
							signature: {}
						}
						delete identity.contactProofBundle;

						identities.push(info);
					}
					return callback(null);
				});
			});
		});
	});
	return waitfor();
}

