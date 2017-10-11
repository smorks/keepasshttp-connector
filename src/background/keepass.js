var keepass = {};

keepass.associated = {"value": false, "hash": null};
keepass.isDatabaseClosed = false;
keepass.isKeePassHttpAvailable = false;
keepass.isEncryptionKeyUnrecognized = false;
keepass.currentKeePassHttp = {"version": 0, "versionParsed": 0};
keepass.keySize = 8; // wtf? stupid cryptoHelpers
keepass.pluginUrlDefault = "http://localhost:19455/";
keepass.latestVersionUrl = "https://passifox.appspot.com/kph/latest-version.txt";
keepass.cacheTimeout = 30 * 1000; // milliseconds
keepass.databaseHash = "no-hash"; //no-hash = keepasshttp is too old and does not return a hash value
keepass.keyId = "chromeipass-cryptokey-name";
keepass.keyBody = "chromeipass-key";
keepass.to_s = cryptoHelpers.convertByteArrayToString;
keepass.to_b = cryptoHelpers.convertStringToByteArray;

browser.storage.local.get({
	'latestKeePassHttp': {'version': 0, 'versionParsed': 0, 'lastChecked': null},
	'keyRing': {}})
	.then((item) => {
	keepass.latestKeePassHttp = item.latestKeePassHttp;
	keepass.keyRing = item.keyRing;
});

keepass.addCredentials = function(callback, tab, username, password, url) {
	keepass.updateCredentials(callback, tab, null, username, password, url);
}

keepass.updateCredentials = function(callback, tab, entryId, username, password, url) {
	page.debug("keepass.updateCredentials(callback, {1}, {2}, {3}, [password], {4})", tab.id, entryId, username, url);

	// unset error message
	page.tabs[tab.id].errorMessage = null;

	// is browser associated to keepass?
	keepass.testAssociation(tab).then((configured) => {
		if(!configured) {
			browserAction.showDefault(null, tab);
			callback("error");
			return;
		}

		// build request
		var request = {
			RequestType: "set-login"
		};
		var verifier = keepass.setVerifier(request);
		var id = verifier[0];
		var key = verifier[1];
		var iv = request.Nonce;

		request.Login = keepass.encrypt(cryptoHelpers.encode_utf8(username), key, iv);

		request.Password = keepass.encrypt(cryptoHelpers.encode_utf8(password), key, iv);
		request.Url = keepass.encrypt(url, key, iv);
		request.SubmitUrl = keepass.encrypt(url, key, iv);

		if(entryId) {
			request.Uuid = keepass.encrypt(entryId, key, iv);
		}

		// send request
		keepass.sendAsync(request).then((result) => {
			var status = result[0];
			var response = result[1];

			// verify response
			var code = "error";
			if(keepass.checkStatus(status, tab)) {
				var r = JSON.parse(response);
				if (keepass.verifyResponse(r, key, id)) {
					code = "success";
				}
				else {
					code = "error";
				}
			}

			callback(code);
		});
	});
}

keepass.retrieveCredentials = function (callback, tab, url, submiturl, forceCallback, triggerUnlock) {
	page.debug("keepass.retrieveCredentials(callback, {1}, {2}, {3}, {4})", tab.id, url, submiturl, forceCallback);

	// unset error message
	page.tabs[tab.id].errorMessage = null;

	// is browser associated to keepass?
	keepass.testAssociation(tab, triggerUnlock).then((configured) => {
		if(!configured) {
			browserAction.showDefault(null, tab);
			if(forceCallback) {
				callback([]);
			}
			return;
		}

		// build request
		var request = {
			"RequestType": "get-logins",
			"SortSelection": "true",
			"TriggerUnlock": (triggerUnlock === true) ? "true" : "false"
		};
		var verifier = keepass.setVerifier(request);
		var id = verifier[0];
		var key = verifier[1];
		var iv = request.Nonce;
		request.Url = keepass.encrypt(url, key, iv);

		if(submiturl) {
			request.SubmitUrl = keepass.encrypt(submiturl, key, iv);
		}

		// send request
		keepass.sendAsync(request).then((result) => {
			var status = result[0];
			var response = result[1];
			var entries = [];

			// verify response
			if(keepass.checkStatus(status, tab)) {
				var r = JSON.parse(response);

				keepass.setCurrentKeePassHttpVersion(r.Version);

				if (keepass.verifyResponse(r, key, id)) {
					var rIv = r.Nonce;
					for (var i = 0; i < r.Entries.length; i++) {
						keepass.decryptEntry(r.Entries[i], key, rIv);
					}
					entries = r.Entries;
					keepass.updateLastUsed(keepass.databaseHash);
					if(entries.length == 0) {
						//questionmark-icon is not triggered, so we have to trigger for the normal symbol
						browserAction.showDefault(null, tab);
					}
				}
				else {
					console.log("RetrieveCredentials for " + url + " rejected");
				}
			}
			else {
				browserAction.showDefault(null, tab);
			}

			page.debug("keepass.retrieveCredentials() => entries.length = {1}", entries.length);
			callback(entries);
		});
	});
}

keepass.generatePassword = function (callback, tab, forceCallback) {
	// is browser associated to keepass?
	keepass.testAssociation(tab).then((configured) => {
		if(!configured) {
			browserAction.showDefault(null, tab);
			if(forceCallback) {
				callback([]);
			}
			return;
		}

		if(keepass.currentKeePassHttp.versionParsed < 1400) {
			callback([]);
			return;
		}

		// build request
		var request = {
			RequestType: "generate-password"
		};
		var verifier = keepass.setVerifier(request);
		var id = verifier[0];
		var key = verifier[1];

		// send request
		keepass.sendAsync(request).then((result) => {
			var status = result[0];
			var response = result[1];
			var passwords = [];

			// verify response
			if(keepass.checkStatus(status, tab)) {
				var r = JSON.parse(response);

				keepass.setCurrentKeePassHttpVersion(r.Version);

				if (keepass.verifyResponse(r, key, id)) {
					var rIv = r.Nonce;
	
					if(r.Entries) {
						for (var i = 0; i < r.Entries.length; i++) {
							keepass.decryptEntry(r.Entries[i], key, rIv);
						}
						passwords = r.Entries;
						keepass.updateLastUsed(keepass.databaseHash);
					}
					else {
						console.log("No entries returned. Is KeePassHttp up-to-date?");
					}
				}
				else {
					console.log("GeneratePassword rejected");
				}
			}
			else {
				browserAction.showDefault(null, tab);
			}

			callback(passwords);
		});
	});
}

keepass.associate = function(callback, tab) {
	if(keepass.isAssociated()) {
		return;
	}

	keepass.getDatabaseHash(tab).then(() => {
		if(keepass.isDatabaseClosed || !keepass.isKeePassHttpAvailable) {
			return;
		}

		page.tabs[tab.id].errorMessage = null;

		var rawKey = cryptoHelpers.generateSharedKey(keepass.keySize * 2);
		var key = keepass.b64e(rawKey);

		var request = {
			RequestType: "associate",
			Key: key
		};

		keepass.setVerifier(request, key);

		keepass.sendAsync(request).then((result) => {
			if(keepass.checkStatus(result[0], tab)) {
				var r = JSON.parse(result[1]);

				if(r.Version) {
					keepass.currentKeePassHttp = {
						"version": r.Version,
						"versionParsed": parseInt(r.Version.replace(/\./g,""))
					};
				}

				var id = r.Id;
				if(!keepass.verifyResponse(r, key)) {
					page.tabs[tab.id].errorMessage = "KeePass association failed, try again.";
				}
				else {
					keepass.setCryptoKey(id, key);
					keepass.associated.value = true;
					keepass.associated.hash = r.Hash || 0;
				}

				browserAction.show(callback, tab);
			}
		});
	});
}

keepass.isConfigured = function() {
	return new Promise((resolve, reject) => {
		if(typeof(keepass.databaseHash) == "undefined") {
			keepass.getDatabaseHash().then((hash) => {
				resolve(hash in keepass.keyRing);
			});
		} else {
			resolve(keepass.databaseHash in keepass.keyRing);
		}
	});
}

keepass.isAssociated = function() {
	return (keepass.associated.value && keepass.associated.hash && keepass.associated.hash == keepass.databaseHash);
}

keepass.sendAsync = function(request) {
	return new Promise((resolve, reject) => {
		var xhr = new XMLHttpRequest();
		xhr.open("POST", keepass.getPluginUrl(), true);
		xhr.setRequestHeader("Content-Type", "application/json");
		xhr.onload = () => {
			page.debug("Response: {1} => {2}", xhr.status, xhr.responseText);
			resolve([xhr.status, xhr.responseText]);
		};
		xhr.onerror = (err) => {
			reject(err);
		};
		try {
			var r = JSON.stringify(request);
			page.debug("Request: {1}", r);
			xhr.send(r);
		}
		catch (e) {
			console.log("KeePassHttp: " + e);
		}
	});
}

keepass.checkStatus = function (status, tab) {
	var success = (status >= 200 && status <= 299);
	keepass.isDatabaseClosed = false;
	keepass.isKeePassHttpAvailable = true;

	if(tab && page.tabs[tab.id]) {
		delete page.tabs[tab.id].errorMessage;
	}
	if (!success) {
		keepass.associated.value = false;
		keepass.associated.hash = null;
		if(tab && page.tabs[tab.id]) {
			page.tabs[tab.id].errorMessage = "Unknown error: " + status;
		}
		console.log("Error: "+ status);
		if (status == 503) {
			keepass.isDatabaseClosed = true;
			console.log("KeePass database is not opened");
			if(tab && page.tabs[tab.id]) {
				page.tabs[tab.id].errorMessage = "KeePass database is not opened.";
			}
		}
		else if (status == 0) {
			keepass.isKeePassHttpAvailable = false;
			console.log("Could not connect to keepass");
			if(tab && page.tabs[tab.id]) {
				page.tabs[tab.id].errorMessage = "Is KeePassHttp installed and is KeePass running?";
			}
		}
	}

	page.debug("keepass.checkStatus({1}, [tabID]) => {2}", status, success);

	return success;
}

keepass.migrateKeyRing = () => {
	return new Promise((resolve, reject) => {
		browser.storage.local.get('keyRing').then((item) => {
			var keyring = item.keyRing;
			// change dates to numbers, for compatibilty with chrome
			if (keyring) {
				var num = 0;
				for (var keyHash in keyring) {
					var key = keyring[keyHash];
					['created', 'lastUsed'].forEach((fld) => {
						var v = key[fld];
						if (v instanceof Date && v.valueOf() >= 0) {
							key[fld] = v.valueOf();
							num++;
						} else if (typeof v !== 'number') {
							key[fld] = Date.now().valueOf();
							num++;
						}
					});
				}
				if (num > 0) {
					browser.storage.local.set({ keyRing: keyring });
				}
			}
			resolve();
		});
	});
};

keepass.saveKey = function(hash, id, key) {
	if(!(hash in keepass.keyRing)) {
		keepass.keyRing[hash] = {
			"id": id,
			"key": key,
			"icon": "blue",
			"created": new Date().valueOf(),
			"lastUsed": new Date().valueOf()
		}
	}
	else {
		keepass.keyRing[hash].id = id;
		keepass.keyRing[hash].key = key;
	}
	browser.storage.local.set({'keyRing': keepass.keyRing});
}

keepass.updateLastUsed = function(hash) {
	if((hash in keepass.keyRing)) {
		keepass.keyRing[hash].lastUsed = new Date().valueOf();
		browser.storage.local.set({'keyRing': keepass.keyRing});
	}
}

keepass.deleteKey = function(hash) {
	delete keepass.keyRing[hash];
	browser.storage.local.set({'keyRing': keepass.keyRing});
}

keepass.getIconColor = function() {
	return ((keepass.databaseHash in keepass.keyRing) && keepass.keyRing[keepass.databaseHash].icon) ? keepass.keyRing[keepass.databaseHash].icon : "blue";
}

keepass.getPluginUrl = function() {
	if(page.settings.hostname && page.settings.port) {
		return "http://" + page.settings.hostname + ":" + page.settings.port;
	}
	return keepass.pluginUrlDefault;
}

keepass.setCurrentKeePassHttpVersion = function(version) {
	if(version) {
		keepass.currentKeePassHttp = {
			"version": version,
			"versionParsed": parseInt(version.replace(/\./g,""))
		};
	}
}

keepass.keePassHttpUpdateAvailable = function() {
	return false;
}

keepass.checkForNewKeePassHttpVersion = function() {
	return false;
}

keepass.testAssociation = function (tab, triggerUnlock) {
	return new Promise((resolve, reject) => {
		keepass.getDatabaseHash(tab, triggerUnlock).then(() => {
			if(keepass.isDatabaseClosed || !keepass.isKeePassHttpAvailable) {
				resolve(false);
				return;
			}

			if(keepass.isAssociated()) {
				resolve(true);
				return;
			}

			var request = {
				"RequestType": "test-associate",
				"TriggerUnlock": (triggerUnlock === true) ? "true" : false
			};
			var verifier = keepass.setVerifier(request);

			if(!verifier) {
				keepass.associated.value = false;
				keepass.associated.hash = null;
				resolve(false);
				return;
			}

			keepass.sendAsync(request).then((result) => {
				var status = result[0];
				var response = result[1];
	
				if(keepass.checkStatus(status, tab)) {
					var r = JSON.parse(response);
					var id = verifier[0];
					var key = verifier[1];
	
					if(r.Version) {
						keepass.currentKeePassHttp = {
							"version": r.Version,
							"versionParsed": parseInt(r.Version.replace(/\./g,""))
						};
					}

				keepass.isEncryptionKeyUnrecognized = false;
					if(!keepass.verifyResponse(r, key, id)) {
						var hash = r.Hash || 0;
						keepass.deleteKey(hash);
						keepass.isEncryptionKeyUnrecognized = true;
						console.log("Encryption key is not recognized!");
						page.tabs[tab.id].errorMessage = "Encryption key is not recognized.";
						keepass.associated.value = false;
						keepass.associated.hash = null;
					}
					else if(!keepass.isAssociated()) {
						console.log("Association was not successful");
						page.tabs[tab.id].errorMessage = "Association was not successful.";
					}
				}

				resolve(keepass.isAssociated());
			});
		});
	});
}

keepass.getDatabaseHash = function (tab, triggerUnlock) {
	return new Promise((resolve, reject) => {
		var request = {
			"RequestType": "test-associate",
			"TriggerUnlock": (triggerUnlock === true) ? "true" : false
		};

		var oldDatabaseHash = keepass.databaseHash;

		keepass.sendAsync(request).then((result) => {
			if(keepass.checkStatus(result[0], tab)) {
				var response = JSON.parse(result[1]);
				keepass.setCurrentKeePassHttpVersion(response.Version);
				keepass.databaseHash = response.Hash || "no-hash";
			} else {
				keepass.databaseHash = "no-hash";
			}

			if(oldDatabaseHash && oldDatabaseHash != keepass.databaseHash) {
				//console.log("clear association (old db hash != new db hash ==> " + oldDatabaseHash + " != " + keepass.databaseHash);
				keepass.associated.value = false;
				keepass.associated.hash = null;
			}

			resolve(keepass.databaseHash);
		}).catch((reason) => {
			page.tabs[tab.id].errorMessage = "Unable to connect to KeePassHttp";
			resolve(null);
		});
	});
}

keepass.setVerifier = function(request, inputKey) {
	var key = inputKey || null;
	var id = null;

	if(!key) {
		var info = keepass.getCryptoKey();
		if (info == null) {
			return null;
		}
		id = info[0];
		key = info[1];
	}

	if(id) {
		request.Id = id;
	}

	var iv = cryptoHelpers.generateSharedKey(keepass.keySize);
	request.Nonce = keepass.b64e(iv);

	//var decodedKey = keepass.b64d(key);
	request.Verifier = keepass.encrypt(request.Nonce, key, request.Nonce);

	return [id, key];
}

keepass.verifyResponse = function(response, key, id) {
	keepass.associated.value = response.Success;
	if (!response.Success) {
		keepass.associated.hash = null;
		return false;
	}

	keepass.associated.hash = keepass.databaseHash;

	var iv = response.Nonce;
	var value = keepass.decrypt(response.Verifier, key, iv, true);

	keepass.associated.value = (value == iv);

	if(id) {
		keepass.associated.value = (keepass.associated.value && id == response.Id);
	}

	keepass.associated.hash = (keepass.associated.value) ? keepass.databaseHash : null;

	return keepass.isAssociated();

}

keepass.b64e = function(d) {
	return btoa(keepass.to_s(d));
}

keepass.b64d = function(d) {
	return keepass.to_b(atob(d));
}

keepass.getCryptoKey = function() {
	if(!(keepass.databaseHash in keepass.keyRing)) {
		return null;
	}

	var id = keepass.keyRing[keepass.databaseHash].id;
	var key = null;

	if(id) {
		key = keepass.keyRing[keepass.databaseHash].key;
	}

	return key ? [id, key] : null;
}

keepass.setCryptoKey = function(id, key) {
	keepass.saveKey(keepass.databaseHash, id, key);
}

keepass.encrypt = function(input, key, iv) {
	return keepass.b64e(
		slowAES.encrypt(
			keepass.to_b(input),
			slowAES.modeOfOperation.CBC,
			keepass.b64d(key),
			keepass.b64d(iv)
		)
	);
}

keepass.decrypt = function(input, key, iv, toStr) {
	var output = slowAES.decrypt(
			keepass.b64d(input),
			slowAES.modeOfOperation.CBC,
			keepass.b64d(key),
			keepass.b64d(iv)
		);

	return toStr ? keepass.to_s(output) : output;
}

keepass.decryptEntry = function (e, key, iv) {
	e.Uuid = keepass.decrypt(e.Uuid, key, iv, true);
	e.Name = UTF8.decode(keepass.decrypt(e.Name, key, iv, true));
	e.Login = UTF8.decode(keepass.decrypt(e.Login, key, iv, true));
	e.Password = UTF8.decode(keepass.decrypt(e.Password, key, iv, true));

	if(e.StringFields) {
		for(var i = 0; i < e.StringFields.length; i++) {
			e.StringFields[i].Key = UTF8.decode(keepass.decrypt(e.StringFields[i].Key, key, iv, true))
			e.StringFields[i].Value = UTF8.decode(keepass.decrypt(e.StringFields[i].Value, key, iv, true))
		}
	}
}
