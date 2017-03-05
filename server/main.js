var mongodb = require("mongodb");
var crypto = require("crypto");
var http = require("http");
var url = require("url");
var qs = require("querystring");

var err = {
	no_int: "no such interface",
	no_method: "unsupported method",
	no_uid: "no such uid",
	internal: "internal error",
	wrong_arg: "wrong argument",
	illegal_key: "illegal key",
	auth_failed: "auth failed"
};

var server = new mongodb.Server("localhost", 3137, { auto_reconnect: true });
var db = new mongodb.Db("sdauth", server, { safe: true });
db.open();

http.ServerResponse.prototype.qerr = function (msg, status) {
	this.writeHead(status || 200, { "Content-Type": "application/json" });
	this.end(JSON.stringify({ suc: false, msg: msg }));
};

http.ServerResponse.prototype.qjson = function (obj, status) {
	this.writeHead(status || 200, { "Content-Type": "application/json" });
	this.end(JSON.stringify(obj));
};

var errwrap = function (res, cb) {
	return function (err, ret) {
		if (err) {
			console.log(err);
			res.qjson(err.internal);
			// log
		} else {
			try {
				cb(ret);
			} catch (e) {
				console.log(e);
			}
		}
	};
};

var checkArgc = function (res, args, expect) {
	if (args.length < expect) {
		res.qerr(err.wrong_arg);
		return false;
	}

	return true;
};

var genkey = function () {
	return crypto.createHash("md5").update(Math.random().toString()).digest("base64");
};

var int = {
	// args:
	//     1. card uid(base64 encoded)
	//     2. card key(base64 encoded)
	check: function (req, res, args, query) {
		if (!(query.uid && query.key)) {
			res.qerr(err.wrong_arg);
			return;
		}

		db.collection("card", errwrap(res, function (col) {
			var newkey = genkey();

			col.findOneAndUpdate(
				{ uid: query.uid }, { $set: { pending: newkey } }, { returnOriginal: false, upsert: true },
				errwrap(res, function (ret) {
					if (!ret.value.key || ret.value.key == query.key) {
						console.log(query.uid + ": " + query.key);
						res.qjson({ suc: true, new: newkey });
					} else {
						res.qerr(err.auth_failed);
					}
				})
			);
		}));
	},

	// args:
	//     1. card uid(base64 encoded)
	//     2. card key(base64 encoded)
	update: function (req, res, args, query) {
		if (!(query.uid && query.key)) {
			res.qerr(err.wrong_arg);
			return;
		}
	
		db.collection("card", errwrap(res, function (col) {
			col.findOne(
				{ uid: query.uid },
				errwrap(res, function (ret) {
					if (!ret || !ret.pending) {
						res.qerr(err.no_uid);
					} else if (ret.key && ret.key != query.key) {
						res.qerr(err.auth_failed);
					} else {
						col.findOneAndUpdate(
							{ uid: query.uid },
							{ $set: { key: ret.pending } },
							errwrap(res, function () {
								res.qjson({ suc: true });
							})
						);
					}
				})
			);
		}));
	}
};

function reqHandle(req, res) {
	var parsed = url.parse(req.url);
	var args = parsed.pathname.substring(1).split("/");

	if (req.method != "GET") {
		res.qerr(err.no_method, 500);
		return;
	}

	if (!int.hasOwnProperty(args[0])) {
		res.qerr(err.no_int, 400);
		return;
	}

	var query = qs.parse(parsed.query);

	int[args[0]](req, res, args.slice(1), query);
}

http.createServer(reqHandle).listen(3136);
