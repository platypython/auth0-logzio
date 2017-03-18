module.exports =
/******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};

/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {

/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId])
/******/ 			return installedModules[moduleId].exports;

/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			exports: {},
/******/ 			id: moduleId,
/******/ 			loaded: false
/******/ 		};

/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);

/******/ 		// Flag the module as loaded
/******/ 		module.loaded = true;

/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}


/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;

/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;

/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "/build/";

/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(0);
/******/ })
/************************************************************************/
/******/ ([
/* 0 */
/***/ function(module, exports, __webpack_require__) {

	'use strict';

	var _logTypes;

	function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

	var Logzio = __webpack_require__(1);
	var async = __webpack_require__(51);
	var moment = __webpack_require__(52);
	var useragent = __webpack_require__(53);
	var express = __webpack_require__(54);
	var Webtask = __webpack_require__(55);
	var app = express();
	var Request = __webpack_require__(2);
	var memoizer = __webpack_require__(56);

	function lastLogCheckpoint(req, res) {
	  var ctx = req.webtaskContext;
	  var required_settings = ['AUTH0_DOMAIN', 'AUTH0_CLIENT_ID', 'AUTH0_CLIENT_SECRET', 'LOGZIO_API_TOKEN', 'LOGZIO_LOG_TYPE', 'LOGZIO_PROTOCOL'];
	  var missing_settings = required_settings.filter(function (setting) {
	    return !ctx.data[setting];
	  });

	  if (missing_settings.length) {
	    return res.status(400).send({ message: 'Missing settings: ' + missing_settings.join(', ') });
	  }

	  // If this is a scheduled task, we'll get the last log checkpoint from the previous run and continue from there.
	  req.webtaskContext.storage.get(function (err, data) {
	    var startFromId = ctx.data.START_FROM ? ctx.data.START_FROM : null;
	    var startCheckpointId = typeof data === 'undefined' ? startFromId : data.checkpointId;

	    var logzio = Logzio.createLogger({
	      token: ctx.data.LOGZIO_API_TOKEN,
	      type: ctx.data.LOGZIO_LOG_TYPE,
	      protocol: ctx.data.LOGZIO_PROTOCOL,
	      debug: true
	    });

	    // Start the process.
	    async.waterfall([function (callback) {
	      var getLogs = function getLogs(context) {
	        console.log('Logs from: ' + (context.checkpointId || 'Start') + '.');

	        var take = Number.parseInt(ctx.data.BATCH_SIZE);

	        take = take ? take : 100;

	        context.logs = context.logs || [];

	        getLogsFromAuth0(req.webtaskContext.data.AUTH0_DOMAIN, req.access_token, take, context.checkpointId, function (logs, err) {
	          if (err) {
	            console.log('Error getting logs from Auth0', err);
	            return callback(err);
	          }

	          if (logs && logs.length) {
	            logs.forEach(function (l) {
	              return context.logs.push(l);
	            });
	            context.checkpointId = context.logs[context.logs.length - 1]._id;
	          }

	          console.log('Total logs: ' + context.logs.length + '.');
	          return callback(null, context);
	        });
	      };

	      getLogs({ checkpointId: startCheckpointId });
	    }, function (context, callback) {
	      var min_log_level = parseInt(ctx.data.LOG_LEVEL) || 0;
	      var log_matches_level = function log_matches_level(log) {
	        if (logTypes[log.type]) {
	          return logTypes[log.type].level >= min_log_level;
	        }
	        return true;
	      };

	      var types_filter = ctx.data.LOG_TYPES && ctx.data.LOG_TYPES.split(',') || [];
	      var log_matches_types = function log_matches_types(log) {
	        if (!types_filter || !types_filter.length) return true;
	        return log.type && types_filter.indexOf(log.type) >= 0;
	      };

	      context.logs = context.logs.filter(function (l) {
	        return l.type !== 'sapi' && l.type !== 'fapi';
	      }).filter(log_matches_level).filter(log_matches_types);

	      callback(null, context);
	    }, function (context, callback) {
	      console.log('Sending ' + context.logs.length);

	      // logzio
	      logzio.log(context.logs, function (err) {
	        if (err) {
	          console.log('Error sending logs to LogZio', err);
	          return callback(err);
	        }

	        console.log('Upload complete.');

	        return callback(null, context);
	      });
	    }], function (err, context) {
	      if (err) {
	        console.log('Job failed.');

	        return req.webtaskContext.storage.set({ checkpointId: startCheckpointId }, { force: 1 }, function (error) {
	          if (error) {
	            console.log('Error storing startCheckpoint', error);
	            return res.status(500).send({ error: error });
	          }

	          res.status(500).send({
	            error: err
	          });
	        });
	      }

	      console.log('Job complete.');

	      return req.webtaskContext.storage.set({
	        checkpointId: context.checkpointId,
	        totalLogsProcessed: context.logs.length
	      }, { force: 1 }, function (error) {
	        if (error) {
	          console.log('Error storing checkpoint', error);
	          return res.status(500).send({ error: error });
	        }

	        res.sendStatus(200);
	      });
	    });
	  });
	}

	var logTypes = (_logTypes = {
	  's': {
	    event: 'Success Login',
	    level: 1 // Info
	  },
	  'seacft': {
	    event: 'Success Exchange',
	    level: 1 // Info
	  },
	  'seccft': {
	    event: 'Success Exchange (Client Credentials)',
	    level: 1 // Info
	  },
	  'feacft': {
	    event: 'Failed Exchange',
	    level: 3 // Error
	  },
	  'feccft': {
	    event: 'Failed Exchange (Client Credentials)',
	    level: 3 // Error
	  },
	  'f': {
	    event: 'Failed Login',
	    level: 3 // Error
	  },
	  'w': {
	    event: 'Warnings During Login',
	    level: 2 // Warning
	  },
	  'du': {
	    event: 'Deleted User',
	    level: 1 // Info
	  },
	  'fu': {
	    event: 'Failed Login (invalid email/username)',
	    level: 3 // Error
	  },
	  'fp': {
	    event: 'Failed Login (wrong password)',
	    level: 3 // Error
	  },
	  'fc': {
	    event: 'Failed by Connector',
	    level: 3 // Error
	  },
	  'fco': {
	    event: 'Failed by CORS',
	    level: 3 // Error
	  },
	  'con': {
	    event: 'Connector Online',
	    level: 1 // Info
	  },
	  'coff': {
	    event: 'Connector Offline',
	    level: 3 // Error
	  },
	  'fcpro': {
	    event: 'Failed Connector Provisioning',
	    level: 4 // Critical
	  },
	  'ss': {
	    event: 'Success Signup',
	    level: 1 // Info
	  },
	  'fs': {
	    event: 'Failed Signup',
	    level: 3 // Error
	  },
	  'cs': {
	    event: 'Code Sent',
	    level: 0 // Debug
	  },
	  'cls': {
	    event: 'Code/Link Sent',
	    level: 0 // Debug
	  },
	  'sv': {
	    event: 'Success Verification Email',
	    level: 0 // Debug
	  },
	  'fv': {
	    event: 'Failed Verification Email',
	    level: 0 // Debug
	  },
	  'scp': {
	    event: 'Success Change Password',
	    level: 1 // Info
	  },
	  'fcp': {
	    event: 'Failed Change Password',
	    level: 3 // Error
	  },
	  'sce': {
	    event: 'Success Change Email',
	    level: 1 // Info
	  },
	  'fce': {
	    event: 'Failed Change Email',
	    level: 3 // Error
	  },
	  'scu': {
	    event: 'Success Change Username',
	    level: 1 // Info
	  },
	  'fcu': {
	    event: 'Failed Change Username',
	    level: 3 // Error
	  },
	  'scpn': {
	    event: 'Success Change Phone Number',
	    level: 1 // Info
	  },
	  'fcpn': {
	    event: 'Failed Change Phone Number',
	    level: 3 // Error
	  },
	  'svr': {
	    event: 'Success Verification Email Request',
	    level: 0 // Debug
	  },
	  'fvr': {
	    event: 'Failed Verification Email Request',
	    level: 3 // Error
	  },
	  'scpr': {
	    event: 'Success Change Password Request',
	    level: 0 // Debug
	  },
	  'fcpr': {
	    event: 'Failed Change Password Request',
	    level: 3 // Error
	  },
	  'fn': {
	    event: 'Failed Sending Notification',
	    level: 3 // Error
	  },
	  'sapi': {
	    event: 'API Operation'
	  },
	  'fapi': {
	    event: 'Failed API Operation'
	  },
	  'limit_wc': {
	    event: 'Blocked Account',
	    level: 4 // Critical
	  },
	  'limit_ui': {
	    event: 'Too Many Calls to /userinfo',
	    level: 4 // Critical
	  },
	  'api_limit': {
	    event: 'Rate Limit On API',
	    level: 4 // Critical
	  },
	  'sdu': {
	    event: 'Successful User Deletion',
	    level: 1 // Info
	  },
	  'fdu': {
	    event: 'Failed User Deletion',
	    level: 3 // Error
	  }
	}, _defineProperty(_logTypes, 'fapi', {
	  event: 'Failed API Operation',
	  level: 3 // Error
	}), _defineProperty(_logTypes, 'limit_wc', {
	  event: 'Blocked Account',
	  level: 3 // Error
	}), _defineProperty(_logTypes, 'limit_mu', {
	  event: 'Blocked IP Address',
	  level: 3 // Error
	}), _defineProperty(_logTypes, 'slo', {
	  event: 'Success Logout',
	  level: 1 // Info
	}), _defineProperty(_logTypes, 'flo', {
	  event: ' Failed Logout',
	  level: 3 // Error
	}), _defineProperty(_logTypes, 'sd', {
	  event: 'Success Delegation',
	  level: 1 // Info
	}), _defineProperty(_logTypes, 'fd', {
	  event: 'Failed Delegation',
	  level: 3 // Error
	}), _logTypes);

	function getLogsFromAuth0(domain, token, take, from, cb) {
	  var url = 'https://' + domain + '/api/v2/logs';

	  Request({
	    method: 'GET',
	    url: url,
	    json: true,
	    qs: {
	      take: take,
	      from: from,
	      sort: 'date:1',
	      per_page: take
	    },
	    headers: {
	      Authorization: 'Bearer ' + token,
	      Accept: 'application/json'
	    }
	  }, function (err, res, body) {
	    if (err) {
	      console.log('Error getting logs', err);
	      cb(null, err);
	    } else {
	      cb(body);
	    }
	  });
	}

	var getTokenCached = memoizer({
	  load: function load(apiUrl, audience, clientId, clientSecret, cb) {
	    Request({
	      method: 'POST',
	      url: apiUrl,
	      json: true,
	      body: {
	        audience: audience,
	        grant_type: 'client_credentials',
	        client_id: clientId,
	        client_secret: clientSecret
	      }
	    }, function (err, res, body) {
	      if (err) {
	        cb(null, err);
	      } else {
	        cb(body.access_token);
	      }
	    });
	  },
	  hash: function hash(apiUrl) {
	    return apiUrl;
	  },
	  max: 100,
	  maxAge: 1000 * 60 * 60
	});

	app.use(function (req, res, next) {
	  var apiUrl = 'https://' + req.webtaskContext.data.AUTH0_DOMAIN + '/oauth/token';
	  var audience = 'https://' + req.webtaskContext.data.AUTH0_DOMAIN + '/api/v2/';
	  var clientId = req.webtaskContext.data.AUTH0_CLIENT_ID;
	  var clientSecret = req.webtaskContext.data.AUTH0_CLIENT_SECRET;

	  getTokenCached(apiUrl, audience, clientId, clientSecret, function (access_token, err) {
	    if (err) {
	      console.log('Error getting access_token', err);
	      return next(err);
	    }

	    req.access_token = access_token;
	    next();
	  });
	});

	app.get('/', lastLogCheckpoint);
	app.post('/', lastLogCheckpoint);

	module.exports = Webtask.fromExpress(app);

/***/ },
/* 1 */
/***/ function(module, exports, __webpack_require__) {

	'use strict';

	var request = __webpack_require__(2);
	var stringifySafe = __webpack_require__(3);
	var _assign = __webpack_require__(4);
	var dgram = __webpack_require__(5);
	var callback = __webpack_require__(6).callback;

	//exports.version = require('../package.json').version;

	var LogzioLogger = function LogzioLogger(options) {
	  if (!options || !options.token) {
	    throw new Error('You are required to supply a token for logging.');
	  }

	  this.token = options.token;
	  this.host = options.host || 'listener.logz.io';
	  this.userAgent = 'Logzio-Logger NodeJS';
	  this.type = options.type || 'nodejs';
	  this.sendIntervalMs = options.sendIntervalMs || 10 * 1000;
	  this.bufferSize = options.bufferSize || 100;
	  this.debug = options.debug || false;
	  this.numberOfRetries = options.numberOfRetries || 3;
	  this.timer = null;
	  this.closed = false;
	  this.supressErrors = options.supressErrors || false;
	  this.addTimestampWithNanoSecs = options.addTimestampWithNanoSecs || false;

	  var protocolToPortMap = {
	    'udp': 5050,
	    'http': 8070,
	    'https': 8071
	  };
	  this.protocol = options.protocol || 'http';
	  if (!protocolToPortMap.hasOwnProperty(this.protocol)) {
	    throw new Error('Invalid protocol defined. Valid options are : ' + JSON.stringify(Object.keys(protocolToPortMap)));
	  }
	  this.port = protocolToPortMap[this.protocol];

	  if (this.protocol === 'udp') {
	    this.udpClient = dgram.createSocket('udp4');
	  }

	  /*
	   Callback method executed on each bulk of messages sent to logzio.
	   If the bulk failed, it will be called: callback(exception), otherwise upon
	   success it will called as callback()
	   */
	  this.callback = options.callback || this._defaultCallback;

	  /*
	   * the read/write/connection timeout in milliseconds of the outgoing HTTP request
	   */
	  this.timeout = options.timeout;

	  // build the url for logging
	  this.url = this.protocol + '://' + this.host + ':' + this.port + '?token=' + this.token;

	  this.messages = [];
	  this.bulkId = 1;
	  this.extraFields = options.extraFields || {};
	};

	exports.createLogger = function (options) {
	  var l = new LogzioLogger(options);
	  l._timerSend();
	  return l;
	};

	var jsonToString = exports.jsonToString = function (json) {
	  try {
	    return JSON.stringify(json);
	  } catch (ex) {
	    return stringifySafe(json, null, null, function () {});
	  }
	};

	LogzioLogger.prototype._defaultCallback = function (err) {
	  if (err && !this.supressErrors) {
	    console.error('logzio-logger error: ' + err, err);
	  }
	};

	LogzioLogger.prototype.sendAndClose = function (callback) {
	  this.callback = callback || this._defaultCallback;
	  this._debug("Sending last messages and closing...");
	  this._popMsgsAndSend();
	  clearTimeout(this.timer);

	  if (this.protocol === 'udp') {
	    this.udpClient.close();
	  }
	};

	LogzioLogger.prototype._timerSend = function () {
	  if (this.messages.length > 0) {
	    this._debug('Woke up and saw ' + this.messages.length + ' messages to send. Sending now...');
	    this._popMsgsAndSend();
	  }

	  var mythis = this;
	  this.timer = setTimeout(function () {
	    mythis._timerSend();
	  }, this.sendIntervalMs);
	};

	LogzioLogger.prototype._sendMessagesUDP = function () {
	  var messagesLength = this.messages.length;

	  var udpSentCallback = function udpSentCallback(err, bytes) {
	    if (err) {
	      this._debug('Error while sending udp packets. err = ' + err);
	      callback(new Error('Failed to send udp log message. err = ' + err));
	    }
	  };

	  for (var i = 0; i < messagesLength; i++) {

	    var msg = this.messages[i];
	    msg.token = this.token;
	    var buff = new Buffer(stringifySafe(msg));

	    this._debug('Starting to send messages via udp.');
	    this.udpClient.send(buff, 0, buff.length, this.port, this.host, udpSentCallback);
	  }
	};

	LogzioLogger.prototype.close = function () {
	  // clearing the timer allows the node event loop to quit when needed
	  clearTimeout(this.timer);
	  if (this.protocol === 'udp') {
	    this.udpClient.close();
	  }

	  // send pending messages, if any
	  if (this.messages.length > 0) {
	    this._debug("Closing, purging messages.");
	    this._popMsgsAndSend();
	  }

	  // no more logging allowed
	  this.closed = true;
	};

	LogzioLogger.prototype.log = function (msg) {
	  if (this.closed === true) {
	    throw new Error('Logging into a logger that has been closed!');
	  }
	  if (typeof msg === 'string') {
	    msg = { message: msg };
	    if (this.type) msg.type = this.type;
	  }
	  msg = _assign(msg, this.extraFields);
	  msg.type = this.type;

	  if (this.addTimestampWithNanoSecs) {
	    var time = process.hrtime();
	    var now = new Date().toISOString();
	    msg['@timestamp_nano'] = [now, time[0].toString(), time[1].toString()].join('-');
	  }

	  this.messages.push(msg);
	  if (this.messages.length >= this.bufferSize) {
	    this._debug('Buffer is full - sending bulk');
	    this._popMsgsAndSend();
	  }
	};

	LogzioLogger.prototype._popMsgsAndSend = function () {

	  if (this.protocol === 'udp') {
	    this._debug('Sending messages via udp');
	    this._sendMessagesUDP();
	  } else {
	    var bulk = this._createBulk(this.messages);
	    this._debug('Sending bulk #' + bulk.id);
	    this._send(bulk);
	  }

	  this.messages = [];
	};

	LogzioLogger.prototype._createBulk = function (msgs) {
	  var bulk = {};
	  // creates a new copy of the array. Objects references are copied (no deep copy)
	  bulk.msgs = msgs.slice();
	  bulk.attemptNumber = 1;
	  bulk.sleepUntilNextRetry = 2 * 1000;
	  bulk.id = this.bulkId++;

	  return bulk;
	};

	LogzioLogger.prototype._messagesToBody = function (msgs) {
	  var body = '';
	  for (var i = 0; i < msgs.length; i++) {
	    body = body + jsonToString(msgs[i]) + '\n';
	  }
	  return body;
	};

	LogzioLogger.prototype._debug = function (msg) {
	  if (this.debug) console.log('logzio-nodejs: ' + msg);
	};

	LogzioLogger.prototype._send = function (bulk) {
	  var mythis = this;
	  function tryAgainIn(sleepTimeMs) {
	    mythis._debug('Bulk #' + bulk.id + ' - Trying again in ' + sleepTimeMs + '[ms], attempt no. ' + bulk.attemptNumber);
	    setTimeout(function () {
	      mythis._send(bulk);
	    }, sleepTimeMs);
	  }

	  var body = this._messagesToBody(bulk.msgs);
	  mythis._debug('Request body = ' + body);
	  var options = {
	    uri: this.url,
	    body: body,
	    headers: {
	      'host': this.host,
	      'accept': '*/*',
	      'user-agent': this.userAgent,
	      'content-type': 'text/plain',
	      'content-length': Buffer.byteLength(body)
	    }
	  };
	  if (typeof this.timeout !== 'undefined') {
	    options.timeout = this.timeout;
	  }

	  var callback = this.callback;
	  try {
	    request.post(options, function (err, res, body) {
	      if (err) {
	        // In rare cases server is busy
	        if (err.code === 'ETIMEDOUT' || err.code === 'ECONNRESET' || err.code === 'ESOCKETTIMEDOUT' || err.code === 'ECONNABORTED') {
	          if (bulk.attemptNumber >= mythis.numberOfRetries) {
	            callback(new Error('Failed after ' + bulk.attemptNumber + ' retries on error = ' + err, err));
	          } else {
	            mythis._debug('Bulk #' + bulk.id + ' - failed on error: ' + err);
	            var sleepTimeMs = bulk.sleepUntilNextRetry;
	            bulk.sleepUntilNextRetry = bulk.sleepUntilNextRetry * 2;
	            bulk.attemptNumber++;
	            tryAgainIn(sleepTimeMs);
	          }
	        } else {
	          callback(err);
	        }
	      } else {
	        var responseCode = res.statusCode.toString();
	        if (responseCode !== '200') {
	          callback(new Error('There was a problem with the request.\nResponse: ' + responseCode + ': ' + body.toString()));
	        } else {
	          mythis._debug('Bulk #' + bulk.id + ' - sent successfully');
	          callback();
	        }
	      }
	    });
	  } catch (ex) {
	    callback(ex);
	  }
	};

/***/ },
/* 2 */
/***/ function(module, exports) {

	module.exports = require("request");

/***/ },
/* 3 */
/***/ function(module, exports) {

	module.exports = require("json-stringify-safe");

/***/ },
/* 4 */
/***/ function(module, exports) {

	/**
	 * lodash (Custom Build) <https://lodash.com/>
	 * Build: `lodash modularize exports="npm" -o ./`
	 * Copyright jQuery Foundation and other contributors <https://jquery.org/>
	 * Released under MIT license <https://lodash.com/license>
	 * Based on Underscore.js 1.8.3 <http://underscorejs.org/LICENSE>
	 * Copyright Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
	 */

	/** Used as references for various `Number` constants. */
	var MAX_SAFE_INTEGER = 9007199254740991;

	/** `Object#toString` result references. */
	var argsTag = '[object Arguments]',
	    funcTag = '[object Function]',
	    genTag = '[object GeneratorFunction]';

	/** Used to detect unsigned integer values. */
	var reIsUint = /^(?:0|[1-9]\d*)$/;

	/**
	 * A faster alternative to `Function#apply`, this function invokes `func`
	 * with the `this` binding of `thisArg` and the arguments of `args`.
	 *
	 * @private
	 * @param {Function} func The function to invoke.
	 * @param {*} thisArg The `this` binding of `func`.
	 * @param {Array} args The arguments to invoke `func` with.
	 * @returns {*} Returns the result of `func`.
	 */
	function apply(func, thisArg, args) {
	  switch (args.length) {
	    case 0: return func.call(thisArg);
	    case 1: return func.call(thisArg, args[0]);
	    case 2: return func.call(thisArg, args[0], args[1]);
	    case 3: return func.call(thisArg, args[0], args[1], args[2]);
	  }
	  return func.apply(thisArg, args);
	}

	/**
	 * The base implementation of `_.times` without support for iteratee shorthands
	 * or max array length checks.
	 *
	 * @private
	 * @param {number} n The number of times to invoke `iteratee`.
	 * @param {Function} iteratee The function invoked per iteration.
	 * @returns {Array} Returns the array of results.
	 */
	function baseTimes(n, iteratee) {
	  var index = -1,
	      result = Array(n);

	  while (++index < n) {
	    result[index] = iteratee(index);
	  }
	  return result;
	}

	/**
	 * Creates a unary function that invokes `func` with its argument transformed.
	 *
	 * @private
	 * @param {Function} func The function to wrap.
	 * @param {Function} transform The argument transform.
	 * @returns {Function} Returns the new function.
	 */
	function overArg(func, transform) {
	  return function(arg) {
	    return func(transform(arg));
	  };
	}

	/** Used for built-in method references. */
	var objectProto = Object.prototype;

	/** Used to check objects for own properties. */
	var hasOwnProperty = objectProto.hasOwnProperty;

	/**
	 * Used to resolve the
	 * [`toStringTag`](http://ecma-international.org/ecma-262/7.0/#sec-object.prototype.tostring)
	 * of values.
	 */
	var objectToString = objectProto.toString;

	/** Built-in value references. */
	var propertyIsEnumerable = objectProto.propertyIsEnumerable;

	/* Built-in method references for those with the same name as other `lodash` methods. */
	var nativeKeys = overArg(Object.keys, Object),
	    nativeMax = Math.max;

	/** Detect if properties shadowing those on `Object.prototype` are non-enumerable. */
	var nonEnumShadows = !propertyIsEnumerable.call({ 'valueOf': 1 }, 'valueOf');

	/**
	 * Creates an array of the enumerable property names of the array-like `value`.
	 *
	 * @private
	 * @param {*} value The value to query.
	 * @param {boolean} inherited Specify returning inherited property names.
	 * @returns {Array} Returns the array of property names.
	 */
	function arrayLikeKeys(value, inherited) {
	  // Safari 8.1 makes `arguments.callee` enumerable in strict mode.
	  // Safari 9 makes `arguments.length` enumerable in strict mode.
	  var result = (isArray(value) || isArguments(value))
	    ? baseTimes(value.length, String)
	    : [];

	  var length = result.length,
	      skipIndexes = !!length;

	  for (var key in value) {
	    if ((inherited || hasOwnProperty.call(value, key)) &&
	        !(skipIndexes && (key == 'length' || isIndex(key, length)))) {
	      result.push(key);
	    }
	  }
	  return result;
	}

	/**
	 * Assigns `value` to `key` of `object` if the existing value is not equivalent
	 * using [`SameValueZero`](http://ecma-international.org/ecma-262/7.0/#sec-samevaluezero)
	 * for equality comparisons.
	 *
	 * @private
	 * @param {Object} object The object to modify.
	 * @param {string} key The key of the property to assign.
	 * @param {*} value The value to assign.
	 */
	function assignValue(object, key, value) {
	  var objValue = object[key];
	  if (!(hasOwnProperty.call(object, key) && eq(objValue, value)) ||
	      (value === undefined && !(key in object))) {
	    object[key] = value;
	  }
	}

	/**
	 * The base implementation of `_.keys` which doesn't treat sparse arrays as dense.
	 *
	 * @private
	 * @param {Object} object The object to query.
	 * @returns {Array} Returns the array of property names.
	 */
	function baseKeys(object) {
	  if (!isPrototype(object)) {
	    return nativeKeys(object);
	  }
	  var result = [];
	  for (var key in Object(object)) {
	    if (hasOwnProperty.call(object, key) && key != 'constructor') {
	      result.push(key);
	    }
	  }
	  return result;
	}

	/**
	 * The base implementation of `_.rest` which doesn't validate or coerce arguments.
	 *
	 * @private
	 * @param {Function} func The function to apply a rest parameter to.
	 * @param {number} [start=func.length-1] The start position of the rest parameter.
	 * @returns {Function} Returns the new function.
	 */
	function baseRest(func, start) {
	  start = nativeMax(start === undefined ? (func.length - 1) : start, 0);
	  return function() {
	    var args = arguments,
	        index = -1,
	        length = nativeMax(args.length - start, 0),
	        array = Array(length);

	    while (++index < length) {
	      array[index] = args[start + index];
	    }
	    index = -1;
	    var otherArgs = Array(start + 1);
	    while (++index < start) {
	      otherArgs[index] = args[index];
	    }
	    otherArgs[start] = array;
	    return apply(func, this, otherArgs);
	  };
	}

	/**
	 * Copies properties of `source` to `object`.
	 *
	 * @private
	 * @param {Object} source The object to copy properties from.
	 * @param {Array} props The property identifiers to copy.
	 * @param {Object} [object={}] The object to copy properties to.
	 * @param {Function} [customizer] The function to customize copied values.
	 * @returns {Object} Returns `object`.
	 */
	function copyObject(source, props, object, customizer) {
	  object || (object = {});

	  var index = -1,
	      length = props.length;

	  while (++index < length) {
	    var key = props[index];

	    var newValue = customizer
	      ? customizer(object[key], source[key], key, object, source)
	      : undefined;

	    assignValue(object, key, newValue === undefined ? source[key] : newValue);
	  }
	  return object;
	}

	/**
	 * Creates a function like `_.assign`.
	 *
	 * @private
	 * @param {Function} assigner The function to assign values.
	 * @returns {Function} Returns the new assigner function.
	 */
	function createAssigner(assigner) {
	  return baseRest(function(object, sources) {
	    var index = -1,
	        length = sources.length,
	        customizer = length > 1 ? sources[length - 1] : undefined,
	        guard = length > 2 ? sources[2] : undefined;

	    customizer = (assigner.length > 3 && typeof customizer == 'function')
	      ? (length--, customizer)
	      : undefined;

	    if (guard && isIterateeCall(sources[0], sources[1], guard)) {
	      customizer = length < 3 ? undefined : customizer;
	      length = 1;
	    }
	    object = Object(object);
	    while (++index < length) {
	      var source = sources[index];
	      if (source) {
	        assigner(object, source, index, customizer);
	      }
	    }
	    return object;
	  });
	}

	/**
	 * Checks if `value` is a valid array-like index.
	 *
	 * @private
	 * @param {*} value The value to check.
	 * @param {number} [length=MAX_SAFE_INTEGER] The upper bounds of a valid index.
	 * @returns {boolean} Returns `true` if `value` is a valid index, else `false`.
	 */
	function isIndex(value, length) {
	  length = length == null ? MAX_SAFE_INTEGER : length;
	  return !!length &&
	    (typeof value == 'number' || reIsUint.test(value)) &&
	    (value > -1 && value % 1 == 0 && value < length);
	}

	/**
	 * Checks if the given arguments are from an iteratee call.
	 *
	 * @private
	 * @param {*} value The potential iteratee value argument.
	 * @param {*} index The potential iteratee index or key argument.
	 * @param {*} object The potential iteratee object argument.
	 * @returns {boolean} Returns `true` if the arguments are from an iteratee call,
	 *  else `false`.
	 */
	function isIterateeCall(value, index, object) {
	  if (!isObject(object)) {
	    return false;
	  }
	  var type = typeof index;
	  if (type == 'number'
	        ? (isArrayLike(object) && isIndex(index, object.length))
	        : (type == 'string' && index in object)
	      ) {
	    return eq(object[index], value);
	  }
	  return false;
	}

	/**
	 * Checks if `value` is likely a prototype object.
	 *
	 * @private
	 * @param {*} value The value to check.
	 * @returns {boolean} Returns `true` if `value` is a prototype, else `false`.
	 */
	function isPrototype(value) {
	  var Ctor = value && value.constructor,
	      proto = (typeof Ctor == 'function' && Ctor.prototype) || objectProto;

	  return value === proto;
	}

	/**
	 * Performs a
	 * [`SameValueZero`](http://ecma-international.org/ecma-262/7.0/#sec-samevaluezero)
	 * comparison between two values to determine if they are equivalent.
	 *
	 * @static
	 * @memberOf _
	 * @since 4.0.0
	 * @category Lang
	 * @param {*} value The value to compare.
	 * @param {*} other The other value to compare.
	 * @returns {boolean} Returns `true` if the values are equivalent, else `false`.
	 * @example
	 *
	 * var object = { 'a': 1 };
	 * var other = { 'a': 1 };
	 *
	 * _.eq(object, object);
	 * // => true
	 *
	 * _.eq(object, other);
	 * // => false
	 *
	 * _.eq('a', 'a');
	 * // => true
	 *
	 * _.eq('a', Object('a'));
	 * // => false
	 *
	 * _.eq(NaN, NaN);
	 * // => true
	 */
	function eq(value, other) {
	  return value === other || (value !== value && other !== other);
	}

	/**
	 * Checks if `value` is likely an `arguments` object.
	 *
	 * @static
	 * @memberOf _
	 * @since 0.1.0
	 * @category Lang
	 * @param {*} value The value to check.
	 * @returns {boolean} Returns `true` if `value` is an `arguments` object,
	 *  else `false`.
	 * @example
	 *
	 * _.isArguments(function() { return arguments; }());
	 * // => true
	 *
	 * _.isArguments([1, 2, 3]);
	 * // => false
	 */
	function isArguments(value) {
	  // Safari 8.1 makes `arguments.callee` enumerable in strict mode.
	  return isArrayLikeObject(value) && hasOwnProperty.call(value, 'callee') &&
	    (!propertyIsEnumerable.call(value, 'callee') || objectToString.call(value) == argsTag);
	}

	/**
	 * Checks if `value` is classified as an `Array` object.
	 *
	 * @static
	 * @memberOf _
	 * @since 0.1.0
	 * @category Lang
	 * @param {*} value The value to check.
	 * @returns {boolean} Returns `true` if `value` is an array, else `false`.
	 * @example
	 *
	 * _.isArray([1, 2, 3]);
	 * // => true
	 *
	 * _.isArray(document.body.children);
	 * // => false
	 *
	 * _.isArray('abc');
	 * // => false
	 *
	 * _.isArray(_.noop);
	 * // => false
	 */
	var isArray = Array.isArray;

	/**
	 * Checks if `value` is array-like. A value is considered array-like if it's
	 * not a function and has a `value.length` that's an integer greater than or
	 * equal to `0` and less than or equal to `Number.MAX_SAFE_INTEGER`.
	 *
	 * @static
	 * @memberOf _
	 * @since 4.0.0
	 * @category Lang
	 * @param {*} value The value to check.
	 * @returns {boolean} Returns `true` if `value` is array-like, else `false`.
	 * @example
	 *
	 * _.isArrayLike([1, 2, 3]);
	 * // => true
	 *
	 * _.isArrayLike(document.body.children);
	 * // => true
	 *
	 * _.isArrayLike('abc');
	 * // => true
	 *
	 * _.isArrayLike(_.noop);
	 * // => false
	 */
	function isArrayLike(value) {
	  return value != null && isLength(value.length) && !isFunction(value);
	}

	/**
	 * This method is like `_.isArrayLike` except that it also checks if `value`
	 * is an object.
	 *
	 * @static
	 * @memberOf _
	 * @since 4.0.0
	 * @category Lang
	 * @param {*} value The value to check.
	 * @returns {boolean} Returns `true` if `value` is an array-like object,
	 *  else `false`.
	 * @example
	 *
	 * _.isArrayLikeObject([1, 2, 3]);
	 * // => true
	 *
	 * _.isArrayLikeObject(document.body.children);
	 * // => true
	 *
	 * _.isArrayLikeObject('abc');
	 * // => false
	 *
	 * _.isArrayLikeObject(_.noop);
	 * // => false
	 */
	function isArrayLikeObject(value) {
	  return isObjectLike(value) && isArrayLike(value);
	}

	/**
	 * Checks if `value` is classified as a `Function` object.
	 *
	 * @static
	 * @memberOf _
	 * @since 0.1.0
	 * @category Lang
	 * @param {*} value The value to check.
	 * @returns {boolean} Returns `true` if `value` is a function, else `false`.
	 * @example
	 *
	 * _.isFunction(_);
	 * // => true
	 *
	 * _.isFunction(/abc/);
	 * // => false
	 */
	function isFunction(value) {
	  // The use of `Object#toString` avoids issues with the `typeof` operator
	  // in Safari 8-9 which returns 'object' for typed array and other constructors.
	  var tag = isObject(value) ? objectToString.call(value) : '';
	  return tag == funcTag || tag == genTag;
	}

	/**
	 * Checks if `value` is a valid array-like length.
	 *
	 * **Note:** This method is loosely based on
	 * [`ToLength`](http://ecma-international.org/ecma-262/7.0/#sec-tolength).
	 *
	 * @static
	 * @memberOf _
	 * @since 4.0.0
	 * @category Lang
	 * @param {*} value The value to check.
	 * @returns {boolean} Returns `true` if `value` is a valid length, else `false`.
	 * @example
	 *
	 * _.isLength(3);
	 * // => true
	 *
	 * _.isLength(Number.MIN_VALUE);
	 * // => false
	 *
	 * _.isLength(Infinity);
	 * // => false
	 *
	 * _.isLength('3');
	 * // => false
	 */
	function isLength(value) {
	  return typeof value == 'number' &&
	    value > -1 && value % 1 == 0 && value <= MAX_SAFE_INTEGER;
	}

	/**
	 * Checks if `value` is the
	 * [language type](http://www.ecma-international.org/ecma-262/7.0/#sec-ecmascript-language-types)
	 * of `Object`. (e.g. arrays, functions, objects, regexes, `new Number(0)`, and `new String('')`)
	 *
	 * @static
	 * @memberOf _
	 * @since 0.1.0
	 * @category Lang
	 * @param {*} value The value to check.
	 * @returns {boolean} Returns `true` if `value` is an object, else `false`.
	 * @example
	 *
	 * _.isObject({});
	 * // => true
	 *
	 * _.isObject([1, 2, 3]);
	 * // => true
	 *
	 * _.isObject(_.noop);
	 * // => true
	 *
	 * _.isObject(null);
	 * // => false
	 */
	function isObject(value) {
	  var type = typeof value;
	  return !!value && (type == 'object' || type == 'function');
	}

	/**
	 * Checks if `value` is object-like. A value is object-like if it's not `null`
	 * and has a `typeof` result of "object".
	 *
	 * @static
	 * @memberOf _
	 * @since 4.0.0
	 * @category Lang
	 * @param {*} value The value to check.
	 * @returns {boolean} Returns `true` if `value` is object-like, else `false`.
	 * @example
	 *
	 * _.isObjectLike({});
	 * // => true
	 *
	 * _.isObjectLike([1, 2, 3]);
	 * // => true
	 *
	 * _.isObjectLike(_.noop);
	 * // => false
	 *
	 * _.isObjectLike(null);
	 * // => false
	 */
	function isObjectLike(value) {
	  return !!value && typeof value == 'object';
	}

	/**
	 * Assigns own enumerable string keyed properties of source objects to the
	 * destination object. Source objects are applied from left to right.
	 * Subsequent sources overwrite property assignments of previous sources.
	 *
	 * **Note:** This method mutates `object` and is loosely based on
	 * [`Object.assign`](https://mdn.io/Object/assign).
	 *
	 * @static
	 * @memberOf _
	 * @since 0.10.0
	 * @category Object
	 * @param {Object} object The destination object.
	 * @param {...Object} [sources] The source objects.
	 * @returns {Object} Returns `object`.
	 * @see _.assignIn
	 * @example
	 *
	 * function Foo() {
	 *   this.a = 1;
	 * }
	 *
	 * function Bar() {
	 *   this.c = 3;
	 * }
	 *
	 * Foo.prototype.b = 2;
	 * Bar.prototype.d = 4;
	 *
	 * _.assign({ 'a': 0 }, new Foo, new Bar);
	 * // => { 'a': 1, 'c': 3 }
	 */
	var assign = createAssigner(function(object, source) {
	  if (nonEnumShadows || isPrototype(source) || isArrayLike(source)) {
	    copyObject(source, keys(source), object);
	    return;
	  }
	  for (var key in source) {
	    if (hasOwnProperty.call(source, key)) {
	      assignValue(object, key, source[key]);
	    }
	  }
	});

	/**
	 * Creates an array of the own enumerable property names of `object`.
	 *
	 * **Note:** Non-object values are coerced to objects. See the
	 * [ES spec](http://ecma-international.org/ecma-262/7.0/#sec-object.keys)
	 * for more details.
	 *
	 * @static
	 * @since 0.1.0
	 * @memberOf _
	 * @category Object
	 * @param {Object} object The object to query.
	 * @returns {Array} Returns the array of property names.
	 * @example
	 *
	 * function Foo() {
	 *   this.a = 1;
	 *   this.b = 2;
	 * }
	 *
	 * Foo.prototype.c = 3;
	 *
	 * _.keys(new Foo);
	 * // => ['a', 'b'] (iteration order is not guaranteed)
	 *
	 * _.keys('hi');
	 * // => ['0', '1']
	 */
	function keys(object) {
	  return isArrayLike(object) ? arrayLikeKeys(object) : baseKeys(object);
	}

	module.exports = assign;


/***/ },
/* 5 */
/***/ function(module, exports) {

	module.exports = require("dgram");

/***/ },
/* 6 */
/***/ function(module, exports, __webpack_require__) {

	'use strict'

	var http = __webpack_require__(7)
	  , https = __webpack_require__(8)
	  , url = __webpack_require__(9)
	  , util = __webpack_require__(10)
	  , stream = __webpack_require__(11)
	  , zlib = __webpack_require__(12)
	  , hawk = __webpack_require__(13)
	  , aws2 = __webpack_require__(14)
	  , aws4 = __webpack_require__(15)
	  , httpSignature = __webpack_require__(19)
	  , mime = __webpack_require__(20)
	  , stringstream = __webpack_require__(21)
	  , caseless = __webpack_require__(22)
	  , ForeverAgent = __webpack_require__(23)
	  , FormData = __webpack_require__(24)
	  , extend = __webpack_require__(25)
	  , isstream = __webpack_require__(26)
	  , isTypedArray = __webpack_require__(27).strict
	  , helpers = __webpack_require__(28)
	  , cookies = __webpack_require__(33)
	  , getProxyFromURI = __webpack_require__(35)
	  , Querystring = __webpack_require__(36).Querystring
	  , Har = __webpack_require__(38).Har
	  , Auth = __webpack_require__(41).Auth
	  , OAuth = __webpack_require__(43).OAuth
	  , Multipart = __webpack_require__(45).Multipart
	  , Redirect = __webpack_require__(47).Redirect
	  , Tunnel = __webpack_require__(48).Tunnel
	  , now = __webpack_require__(50)
	  , Buffer = __webpack_require__(31).Buffer

	var safeStringify = helpers.safeStringify
	  , isReadStream = helpers.isReadStream
	  , toBase64 = helpers.toBase64
	  , defer = helpers.defer
	  , copy = helpers.copy
	  , version = helpers.version
	  , globalCookieJar = cookies.jar()


	var globalPool = {}

	function filterForNonReserved(reserved, options) {
	  // Filter out properties that are not reserved.
	  // Reserved values are passed in at call site.

	  var object = {}
	  for (var i in options) {
	    var notReserved = (reserved.indexOf(i) === -1)
	    if (notReserved) {
	      object[i] = options[i]
	    }
	  }
	  return object
	}

	function filterOutReservedFunctions(reserved, options) {
	  // Filter out properties that are functions and are reserved.
	  // Reserved values are passed in at call site.

	  var object = {}
	  for (var i in options) {
	    var isReserved = !(reserved.indexOf(i) === -1)
	    var isFunction = (typeof options[i] === 'function')
	    if (!(isReserved && isFunction)) {
	      object[i] = options[i]
	    }
	  }
	  return object

	}

	// Return a simpler request object to allow serialization
	function requestToJSON() {
	  var self = this
	  return {
	    uri: self.uri,
	    method: self.method,
	    headers: self.headers
	  }
	}

	// Return a simpler response object to allow serialization
	function responseToJSON() {
	  var self = this
	  return {
	    statusCode: self.statusCode,
	    body: self.body,
	    headers: self.headers,
	    request: requestToJSON.call(self.request)
	  }
	}

	function Request (options) {
	  // if given the method property in options, set property explicitMethod to true

	  // extend the Request instance with any non-reserved properties
	  // remove any reserved functions from the options object
	  // set Request instance to be readable and writable
	  // call init

	  var self = this

	  // start with HAR, then override with additional options
	  if (options.har) {
	    self._har = new Har(self)
	    options = self._har.options(options)
	  }

	  stream.Stream.call(self)
	  var reserved = Object.keys(Request.prototype)
	  var nonReserved = filterForNonReserved(reserved, options)

	  extend(self, nonReserved)
	  options = filterOutReservedFunctions(reserved, options)

	  self.readable = true
	  self.writable = true
	  if (options.method) {
	    self.explicitMethod = true
	  }
	  self._qs = new Querystring(self)
	  self._auth = new Auth(self)
	  self._oauth = new OAuth(self)
	  self._multipart = new Multipart(self)
	  self._redirect = new Redirect(self)
	  self._tunnel = new Tunnel(self)
	  self.init(options)
	}

	util.inherits(Request, stream.Stream)

	// Debugging
	Request.debug = process.env.NODE_DEBUG && /\brequest\b/.test(process.env.NODE_DEBUG)
	function debug() {
	  if (Request.debug) {
	    console.error('REQUEST %s', util.format.apply(util, arguments))
	  }
	}
	Request.prototype.debug = debug

	Request.prototype.init = function (options) {
	  // init() contains all the code to setup the request object.
	  // the actual outgoing request is not started until start() is called
	  // this function is called from both the constructor and on redirect.
	  var self = this
	  if (!options) {
	    options = {}
	  }
	  self.headers = self.headers ? copy(self.headers) : {}

	  // Delete headers with value undefined since they break
	  // ClientRequest.OutgoingMessage.setHeader in node 0.12
	  for (var headerName in self.headers) {
	    if (typeof self.headers[headerName] === 'undefined') {
	      delete self.headers[headerName]
	    }
	  }

	  caseless.httpify(self, self.headers)

	  if (!self.method) {
	    self.method = options.method || 'GET'
	  }
	  if (!self.localAddress) {
	    self.localAddress = options.localAddress
	  }

	  self._qs.init(options)

	  debug(options)
	  if (!self.pool && self.pool !== false) {
	    self.pool = globalPool
	  }
	  self.dests = self.dests || []
	  self.__isRequestRequest = true

	  // Protect against double callback
	  if (!self._callback && self.callback) {
	    self._callback = self.callback
	    self.callback = function () {
	      if (self._callbackCalled) {
	        return // Print a warning maybe?
	      }
	      self._callbackCalled = true
	      self._callback.apply(self, arguments)
	    }
	    self.on('error', self.callback.bind())
	    self.on('complete', self.callback.bind(self, null))
	  }

	  // People use this property instead all the time, so support it
	  if (!self.uri && self.url) {
	    self.uri = self.url
	    delete self.url
	  }

	  // If there's a baseUrl, then use it as the base URL (i.e. uri must be
	  // specified as a relative path and is appended to baseUrl).
	  if (self.baseUrl) {
	    if (typeof self.baseUrl !== 'string') {
	      return self.emit('error', new Error('options.baseUrl must be a string'))
	    }

	    if (typeof self.uri !== 'string') {
	      return self.emit('error', new Error('options.uri must be a string when using options.baseUrl'))
	    }

	    if (self.uri.indexOf('//') === 0 || self.uri.indexOf('://') !== -1) {
	      return self.emit('error', new Error('options.uri must be a path when using options.baseUrl'))
	    }

	    // Handle all cases to make sure that there's only one slash between
	    // baseUrl and uri.
	    var baseUrlEndsWithSlash = self.baseUrl.lastIndexOf('/') === self.baseUrl.length - 1
	    var uriStartsWithSlash = self.uri.indexOf('/') === 0

	    if (baseUrlEndsWithSlash && uriStartsWithSlash) {
	      self.uri = self.baseUrl + self.uri.slice(1)
	    } else if (baseUrlEndsWithSlash || uriStartsWithSlash) {
	      self.uri = self.baseUrl + self.uri
	    } else if (self.uri === '') {
	      self.uri = self.baseUrl
	    } else {
	      self.uri = self.baseUrl + '/' + self.uri
	    }
	    delete self.baseUrl
	  }

	  // A URI is needed by this point, emit error if we haven't been able to get one
	  if (!self.uri) {
	    return self.emit('error', new Error('options.uri is a required argument'))
	  }

	  // If a string URI/URL was given, parse it into a URL object
	  if (typeof self.uri === 'string') {
	    self.uri = url.parse(self.uri)
	  }

	  // Some URL objects are not from a URL parsed string and need href added
	  if (!self.uri.href) {
	    self.uri.href = url.format(self.uri)
	  }

	  // DEPRECATED: Warning for users of the old Unix Sockets URL Scheme
	  if (self.uri.protocol === 'unix:') {
	    return self.emit('error', new Error('`unix://` URL scheme is no longer supported. Please use the format `http://unix:SOCKET:PATH`'))
	  }

	  // Support Unix Sockets
	  if (self.uri.host === 'unix') {
	    self.enableUnixSocket()
	  }

	  if (self.strictSSL === false) {
	    self.rejectUnauthorized = false
	  }

	  if (!self.uri.pathname) {self.uri.pathname = '/'}

	  if (!(self.uri.host || (self.uri.hostname && self.uri.port)) && !self.uri.isUnix) {
	    // Invalid URI: it may generate lot of bad errors, like 'TypeError: Cannot call method `indexOf` of undefined' in CookieJar
	    // Detect and reject it as soon as possible
	    var faultyUri = url.format(self.uri)
	    var message = 'Invalid URI "' + faultyUri + '"'
	    if (Object.keys(options).length === 0) {
	      // No option ? This can be the sign of a redirect
	      // As this is a case where the user cannot do anything (they didn't call request directly with this URL)
	      // they should be warned that it can be caused by a redirection (can save some hair)
	      message += '. This can be caused by a crappy redirection.'
	    }
	    // This error was fatal
	    self.abort()
	    return self.emit('error', new Error(message))
	  }

	  if (!self.hasOwnProperty('proxy')) {
	    self.proxy = getProxyFromURI(self.uri)
	  }

	  self.tunnel = self._tunnel.isEnabled()
	  if (self.proxy) {
	    self._tunnel.setup(options)
	  }

	  self._redirect.onRequest(options)

	  self.setHost = false
	  if (!self.hasHeader('host')) {
	    var hostHeaderName = self.originalHostHeaderName || 'host'
	    // When used with an IPv6 address, `host` will provide
	    // the correct bracketed format, unlike using `hostname` and
	    // optionally adding the `port` when necessary.
	    self.setHeader(hostHeaderName, self.uri.host)
	    self.setHost = true
	  }

	  self.jar(self._jar || options.jar)

	  if (!self.uri.port) {
	    if (self.uri.protocol === 'http:') {self.uri.port = 80}
	    else if (self.uri.protocol === 'https:') {self.uri.port = 443}
	  }

	  if (self.proxy && !self.tunnel) {
	    self.port = self.proxy.port
	    self.host = self.proxy.hostname
	  } else {
	    self.port = self.uri.port
	    self.host = self.uri.hostname
	  }

	  if (options.form) {
	    self.form(options.form)
	  }

	  if (options.formData) {
	    var formData = options.formData
	    var requestForm = self.form()
	    var appendFormValue = function (key, value) {
	      if (value && value.hasOwnProperty('value') && value.hasOwnProperty('options')) {
	        requestForm.append(key, value.value, value.options)
	      } else {
	        requestForm.append(key, value)
	      }
	    }
	    for (var formKey in formData) {
	      if (formData.hasOwnProperty(formKey)) {
	        var formValue = formData[formKey]
	        if (formValue instanceof Array) {
	          for (var j = 0; j < formValue.length; j++) {
	            appendFormValue(formKey, formValue[j])
	          }
	        } else {
	          appendFormValue(formKey, formValue)
	        }
	      }
	    }
	  }

	  if (options.qs) {
	    self.qs(options.qs)
	  }

	  if (self.uri.path) {
	    self.path = self.uri.path
	  } else {
	    self.path = self.uri.pathname + (self.uri.search || '')
	  }

	  if (self.path.length === 0) {
	    self.path = '/'
	  }

	  // Auth must happen last in case signing is dependent on other headers
	  if (options.aws) {
	    self.aws(options.aws)
	  }

	  if (options.hawk) {
	    self.hawk(options.hawk)
	  }

	  if (options.httpSignature) {
	    self.httpSignature(options.httpSignature)
	  }

	  if (options.auth) {
	    if (Object.prototype.hasOwnProperty.call(options.auth, 'username')) {
	      options.auth.user = options.auth.username
	    }
	    if (Object.prototype.hasOwnProperty.call(options.auth, 'password')) {
	      options.auth.pass = options.auth.password
	    }

	    self.auth(
	      options.auth.user,
	      options.auth.pass,
	      options.auth.sendImmediately,
	      options.auth.bearer
	    )
	  }

	  if (self.gzip && !self.hasHeader('accept-encoding')) {
	    self.setHeader('accept-encoding', 'gzip, deflate')
	  }

	  if (self.uri.auth && !self.hasHeader('authorization')) {
	    var uriAuthPieces = self.uri.auth.split(':').map(function(item) {return self._qs.unescape(item)})
	    self.auth(uriAuthPieces[0], uriAuthPieces.slice(1).join(':'), true)
	  }

	  if (!self.tunnel && self.proxy && self.proxy.auth && !self.hasHeader('proxy-authorization')) {
	    var proxyAuthPieces = self.proxy.auth.split(':').map(function(item) {return self._qs.unescape(item)})
	    var authHeader = 'Basic ' + toBase64(proxyAuthPieces.join(':'))
	    self.setHeader('proxy-authorization', authHeader)
	  }

	  if (self.proxy && !self.tunnel) {
	    self.path = (self.uri.protocol + '//' + self.uri.host + self.path)
	  }

	  if (options.json) {
	    self.json(options.json)
	  }
	  if (options.multipart) {
	    self.multipart(options.multipart)
	  }

	  if (options.time) {
	    self.timing = true

	    // NOTE: elapsedTime is deprecated in favor of .timings
	    self.elapsedTime = self.elapsedTime || 0
	  }

	  function setContentLength () {
	    if (isTypedArray(self.body)) {
	      self.body = Buffer.from(self.body)
	    }

	    if (!self.hasHeader('content-length')) {
	      var length
	      if (typeof self.body === 'string') {
	        length = Buffer.byteLength(self.body)
	      }
	      else if (Array.isArray(self.body)) {
	        length = self.body.reduce(function (a, b) {return a + b.length}, 0)
	      }
	      else {
	        length = self.body.length
	      }

	      if (length) {
	        self.setHeader('content-length', length)
	      } else {
	        self.emit('error', new Error('Argument error, options.body.'))
	      }
	    }
	  }
	  if (self.body && !isstream(self.body)) {
	    setContentLength()
	  }

	  if (options.oauth) {
	    self.oauth(options.oauth)
	  } else if (self._oauth.params && self.hasHeader('authorization')) {
	    self.oauth(self._oauth.params)
	  }

	  var protocol = self.proxy && !self.tunnel ? self.proxy.protocol : self.uri.protocol
	    , defaultModules = {'http:':http, 'https:':https}
	    , httpModules = self.httpModules || {}

	  self.httpModule = httpModules[protocol] || defaultModules[protocol]

	  if (!self.httpModule) {
	    return self.emit('error', new Error('Invalid protocol: ' + protocol))
	  }

	  if (options.ca) {
	    self.ca = options.ca
	  }

	  if (!self.agent) {
	    if (options.agentOptions) {
	      self.agentOptions = options.agentOptions
	    }

	    if (options.agentClass) {
	      self.agentClass = options.agentClass
	    } else if (options.forever) {
	      var v = version()
	      // use ForeverAgent in node 0.10- only
	      if (v.major === 0 && v.minor <= 10) {
	        self.agentClass = protocol === 'http:' ? ForeverAgent : ForeverAgent.SSL
	      } else {
	        self.agentClass = self.httpModule.Agent
	        self.agentOptions = self.agentOptions || {}
	        self.agentOptions.keepAlive = true
	      }
	    } else {
	      self.agentClass = self.httpModule.Agent
	    }
	  }

	  if (self.pool === false) {
	    self.agent = false
	  } else {
	    self.agent = self.agent || self.getNewAgent()
	  }

	  self.on('pipe', function (src) {
	    if (self.ntick && self._started) {
	      self.emit('error', new Error('You cannot pipe to this stream after the outbound request has started.'))
	    }
	    self.src = src
	    if (isReadStream(src)) {
	      if (!self.hasHeader('content-type')) {
	        self.setHeader('content-type', mime.lookup(src.path))
	      }
	    } else {
	      if (src.headers) {
	        for (var i in src.headers) {
	          if (!self.hasHeader(i)) {
	            self.setHeader(i, src.headers[i])
	          }
	        }
	      }
	      if (self._json && !self.hasHeader('content-type')) {
	        self.setHeader('content-type', 'application/json')
	      }
	      if (src.method && !self.explicitMethod) {
	        self.method = src.method
	      }
	    }

	    // self.on('pipe', function () {
	    //   console.error('You have already piped to this stream. Pipeing twice is likely to break the request.')
	    // })
	  })

	  defer(function () {
	    if (self._aborted) {
	      return
	    }

	    var end = function () {
	      if (self._form) {
	        if (!self._auth.hasAuth) {
	          self._form.pipe(self)
	        }
	        else if (self._auth.hasAuth && self._auth.sentAuth) {
	          self._form.pipe(self)
	        }
	      }
	      if (self._multipart && self._multipart.chunked) {
	        self._multipart.body.pipe(self)
	      }
	      if (self.body) {
	        if (isstream(self.body)) {
	          self.body.pipe(self)
	        } else {
	          setContentLength()
	          if (Array.isArray(self.body)) {
	            self.body.forEach(function (part) {
	              self.write(part)
	            })
	          } else {
	            self.write(self.body)
	          }
	          self.end()
	        }
	      } else if (self.requestBodyStream) {
	        console.warn('options.requestBodyStream is deprecated, please pass the request object to stream.pipe.')
	        self.requestBodyStream.pipe(self)
	      } else if (!self.src) {
	        if (self._auth.hasAuth && !self._auth.sentAuth) {
	          self.end()
	          return
	        }
	        if (self.method !== 'GET' && typeof self.method !== 'undefined') {
	          self.setHeader('content-length', 0)
	        }
	        self.end()
	      }
	    }

	    if (self._form && !self.hasHeader('content-length')) {
	      // Before ending the request, we had to compute the length of the whole form, asyncly
	      self.setHeader(self._form.getHeaders(), true)
	      self._form.getLength(function (err, length) {
	        if (!err && !isNaN(length)) {
	          self.setHeader('content-length', length)
	        }
	        end()
	      })
	    } else {
	      end()
	    }

	    self.ntick = true
	  })

	}

	Request.prototype.getNewAgent = function () {
	  var self = this
	  var Agent = self.agentClass
	  var options = {}
	  if (self.agentOptions) {
	    for (var i in self.agentOptions) {
	      options[i] = self.agentOptions[i]
	    }
	  }
	  if (self.ca) {
	    options.ca = self.ca
	  }
	  if (self.ciphers) {
	    options.ciphers = self.ciphers
	  }
	  if (self.secureProtocol) {
	    options.secureProtocol = self.secureProtocol
	  }
	  if (self.secureOptions) {
	    options.secureOptions = self.secureOptions
	  }
	  if (typeof self.rejectUnauthorized !== 'undefined') {
	    options.rejectUnauthorized = self.rejectUnauthorized
	  }

	  if (self.cert && self.key) {
	    options.key = self.key
	    options.cert = self.cert
	  }

	  if (self.pfx) {
	    options.pfx = self.pfx
	  }

	  if (self.passphrase) {
	    options.passphrase = self.passphrase
	  }

	  var poolKey = ''

	  // different types of agents are in different pools
	  if (Agent !== self.httpModule.Agent) {
	    poolKey += Agent.name
	  }

	  // ca option is only relevant if proxy or destination are https
	  var proxy = self.proxy
	  if (typeof proxy === 'string') {
	    proxy = url.parse(proxy)
	  }
	  var isHttps = (proxy && proxy.protocol === 'https:') || this.uri.protocol === 'https:'

	  if (isHttps) {
	    if (options.ca) {
	      if (poolKey) {
	        poolKey += ':'
	      }
	      poolKey += options.ca
	    }

	    if (typeof options.rejectUnauthorized !== 'undefined') {
	      if (poolKey) {
	        poolKey += ':'
	      }
	      poolKey += options.rejectUnauthorized
	    }

	    if (options.cert) {
	      if (poolKey) {
	        poolKey += ':'
	      }
	      poolKey += options.cert.toString('ascii') + options.key.toString('ascii')
	    }

	    if (options.pfx) {
	      if (poolKey) {
	        poolKey += ':'
	      }
	      poolKey += options.pfx.toString('ascii')
	    }

	    if (options.ciphers) {
	      if (poolKey) {
	        poolKey += ':'
	      }
	      poolKey += options.ciphers
	    }

	    if (options.secureProtocol) {
	      if (poolKey) {
	        poolKey += ':'
	      }
	      poolKey += options.secureProtocol
	    }

	    if (options.secureOptions) {
	      if (poolKey) {
	        poolKey += ':'
	      }
	      poolKey += options.secureOptions
	    }
	  }

	  if (self.pool === globalPool && !poolKey && Object.keys(options).length === 0 && self.httpModule.globalAgent) {
	    // not doing anything special.  Use the globalAgent
	    return self.httpModule.globalAgent
	  }

	  // we're using a stored agent.  Make sure it's protocol-specific
	  poolKey = self.uri.protocol + poolKey

	  // generate a new agent for this setting if none yet exists
	  if (!self.pool[poolKey]) {
	    self.pool[poolKey] = new Agent(options)
	    // properly set maxSockets on new agents
	    if (self.pool.maxSockets) {
	      self.pool[poolKey].maxSockets = self.pool.maxSockets
	    }
	  }

	  return self.pool[poolKey]
	}

	Request.prototype.start = function () {
	  // start() is called once we are ready to send the outgoing HTTP request.
	  // this is usually called on the first write(), end() or on nextTick()
	  var self = this

	  if (self.timing) {
	    // All timings will be relative to this request's startTime.  In order to do this,
	    // we need to capture the wall-clock start time (via Date), immediately followed
	    // by the high-resolution timer (via now()).  While these two won't be set
	    // at the _exact_ same time, they should be close enough to be able to calculate
	    // high-resolution, monotonically non-decreasing timestamps relative to startTime.
	    var startTime = new Date().getTime()
	    var startTimeNow = now()
	  }

	  if (self._aborted) {
	    return
	  }

	  self._started = true
	  self.method = self.method || 'GET'
	  self.href = self.uri.href

	  if (self.src && self.src.stat && self.src.stat.size && !self.hasHeader('content-length')) {
	    self.setHeader('content-length', self.src.stat.size)
	  }
	  if (self._aws) {
	    self.aws(self._aws, true)
	  }

	  // We have a method named auth, which is completely different from the http.request
	  // auth option.  If we don't remove it, we're gonna have a bad time.
	  var reqOptions = copy(self)
	  delete reqOptions.auth

	  debug('make request', self.uri.href)

	  // node v6.8.0 now supports a `timeout` value in `http.request()`, but we
	  // should delete it for now since we handle timeouts manually for better
	  // consistency with node versions before v6.8.0
	  delete reqOptions.timeout

	  try {
	    self.req = self.httpModule.request(reqOptions)
	  } catch (err) {
	    self.emit('error', err)
	    return
	  }

	  if (self.timing) {
	    self.startTime = startTime
	    self.startTimeNow = startTimeNow

	    // Timing values will all be relative to startTime (by comparing to startTimeNow
	    // so we have an accurate clock)
	    self.timings = {}
	  }

	  var timeout
	  if (self.timeout && !self.timeoutTimer) {
	    if (self.timeout < 0) {
	      timeout = 0
	    } else if (typeof self.timeout === 'number' && isFinite(self.timeout)) {
	      timeout = self.timeout
	    }
	  }

	  self.req.on('response', self.onRequestResponse.bind(self))
	  self.req.on('error', self.onRequestError.bind(self))
	  self.req.on('drain', function() {
	    self.emit('drain')
	  })
	  self.req.on('socket', function(socket) {
	    // `._connecting` was the old property which was made public in node v6.1.0
	    var isConnecting = socket._connecting || socket.connecting
	    if (self.timing) {
	      self.timings.socket = now() - self.startTimeNow

	      if (isConnecting) {
	        var onLookupTiming = function() {
	          self.timings.lookup = now() - self.startTimeNow
	        }

	        var onConnectTiming = function() {
	          self.timings.connect = now() - self.startTimeNow
	        }

	        socket.once('lookup', onLookupTiming)
	        socket.once('connect', onConnectTiming)

	        // clean up timing event listeners if needed on error
	        self.req.once('error', function() {
	          socket.removeListener('lookup', onLookupTiming)
	          socket.removeListener('connect', onConnectTiming)
	        })
	      }
	    }

	    var setReqTimeout = function() {
	      // This timeout sets the amount of time to wait *between* bytes sent
	      // from the server once connected.
	      //
	      // In particular, it's useful for erroring if the server fails to send
	      // data halfway through streaming a response.
	      self.req.setTimeout(timeout, function () {
	        if (self.req) {
	          self.abort()
	          var e = new Error('ESOCKETTIMEDOUT')
	          e.code = 'ESOCKETTIMEDOUT'
	          e.connect = false
	          self.emit('error', e)
	        }
	      })
	    }
	    if (timeout !== undefined) {
	      // Only start the connection timer if we're actually connecting a new
	      // socket, otherwise if we're already connected (because this is a
	      // keep-alive connection) do not bother. This is important since we won't
	      // get a 'connect' event for an already connected socket.
	      if (isConnecting) {
	        var onReqSockConnect = function() {
	          socket.removeListener('connect', onReqSockConnect)
	          clearTimeout(self.timeoutTimer)
	          self.timeoutTimer = null
	          setReqTimeout()
	        }

	        socket.on('connect', onReqSockConnect)

	        self.req.on('error', function(err) {
	          socket.removeListener('connect', onReqSockConnect)
	        })

	        // Set a timeout in memory - this block will throw if the server takes more
	        // than `timeout` to write the HTTP status and headers (corresponding to
	        // the on('response') event on the client). NB: this measures wall-clock
	        // time, not the time between bytes sent by the server.
	        self.timeoutTimer = setTimeout(function () {
	          socket.removeListener('connect', onReqSockConnect)
	          self.abort()
	          var e = new Error('ETIMEDOUT')
	          e.code = 'ETIMEDOUT'
	          e.connect = true
	          self.emit('error', e)
	        }, timeout)
	      } else {
	        // We're already connected
	        setReqTimeout()
	      }
	    }
	    self.emit('socket', socket)
	  })

	  self.emit('request', self.req)
	}

	Request.prototype.onRequestError = function (error) {
	  var self = this
	  if (self._aborted) {
	    return
	  }
	  if (self.req && self.req._reusedSocket && error.code === 'ECONNRESET'
	      && self.agent.addRequestNoreuse) {
	    self.agent = { addRequest: self.agent.addRequestNoreuse.bind(self.agent) }
	    self.start()
	    self.req.end()
	    return
	  }
	  if (self.timeout && self.timeoutTimer) {
	    clearTimeout(self.timeoutTimer)
	    self.timeoutTimer = null
	  }
	  self.emit('error', error)
	}

	Request.prototype.onRequestResponse = function (response) {
	  var self = this

	  if (self.timing) {
	    self.timings.response = now() - self.startTimeNow
	  }

	  debug('onRequestResponse', self.uri.href, response.statusCode, response.headers)
	  response.on('end', function() {
	    if (self.timing) {
	      self.timings.end = now() - self.startTimeNow
	      response.timingStart = self.startTime

	      // fill in the blanks for any periods that didn't trigger, such as
	      // no lookup or connect due to keep alive
	      if (!self.timings.socket) {
	        self.timings.socket = 0
	      }
	      if (!self.timings.lookup) {
	        self.timings.lookup = self.timings.socket
	      }
	      if (!self.timings.connect) {
	        self.timings.connect = self.timings.lookup
	      }
	      if (!self.timings.response) {
	        self.timings.response = self.timings.connect
	      }

	      debug('elapsed time', self.timings.end)

	      // elapsedTime includes all redirects
	      self.elapsedTime += Math.round(self.timings.end)

	      // NOTE: elapsedTime is deprecated in favor of .timings
	      response.elapsedTime = self.elapsedTime

	      // timings is just for the final fetch
	      response.timings = self.timings

	      // pre-calculate phase timings as well
	      response.timingPhases = {
	        wait: self.timings.socket,
	        dns: self.timings.lookup - self.timings.socket,
	        tcp: self.timings.connect - self.timings.lookup,
	        firstByte: self.timings.response - self.timings.connect,
	        download: self.timings.end - self.timings.response,
	        total: self.timings.end
	      }
	    }
	    debug('response end', self.uri.href, response.statusCode, response.headers)
	  })

	  if (self._aborted) {
	    debug('aborted', self.uri.href)
	    response.resume()
	    return
	  }

	  self.response = response
	  response.request = self
	  response.toJSON = responseToJSON

	  // XXX This is different on 0.10, because SSL is strict by default
	  if (self.httpModule === https &&
	      self.strictSSL && (!response.hasOwnProperty('socket') ||
	      !response.socket.authorized)) {
	    debug('strict ssl error', self.uri.href)
	    var sslErr = response.hasOwnProperty('socket') ? response.socket.authorizationError : self.uri.href + ' does not support SSL'
	    self.emit('error', new Error('SSL Error: ' + sslErr))
	    return
	  }

	  // Save the original host before any redirect (if it changes, we need to
	  // remove any authorization headers).  Also remember the case of the header
	  // name because lots of broken servers expect Host instead of host and we
	  // want the caller to be able to specify this.
	  self.originalHost = self.getHeader('host')
	  if (!self.originalHostHeaderName) {
	    self.originalHostHeaderName = self.hasHeader('host')
	  }
	  if (self.setHost) {
	    self.removeHeader('host')
	  }
	  if (self.timeout && self.timeoutTimer) {
	    clearTimeout(self.timeoutTimer)
	    self.timeoutTimer = null
	  }

	  var targetCookieJar = (self._jar && self._jar.setCookie) ? self._jar : globalCookieJar
	  var addCookie = function (cookie) {
	    //set the cookie if it's domain in the href's domain.
	    try {
	      targetCookieJar.setCookie(cookie, self.uri.href, {ignoreError: true})
	    } catch (e) {
	      self.emit('error', e)
	    }
	  }

	  response.caseless = caseless(response.headers)

	  if (response.caseless.has('set-cookie') && (!self._disableCookies)) {
	    var headerName = response.caseless.has('set-cookie')
	    if (Array.isArray(response.headers[headerName])) {
	      response.headers[headerName].forEach(addCookie)
	    } else {
	      addCookie(response.headers[headerName])
	    }
	  }

	  if (self._redirect.onResponse(response)) {
	    return // Ignore the rest of the response
	  } else {
	    // Be a good stream and emit end when the response is finished.
	    // Hack to emit end on close because of a core bug that never fires end
	    response.on('close', function () {
	      if (!self._ended) {
	        self.response.emit('end')
	      }
	    })

	    response.once('end', function () {
	      self._ended = true
	    })

	    var noBody = function (code) {
	      return (
	        self.method === 'HEAD'
	        // Informational
	        || (code >= 100 && code < 200)
	        // No Content
	        || code === 204
	        // Not Modified
	        || code === 304
	      )
	    }

	    var responseContent
	    if (self.gzip && !noBody(response.statusCode)) {
	      var contentEncoding = response.headers['content-encoding'] || 'identity'
	      contentEncoding = contentEncoding.trim().toLowerCase()

	      // Be more lenient with decoding compressed responses, since (very rarely)
	      // servers send slightly invalid gzip responses that are still accepted
	      // by common browsers.
	      // Always using Z_SYNC_FLUSH is what cURL does.
	      var zlibOptions = {
	        flush: zlib.Z_SYNC_FLUSH
	      , finishFlush: zlib.Z_SYNC_FLUSH
	      }

	      if (contentEncoding === 'gzip') {
	        responseContent = zlib.createGunzip(zlibOptions)
	        response.pipe(responseContent)
	      } else if (contentEncoding === 'deflate') {
	        responseContent = zlib.createInflate(zlibOptions)
	        response.pipe(responseContent)
	      } else {
	        // Since previous versions didn't check for Content-Encoding header,
	        // ignore any invalid values to preserve backwards-compatibility
	        if (contentEncoding !== 'identity') {
	          debug('ignoring unrecognized Content-Encoding ' + contentEncoding)
	        }
	        responseContent = response
	      }
	    } else {
	      responseContent = response
	    }

	    if (self.encoding) {
	      if (self.dests.length !== 0) {
	        console.error('Ignoring encoding parameter as this stream is being piped to another stream which makes the encoding option invalid.')
	      } else if (responseContent.setEncoding) {
	        responseContent.setEncoding(self.encoding)
	      } else {
	        // Should only occur on node pre-v0.9.4 (joyent/node@9b5abe5) with
	        // zlib streams.
	        // If/When support for 0.9.4 is dropped, this should be unnecessary.
	        responseContent = responseContent.pipe(stringstream(self.encoding))
	      }
	    }

	    if (self._paused) {
	      responseContent.pause()
	    }

	    self.responseContent = responseContent

	    self.emit('response', response)

	    self.dests.forEach(function (dest) {
	      self.pipeDest(dest)
	    })

	    responseContent.on('data', function (chunk) {
	      if (self.timing && !self.responseStarted) {
	        self.responseStartTime = (new Date()).getTime()

	        // NOTE: responseStartTime is deprecated in favor of .timings
	        response.responseStartTime = self.responseStartTime
	      }
	      self._destdata = true
	      self.emit('data', chunk)
	    })
	    responseContent.once('end', function (chunk) {
	      self.emit('end', chunk)
	    })
	    responseContent.on('error', function (error) {
	      self.emit('error', error)
	    })
	    responseContent.on('close', function () {self.emit('close')})

	    if (self.callback) {
	      self.readResponseBody(response)
	    }
	    //if no callback
	    else {
	      self.on('end', function () {
	        if (self._aborted) {
	          debug('aborted', self.uri.href)
	          return
	        }
	        self.emit('complete', response)
	      })
	    }
	  }
	  debug('finish init function', self.uri.href)
	}

	Request.prototype.readResponseBody = function (response) {
	  var self = this
	  debug('reading response\'s body')
	  var buffers = []
	    , bufferLength = 0
	    , strings = []

	  self.on('data', function (chunk) {
	    if (!Buffer.isBuffer(chunk)) {
	      strings.push(chunk)
	    } else if (chunk.length) {
	      bufferLength += chunk.length
	      buffers.push(chunk)
	    }
	  })
	  self.on('end', function () {
	    debug('end event', self.uri.href)
	    if (self._aborted) {
	      debug('aborted', self.uri.href)
	      // `buffer` is defined in the parent scope and used in a closure it exists for the life of the request.
	      // This can lead to leaky behavior if the user retains a reference to the request object.
	      buffers = []
	      bufferLength = 0
	      return
	    }

	    if (bufferLength) {
	      debug('has body', self.uri.href, bufferLength)
	      response.body = Buffer.concat(buffers, bufferLength)
	      if (self.encoding !== null) {
	        response.body = response.body.toString(self.encoding)
	      }
	      // `buffer` is defined in the parent scope and used in a closure it exists for the life of the Request.
	      // This can lead to leaky behavior if the user retains a reference to the request object.
	      buffers = []
	      bufferLength = 0
	    } else if (strings.length) {
	      // The UTF8 BOM [0xEF,0xBB,0xBF] is converted to [0xFE,0xFF] in the JS UTC16/UCS2 representation.
	      // Strip this value out when the encoding is set to 'utf8', as upstream consumers won't expect it and it breaks JSON.parse().
	      if (self.encoding === 'utf8' && strings[0].length > 0 && strings[0][0] === '\uFEFF') {
	        strings[0] = strings[0].substring(1)
	      }
	      response.body = strings.join('')
	    }

	    if (self._json) {
	      try {
	        response.body = JSON.parse(response.body, self._jsonReviver)
	      } catch (e) {
	        debug('invalid JSON received', self.uri.href)
	      }
	    }
	    debug('emitting complete', self.uri.href)
	    if (typeof response.body === 'undefined' && !self._json) {
	      response.body = self.encoding === null ? Buffer.alloc(0) : ''
	    }
	    self.emit('complete', response, response.body)
	  })
	}

	Request.prototype.abort = function () {
	  var self = this
	  self._aborted = true

	  if (self.req) {
	    self.req.abort()
	  }
	  else if (self.response) {
	    self.response.destroy()
	  }

	  self.emit('abort')
	}

	Request.prototype.pipeDest = function (dest) {
	  var self = this
	  var response = self.response
	  // Called after the response is received
	  if (dest.headers && !dest.headersSent) {
	    if (response.caseless.has('content-type')) {
	      var ctname = response.caseless.has('content-type')
	      if (dest.setHeader) {
	        dest.setHeader(ctname, response.headers[ctname])
	      }
	      else {
	        dest.headers[ctname] = response.headers[ctname]
	      }
	    }

	    if (response.caseless.has('content-length')) {
	      var clname = response.caseless.has('content-length')
	      if (dest.setHeader) {
	        dest.setHeader(clname, response.headers[clname])
	      } else {
	        dest.headers[clname] = response.headers[clname]
	      }
	    }
	  }
	  if (dest.setHeader && !dest.headersSent) {
	    for (var i in response.headers) {
	      // If the response content is being decoded, the Content-Encoding header
	      // of the response doesn't represent the piped content, so don't pass it.
	      if (!self.gzip || i !== 'content-encoding') {
	        dest.setHeader(i, response.headers[i])
	      }
	    }
	    dest.statusCode = response.statusCode
	  }
	  if (self.pipefilter) {
	    self.pipefilter(response, dest)
	  }
	}

	Request.prototype.qs = function (q, clobber) {
	  var self = this
	  var base
	  if (!clobber && self.uri.query) {
	    base = self._qs.parse(self.uri.query)
	  } else {
	    base = {}
	  }

	  for (var i in q) {
	    base[i] = q[i]
	  }

	  var qs = self._qs.stringify(base)

	  if (qs === '') {
	    return self
	  }

	  self.uri = url.parse(self.uri.href.split('?')[0] + '?' + qs)
	  self.url = self.uri
	  self.path = self.uri.path

	  if (self.uri.host === 'unix') {
	    self.enableUnixSocket()
	  }

	  return self
	}
	Request.prototype.form = function (form) {
	  var self = this
	  if (form) {
	    if (!/^application\/x-www-form-urlencoded\b/.test(self.getHeader('content-type'))) {
	      self.setHeader('content-type', 'application/x-www-form-urlencoded')
	    }
	    self.body = (typeof form === 'string')
	      ? self._qs.rfc3986(form.toString('utf8'))
	      : self._qs.stringify(form).toString('utf8')
	    return self
	  }
	  // create form-data object
	  self._form = new FormData()
	  self._form.on('error', function(err) {
	    err.message = 'form-data: ' + err.message
	    self.emit('error', err)
	    self.abort()
	  })
	  return self._form
	}
	Request.prototype.multipart = function (multipart) {
	  var self = this

	  self._multipart.onRequest(multipart)

	  if (!self._multipart.chunked) {
	    self.body = self._multipart.body
	  }

	  return self
	}
	Request.prototype.json = function (val) {
	  var self = this

	  if (!self.hasHeader('accept')) {
	    self.setHeader('accept', 'application/json')
	  }

	  if (typeof self.jsonReplacer === 'function') {
	    self._jsonReplacer = self.jsonReplacer
	  }

	  self._json = true
	  if (typeof val === 'boolean') {
	    if (self.body !== undefined) {
	      if (!/^application\/x-www-form-urlencoded\b/.test(self.getHeader('content-type'))) {
	        self.body = safeStringify(self.body, self._jsonReplacer)
	      } else {
	        self.body = self._qs.rfc3986(self.body)
	      }
	      if (!self.hasHeader('content-type')) {
	        self.setHeader('content-type', 'application/json')
	      }
	    }
	  } else {
	    self.body = safeStringify(val, self._jsonReplacer)
	    if (!self.hasHeader('content-type')) {
	      self.setHeader('content-type', 'application/json')
	    }
	  }

	  if (typeof self.jsonReviver === 'function') {
	    self._jsonReviver = self.jsonReviver
	  }

	  return self
	}
	Request.prototype.getHeader = function (name, headers) {
	  var self = this
	  var result, re, match
	  if (!headers) {
	    headers = self.headers
	  }
	  Object.keys(headers).forEach(function (key) {
	    if (key.length !== name.length) {
	      return
	    }
	    re = new RegExp(name, 'i')
	    match = key.match(re)
	    if (match) {
	      result = headers[key]
	    }
	  })
	  return result
	}
	Request.prototype.enableUnixSocket = function () {
	  // Get the socket & request paths from the URL
	  var unixParts = this.uri.path.split(':')
	    , host = unixParts[0]
	    , path = unixParts[1]
	  // Apply unix properties to request
	  this.socketPath = host
	  this.uri.pathname = path
	  this.uri.path = path
	  this.uri.host = host
	  this.uri.hostname = host
	  this.uri.isUnix = true
	}


	Request.prototype.auth = function (user, pass, sendImmediately, bearer) {
	  var self = this

	  self._auth.onRequest(user, pass, sendImmediately, bearer)

	  return self
	}
	Request.prototype.aws = function (opts, now) {
	  var self = this

	  if (!now) {
	    self._aws = opts
	    return self
	  }

	  if (opts.sign_version == 4 || opts.sign_version == '4') {
	    // use aws4
	    var options = {
	      host: self.uri.host,
	      path: self.uri.path,
	      method: self.method,
	      headers: {
	        'content-type': self.getHeader('content-type') || ''
	      },
	      body: self.body
	    }
	    var signRes = aws4.sign(options, {
	      accessKeyId: opts.key,
	      secretAccessKey: opts.secret,
	      sessionToken: opts.session
	    })
	    self.setHeader('authorization', signRes.headers.Authorization)
	    self.setHeader('x-amz-date', signRes.headers['X-Amz-Date'])
	    if (signRes.headers['X-Amz-Security-Token']) {
	      self.setHeader('x-amz-security-token', signRes.headers['X-Amz-Security-Token'])
	    }
	  }
	  else {
	    // default: use aws-sign2
	    var date = new Date()
	    self.setHeader('date', date.toUTCString())
	    var auth =
	      { key: opts.key
	      , secret: opts.secret
	      , verb: self.method.toUpperCase()
	      , date: date
	      , contentType: self.getHeader('content-type') || ''
	      , md5: self.getHeader('content-md5') || ''
	      , amazonHeaders: aws2.canonicalizeHeaders(self.headers)
	      }
	    var path = self.uri.path
	    if (opts.bucket && path) {
	      auth.resource = '/' + opts.bucket + path
	    } else if (opts.bucket && !path) {
	      auth.resource = '/' + opts.bucket
	    } else if (!opts.bucket && path) {
	      auth.resource = path
	    } else if (!opts.bucket && !path) {
	      auth.resource = '/'
	    }
	    auth.resource = aws2.canonicalizeResource(auth.resource)
	    self.setHeader('authorization', aws2.authorization(auth))
	  }

	  return self
	}
	Request.prototype.httpSignature = function (opts) {
	  var self = this
	  httpSignature.signRequest({
	    getHeader: function(header) {
	      return self.getHeader(header, self.headers)
	    },
	    setHeader: function(header, value) {
	      self.setHeader(header, value)
	    },
	    method: self.method,
	    path: self.path
	  }, opts)
	  debug('httpSignature authorization', self.getHeader('authorization'))

	  return self
	}
	Request.prototype.hawk = function (opts) {
	  var self = this
	  self.setHeader('Authorization', hawk.client.header(self.uri, self.method, opts).field)
	}
	Request.prototype.oauth = function (_oauth) {
	  var self = this

	  self._oauth.onRequest(_oauth)

	  return self
	}

	Request.prototype.jar = function (jar) {
	  var self = this
	  var cookies

	  if (self._redirect.redirectsFollowed === 0) {
	    self.originalCookieHeader = self.getHeader('cookie')
	  }

	  if (!jar) {
	    // disable cookies
	    cookies = false
	    self._disableCookies = true
	  } else {
	    var targetCookieJar = (jar && jar.getCookieString) ? jar : globalCookieJar
	    var urihref = self.uri.href
	    //fetch cookie in the Specified host
	    if (targetCookieJar) {
	      cookies = targetCookieJar.getCookieString(urihref)
	    }
	  }

	  //if need cookie and cookie is not empty
	  if (cookies && cookies.length) {
	    if (self.originalCookieHeader) {
	      // Don't overwrite existing Cookie header
	      self.setHeader('cookie', self.originalCookieHeader + '; ' + cookies)
	    } else {
	      self.setHeader('cookie', cookies)
	    }
	  }
	  self._jar = jar
	  return self
	}


	// Stream API
	Request.prototype.pipe = function (dest, opts) {
	  var self = this

	  if (self.response) {
	    if (self._destdata) {
	      self.emit('error', new Error('You cannot pipe after data has been emitted from the response.'))
	    } else if (self._ended) {
	      self.emit('error', new Error('You cannot pipe after the response has been ended.'))
	    } else {
	      stream.Stream.prototype.pipe.call(self, dest, opts)
	      self.pipeDest(dest)
	      return dest
	    }
	  } else {
	    self.dests.push(dest)
	    stream.Stream.prototype.pipe.call(self, dest, opts)
	    return dest
	  }
	}
	Request.prototype.write = function () {
	  var self = this
	  if (self._aborted) {return}

	  if (!self._started) {
	    self.start()
	  }
	  if (self.req) {
	    return self.req.write.apply(self.req, arguments)
	  }
	}
	Request.prototype.end = function (chunk) {
	  var self = this
	  if (self._aborted) {return}

	  if (chunk) {
	    self.write(chunk)
	  }
	  if (!self._started) {
	    self.start()
	  }
	  if (self.req) {
	    self.req.end()
	  }
	}
	Request.prototype.pause = function () {
	  var self = this
	  if (!self.responseContent) {
	    self._paused = true
	  } else {
	    self.responseContent.pause.apply(self.responseContent, arguments)
	  }
	}
	Request.prototype.resume = function () {
	  var self = this
	  if (!self.responseContent) {
	    self._paused = false
	  } else {
	    self.responseContent.resume.apply(self.responseContent, arguments)
	  }
	}
	Request.prototype.destroy = function () {
	  var self = this
	  if (!self._ended) {
	    self.end()
	  } else if (self.response) {
	    self.response.destroy()
	  }
	}

	Request.defaultProxyHeaderWhiteList =
	  Tunnel.defaultProxyHeaderWhiteList.slice()

	Request.defaultProxyHeaderExclusiveList =
	  Tunnel.defaultProxyHeaderExclusiveList.slice()

	// Exports

	Request.prototype.toJSON = requestToJSON
	module.exports = Request


/***/ },
/* 7 */
/***/ function(module, exports) {

	module.exports = require("http");

/***/ },
/* 8 */
/***/ function(module, exports) {

	module.exports = require("https");

/***/ },
/* 9 */
/***/ function(module, exports) {

	module.exports = require("url");

/***/ },
/* 10 */
/***/ function(module, exports) {

	module.exports = require("util");

/***/ },
/* 11 */
/***/ function(module, exports) {

	module.exports = require("stream");

/***/ },
/* 12 */
/***/ function(module, exports) {

	module.exports = require("zlib");

/***/ },
/* 13 */
/***/ function(module, exports) {

	module.exports = require("hawk");

/***/ },
/* 14 */
/***/ function(module, exports) {

	module.exports = require("aws-sign2");

/***/ },
/* 15 */
/***/ function(module, exports, __webpack_require__) {

	var aws4 = exports,
	    url = __webpack_require__(9),
	    querystring = __webpack_require__(16),
	    crypto = __webpack_require__(17),
	    lru = __webpack_require__(18),
	    credentialsCache = lru(1000)

	// http://docs.amazonwebservices.com/general/latest/gr/signature-version-4.html

	function hmac(key, string, encoding) {
	  return crypto.createHmac('sha256', key).update(string, 'utf8').digest(encoding)
	}

	function hash(string, encoding) {
	  return crypto.createHash('sha256').update(string, 'utf8').digest(encoding)
	}

	// This function assumes the string has already been percent encoded
	function encodeRfc3986(urlEncodedString) {
	  return urlEncodedString.replace(/[!'()*]/g, function(c) {
	    return '%' + c.charCodeAt(0).toString(16).toUpperCase()
	  })
	}

	// request: { path | body, [host], [method], [headers], [service], [region] }
	// credentials: { accessKeyId, secretAccessKey, [sessionToken] }
	function RequestSigner(request, credentials) {

	  if (typeof request === 'string') request = url.parse(request)

	  var headers = request.headers = (request.headers || {}),
	      hostParts = this.matchHost(request.hostname || request.host || headers.Host || headers.host)

	  this.request = request
	  this.credentials = credentials || this.defaultCredentials()

	  this.service = request.service || hostParts[0] || ''
	  this.region = request.region || hostParts[1] || 'us-east-1'

	  // SES uses a different domain from the service name
	  if (this.service === 'email') this.service = 'ses'

	  if (!request.method && request.body)
	    request.method = 'POST'

	  if (!headers.Host && !headers.host) {
	    headers.Host = request.hostname || request.host || this.createHost()

	    // If a port is specified explicitly, use it as is
	    if (request.port)
	      headers.Host += ':' + request.port
	  }
	  if (!request.hostname && !request.host)
	    request.hostname = headers.Host || headers.host

	  this.isCodeCommitGit = this.service === 'codecommit' && request.method === 'GIT'
	}

	RequestSigner.prototype.matchHost = function(host) {
	  var match = (host || '').match(/([^\.]+)\.(?:([^\.]*)\.)?amazonaws\.com$/)
	  var hostParts = (match || []).slice(1, 3)

	  // ES's hostParts are sometimes the other way round, if the value that is expected
	  // to be region equals ‘es’ switch them back
	  // e.g. search-cluster-name-aaaa00aaaa0aaa0aaaaaaa0aaa.us-east-1.es.amazonaws.com
	  if (hostParts[1] === 'es')
	    hostParts = hostParts.reverse()

	  return hostParts
	}

	// http://docs.aws.amazon.com/general/latest/gr/rande.html
	RequestSigner.prototype.isSingleRegion = function() {
	  // Special case for S3 and SimpleDB in us-east-1
	  if (['s3', 'sdb'].indexOf(this.service) >= 0 && this.region === 'us-east-1') return true

	  return ['cloudfront', 'ls', 'route53', 'iam', 'importexport', 'sts']
	    .indexOf(this.service) >= 0
	}

	RequestSigner.prototype.createHost = function() {
	  var region = this.isSingleRegion() ? '' :
	        (this.service === 's3' && this.region !== 'us-east-1' ? '-' : '.') + this.region,
	      service = this.service === 'ses' ? 'email' : this.service
	  return service + region + '.amazonaws.com'
	}

	RequestSigner.prototype.prepareRequest = function() {
	  this.parsePath()

	  var request = this.request, headers = request.headers, query

	  if (request.signQuery) {

	    this.parsedPath.query = query = this.parsedPath.query || {}

	    if (this.credentials.sessionToken)
	      query['X-Amz-Security-Token'] = this.credentials.sessionToken

	    if (this.service === 's3' && !query['X-Amz-Expires'])
	      query['X-Amz-Expires'] = 86400

	    if (query['X-Amz-Date'])
	      this.datetime = query['X-Amz-Date']
	    else
	      query['X-Amz-Date'] = this.getDateTime()

	    query['X-Amz-Algorithm'] = 'AWS4-HMAC-SHA256'
	    query['X-Amz-Credential'] = this.credentials.accessKeyId + '/' + this.credentialString()
	    query['X-Amz-SignedHeaders'] = this.signedHeaders()

	  } else {

	    if (!request.doNotModifyHeaders && !this.isCodeCommitGit) {
	      if (request.body && !headers['Content-Type'] && !headers['content-type'])
	        headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=utf-8'

	      if (request.body && !headers['Content-Length'] && !headers['content-length'])
	        headers['Content-Length'] = Buffer.byteLength(request.body)

	      if (this.credentials.sessionToken && !headers['X-Amz-Security-Token'] && !headers['x-amz-security-token'])
	        headers['X-Amz-Security-Token'] = this.credentials.sessionToken

	      if (this.service === 's3' && !headers['X-Amz-Content-Sha256'] && !headers['x-amz-content-sha256'])
	        headers['X-Amz-Content-Sha256'] = hash(this.request.body || '', 'hex')

	      if (headers['X-Amz-Date'] || headers['x-amz-date'])
	        this.datetime = headers['X-Amz-Date'] || headers['x-amz-date']
	      else
	        headers['X-Amz-Date'] = this.getDateTime()
	    }

	    delete headers.Authorization
	    delete headers.authorization
	  }
	}

	RequestSigner.prototype.sign = function() {
	  if (!this.parsedPath) this.prepareRequest()

	  if (this.request.signQuery) {
	    this.parsedPath.query['X-Amz-Signature'] = this.signature()
	  } else {
	    this.request.headers.Authorization = this.authHeader()
	  }

	  this.request.path = this.formatPath()

	  return this.request
	}

	RequestSigner.prototype.getDateTime = function() {
	  if (!this.datetime) {
	    var headers = this.request.headers,
	      date = new Date(headers.Date || headers.date || new Date)

	    this.datetime = date.toISOString().replace(/[:\-]|\.\d{3}/g, '')

	    // Remove the trailing 'Z' on the timestamp string for CodeCommit git access
	    if (this.isCodeCommitGit) this.datetime = this.datetime.slice(0, -1)
	  }
	  return this.datetime
	}

	RequestSigner.prototype.getDate = function() {
	  return this.getDateTime().substr(0, 8)
	}

	RequestSigner.prototype.authHeader = function() {
	  return [
	    'AWS4-HMAC-SHA256 Credential=' + this.credentials.accessKeyId + '/' + this.credentialString(),
	    'SignedHeaders=' + this.signedHeaders(),
	    'Signature=' + this.signature(),
	  ].join(', ')
	}

	RequestSigner.prototype.signature = function() {
	  var date = this.getDate(),
	      cacheKey = [this.credentials.secretAccessKey, date, this.region, this.service].join(),
	      kDate, kRegion, kService, kCredentials = credentialsCache.get(cacheKey)
	  if (!kCredentials) {
	    kDate = hmac('AWS4' + this.credentials.secretAccessKey, date)
	    kRegion = hmac(kDate, this.region)
	    kService = hmac(kRegion, this.service)
	    kCredentials = hmac(kService, 'aws4_request')
	    credentialsCache.set(cacheKey, kCredentials)
	  }
	  return hmac(kCredentials, this.stringToSign(), 'hex')
	}

	RequestSigner.prototype.stringToSign = function() {
	  return [
	    'AWS4-HMAC-SHA256',
	    this.getDateTime(),
	    this.credentialString(),
	    hash(this.canonicalString(), 'hex'),
	  ].join('\n')
	}

	RequestSigner.prototype.canonicalString = function() {
	  if (!this.parsedPath) this.prepareRequest()

	  var pathStr = this.parsedPath.path,
	      query = this.parsedPath.query,
	      headers = this.request.headers,
	      queryStr = '',
	      normalizePath = this.service !== 's3',
	      decodePath = this.service === 's3' || this.request.doNotEncodePath,
	      decodeSlashesInPath = this.service === 's3',
	      firstValOnly = this.service === 's3',
	      bodyHash

	  if (this.service === 's3' && this.request.signQuery) {
	    bodyHash = 'UNSIGNED-PAYLOAD'
	  } else if (this.isCodeCommitGit) {
	    bodyHash = ''
	  } else {
	    bodyHash = headers['X-Amz-Content-Sha256'] || headers['x-amz-content-sha256'] ||
	      hash(this.request.body || '', 'hex')
	  }

	  if (query) {
	    queryStr = encodeRfc3986(querystring.stringify(Object.keys(query).sort().reduce(function(obj, key) {
	      if (!key) return obj
	      obj[key] = !Array.isArray(query[key]) ? query[key] :
	        (firstValOnly ? query[key][0] : query[key].slice().sort())
	      return obj
	    }, {})))
	  }
	  if (pathStr !== '/') {
	    if (normalizePath) pathStr = pathStr.replace(/\/{2,}/g, '/')
	    pathStr = pathStr.split('/').reduce(function(path, piece) {
	      if (normalizePath && piece === '..') {
	        path.pop()
	      } else if (!normalizePath || piece !== '.') {
	        if (decodePath) piece = querystring.unescape(piece)
	        path.push(encodeRfc3986(querystring.escape(piece)))
	      }
	      return path
	    }, []).join('/')
	    if (pathStr[0] !== '/') pathStr = '/' + pathStr
	    if (decodeSlashesInPath) pathStr = pathStr.replace(/%2F/g, '/')
	  }

	  return [
	    this.request.method || 'GET',
	    pathStr,
	    queryStr,
	    this.canonicalHeaders() + '\n',
	    this.signedHeaders(),
	    bodyHash,
	  ].join('\n')
	}

	RequestSigner.prototype.canonicalHeaders = function() {
	  var headers = this.request.headers
	  function trimAll(header) {
	    return header.toString().trim().replace(/\s+/g, ' ')
	  }
	  return Object.keys(headers)
	    .sort(function(a, b) { return a.toLowerCase() < b.toLowerCase() ? -1 : 1 })
	    .map(function(key) { return key.toLowerCase() + ':' + trimAll(headers[key]) })
	    .join('\n')
	}

	RequestSigner.prototype.signedHeaders = function() {
	  return Object.keys(this.request.headers)
	    .map(function(key) { return key.toLowerCase() })
	    .sort()
	    .join(';')
	}

	RequestSigner.prototype.credentialString = function() {
	  return [
	    this.getDate(),
	    this.region,
	    this.service,
	    'aws4_request',
	  ].join('/')
	}

	RequestSigner.prototype.defaultCredentials = function() {
	  var env = process.env
	  return {
	    accessKeyId: env.AWS_ACCESS_KEY_ID || env.AWS_ACCESS_KEY,
	    secretAccessKey: env.AWS_SECRET_ACCESS_KEY || env.AWS_SECRET_KEY,
	    sessionToken: env.AWS_SESSION_TOKEN,
	  }
	}

	RequestSigner.prototype.parsePath = function() {
	  var path = this.request.path || '/',
	      queryIx = path.indexOf('?'),
	      query = null

	  if (queryIx >= 0) {
	    query = querystring.parse(path.slice(queryIx + 1))
	    path = path.slice(0, queryIx)
	  }

	  // S3 doesn't always encode characters > 127 correctly and
	  // all services don't encode characters > 255 correctly
	  // So if there are non-reserved chars (and it's not already all % encoded), just encode them all
	  if (/[^0-9A-Za-z!'()*\-._~%/]/.test(path)) {
	    path = path.split('/').map(function(piece) {
	      return querystring.escape(querystring.unescape(piece))
	    }).join('/')
	  }

	  this.parsedPath = {
	    path: path,
	    query: query,
	  }
	}

	RequestSigner.prototype.formatPath = function() {
	  var path = this.parsedPath.path,
	      query = this.parsedPath.query

	  if (!query) return path

	  // Services don't support empty query string keys
	  if (query[''] != null) delete query['']

	  return path + '?' + encodeRfc3986(querystring.stringify(query))
	}

	aws4.RequestSigner = RequestSigner

	aws4.sign = function(request, credentials) {
	  return new RequestSigner(request, credentials).sign()
	}


/***/ },
/* 16 */
/***/ function(module, exports) {

	module.exports = require("querystring");

/***/ },
/* 17 */
/***/ function(module, exports) {

	module.exports = require("crypto");

/***/ },
/* 18 */
/***/ function(module, exports) {

	module.exports = function(size) {
	  return new LruCache(size)
	}

	function LruCache(size) {
	  this.capacity = size | 0
	  this.map = Object.create(null)
	  this.list = new DoublyLinkedList()
	}

	LruCache.prototype.get = function(key) {
	  var node = this.map[key]
	  if (node == null) return undefined
	  this.used(node)
	  return node.val
	}

	LruCache.prototype.set = function(key, val) {
	  var node = this.map[key]
	  if (node != null) {
	    node.val = val
	  } else {
	    if (!this.capacity) this.prune()
	    if (!this.capacity) return false
	    node = new DoublyLinkedNode(key, val)
	    this.map[key] = node
	    this.capacity--
	  }
	  this.used(node)
	  return true
	}

	LruCache.prototype.used = function(node) {
	  this.list.moveToFront(node)
	}

	LruCache.prototype.prune = function() {
	  var node = this.list.pop()
	  if (node != null) {
	    delete this.map[node.key]
	    this.capacity++
	  }
	}


	function DoublyLinkedList() {
	  this.firstNode = null
	  this.lastNode = null
	}

	DoublyLinkedList.prototype.moveToFront = function(node) {
	  if (this.firstNode == node) return

	  this.remove(node)

	  if (this.firstNode == null) {
	    this.firstNode = node
	    this.lastNode = node
	    node.prev = null
	    node.next = null
	  } else {
	    node.prev = null
	    node.next = this.firstNode
	    node.next.prev = node
	    this.firstNode = node
	  }
	}

	DoublyLinkedList.prototype.pop = function() {
	  var lastNode = this.lastNode
	  if (lastNode != null) {
	    this.remove(lastNode)
	  }
	  return lastNode
	}

	DoublyLinkedList.prototype.remove = function(node) {
	  if (this.firstNode == node) {
	    this.firstNode = node.next
	  } else if (node.prev != null) {
	    node.prev.next = node.next
	  }
	  if (this.lastNode == node) {
	    this.lastNode = node.prev
	  } else if (node.next != null) {
	    node.next.prev = node.prev
	  }
	}


	function DoublyLinkedNode(key, val) {
	  this.key = key
	  this.val = val
	  this.prev = null
	  this.next = null
	}


/***/ },
/* 19 */
/***/ function(module, exports) {

	module.exports = require("http-signature");

/***/ },
/* 20 */
/***/ function(module, exports) {

	module.exports = require("mime-types");

/***/ },
/* 21 */
/***/ function(module, exports) {

	module.exports = require("stringstream");

/***/ },
/* 22 */
/***/ function(module, exports) {

	module.exports = require("caseless");

/***/ },
/* 23 */
/***/ function(module, exports) {

	module.exports = require("forever-agent");

/***/ },
/* 24 */
/***/ function(module, exports) {

	module.exports = require("form-data");

/***/ },
/* 25 */
/***/ function(module, exports) {

	module.exports = require("extend");

/***/ },
/* 26 */
/***/ function(module, exports) {

	module.exports = require("isstream");

/***/ },
/* 27 */
/***/ function(module, exports) {

	module.exports      = isTypedArray
	isTypedArray.strict = isStrictTypedArray
	isTypedArray.loose  = isLooseTypedArray

	var toString = Object.prototype.toString
	var names = {
	    '[object Int8Array]': true
	  , '[object Int16Array]': true
	  , '[object Int32Array]': true
	  , '[object Uint8Array]': true
	  , '[object Uint8ClampedArray]': true
	  , '[object Uint16Array]': true
	  , '[object Uint32Array]': true
	  , '[object Float32Array]': true
	  , '[object Float64Array]': true
	}

	function isTypedArray(arr) {
	  return (
	       isStrictTypedArray(arr)
	    || isLooseTypedArray(arr)
	  )
	}

	function isStrictTypedArray(arr) {
	  return (
	       arr instanceof Int8Array
	    || arr instanceof Int16Array
	    || arr instanceof Int32Array
	    || arr instanceof Uint8Array
	    || arr instanceof Uint8ClampedArray
	    || arr instanceof Uint16Array
	    || arr instanceof Uint32Array
	    || arr instanceof Float32Array
	    || arr instanceof Float64Array
	  )
	}

	function isLooseTypedArray(arr) {
	  return names[toString.call(arr)]
	}


/***/ },
/* 28 */
/***/ function(module, exports, __webpack_require__) {

	/* WEBPACK VAR INJECTION */(function(setImmediate) {'use strict'

	var jsonSafeStringify = __webpack_require__(3)
	  , crypto = __webpack_require__(17)
	  , Buffer = __webpack_require__(31).Buffer

	var defer = typeof setImmediate === 'undefined'
	  ? process.nextTick
	  : setImmediate

	function paramsHaveRequestBody(params) {
	  return (
	    params.body ||
	    params.requestBodyStream ||
	    (params.json && typeof params.json !== 'boolean') ||
	    params.multipart
	  )
	}

	function safeStringify (obj, replacer) {
	  var ret
	  try {
	    ret = JSON.stringify(obj, replacer)
	  } catch (e) {
	    ret = jsonSafeStringify(obj, replacer)
	  }
	  return ret
	}

	function md5 (str) {
	  return crypto.createHash('md5').update(str).digest('hex')
	}

	function isReadStream (rs) {
	  return rs.readable && rs.path && rs.mode
	}

	function toBase64 (str) {
	  return Buffer.from(str || '', 'utf8').toString('base64')
	}

	function copy (obj) {
	  var o = {}
	  Object.keys(obj).forEach(function (i) {
	    o[i] = obj[i]
	  })
	  return o
	}

	function version () {
	  var numbers = process.version.replace('v', '').split('.')
	  return {
	    major: parseInt(numbers[0], 10),
	    minor: parseInt(numbers[1], 10),
	    patch: parseInt(numbers[2], 10)
	  }
	}

	exports.paramsHaveRequestBody = paramsHaveRequestBody
	exports.safeStringify         = safeStringify
	exports.md5                   = md5
	exports.isReadStream          = isReadStream
	exports.toBase64              = toBase64
	exports.copy                  = copy
	exports.version               = version
	exports.defer                 = defer

	/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(29).setImmediate))

/***/ },
/* 29 */
/***/ function(module, exports, __webpack_require__) {

	var apply = Function.prototype.apply;

	// DOM APIs, for completeness

	exports.setTimeout = function() {
	  return new Timeout(apply.call(setTimeout, window, arguments), clearTimeout);
	};
	exports.setInterval = function() {
	  return new Timeout(apply.call(setInterval, window, arguments), clearInterval);
	};
	exports.clearTimeout =
	exports.clearInterval = function(timeout) {
	  if (timeout) {
	    timeout.close();
	  }
	};

	function Timeout(id, clearFn) {
	  this._id = id;
	  this._clearFn = clearFn;
	}
	Timeout.prototype.unref = Timeout.prototype.ref = function() {};
	Timeout.prototype.close = function() {
	  this._clearFn.call(window, this._id);
	};

	// Does not start the time, just sets up the members needed.
	exports.enroll = function(item, msecs) {
	  clearTimeout(item._idleTimeoutId);
	  item._idleTimeout = msecs;
	};

	exports.unenroll = function(item) {
	  clearTimeout(item._idleTimeoutId);
	  item._idleTimeout = -1;
	};

	exports._unrefActive = exports.active = function(item) {
	  clearTimeout(item._idleTimeoutId);

	  var msecs = item._idleTimeout;
	  if (msecs >= 0) {
	    item._idleTimeoutId = setTimeout(function onTimeout() {
	      if (item._onTimeout)
	        item._onTimeout();
	    }, msecs);
	  }
	};

	// setimmediate attaches itself to the global object
	__webpack_require__(30);
	exports.setImmediate = setImmediate;
	exports.clearImmediate = clearImmediate;


/***/ },
/* 30 */
/***/ function(module, exports) {

	(function (global, undefined) {
	    "use strict";

	    if (global.setImmediate) {
	        return;
	    }

	    var nextHandle = 1; // Spec says greater than zero
	    var tasksByHandle = {};
	    var currentlyRunningATask = false;
	    var doc = global.document;
	    var registerImmediate;

	    function setImmediate(callback) {
	      // Callback can either be a function or a string
	      if (typeof callback !== "function") {
	        callback = new Function("" + callback);
	      }
	      // Copy function arguments
	      var args = new Array(arguments.length - 1);
	      for (var i = 0; i < args.length; i++) {
	          args[i] = arguments[i + 1];
	      }
	      // Store and register the task
	      var task = { callback: callback, args: args };
	      tasksByHandle[nextHandle] = task;
	      registerImmediate(nextHandle);
	      return nextHandle++;
	    }

	    function clearImmediate(handle) {
	        delete tasksByHandle[handle];
	    }

	    function run(task) {
	        var callback = task.callback;
	        var args = task.args;
	        switch (args.length) {
	        case 0:
	            callback();
	            break;
	        case 1:
	            callback(args[0]);
	            break;
	        case 2:
	            callback(args[0], args[1]);
	            break;
	        case 3:
	            callback(args[0], args[1], args[2]);
	            break;
	        default:
	            callback.apply(undefined, args);
	            break;
	        }
	    }

	    function runIfPresent(handle) {
	        // From the spec: "Wait until any invocations of this algorithm started before this one have completed."
	        // So if we're currently running a task, we'll need to delay this invocation.
	        if (currentlyRunningATask) {
	            // Delay by doing a setTimeout. setImmediate was tried instead, but in Firefox 7 it generated a
	            // "too much recursion" error.
	            setTimeout(runIfPresent, 0, handle);
	        } else {
	            var task = tasksByHandle[handle];
	            if (task) {
	                currentlyRunningATask = true;
	                try {
	                    run(task);
	                } finally {
	                    clearImmediate(handle);
	                    currentlyRunningATask = false;
	                }
	            }
	        }
	    }

	    function installNextTickImplementation() {
	        registerImmediate = function(handle) {
	            process.nextTick(function () { runIfPresent(handle); });
	        };
	    }

	    function canUsePostMessage() {
	        // The test against `importScripts` prevents this implementation from being installed inside a web worker,
	        // where `global.postMessage` means something completely different and can't be used for this purpose.
	        if (global.postMessage && !global.importScripts) {
	            var postMessageIsAsynchronous = true;
	            var oldOnMessage = global.onmessage;
	            global.onmessage = function() {
	                postMessageIsAsynchronous = false;
	            };
	            global.postMessage("", "*");
	            global.onmessage = oldOnMessage;
	            return postMessageIsAsynchronous;
	        }
	    }

	    function installPostMessageImplementation() {
	        // Installs an event handler on `global` for the `message` event: see
	        // * https://developer.mozilla.org/en/DOM/window.postMessage
	        // * http://www.whatwg.org/specs/web-apps/current-work/multipage/comms.html#crossDocumentMessages

	        var messagePrefix = "setImmediate$" + Math.random() + "$";
	        var onGlobalMessage = function(event) {
	            if (event.source === global &&
	                typeof event.data === "string" &&
	                event.data.indexOf(messagePrefix) === 0) {
	                runIfPresent(+event.data.slice(messagePrefix.length));
	            }
	        };

	        if (global.addEventListener) {
	            global.addEventListener("message", onGlobalMessage, false);
	        } else {
	            global.attachEvent("onmessage", onGlobalMessage);
	        }

	        registerImmediate = function(handle) {
	            global.postMessage(messagePrefix + handle, "*");
	        };
	    }

	    function installMessageChannelImplementation() {
	        var channel = new MessageChannel();
	        channel.port1.onmessage = function(event) {
	            var handle = event.data;
	            runIfPresent(handle);
	        };

	        registerImmediate = function(handle) {
	            channel.port2.postMessage(handle);
	        };
	    }

	    function installReadyStateChangeImplementation() {
	        var html = doc.documentElement;
	        registerImmediate = function(handle) {
	            // Create a <script> element; its readystatechange event will be fired asynchronously once it is inserted
	            // into the document. Do so, thus queuing up the task. Remember to clean up once it's been called.
	            var script = doc.createElement("script");
	            script.onreadystatechange = function () {
	                runIfPresent(handle);
	                script.onreadystatechange = null;
	                html.removeChild(script);
	                script = null;
	            };
	            html.appendChild(script);
	        };
	    }

	    function installSetTimeoutImplementation() {
	        registerImmediate = function(handle) {
	            setTimeout(runIfPresent, 0, handle);
	        };
	    }

	    // If supported, we should attach to the prototype of global, since that is where setTimeout et al. live.
	    var attachTo = Object.getPrototypeOf && Object.getPrototypeOf(global);
	    attachTo = attachTo && attachTo.setTimeout ? attachTo : global;

	    // Don't get fooled by e.g. browserify environments.
	    if ({}.toString.call(global.process) === "[object process]") {
	        // For Node.js before 0.9
	        installNextTickImplementation();

	    } else if (canUsePostMessage()) {
	        // For non-IE10 modern browsers
	        installPostMessageImplementation();

	    } else if (global.MessageChannel) {
	        // For web workers, where supported
	        installMessageChannelImplementation();

	    } else if (doc && "onreadystatechange" in doc.createElement("script")) {
	        // For IE 6–8
	        installReadyStateChangeImplementation();

	    } else {
	        // For older browsers
	        installSetTimeoutImplementation();
	    }

	    attachTo.setImmediate = setImmediate;
	    attachTo.clearImmediate = clearImmediate;
	}(typeof self === "undefined" ? typeof global === "undefined" ? this : global : self));


/***/ },
/* 31 */
/***/ function(module, exports, __webpack_require__) {

	module.exports = __webpack_require__(32)


/***/ },
/* 32 */
/***/ function(module, exports) {

	module.exports = require("buffer");

/***/ },
/* 33 */
/***/ function(module, exports, __webpack_require__) {

	'use strict'

	var tough = __webpack_require__(34)

	var Cookie = tough.Cookie
	  , CookieJar = tough.CookieJar


	exports.parse = function(str) {
	  if (str && str.uri) {
	    str = str.uri
	  }
	  if (typeof str !== 'string') {
	    throw new Error('The cookie function only accepts STRING as param')
	  }
	  return Cookie.parse(str, {loose: true})
	}

	// Adapt the sometimes-Async api of tough.CookieJar to our requirements
	function RequestJar(store) {
	  var self = this
	  self._jar = new CookieJar(store, {looseMode: true})
	}
	RequestJar.prototype.setCookie = function(cookieOrStr, uri, options) {
	  var self = this
	  return self._jar.setCookieSync(cookieOrStr, uri, options || {})
	}
	RequestJar.prototype.getCookieString = function(uri) {
	  var self = this
	  return self._jar.getCookieStringSync(uri)
	}
	RequestJar.prototype.getCookies = function(uri) {
	  var self = this
	  return self._jar.getCookiesSync(uri)
	}

	exports.jar = function(store) {
	  return new RequestJar(store)
	}


/***/ },
/* 34 */
/***/ function(module, exports) {

	module.exports = require("tough-cookie");

/***/ },
/* 35 */
/***/ function(module, exports) {

	'use strict'

	function formatHostname(hostname) {
	  // canonicalize the hostname, so that 'oogle.com' won't match 'google.com'
	  return hostname.replace(/^\.*/, '.').toLowerCase()
	}

	function parseNoProxyZone(zone) {
	  zone = zone.trim().toLowerCase()

	  var zoneParts = zone.split(':', 2)
	    , zoneHost = formatHostname(zoneParts[0])
	    , zonePort = zoneParts[1]
	    , hasPort = zone.indexOf(':') > -1

	  return {hostname: zoneHost, port: zonePort, hasPort: hasPort}
	}

	function uriInNoProxy(uri, noProxy) {
	  var port = uri.port || (uri.protocol === 'https:' ? '443' : '80')
	    , hostname = formatHostname(uri.hostname)
	    , noProxyList = noProxy.split(',')

	  // iterate through the noProxyList until it finds a match.
	  return noProxyList.map(parseNoProxyZone).some(function(noProxyZone) {
	    var isMatchedAt = hostname.indexOf(noProxyZone.hostname)
	      , hostnameMatched = (
	          isMatchedAt > -1 &&
	          (isMatchedAt === hostname.length - noProxyZone.hostname.length)
	        )

	    if (noProxyZone.hasPort) {
	      return (port === noProxyZone.port) && hostnameMatched
	    }

	    return hostnameMatched
	  })
	}

	function getProxyFromURI(uri) {
	  // Decide the proper request proxy to use based on the request URI object and the
	  // environmental variables (NO_PROXY, HTTP_PROXY, etc.)
	  // respect NO_PROXY environment variables (see: http://lynx.isc.org/current/breakout/lynx_help/keystrokes/environments.html)

	  var noProxy = process.env.NO_PROXY || process.env.no_proxy || ''

	  // if the noProxy is a wildcard then return null

	  if (noProxy === '*') {
	    return null
	  }

	  // if the noProxy is not empty and the uri is found return null

	  if (noProxy !== '' && uriInNoProxy(uri, noProxy)) {
	    return null
	  }

	  // Check for HTTP or HTTPS Proxy in environment Else default to null

	  if (uri.protocol === 'http:') {
	    return process.env.HTTP_PROXY ||
	           process.env.http_proxy || null
	  }

	  if (uri.protocol === 'https:') {
	    return process.env.HTTPS_PROXY ||
	           process.env.https_proxy ||
	           process.env.HTTP_PROXY  ||
	           process.env.http_proxy  || null
	  }

	  // if none of that works, return null
	  // (What uri protocol are you using then?)

	  return null
	}

	module.exports = getProxyFromURI


/***/ },
/* 36 */
/***/ function(module, exports, __webpack_require__) {

	'use strict'

	var qs = __webpack_require__(37)
	  , querystring = __webpack_require__(16)


	function Querystring (request) {
	  this.request = request
	  this.lib = null
	  this.useQuerystring = null
	  this.parseOptions = null
	  this.stringifyOptions = null
	}

	Querystring.prototype.init = function (options) {
	  if (this.lib) {return}

	  this.useQuerystring = options.useQuerystring
	  this.lib = (this.useQuerystring ? querystring : qs)

	  this.parseOptions = options.qsParseOptions || {}
	  this.stringifyOptions = options.qsStringifyOptions || {}
	}

	Querystring.prototype.stringify = function (obj) {
	  return (this.useQuerystring)
	    ? this.rfc3986(this.lib.stringify(obj,
	      this.stringifyOptions.sep || null,
	      this.stringifyOptions.eq || null,
	      this.stringifyOptions))
	    : this.lib.stringify(obj, this.stringifyOptions)
	}

	Querystring.prototype.parse = function (str) {
	  return (this.useQuerystring)
	    ? this.lib.parse(str,
	      this.parseOptions.sep || null,
	      this.parseOptions.eq || null,
	      this.parseOptions)
	    : this.lib.parse(str, this.parseOptions)
	}

	Querystring.prototype.rfc3986 = function (str) {
	  return str.replace(/[!'()*]/g, function (c) {
	    return '%' + c.charCodeAt(0).toString(16).toUpperCase()
	  })
	}

	Querystring.prototype.unescape = querystring.unescape

	exports.Querystring = Querystring


/***/ },
/* 37 */
/***/ function(module, exports) {

	module.exports = require("qs");

/***/ },
/* 38 */
/***/ function(module, exports, __webpack_require__) {

	'use strict'

	var fs = __webpack_require__(39)
	var qs = __webpack_require__(16)
	var validate = __webpack_require__(40)
	var extend = __webpack_require__(25)

	function Har (request) {
	  this.request = request
	}

	Har.prototype.reducer = function (obj, pair) {
	  // new property ?
	  if (obj[pair.name] === undefined) {
	    obj[pair.name] = pair.value
	    return obj
	  }

	  // existing? convert to array
	  var arr = [
	    obj[pair.name],
	    pair.value
	  ]

	  obj[pair.name] = arr

	  return obj
	}

	Har.prototype.prep = function (data) {
	  // construct utility properties
	  data.queryObj = {}
	  data.headersObj = {}
	  data.postData.jsonObj = false
	  data.postData.paramsObj = false

	  // construct query objects
	  if (data.queryString && data.queryString.length) {
	    data.queryObj = data.queryString.reduce(this.reducer, {})
	  }

	  // construct headers objects
	  if (data.headers && data.headers.length) {
	    // loweCase header keys
	    data.headersObj = data.headers.reduceRight(function (headers, header) {
	      headers[header.name] = header.value
	      return headers
	    }, {})
	  }

	  // construct Cookie header
	  if (data.cookies && data.cookies.length) {
	    var cookies = data.cookies.map(function (cookie) {
	      return cookie.name + '=' + cookie.value
	    })

	    if (cookies.length) {
	      data.headersObj.cookie = cookies.join('; ')
	    }
	  }

	  // prep body
	  function some (arr) {
	    return arr.some(function (type) {
	      return data.postData.mimeType.indexOf(type) === 0
	    })
	  }

	  if (some([
	    'multipart/mixed',
	    'multipart/related',
	    'multipart/form-data',
	    'multipart/alternative'])) {

	    // reset values
	    data.postData.mimeType = 'multipart/form-data'
	  }

	  else if (some([
	    'application/x-www-form-urlencoded'])) {

	    if (!data.postData.params) {
	      data.postData.text = ''
	    } else {
	      data.postData.paramsObj = data.postData.params.reduce(this.reducer, {})

	      // always overwrite
	      data.postData.text = qs.stringify(data.postData.paramsObj)
	    }
	  }

	  else if (some([
	    'text/json',
	    'text/x-json',
	    'application/json',
	    'application/x-json'])) {

	    data.postData.mimeType = 'application/json'

	    if (data.postData.text) {
	      try {
	        data.postData.jsonObj = JSON.parse(data.postData.text)
	      } catch (e) {
	        this.request.debug(e)

	        // force back to text/plain
	        data.postData.mimeType = 'text/plain'
	      }
	    }
	  }

	  return data
	}

	Har.prototype.options = function (options) {
	  // skip if no har property defined
	  if (!options.har) {
	    return options
	  }

	  var har = {}
	  extend(har, options.har)

	  // only process the first entry
	  if (har.log && har.log.entries) {
	    har = har.log.entries[0]
	  }

	  // add optional properties to make validation successful
	  har.url = har.url || options.url || options.uri || options.baseUrl || '/'
	  har.httpVersion = har.httpVersion || 'HTTP/1.1'
	  har.queryString = har.queryString || []
	  har.headers = har.headers || []
	  har.cookies = har.cookies || []
	  har.postData = har.postData || {}
	  har.postData.mimeType = har.postData.mimeType || 'application/octet-stream'

	  har.bodySize = 0
	  har.headersSize = 0
	  har.postData.size = 0

	  if (!validate.request(har)) {
	    return options
	  }

	  // clean up and get some utility properties
	  var req = this.prep(har)

	  // construct new options
	  if (req.url) {
	    options.url = req.url
	  }

	  if (req.method) {
	    options.method = req.method
	  }

	  if (Object.keys(req.queryObj).length) {
	    options.qs = req.queryObj
	  }

	  if (Object.keys(req.headersObj).length) {
	    options.headers = req.headersObj
	  }

	  function test (type) {
	    return req.postData.mimeType.indexOf(type) === 0
	  }
	  if (test('application/x-www-form-urlencoded')) {
	    options.form = req.postData.paramsObj
	  }
	  else if (test('application/json')) {
	    if (req.postData.jsonObj) {
	      options.body = req.postData.jsonObj
	      options.json = true
	    }
	  }
	  else if (test('multipart/form-data')) {
	    options.formData = {}

	    req.postData.params.forEach(function (param) {
	      var attachment = {}

	      if (!param.fileName && !param.fileName && !param.contentType) {
	        options.formData[param.name] = param.value
	        return
	      }

	      // attempt to read from disk!
	      if (param.fileName && !param.value) {
	        attachment.value = fs.createReadStream(param.fileName)
	      } else if (param.value) {
	        attachment.value = param.value
	      }

	      if (param.fileName) {
	        attachment.options = {
	          filename: param.fileName,
	          contentType: param.contentType ? param.contentType : null
	        }
	      }

	      options.formData[param.name] = attachment
	    })
	  }
	  else {
	    if (req.postData.text) {
	      options.body = req.postData.text
	    }
	  }

	  return options
	}

	exports.Har = Har


/***/ },
/* 39 */
/***/ function(module, exports) {

	module.exports = require("fs");

/***/ },
/* 40 */
/***/ function(module, exports) {

	module.exports = require("har-validator");

/***/ },
/* 41 */
/***/ function(module, exports, __webpack_require__) {

	'use strict'

	var caseless = __webpack_require__(22)
	  , uuid = __webpack_require__(42)
	  , helpers = __webpack_require__(28)

	var md5 = helpers.md5
	  , toBase64 = helpers.toBase64


	function Auth (request) {
	  // define all public properties here
	  this.request = request
	  this.hasAuth = false
	  this.sentAuth = false
	  this.bearerToken = null
	  this.user = null
	  this.pass = null
	}

	Auth.prototype.basic = function (user, pass, sendImmediately) {
	  var self = this
	  if (typeof user !== 'string' || (pass !== undefined && typeof pass !== 'string')) {
	    self.request.emit('error', new Error('auth() received invalid user or password'))
	  }
	  self.user = user
	  self.pass = pass
	  self.hasAuth = true
	  var header = user + ':' + (pass || '')
	  if (sendImmediately || typeof sendImmediately === 'undefined') {
	    var authHeader = 'Basic ' + toBase64(header)
	    self.sentAuth = true
	    return authHeader
	  }
	}

	Auth.prototype.bearer = function (bearer, sendImmediately) {
	  var self = this
	  self.bearerToken = bearer
	  self.hasAuth = true
	  if (sendImmediately || typeof sendImmediately === 'undefined') {
	    if (typeof bearer === 'function') {
	      bearer = bearer()
	    }
	    var authHeader = 'Bearer ' + (bearer || '')
	    self.sentAuth = true
	    return authHeader
	  }
	}

	Auth.prototype.digest = function (method, path, authHeader) {
	  // TODO: More complete implementation of RFC 2617.
	  //   - handle challenge.domain
	  //   - support qop="auth-int" only
	  //   - handle Authentication-Info (not necessarily?)
	  //   - check challenge.stale (not necessarily?)
	  //   - increase nc (not necessarily?)
	  // For reference:
	  // http://tools.ietf.org/html/rfc2617#section-3
	  // https://github.com/bagder/curl/blob/master/lib/http_digest.c

	  var self = this

	  var challenge = {}
	  var re = /([a-z0-9_-]+)=(?:"([^"]+)"|([a-z0-9_-]+))/gi
	  for (;;) {
	    var match = re.exec(authHeader)
	    if (!match) {
	      break
	    }
	    challenge[match[1]] = match[2] || match[3]
	  }

	  /**
	   * RFC 2617: handle both MD5 and MD5-sess algorithms.
	   *
	   * If the algorithm directive's value is "MD5" or unspecified, then HA1 is
	   *   HA1=MD5(username:realm:password)
	   * If the algorithm directive's value is "MD5-sess", then HA1 is
	   *   HA1=MD5(MD5(username:realm:password):nonce:cnonce)
	   */
	  var ha1Compute = function (algorithm, user, realm, pass, nonce, cnonce) {
	    var ha1 = md5(user + ':' + realm + ':' + pass)
	    if (algorithm && algorithm.toLowerCase() === 'md5-sess') {
	      return md5(ha1 + ':' + nonce + ':' + cnonce)
	    } else {
	      return ha1
	    }
	  }

	  var qop = /(^|,)\s*auth\s*($|,)/.test(challenge.qop) && 'auth'
	  var nc = qop && '00000001'
	  var cnonce = qop && uuid().replace(/-/g, '')
	  var ha1 = ha1Compute(challenge.algorithm, self.user, challenge.realm, self.pass, challenge.nonce, cnonce)
	  var ha2 = md5(method + ':' + path)
	  var digestResponse = qop
	    ? md5(ha1 + ':' + challenge.nonce + ':' + nc + ':' + cnonce + ':' + qop + ':' + ha2)
	    : md5(ha1 + ':' + challenge.nonce + ':' + ha2)
	  var authValues = {
	    username: self.user,
	    realm: challenge.realm,
	    nonce: challenge.nonce,
	    uri: path,
	    qop: qop,
	    response: digestResponse,
	    nc: nc,
	    cnonce: cnonce,
	    algorithm: challenge.algorithm,
	    opaque: challenge.opaque
	  }

	  authHeader = []
	  for (var k in authValues) {
	    if (authValues[k]) {
	      if (k === 'qop' || k === 'nc' || k === 'algorithm') {
	        authHeader.push(k + '=' + authValues[k])
	      } else {
	        authHeader.push(k + '="' + authValues[k] + '"')
	      }
	    }
	  }
	  authHeader = 'Digest ' + authHeader.join(', ')
	  self.sentAuth = true
	  return authHeader
	}

	Auth.prototype.onRequest = function (user, pass, sendImmediately, bearer) {
	  var self = this
	    , request = self.request

	  var authHeader
	  if (bearer === undefined && user === undefined) {
	    self.request.emit('error', new Error('no auth mechanism defined'))
	  } else if (bearer !== undefined) {
	    authHeader = self.bearer(bearer, sendImmediately)
	  } else {
	    authHeader = self.basic(user, pass, sendImmediately)
	  }
	  if (authHeader) {
	    request.setHeader('authorization', authHeader)
	  }
	}

	Auth.prototype.onResponse = function (response) {
	  var self = this
	    , request = self.request

	  if (!self.hasAuth || self.sentAuth) { return null }

	  var c = caseless(response.headers)

	  var authHeader = c.get('www-authenticate')
	  var authVerb = authHeader && authHeader.split(' ')[0].toLowerCase()
	  request.debug('reauth', authVerb)

	  switch (authVerb) {
	    case 'basic':
	      return self.basic(self.user, self.pass, true)

	    case 'bearer':
	      return self.bearer(self.bearerToken, true)

	    case 'digest':
	      return self.digest(request.method, request.path, authHeader)
	  }
	}

	exports.Auth = Auth


/***/ },
/* 42 */
/***/ function(module, exports) {

	module.exports = require("uuid");

/***/ },
/* 43 */
/***/ function(module, exports, __webpack_require__) {

	'use strict'

	var url = __webpack_require__(9)
	  , qs = __webpack_require__(37)
	  , caseless = __webpack_require__(22)
	  , uuid = __webpack_require__(42)
	  , oauth = __webpack_require__(44)
	  , crypto = __webpack_require__(17)
	  , Buffer = __webpack_require__(31).Buffer


	function OAuth (request) {
	  this.request = request
	  this.params = null
	}

	OAuth.prototype.buildParams = function (_oauth, uri, method, query, form, qsLib) {
	  var oa = {}
	  for (var i in _oauth) {
	    oa['oauth_' + i] = _oauth[i]
	  }
	  if (!oa.oauth_version) {
	    oa.oauth_version = '1.0'
	  }
	  if (!oa.oauth_timestamp) {
	    oa.oauth_timestamp = Math.floor( Date.now() / 1000 ).toString()
	  }
	  if (!oa.oauth_nonce) {
	    oa.oauth_nonce = uuid().replace(/-/g, '')
	  }
	  if (!oa.oauth_signature_method) {
	    oa.oauth_signature_method = 'HMAC-SHA1'
	  }

	  var consumer_secret_or_private_key = oa.oauth_consumer_secret || oa.oauth_private_key
	  delete oa.oauth_consumer_secret
	  delete oa.oauth_private_key

	  var token_secret = oa.oauth_token_secret
	  delete oa.oauth_token_secret

	  var realm = oa.oauth_realm
	  delete oa.oauth_realm
	  delete oa.oauth_transport_method

	  var baseurl = uri.protocol + '//' + uri.host + uri.pathname
	  var params = qsLib.parse([].concat(query, form, qsLib.stringify(oa)).join('&'))

	  oa.oauth_signature = oauth.sign(
	    oa.oauth_signature_method,
	    method,
	    baseurl,
	    params,
	    consumer_secret_or_private_key,
	    token_secret)

	  if (realm) {
	    oa.realm = realm
	  }

	  return oa
	}

	OAuth.prototype.buildBodyHash = function(_oauth, body) {
	  if (['HMAC-SHA1', 'RSA-SHA1'].indexOf(_oauth.signature_method || 'HMAC-SHA1') < 0) {
	    this.request.emit('error', new Error('oauth: ' + _oauth.signature_method +
	      ' signature_method not supported with body_hash signing.'))
	  }

	  var shasum = crypto.createHash('sha1')
	  shasum.update(body || '')
	  var sha1 = shasum.digest('hex')

	  return Buffer.from(sha1).toString('base64')
	}

	OAuth.prototype.concatParams = function (oa, sep, wrap) {
	  wrap = wrap || ''

	  var params = Object.keys(oa).filter(function (i) {
	    return i !== 'realm' && i !== 'oauth_signature'
	  }).sort()

	  if (oa.realm) {
	    params.splice(0, 0, 'realm')
	  }
	  params.push('oauth_signature')

	  return params.map(function (i) {
	    return i + '=' + wrap + oauth.rfc3986(oa[i]) + wrap
	  }).join(sep)
	}

	OAuth.prototype.onRequest = function (_oauth) {
	  var self = this
	  self.params = _oauth

	  var uri = self.request.uri || {}
	    , method = self.request.method || ''
	    , headers = caseless(self.request.headers)
	    , body = self.request.body || ''
	    , qsLib = self.request.qsLib || qs

	  var form
	    , query
	    , contentType = headers.get('content-type') || ''
	    , formContentType = 'application/x-www-form-urlencoded'
	    , transport = _oauth.transport_method || 'header'

	  if (contentType.slice(0, formContentType.length) === formContentType) {
	    contentType = formContentType
	    form = body
	  }
	  if (uri.query) {
	    query = uri.query
	  }
	  if (transport === 'body' && (method !== 'POST' || contentType !== formContentType)) {
	    self.request.emit('error', new Error('oauth: transport_method of body requires POST ' +
	      'and content-type ' + formContentType))
	  }

	  if (!form && typeof _oauth.body_hash === 'boolean') {
	    _oauth.body_hash = self.buildBodyHash(_oauth, self.request.body.toString())
	  }

	  var oa = self.buildParams(_oauth, uri, method, query, form, qsLib)

	  switch (transport) {
	    case 'header':
	      self.request.setHeader('Authorization', 'OAuth ' + self.concatParams(oa, ',', '"'))
	      break

	    case 'query':
	      var href = self.request.uri.href += (query ? '&' : '?') + self.concatParams(oa, '&')
	      self.request.uri = url.parse(href)
	      self.request.path = self.request.uri.path
	      break

	    case 'body':
	      self.request.body = (form ? form + '&' : '') + self.concatParams(oa, '&')
	      break

	    default:
	      self.request.emit('error', new Error('oauth: transport_method invalid'))
	  }
	}

	exports.OAuth = OAuth


/***/ },
/* 44 */
/***/ function(module, exports) {

	module.exports = require("oauth-sign");

/***/ },
/* 45 */
/***/ function(module, exports, __webpack_require__) {

	'use strict'

	var uuid = __webpack_require__(42)
	  , CombinedStream = __webpack_require__(46)
	  , isstream = __webpack_require__(26)
	  , Buffer = __webpack_require__(31).Buffer


	function Multipart (request) {
	  this.request = request
	  this.boundary = uuid()
	  this.chunked = false
	  this.body = null
	}

	Multipart.prototype.isChunked = function (options) {
	  var self = this
	    , chunked = false
	    , parts = options.data || options

	  if (!parts.forEach) {
	    self.request.emit('error', new Error('Argument error, options.multipart.'))
	  }

	  if (options.chunked !== undefined) {
	    chunked = options.chunked
	  }

	  if (self.request.getHeader('transfer-encoding') === 'chunked') {
	    chunked = true
	  }

	  if (!chunked) {
	    parts.forEach(function (part) {
	      if (typeof part.body === 'undefined') {
	        self.request.emit('error', new Error('Body attribute missing in multipart.'))
	      }
	      if (isstream(part.body)) {
	        chunked = true
	      }
	    })
	  }

	  return chunked
	}

	Multipart.prototype.setHeaders = function (chunked) {
	  var self = this

	  if (chunked && !self.request.hasHeader('transfer-encoding')) {
	    self.request.setHeader('transfer-encoding', 'chunked')
	  }

	  var header = self.request.getHeader('content-type')

	  if (!header || header.indexOf('multipart') === -1) {
	    self.request.setHeader('content-type', 'multipart/related; boundary=' + self.boundary)
	  } else {
	    if (header.indexOf('boundary') !== -1) {
	      self.boundary = header.replace(/.*boundary=([^\s;]+).*/, '$1')
	    } else {
	      self.request.setHeader('content-type', header + '; boundary=' + self.boundary)
	    }
	  }
	}

	Multipart.prototype.build = function (parts, chunked) {
	  var self = this
	  var body = chunked ? new CombinedStream() : []

	  function add (part) {
	    if (typeof part === 'number') {
	      part = part.toString()
	    }
	    return chunked ? body.append(part) : body.push(Buffer.from(part))
	  }

	  if (self.request.preambleCRLF) {
	    add('\r\n')
	  }

	  parts.forEach(function (part) {
	    var preamble = '--' + self.boundary + '\r\n'
	    Object.keys(part).forEach(function (key) {
	      if (key === 'body') { return }
	      preamble += key + ': ' + part[key] + '\r\n'
	    })
	    preamble += '\r\n'
	    add(preamble)
	    add(part.body)
	    add('\r\n')
	  })
	  add('--' + self.boundary + '--')

	  if (self.request.postambleCRLF) {
	    add('\r\n')
	  }

	  return body
	}

	Multipart.prototype.onRequest = function (options) {
	  var self = this

	  var chunked = self.isChunked(options)
	    , parts = options.data || options

	  self.setHeaders(chunked)
	  self.chunked = chunked
	  self.body = self.build(parts, chunked)
	}

	exports.Multipart = Multipart


/***/ },
/* 46 */
/***/ function(module, exports) {

	module.exports = require("combined-stream");

/***/ },
/* 47 */
/***/ function(module, exports, __webpack_require__) {

	'use strict'

	var url = __webpack_require__(9)
	var isUrl = /^https?:/

	function Redirect (request) {
	  this.request = request
	  this.followRedirect = true
	  this.followRedirects = true
	  this.followAllRedirects = false
	  this.followOriginalHttpMethod = false
	  this.allowRedirect = function () {return true}
	  this.maxRedirects = 10
	  this.redirects = []
	  this.redirectsFollowed = 0
	  this.removeRefererHeader = false
	}

	Redirect.prototype.onRequest = function (options) {
	  var self = this

	  if (options.maxRedirects !== undefined) {
	    self.maxRedirects = options.maxRedirects
	  }
	  if (typeof options.followRedirect === 'function') {
	    self.allowRedirect = options.followRedirect
	  }
	  if (options.followRedirect !== undefined) {
	    self.followRedirects = !!options.followRedirect
	  }
	  if (options.followAllRedirects !== undefined) {
	    self.followAllRedirects = options.followAllRedirects
	  }
	  if (self.followRedirects || self.followAllRedirects) {
	    self.redirects = self.redirects || []
	  }
	  if (options.removeRefererHeader !== undefined) {
	    self.removeRefererHeader = options.removeRefererHeader
	  }
	  if (options.followOriginalHttpMethod !== undefined) {
	    self.followOriginalHttpMethod = options.followOriginalHttpMethod
	  }
	}

	Redirect.prototype.redirectTo = function (response) {
	  var self = this
	    , request = self.request

	  var redirectTo = null
	  if (response.statusCode >= 300 && response.statusCode < 400 && response.caseless.has('location')) {
	    var location = response.caseless.get('location')
	    request.debug('redirect', location)

	    if (self.followAllRedirects) {
	      redirectTo = location
	    } else if (self.followRedirects) {
	      switch (request.method) {
	        case 'PATCH':
	        case 'PUT':
	        case 'POST':
	        case 'DELETE':
	          // Do not follow redirects
	          break
	        default:
	          redirectTo = location
	          break
	      }
	    }
	  } else if (response.statusCode === 401) {
	    var authHeader = request._auth.onResponse(response)
	    if (authHeader) {
	      request.setHeader('authorization', authHeader)
	      redirectTo = request.uri
	    }
	  }
	  return redirectTo
	}

	Redirect.prototype.onResponse = function (response) {
	  var self = this
	    , request = self.request

	  var redirectTo = self.redirectTo(response)
	  if (!redirectTo || !self.allowRedirect.call(request, response)) {
	    return false
	  }

	  request.debug('redirect to', redirectTo)

	  // ignore any potential response body.  it cannot possibly be useful
	  // to us at this point.
	  // response.resume should be defined, but check anyway before calling. Workaround for browserify.
	  if (response.resume) {
	    response.resume()
	  }

	  if (self.redirectsFollowed >= self.maxRedirects) {
	    request.emit('error', new Error('Exceeded maxRedirects. Probably stuck in a redirect loop ' + request.uri.href))
	    return false
	  }
	  self.redirectsFollowed += 1

	  if (!isUrl.test(redirectTo)) {
	    redirectTo = url.resolve(request.uri.href, redirectTo)
	  }

	  var uriPrev = request.uri
	  request.uri = url.parse(redirectTo)

	  // handle the case where we change protocol from https to http or vice versa
	  if (request.uri.protocol !== uriPrev.protocol) {
	    delete request.agent
	  }

	  self.redirects.push(
	    { statusCode : response.statusCode
	    , redirectUri: redirectTo
	    }
	  )
	  if (self.followAllRedirects && request.method !== 'HEAD'
	    && response.statusCode !== 401 && response.statusCode !== 307) {
	    request.method = self.followOriginalHttpMethod ? request.method : 'GET'
	  }
	  // request.method = 'GET' // Force all redirects to use GET || commented out fixes #215
	  delete request.src
	  delete request.req
	  delete request._started
	  if (response.statusCode !== 401 && response.statusCode !== 307) {
	    // Remove parameters from the previous response, unless this is the second request
	    // for a server that requires digest authentication.
	    delete request.body
	    delete request._form
	    if (request.headers) {
	      request.removeHeader('host')
	      request.removeHeader('content-type')
	      request.removeHeader('content-length')
	      if (request.uri.hostname !== request.originalHost.split(':')[0]) {
	        // Remove authorization if changing hostnames (but not if just
	        // changing ports or protocols).  This matches the behavior of curl:
	        // https://github.com/bagder/curl/blob/6beb0eee/lib/http.c#L710
	        request.removeHeader('authorization')
	      }
	    }
	  }

	  if (!self.removeRefererHeader) {
	    request.setHeader('referer', uriPrev.href)
	  }

	  request.emit('redirect')

	  request.init()

	  return true
	}

	exports.Redirect = Redirect


/***/ },
/* 48 */
/***/ function(module, exports, __webpack_require__) {

	'use strict'

	var url = __webpack_require__(9)
	  , tunnel = __webpack_require__(49)

	var defaultProxyHeaderWhiteList = [
	  'accept',
	  'accept-charset',
	  'accept-encoding',
	  'accept-language',
	  'accept-ranges',
	  'cache-control',
	  'content-encoding',
	  'content-language',
	  'content-location',
	  'content-md5',
	  'content-range',
	  'content-type',
	  'connection',
	  'date',
	  'expect',
	  'max-forwards',
	  'pragma',
	  'referer',
	  'te',
	  'user-agent',
	  'via'
	]

	var defaultProxyHeaderExclusiveList = [
	  'proxy-authorization'
	]

	function constructProxyHost(uriObject) {
	  var port = uriObject.port
	    , protocol = uriObject.protocol
	    , proxyHost = uriObject.hostname + ':'

	  if (port) {
	    proxyHost += port
	  } else if (protocol === 'https:') {
	    proxyHost += '443'
	  } else {
	    proxyHost += '80'
	  }

	  return proxyHost
	}

	function constructProxyHeaderWhiteList(headers, proxyHeaderWhiteList) {
	  var whiteList = proxyHeaderWhiteList
	    .reduce(function (set, header) {
	      set[header.toLowerCase()] = true
	      return set
	    }, {})

	  return Object.keys(headers)
	    .filter(function (header) {
	      return whiteList[header.toLowerCase()]
	    })
	    .reduce(function (set, header) {
	      set[header] = headers[header]
	      return set
	    }, {})
	}

	function constructTunnelOptions (request, proxyHeaders) {
	  var proxy = request.proxy

	  var tunnelOptions = {
	    proxy : {
	      host      : proxy.hostname,
	      port      : +proxy.port,
	      proxyAuth : proxy.auth,
	      headers   : proxyHeaders
	    },
	    headers            : request.headers,
	    ca                 : request.ca,
	    cert               : request.cert,
	    key                : request.key,
	    passphrase         : request.passphrase,
	    pfx                : request.pfx,
	    ciphers            : request.ciphers,
	    rejectUnauthorized : request.rejectUnauthorized,
	    secureOptions      : request.secureOptions,
	    secureProtocol     : request.secureProtocol
	  }

	  return tunnelOptions
	}

	function constructTunnelFnName(uri, proxy) {
	  var uriProtocol = (uri.protocol === 'https:' ? 'https' : 'http')
	  var proxyProtocol = (proxy.protocol === 'https:' ? 'Https' : 'Http')
	  return [uriProtocol, proxyProtocol].join('Over')
	}

	function getTunnelFn(request) {
	  var uri = request.uri
	  var proxy = request.proxy
	  var tunnelFnName = constructTunnelFnName(uri, proxy)
	  return tunnel[tunnelFnName]
	}


	function Tunnel (request) {
	  this.request = request
	  this.proxyHeaderWhiteList = defaultProxyHeaderWhiteList
	  this.proxyHeaderExclusiveList = []
	  if (typeof request.tunnel !== 'undefined') {
	    this.tunnelOverride = request.tunnel
	  }
	}

	Tunnel.prototype.isEnabled = function () {
	  var self = this
	    , request = self.request
	  // Tunnel HTTPS by default. Allow the user to override this setting.

	  // If self.tunnelOverride is set (the user specified a value), use it.
	  if (typeof self.tunnelOverride !== 'undefined') {
	    return self.tunnelOverride
	  }

	  // If the destination is HTTPS, tunnel.
	  if (request.uri.protocol === 'https:') {
	    return true
	  }

	  // Otherwise, do not use tunnel.
	  return false
	}

	Tunnel.prototype.setup = function (options) {
	  var self = this
	    , request = self.request

	  options = options || {}

	  if (typeof request.proxy === 'string') {
	    request.proxy = url.parse(request.proxy)
	  }

	  if (!request.proxy || !request.tunnel) {
	    return false
	  }

	  // Setup Proxy Header Exclusive List and White List
	  if (options.proxyHeaderWhiteList) {
	    self.proxyHeaderWhiteList = options.proxyHeaderWhiteList
	  }
	  if (options.proxyHeaderExclusiveList) {
	    self.proxyHeaderExclusiveList = options.proxyHeaderExclusiveList
	  }

	  var proxyHeaderExclusiveList = self.proxyHeaderExclusiveList.concat(defaultProxyHeaderExclusiveList)
	  var proxyHeaderWhiteList = self.proxyHeaderWhiteList.concat(proxyHeaderExclusiveList)

	  // Setup Proxy Headers and Proxy Headers Host
	  // Only send the Proxy White Listed Header names
	  var proxyHeaders = constructProxyHeaderWhiteList(request.headers, proxyHeaderWhiteList)
	  proxyHeaders.host = constructProxyHost(request.uri)

	  proxyHeaderExclusiveList.forEach(request.removeHeader, request)

	  // Set Agent from Tunnel Data
	  var tunnelFn = getTunnelFn(request)
	  var tunnelOptions = constructTunnelOptions(request, proxyHeaders)
	  request.agent = tunnelFn(tunnelOptions)

	  return true
	}

	Tunnel.defaultProxyHeaderWhiteList = defaultProxyHeaderWhiteList
	Tunnel.defaultProxyHeaderExclusiveList = defaultProxyHeaderExclusiveList
	exports.Tunnel = Tunnel


/***/ },
/* 49 */
/***/ function(module, exports) {

	module.exports = require("tunnel-agent");

/***/ },
/* 50 */
/***/ function(module, exports) {

	// Generated by CoffeeScript 1.7.1
	(function() {
	  var getNanoSeconds, hrtime, loadTime;

	  if ((typeof performance !== "undefined" && performance !== null) && performance.now) {
	    module.exports = function() {
	      return performance.now();
	    };
	  } else if ((typeof process !== "undefined" && process !== null) && process.hrtime) {
	    module.exports = function() {
	      return (getNanoSeconds() - loadTime) / 1e6;
	    };
	    hrtime = process.hrtime;
	    getNanoSeconds = function() {
	      var hr;
	      hr = hrtime();
	      return hr[0] * 1e9 + hr[1];
	    };
	    loadTime = getNanoSeconds();
	  } else if (Date.now) {
	    module.exports = function() {
	      return Date.now() - loadTime;
	    };
	    loadTime = Date.now();
	  } else {
	    module.exports = function() {
	      return new Date().getTime() - loadTime;
	    };
	    loadTime = new Date().getTime();
	  }

	}).call(this);


/***/ },
/* 51 */
/***/ function(module, exports) {

	module.exports = require("async");

/***/ },
/* 52 */
/***/ function(module, exports) {

	module.exports = require("moment");

/***/ },
/* 53 */
/***/ function(module, exports) {

	module.exports = require("useragent");

/***/ },
/* 54 */
/***/ function(module, exports) {

	module.exports = require("express");

/***/ },
/* 55 */
/***/ function(module, exports) {

	module.exports = require("webtask-tools");

/***/ },
/* 56 */
/***/ function(module, exports) {

	module.exports = require("lru-memoizer");

/***/ }
/******/ ]);