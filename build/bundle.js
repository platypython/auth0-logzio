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
	var async = __webpack_require__(7);
	var moment = __webpack_require__(8);
	var useragent = __webpack_require__(9);
	var express = __webpack_require__(10);
	var Webtask = __webpack_require__(11);
	var app = express();
	var Request = __webpack_require__(2);
	var memoizer = __webpack_require__(12);

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
	      protocol: ctx.data.LOGZIO_PROTOCOL
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

	var request = __webpack_require__(2);
	var stringifySafe = __webpack_require__(3);
	var _assign = __webpack_require__(4);
	var dgram = __webpack_require__(5);

	exports.version = __webpack_require__(6).version;

	var LogzioLogger = function (options) {
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

	var jsonToString = exports.jsonToString = function(json) {
	    try {
	        return JSON.stringify(json);
	    }
	    catch(ex) {
	        return stringifySafe(json, null, null, function() { });
	    }
	};

	LogzioLogger.prototype._defaultCallback = function(err) {
	    if (err && !this.supressErrors) {
	        console.error('logzio-logger error: ' + err, err);
	    }
	};

	LogzioLogger.prototype.sendAndClose = function(callback){
	    this.callback = callback || this._defaultCallback;
	    this._debug("Sending last messages and closing...");
	    this._popMsgsAndSend();
	    clearTimeout(this.timer);

	    if (this.protocol === 'udp') {
	        this.udpClient.close();
	    }
	};

	LogzioLogger.prototype._timerSend = function() {
	    if (this.messages.length > 0) {
	        this._debug('Woke up and saw ' + this.messages.length + ' messages to send. Sending now...');
	        this._popMsgsAndSend();
	    }

	    var mythis = this;
	    this.timer = setTimeout(function() {
	        mythis._timerSend();
	    }, this.sendIntervalMs);
	};

	LogzioLogger.prototype._sendMessagesUDP = function() {
	    var messagesLength = this.messages.length;

	    var udpSentCallback = function(err, bytes) {
	        if (err) {
	            this._debug('Error while sending udp packets. err = ' + err);
	            callback(new Error('Failed to send udp log message. err = ' + err));
	        }
	    };

	    for (var i=0; i<messagesLength; i++) {

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

	LogzioLogger.prototype.log = function(msg) {
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
	        var now = (new Date()).toISOString();
	        msg['@timestamp_nano'] = [now, time[0].toString(), time[1].toString()].join('-');
	    }

	    this.messages.push(msg);
	    if (this.messages.length >= this.bufferSize) {
	        this._debug('Buffer is full - sending bulk');
	        this._popMsgsAndSend();
	    }
	};

	LogzioLogger.prototype._popMsgsAndSend = function() {
	    
	    if (this.protocol === 'udp') {
	        this._debug('Sending messages via udp');
	        this._sendMessagesUDP();
	    }
	    else {
	        var bulk = this._createBulk(this.messages);
	        this._debug('Sending bulk #' + bulk.id);
	        this._send(bulk);
	    }

	    this.messages = [];
	};

	LogzioLogger.prototype._createBulk = function(msgs) {
	    var bulk = {};
	    // creates a new copy of the array. Objects references are copied (no deep copy)
	    bulk.msgs = msgs.slice();
	    bulk.attemptNumber = 1;
	    bulk.sleepUntilNextRetry = 2*1000;
	    bulk.id = this.bulkId++;

	    return bulk;
	};

	LogzioLogger.prototype._messagesToBody = function(msgs) {
	    var body = '';
	    for (var i = 0; i < msgs.length; i++) {
	        body = body + jsonToString(msgs[i]) + '\n';
	    }
	    return body;
	};

	LogzioLogger.prototype._debug = function(msg) {
	    if (this.debug) console.log('logzio-nodejs: ' + msg);
	};

	LogzioLogger.prototype._send = function(bulk) {
	    var mythis = this;
	    function tryAgainIn(sleepTimeMs) {
	        mythis._debug('Bulk #' + bulk.id + ' - Trying again in ' + sleepTimeMs + '[ms], attempt no. ' + bulk.attemptNumber);
	        setTimeout(function() {
	            mythis._send(bulk);
	        }, sleepTimeMs);
	    }

	    var body = this._messagesToBody(bulk.msgs);
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
	                        tryAgainIn(sleepTimeMs)
	                    }
	                }
	                else {
	                    callback(err);
	                }
	            }
	            else {
	                var responseCode = res.statusCode.toString();
	                if (responseCode !== '200') {
	                    callback(new Error('There was a problem with the request.\nResponse: ' + responseCode + ': ' + body.toString()));
	                }
	                else {
	                    mythis._debug('Bulk #' + bulk.id + ' - sent successfully');
	                    callback();
	                }
	            }

	        });
	    }
	    catch (ex) {
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
/***/ function(module, exports) {

	module.exports = {
		"_args": [
			[
				{
					"raw": "logzio-nodejs@0.4.2",
					"scope": null,
					"escapedName": "logzio-nodejs",
					"name": "logzio-nodejs",
					"rawSpec": "0.4.2",
					"spec": "0.4.2",
					"type": "version"
				},
				"/Users/derrick/git/auth0-logzio"
			]
		],
		"_from": "logzio-nodejs@0.4.2",
		"_id": "logzio-nodejs@0.4.2",
		"_inCache": true,
		"_location": "/logzio-nodejs",
		"_nodeVersion": "6.2.2",
		"_npmOperationalInternal": {
			"host": "packages-12-west.internal.npmjs.com",
			"tmp": "tmp/logzio-nodejs-0.4.2.tgz_1481923502068_0.5961509756743908"
		},
		"_npmUser": {
			"name": "gillyb",
			"email": "gillyb@gmail.com"
		},
		"_npmVersion": "3.9.5",
		"_phantomChildren": {
			"aws-sign2": "0.6.0",
			"aws4": "1.6.0",
			"bl": "1.1.2",
			"caseless": "0.11.0",
			"combined-stream": "1.0.5",
			"extend": "3.0.0",
			"forever-agent": "0.6.1",
			"form-data": "2.0.0",
			"har-validator": "2.0.6",
			"hawk": "3.1.3",
			"http-signature": "1.1.1",
			"is-typedarray": "1.0.0",
			"isstream": "0.1.2",
			"json-stringify-safe": "5.0.1",
			"mime-types": "2.1.14",
			"node-uuid": "1.4.7",
			"oauth-sign": "0.8.2",
			"qs": "6.2.0",
			"stringstream": "0.0.5",
			"tough-cookie": "2.3.2",
			"tunnel-agent": "0.4.3"
		},
		"_requested": {
			"raw": "logzio-nodejs@0.4.2",
			"scope": null,
			"escapedName": "logzio-nodejs",
			"name": "logzio-nodejs",
			"rawSpec": "0.4.2",
			"spec": "0.4.2",
			"type": "version"
		},
		"_requiredBy": [
			"/"
		],
		"_resolved": "https://registry.npmjs.org/logzio-nodejs/-/logzio-nodejs-0.4.2.tgz",
		"_shasum": "a848b99469ceb929f124317b291d4e5475c7c88a",
		"_shrinkwrap": null,
		"_spec": "logzio-nodejs@0.4.2",
		"_where": "/Users/derrick/git/auth0-logzio",
		"author": {
			"name": "Gilly Barr",
			"email": "gilly@logz.io"
		},
		"bugs": {
			"url": "https://github.com/logzio/logzio-nodejs/issues"
		},
		"contributors": [
			{
				"name": "Gilly Barr",
				"email": "gillyb@gmail.com"
			},
			{
				"name": "Asaf Mesika",
				"email": "asaf.mesika@gmail.com"
			}
		],
		"dependencies": {
			"json-stringify-safe": "5.0.x",
			"lodash.assign": "4.2.0",
			"request": "2.75.0"
		},
		"description": "A nodejs implementation for sending logs to Logz.IO cloud service",
		"devDependencies": {
			"assert": "^1.3.0",
			"async": "1.4.2",
			"mocha": "^2.3.3",
			"nock": "^2.13.0",
			"should": "^7.1.0",
			"sinon": "^1.17.1"
		},
		"directories": {},
		"dist": {
			"shasum": "a848b99469ceb929f124317b291d4e5475c7c88a",
			"tarball": "https://registry.npmjs.org/logzio-nodejs/-/logzio-nodejs-0.4.2.tgz"
		},
		"engines": {
			"node": ">= 0.8.0"
		},
		"gitHead": "615e2f20ad281594f27a3e591c24a22c81565662",
		"homepage": "https://github.com/logzio/logzio-nodejs#readme",
		"keywords": [
			"cloud computing",
			"log analytics",
			"api",
			"logging",
			"logzio"
		],
		"license": "(Apache-2.0)",
		"main": "./lib/logzio-nodejs",
		"maintainers": [
			{
				"name": "asafm",
				"email": "asaf.mesika@gmail.com"
			},
			{
				"name": "gillyb",
				"email": "gillyb@gmail.com"
			}
		],
		"name": "logzio-nodejs",
		"optionalDependencies": {},
		"readme": "ERROR: No README data found!",
		"repository": {
			"type": "git",
			"url": "git+https://github.com/logzio/logzio-nodejs.git"
		},
		"scripts": {
			"test": "mocha"
		},
		"version": "0.4.2"
	};

/***/ },
/* 7 */
/***/ function(module, exports) {

	module.exports = require("async");

/***/ },
/* 8 */
/***/ function(module, exports) {

	module.exports = require("moment");

/***/ },
/* 9 */
/***/ function(module, exports) {

	module.exports = require("useragent");

/***/ },
/* 10 */
/***/ function(module, exports) {

	module.exports = require("express");

/***/ },
/* 11 */
/***/ function(module, exports) {

	module.exports = require("webtask-tools");

/***/ },
/* 12 */
/***/ function(module, exports) {

	module.exports = require("lru-memoizer");

/***/ }
/******/ ]);