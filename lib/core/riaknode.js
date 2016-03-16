'use strict';

var async = require('async');
var events = require('events');
var Joi = require('joi');
var LinkedList = require('linkedlist');
var logger = require('winston');
var util = require('util');

var RiakConnection = require('./riakconnection');
var Ping = require('../commands/ping');

var rpb = require('../protobuf/riakprotobuf');
var rpbErrorRespCode = rpb.getCodeFor('RpbErrorResp');

var nid = 0;

/**
 * @module Core
 */

/**
 * Provides the RiakNode class and its Builder.
 *
 * Instances of this class maintain connections to and execute commands on
 * a Riak node in a Riak cluster.
 *
 * __options__ is an object with the following defaults:
 *
 *     {
 *       remoteAdddress: '127.0.0.1',
 *       remotePort: 8087,
 *       maxConnections: 128,
 *       minConnections: 1,
 *       idleTimeout: 10000,
 *       connectionTimeout: 3000,
 *       requestTimeout: 5000,
 *       cork: true
 *     }
 *
 * As a convenience a builder class is provided;
 *
 *     var newNode = new RiakNode.Builder().withMinConnections(10).build();
 *
 * See {{#crossLink "RiakNode.Builder"}}RiakNode.Builder{{/crossLink}}
*
 * @class RiakNode
 * @constructor
 * @param {Object} options The options for this RiakNode.
 * @param {String} [options.remoteAddress=127.0.0.1] The address for this node. Can also be a FQDN.
 * @param {Number} [options.remotePort=8087] The port to connect to.
 * @param {Number} [options.minConnections=1] Set the minimum number of active connections to maintain.
 * @param {Number} [options.maxConnections=128] Set the maximum number of connections allowed.
 * @param {Number} [options.idleTimeout=10000] Set the idle timeout used to reap inactive connections.
 * @param {Number} [options.connectionTimeout=3000] Set the connection timeout used when making new connections.
 * @param {Number} [options.requestTimeout=5000] Set the timeout used when executing commands.
 * @param {Object} [options.auth] Set the authentication information for connections made by this node.
 * @param {Boolean} [options.cork] Use 'cork' on all sockets. Default is true.
 * @param {String} options.auth.user Riak username.
 * @param {String} [options.auth.password] Riak password. Not required if using user cert.
 * @param {String|Buffer} [options.auth.pfx] A string or buffer holding the PFX or PKCS12 encoded private key, certificate and CA certificates.
 * @param {String|Buffer} [options.auth.key] A string holding the PEM encoded private key.
 * @param {String} [options.auth.passphrase]  A string of passphrase for the private key or pfx.
 * @param {String|Buffer} [options.auth.cert]  A string holding the PEM encoded certificate.
 * @param {String|String[]|Buffer[]} [options.auth.ca] Either a string or list of strings of PEM encoded CA certificates to trust.
 * @param {String|String[]|Buffer[]} [options.auth.crl] Either a string or list of strings of PEM encoded CRLs (Certificate Revocation List).
 * @param {Boolean} [options.auth.rejectUnauthorized] A boolean indicating whether a server should automatically reject clients with invalid certificates. Only applies to servers with requestCert enabled.
 *
 */
function RiakNode(options) {
    events.EventEmitter.call(this);

    var self = this;

    if (options === undefined) {
        options = {};
    }

    Joi.validate(options, schema, function (err, options) {
        if (err) {
            throw err;
        }
        self.remoteAddress = options.remoteAddress;
        self.remotePort = options.remotePort;
        self.minConnections = options.minConnections;
        self.maxConnections = options.maxConnections;
        self.idleTimeout = options.idleTimeout;
        self.connectionTimeout = options.connectionTimeout;
        self.requestTimeout = options.requestTimeout;
        self.state = State.CREATED;
        self.auth = options.auth;
        self.cork = options.cork;
        self.healthCheck = options.healthCheck;
    });

    this._shutdownCount = 0;
    this.executeCount = 0;

    // This is to facilitate debugging
    this.name = util.format('[RiakNode] (%s:%d-%d)',
        this.remoteAddress, this.remotePort, nid);
    nid++;

    // private data
    var currentNumConnections = 0;
    var available = new LinkedList();

    // protected funcs
    this._getConnectionFromPool = function (cmd_name) {
        var conn = null;
        do {
            if (available.length === 0) {
                break;
            }
            conn = available.shift();
            if (conn.closed) {
                /*
                 * NB: this is expected as connection callbacks can close connections
                 * while they remain within the connection pool
                 */
                logger.debug('%s execute of %s attempted on closed connection', this.name, cmd_name);
                conn = null;
            }
        } while (!conn);
        return conn;
    };

    this._returnConnectionToPool = function (conn) {
        if (this.state < State.SHUTTING_DOWN) {
            conn.executeDone();
            available.unshift(conn);
            logger.debug("%s _returnConnectionToPool a: %d, cnc: %d",
                this.name, available.length, currentNumConnections);
        } else {
            logger.debug('%s connection returned to pool during shutdown.', this.name);
            currentNumConnections--;
            conn.close();
        }
    };

    this._closeConnections = function() {
        available.resetCursor();
        while (available.next()) {
            var conn = available.removeCurrent();
            currentNumConnections--;
            conn.close();
        }
        available.resetCursor();
    };

    this._isPoolEmpty = function () {
        return available.length === 0;
    };

    this._getPoolInfo = function () {
        return {
            cnc: currentNumConnections,
            count: available.length,
        };
    };

    this._incrementConnectionCount = function () {
        currentNumConnections++;
    };

    this._decrementConnectionCount = function () {
        currentNumConnections--;
    };

    this._createNewConnectionAllowed = function () {
        return currentNumConnections < this.maxConnections;
    };

    this._expireIdleConnections = function () {
        logger.debug("%s expiring idle connections", this.name);
        var now = Date.now();
        var count = 0;
        available.resetCursor();
        while (available.next() && currentNumConnections > this.minConnections) {
            var curr = available.current;
            if ((!curr.inFlight) &&
                (curr.closed || (now - curr.lastUsed >= this.idleTimeout))) {
                var conn = available.removeCurrent();
                currentNumConnections--;
                if (!conn.closed) {
                    conn.close();
                }
                count++;
            }
        }
        available.resetCursor();
        logger.debug("%s expired %d connections.", this.name, count);
    };
}

util.inherits(RiakNode, events.EventEmitter);

/**
 * Start this RiakNode.
 * @method start
 * @param {Function} callback - a callback for when node is started.
 */
RiakNode.prototype.start = function(callback) {
    this._stateCheck([State.CREATED]);

    logger.debug('%s starting', this.name);

    // Fire up connection pool
    var funcs = [];
    for (var i = 0; i < this.minConnections; i++) {
        funcs.push(makeNewConnectionFunc(this));
    }

    var self = this;
    async.parallel(funcs, function (err, rslts) {
        if (err) {
            logger.error('%s (%d) error during start:', self.name, self.executeCount, err);
        }

        self._expireTimer =
            setInterval(self._expireIdleConnections.bind(self), 5000);

        self.state = State.RUNNING;
        logger.debug('%s started', self.name);
        self.emit(EVT_SC, self, self.state);
        if (callback) {
            callback(err, self);
        }
    });
};

function makeNewConnectionFunc(node) {
    var f = function (async_cb) {
        var postConnect = function (conn) {
            node._returnConnectionToPool(conn);
            async_cb(null, true);
        };
        var postFail = function (err) {
            async_cb(err, false);
        };
        node._createNewConnection(postConnect, postFail);
    };
    return f;
}

RiakNode.prototype._createNewConnection = function (postConnectFunc, postFailFunc, healthCheck) {
    this._incrementConnectionCount();

    var conn = new RiakConnection({
        remoteAddress : this.remoteAddress,
        remotePort : this.remotePort,
        connectionTimeout : this.connectionTimeout,
        requestTimeout : this.requestTimeout,
        auth: this.auth,
        healthCheck: healthCheck,
        cork: this.cork
    });

    var self = this;

    conn.on('connected', function (conn) {
        logger.debug("%s conn.on-connected", this.name);
        conn.on('responseReceived', self._responseReceived.bind(self));
        conn.on('connectionClosed', self._connectionClosed.bind(self));
        postConnectFunc(conn);
    });

    conn.on('connectFailed', function (conn, err){
       logger.debug("%s conn.on-connectFailed", this.name);
       self._decrementConnectionCount();
       postFailFunc(err);
    });

    conn.connect();
};

/**
 * Stop this RiakNode.
 * @param {Function} callback - called when node completely stopped.
 * @method stop
 */
RiakNode.prototype.stop = function(callback) {
    this._stateCheck([State.RUNNING, State.HEALTH_CHECKING]);
    clearInterval(this._expireTimer);
    this.state = State.SHUTTING_DOWN;
    logger.debug("%s shutting down", this.name);
    this.emit(EVT_SC, this, this.state);
    this._shutdown(callback);
};

RiakNode.prototype._shutdown = function(callback) {
    this._shutdownCount++;
    this._closeConnections();
    var pi = this._getPoolInfo();
    if (this._shutdownCount > 10 || this._isPoolEmpty()) {
        this.state = State.SHUTDOWN;
        logger.debug("%s shut down.", this.name);
        if (this.executeCount > 0) {
            logger.warn('%s execution count (%d) NOT ZERO at shutdown', this.name, this.executeCount);
        }
        if (pi.cnc > 0) {
            logger.warn('%s connection count (%d) NOT ZERO at shutdown', this.name, pi.cnc);
        }
        this.emit(EVT_SC, this, this.state);
        this.removeAllListeners();
        if (callback) {
            callback(null, this.state);
        }
    } else {
        logger.debug("%s connections still in use (%d:%d:%d)",
            this.name, pi.cnc, pi.count, this.executeCount);
        setTimeout(this._shutdown.bind(this, callback), 125);
    }
};

/**
 * Execute a command on this RiakNode.
 * @method execute
 * @param {Object} command - a command to execute.
 * @return {Boolean} - if this RiakNode accepted the command for execution.
 */
RiakNode.prototype.execute = function (command) {
    this._stateCheck([State.RUNNING, State.HEALTH_CHECKING]);

    logger.debug("%s executing command '%s'", this.name, command.name);

    var executed = false;
    if (this.state === State.RUNNING) {
        var conn = this._getConnectionFromPool(command.name);
        // conn will be undefined if there's no available connections.
        if (!conn) {
            if (this._createNewConnectionAllowed()) {
                var self = this;
                this._createNewConnection(function (newConn) {
                    logger.debug("%s executing command '%s' (new connection %d)",
                        self.name, command.name, self.executeCount);
                    if (newConn.execute(command)) {
                        self.executeCount++;
                        logger.debug("%s (%d) executed '%s'",
                            self.name, self.executeCount, command.name);
                    }
                }, function (err) {
                    logger.debug("%s (%d) command execution failed '%s'",
                        self.name, self.executeCount, command.name);
                    if (self.state === State.RUNNING) {
                        self._doHealthCheck();
                    }
                    self._maybeRetryCommand(command, function () {
                        command.onError(err);
                    });
                });
                // NB: returning true is the only option since
                // creating a new connection is async
                executed = true;
            } else {
                logger.debug('%s all connections in use and at max', this.name);
                executed = false;
            }
        } else {
            logger.debug("%s executing command '%s' (existing connection %d)",
                this.name, command.name, this.executeCount);
            if (conn.execute(command)) {
                this.executeCount++;
                logger.debug("%s executed (%d)", this.name, this.executeCount);
            }
            // NB: returning true is the only option since
            // executing a command is async
            executed = true;
        }
    }
    return executed;
};

RiakNode.prototype._responseReceived = function (conn, command, code, decoded) {
    // NB: this function is similar to _receiveHealthCheck in RiakConnection
    logger.debug("%s command '%s' _responseReceived: %d", this.name, command.name, code);
    if (code === rpbErrorRespCode) {
        this.executeCount--;
        this._returnConnectionToPool(conn);
        if (logger.debug) {
            var errmsg = decoded.getErrmsg().toString('utf8');
            var errcode = decoded.getErrcode();
            logger.debug("%s command '%s' received RpbErrorResp (%d) %s",
                this.name, command.name, errcode, errmsg);
        }
        this._maybeRetryCommand(command, function () {
            command.onRiakError(decoded);
        });
    } else if (code !== command.getExpectedResponseCode()) {
        this.executeCount--;
        this._returnConnectionToPool(conn);
        var msg = util.format('%s received incorrect response; expected %d, got %d',
            this.name, command.getExpectedResponseCode(), code);
        logger.error(msg);
        this._maybeRetryCommand(command, function () {
            command.onError(msg);
        });
    } else {
        // All of our responses that return multiple protobuf messages (streaming) use
        // a "done" field. Checking for it allows us to know when a streaming op is done and
        // return the connections to the pool before calling the callback.
        // Some responses will be empty (null body), so we also need to account for that.
        var hasDone = decoded ? decoded.hasOwnProperty('done') : false;
        if ((hasDone && decoded.done) || !hasDone) {
            this.executeCount--;
            this._returnConnectionToPool(conn);
            logger.debug('%s command %s complete (%d)',
                this.name, command.name, this.executeCount);
        }
        command.onSuccess(decoded);
    }
};

RiakNode.prototype._connectionClosed = function (conn) {
    this._decrementConnectionCount();
    // See if a command was being handled
    var command = conn.command;
    logger.debug("%s connection closed; command '%s', in-flight: '%s'",
        this.name, command.name, conn.inFlight);
    if (conn.inFlight) {
        this.executeCount--;
        this._maybeRetryCommand(command, function () {
            command.onError("Connection closed while executing command");
        });
    }
    if (this.state !== State.SHUTTING_DOWN) {
        // TODO: FUTURE review this. Right now the sockets are set to never time out
        // which is probably what we don't want.
        // PB connections don't time out. If one disconnects it's highly likely
        // the node went down or there's a network issue
        if (this.state !== State.HEALTH_CHECKING) {
            this._doHealthCheck();
        }
    }
};

RiakNode.prototype._stateCheck = function (allowedStates) {
    if (allowedStates.indexOf(this.state) === -1) {
        throw new Error("RiakNode: Illegal State; required: " + allowedStates + " current: " + this.state);
    }
};

RiakNode.prototype._doHealthCheck = function () {
    this.state = State.HEALTH_CHECKING;
    this.emit(EVT_SC, this, this.state);
    setImmediate(this._healthCheck.bind(this));
};

RiakNode.prototype._healthCheck = function () {
    var self = this;
    logger.debug("%s running health check", this.name);

    this._createNewConnection(function (newConn) {
        self._returnConnectionToPool(newConn);
        self.state = State.RUNNING;
        logger.debug("%s healthcheck success", self.name);
        self.emit(EVT_SC, self, self.state);
    }, function () {
        logger.debug("%s failed healthcheck.", self.name);
        // NB: healthcheck interval *should* (must?) be less than re-try interval
        // TODO FUTURE should HC interval increase by some percentage each iteration up to a max?
        setTimeout(self._healthCheck.bind(self), 75);
    }, this.healthCheck);
};

RiakNode.prototype._maybeRetryCommand = function (command, errfunc) {
    var tries = command.remainingTries;
    command.remainingTries--;
    logger.debug("%s command %s remaining tries %d -> %d",
        this.name, command.name, tries, command.remainingTries);
    if (command.remainingTries > 0) {
        this.emit(EVT_RC, command, this);
    } else {
        errfunc();
    }
};

/**
 * The state of this node.
 *
 * If listeneing for stateChange events, a numeric value will be sent that
 * can be compared to:
 *
 *     RiakNode.State.CREATED
 *     RiakNode.State.RUNNING
 *     RiakNode.State.HEALTH_CHECKING
 *     RiakNode.State.SHUTTING_DOWN
 *     RiakNode.State.SHUTDOWN
 *
 * See: {{#crossLink "RiakNode/stateChange:event"}}stateChange{{/crossLink}}
 *
 * @property State
 * @type {Object}
 * @static
 * @final
 */
var State = Object.freeze({ CREATED : 0,
                            RUNNING : 1,
                            HEALTH_CHECKING : 2,
                            SHUTTING_DOWN : 3,
                            SHUTDOWN : 4});

var defaultRemoteAddress = '127.0.0.1';
var defaultRemotePort = 8087;
var defaultMinConnections = 1;
var defaultMaxConnections = 256;
var defaultIdleTimeout = 10000;
var defaultConnectionTimeout = 3000;
var defaultRequestTimeout = 5000;
var defaultHealthCheck = new Ping(function (){});

var schema = Joi.object().keys({
    remoteAddress: Joi.string().default(defaultRemoteAddress),
    remotePort: Joi.number().min(1).default(defaultRemotePort),
    minConnections: Joi.number().min(0).default(defaultMinConnections),
    maxConnections: Joi.number().min(0).default(defaultMaxConnections),
    idleTimeout: Joi.number().min(10000).default(defaultIdleTimeout),
    connectionTimeout: Joi.number().min(1).default(defaultConnectionTimeout),
    requestTimeout: Joi.number().min(1).default(defaultRequestTimeout),
    healthCheck: Joi.object().default(defaultHealthCheck),
    cork: Joi.boolean().default(true),
    auth: Joi.object().optional().keys({
        user: Joi.string().required(),
        password: Joi.string().allow(''),
        // https://nodejs.org/api/tls.html#tls_tls_createsecurecontext_details
        pfx: [Joi.string(), Joi.binary()],
        key: [Joi.string(), Joi.binary()],
        passphrase: Joi.string(),
        cert: [Joi.string(), Joi.binary()],
        ca: [Joi.string(), Joi.array().items(Joi.string(), Joi.binary())],
        crl: [Joi.string(), Joi.array().items(Joi.string(), Joi.binary())],
        rejectUnauthorized: Joi.boolean()
    }).xor('password', 'cert', 'pfx')
      .with('cert', 'key')
      .without('password', ['cert', 'pfx'])
});

/**
 * This event is fired whenever the state of the RiakNode changes.
 * @event stateChange
 * @param {Object} node - the RiakNode object whose state changed
 * @param {Number} state - the {{#crossLink "RiakNode/State:property"}}RiakNode.State{{/crossLink}}
 */
var EVT_SC = 'stateChange';

/**
 * This event is fired whenever a command fails and needs to be retried.
 * @event retryCommand
 * @param {Object} command - the command to retry
 * @param {RiakNode} node - this RiakNode
 */
var EVT_RC = 'retryCommand';

/**
 * A Builder for constructing RiakNode instances.
 *
 * Rather than having to manually construct the __options__ and instantiating
 * a RiakNode directly, this builder may be used.
 *
 *      var riakNode = new RiakNode.Builder().withRemotePort(9999).build();
 *
 * @class RiakNode.Builder
 * @constructor
 */
function Builder() {}

Builder.prototype = {

    /**
     * Set the remote address for the RiakNode.
     * @method withRemoteAddress
     * @param {String} address - IP or hostanme of the Riak node (__default:__ 127.0.0.1)
     * @return {RiakNode.Builder}
     */
    withRemoteAddress : function (address) {
        this.remoteAddress = address;
        return this;
    },

    /**
     * Set the remote port for this RiakNode.
     * @method withRemotePort
     * @param {Number} port - remote port of the Riak node (__default:__ 8087)
     * @return {RiakNode.Builder}
     */
    withRemotePort : function (port) {
        this.remotePort = port;
        return this;
    },

    /**
     * Set the minimum number of active connections to maintain.
     * These connections are exempt from the idle timeout.
     * @method withMinConnections
     * @param {Number} minConnections - number of connections to maintain (__default:__ 1)
     * @return {RiakNode.Builder}
     */
    withMinConnections : function (minConnections) {
        this.minConnections = minConnections;
        return this;
    },

    /**
     * Set the maximum number of connections allowed.
     * @method withMaxConnections
     * @param {Number} maxConnections - maximum number of connections to allow (__default:__ 10000)
     * @return {RiakNode.Builder}
     */
    withMaxConnections : function (maxConnections) {
        this.maxConnections = maxConnections;
        return this;
    },

    /**
     * Set the idle timeout used to reap inactive connections.
     * Any connection that has been idle for this amount of time
     * becomes eligible to be closed and discarded excluding the number
     * set via __withMinConnections()__.
     * @method withIdleTimeout
     * @param {Number} idleTimeout - the timeout in milliseconds (__default:__ 10000)
     * @return {RiakNode.Builder}
     */
    withIdleTimeout : function (idleTimeout) {
        this.idleTimeout = idleTimeout;
        return this;
    },

    /**
     * Set the connection timeout used when making new connections.
     * @method withConnectionTimeout
     * @param {Number} connectionTimeout - timeout in milliseconds (__default:__ 3000).
     * @return {RiakNode.Builder}
     */
    withConnectionTimeout : function (connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
        return this;
    },

    /**
     * Set the request timeout used when executing commands.
     * @method withRequestTimeout
     * @param {Number} requestTimeout - timeout in milliseconds (__default:__ 5000).
     * @return {RiakNode.Builder}
     */
    withRequestTimeout : function (requestTimeout) {
        this.requestTimeout = requestTimeout;
        return this;
    },

    /**
     * Set whether to use the cork/uncork socket functions.
     *
     * @method withCork
     * @param {Boolean} [cork=true] use cork/uncork. Default is true.
     * @chainable
     */
    withCork : function (cork) {
        this.cork = cork;
        return this;
    },

    /**
     * Set the authentication information for connections made by this node.
     * @method withAuth
     * @param {Object} auth Set the authentication information for connections made by this node.
     * @param {String} auth.user Riak username.
     * @param {String} [auth.password] Riak password. Not required if using user cert.
     * @param {String|Buffer} [auth.pfx] A string or buffer holding the PFX or PKCS12 encoded private key, certificate and CA certificates.
     * @param {String|Buffer} [auth.key] A string holding the PEM encoded private key.
     * @param {String} [auth.passphrase]  A string of passphrase for the private key or pfx.
     * @param {String|Buffer} [auth.cert]  A string holding the PEM encoded certificate.
     * @param {String|String[]|Buffer[]} [auth.ca] Either a string or list of strings of PEM encoded CA certificates to trust.
     * @param {String|String[]|Buffer[]} [auth.crl] Either a string or list of strings of PEM encoded CRLs (Certificate Revocation List).
     * @param {Boolean} [auth.rejectUnauthorized] A boolean indicating whether a server should automatically reject clients with invalid certificates. Only applies to servers with requestCert enabled.     * @return {RiakNode.Builder}
     */
    withAuth : function (auth) {
        this.auth = auth;
        return this;
    },

    /**
     * Set the command to be used for a health check.
     *
     * If this RiakNode performs a health check, a new connection is made and
     * a command performed. The default is to send a {{#crossLink "Ping"}}{{/crossLink}}
     * command but any command can be used. If it completes successfully the
     * health check is considered a success.
     * @method withHealthCheck
     * @param {Object} healthCheck - a command to execute as a health check.
     * @chainable
     */
    withHealthCheck : function (healthCheck) {
        this.healthCheck = healthCheck;
        return this;
    },

    /**
     * Builds a RiakNode instance.
     * @method build
     * @return {RiakNode}
     */
    build : function () {
        return new RiakNode(this);
    }
};

/**
 * Static factory for constructing a set of RiakNodes.
 *
 * To create a set of RiakNodes with the same options:
 *
 *      var options = new RiakNode.Builder().withMinConnections(10);
 *      var nodes = RiakNode.buildNodes(['192.168.1.1', '192.168.1.2'], options);
 *
 * __options__ can be manually constructed or an instance of the Builder.
 *
 * @static
 * @method buildNodes
 * @param {String[]} addresses - an array of IP|hostname[:port]
 * @param {Object} [options] - the options to use for all RiakNodes.
 * @return {Array/RiakNode}
 */
var buildNodes = function (addresses, options) {
    var riakNodes = [];

    if (options === undefined) {
        options = {};
    }

    for (var i = 0; i < addresses.length; i++) {
        var split = addresses[i].split(':');
        options.remoteAddress = split[0];
        if (split.length === 2) {
            options.remotePort = split[1];
        }
        riakNodes.push(new RiakNode(options));
    }

    return riakNodes;
};

module.exports = RiakNode;
module.exports.buildNodes = buildNodes;
module.exports.Builder = Builder;
module.exports.State = State;
