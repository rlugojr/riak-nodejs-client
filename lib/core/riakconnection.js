'use strict';

var net = require('net');
var tls = require('tls');
var events = require('events');
var util = require('util');
var fs = require('fs');
var logger = require('winston');

var ByteBuffer = require('bytebuffer');
var StartTls = require('./starttls');
var AuthReq = require('./authreq');

var rpb = require('../protobuf/riakprotobuf');
var rpbErrorRespCode = rpb.getCodeFor('RpbErrorResp');

var DEFAULT_MAX_BUFFER = 2048 * 1024;
var DEFAULT_INIT_BUFFER = 2 * 1024;

// TODO FUTURE these are shared with RiakNode
var DEFAULT_CONNECTION_TIMEOUT = 3000;
var DEFAULT_REQUEST_TIMEOUT = 5000;

// NB: fixes GH 104
// https://github.com/basho/riak-nodejs-client/issues/104
// TODO FUTURE: remove this when Riak uses Erlang R17 or higher.
var RIAK_R16_CIPHERS = 'DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:AES128-SHA256:AES128-SHA:AES256-SHA256:AES256-SHA:RC4-SHA';

var cid = {};

/**
 * @module Core
 */

/**
 * Provides the RiakConnection class.
 * @class RiakConnection
 * @constructor
 * @param {Object} options - the options to use.
 */
function RiakConnection(options) {
    events.EventEmitter.call(this);

    this.remoteAddress = options.remoteAddress;
    this.remotePort = options.remotePort;

    // This is to facilitate debugging
    if (!cid[this.remotePort]) {
        cid[this.remotePort] = 1;
    }
    this.name = util.format('[RiakConnection] (%s:%d-%d)',
        this.remoteAddress, this.remotePort, cid[this.remotePort]);
    cid[this.remotePort]++;

    if (options.cork) {
        this.cork = true;
    }

    if (options.auth) {
        this.auth = options.auth;
        this.auth.ciphers = RIAK_R16_CIPHERS;
    }

    if (options.healthCheck) {
        this.healthCheck = options.healthCheck;
    }

    if (options.hasOwnProperty('connectionTimeout')) {
        this.connectionTimeout = options.connectionTimeout;
    } else {
        this.connectionTimeout = DEFAULT_CONNECTION_TIMEOUT;
    }

    if (options.hasOwnProperty('requestTimeout')) {
        this.requestTimeout = options.requestTimeout;
    } else {
        this.requestTimeout = DEFAULT_REQUEST_TIMEOUT;
    }

    if (options.hasOwnProperty('maxBufferSize')) {
        this.maxBufferSize = options.maxBufferSize;
    } else {
        this.maxBufferSize = DEFAULT_MAX_BUFFER;
    }

    if (options.hasOwnProperty('initBufferSize')) {
        this.initBufferSize = options.initBufferSize;
    } else {
        this.initBufferSize = DEFAULT_INIT_BUFFER;
    }

    this.inFlight = false; 
    this.lastUsed = Date.now();

    this._buffer = null;

    this.closed = false;
    this._connectedEmitted = false;

    this._connection = new net.Socket();
    if (this._connection.setKeepAlive) {
        this._connection.setKeepAlive(true, 0);
    }
    if (this._connection.setNoDelay) {
        this._connection.setNoDelay(true);
    }

    // Note: useful for debugging event-related nonsense
    // this._connection.setMaxListeners(1);

    if (this.cork && !this._connection.cork) {
        logger.warn('%s wanted to use cork/uncork but not supported!', this.name);
        this.cork = false;
    } else {
        logger.debug('%s using cork() / uncork()', this.name);
    }

    this._emitAndClose = function(evt, evt_args) {
        if (!this.closed) {
            // NB: this can be useful
            // logger.debug("%s emitting '%s' args '%s'", this.name, evt, evt_args);
            // NB: RiakNode checks inFlight to re-try command if necessary
            this.closed = true;
            this._connection.end();
            this.emit(evt, this, evt_args);
            this.close();
        }
    };

    this._connHandleEnd = function () {
        logger.debug('%s handling "end" event', this.name);
        this._emitAndClose('connectionClosed');
    };

    this._connHandleTimeout = function (command) {
        var err = util.format("%s command '%s' timed out (in-flight: %s)",
            this.name, command.name, this.inFlight);
        if (logger.debug) {
            logger.debug(err);
        }
        this._emitAndClose('connectionClosed');
    };

    this._resetBuffer = function() {
        if (this._buffer && this._buffer.capacity() > this.maxBufferSize) {
            this._buffer = null;
        } 
    };

    this._clearSocketTimeout = function() {
        if (this._boundConnectionTimeout) {
            this._connection.removeListener('timeout', this._boundConnectionTimeout);
            this._boundConnectionTimeout = null;
        }
        this._connection.setTimeout(0);
    };
}

util.inherits(RiakConnection, events.EventEmitter);

RiakConnection.prototype.connect = function() {
    this._boundConnectionError = this._connectionError.bind(this);
    this._connection.on('error', this._boundConnectionError);

    // This *is* the read/write timeout as well as idle timeout
    // https://nodejs.org/api/net.html#net_socket_settimeout_timeout_callback
    this._boundConnectionTimeout = this._connectionTimeout.bind(this);
    this._connection.setTimeout(this.connectionTimeout, this._boundConnectionTimeout);

    this._connection.connect(this.remotePort, this.remoteAddress, this._connected.bind(this));
};

RiakConnection.prototype._connected = function() {
    logger.debug('%s _connected', this.name);

    this._connection.removeListener('error', this._boundConnectionError);
    this._connection.on('error', this._socketError.bind(this));

    this._connection.on('end', this._connHandleEnd.bind(this));

    if (this.auth) {
        /*
         * NB: at this point, we have not yet emitted the 'connected' event,
         * so listeners will not have yet registered for 'connectionClosed'.
         * This is why the 'close' event must raise 'connectFailed' via
         * _boundConnectionError
         */
        logger.debug('%s StartTls', this.name);
        this._connection.on('close', this._boundConnectionError);
        this._boundReceiveStartTls = this._receiveStartTls.bind(this);
        this._connection.on('data', this._boundReceiveStartTls);
        var command = new StartTls(function(){});
        this.execute(command);
    } else if (this.healthCheck) {
         // NB: see above comment re: 'close' event
        this._connection.on('close', this._boundConnectionError);

        this._boundResponseReceived = this._receiveHealthCheck.bind(this);
        this.on('responseReceived', this._boundResponseReceived);

        this._connection.on('data', this._receiveData.bind(this));
        this.execute(this.healthCheck);
    } else {
        this._connection.on('close', this._connClosed.bind(this));
        this._connection.on('data', this._receiveData.bind(this));

        this._clearSocketTimeout();

        logger.debug('%s emit connected, no-auth', this.name);
        this._connectedEmitted = true;
        this.emit('connected', this);
    }
};

RiakConnection.prototype._connectionError = function(err) {
    this._emitAndClose('connectFailed', err);
};

RiakConnection.prototype._connectionTimeout = function(err) {
    if (!err) {
        err = 'timed out or other error trying to connect';
    }
    this._connectionError(err);
};

RiakConnection.prototype._socketError = function(err) {
    // This is only called if we have an error after a successful connection
    // log only because close will be called right after
    // https://nodejs.org/api/net.html#net_event_error
    if (err) {
        logger.error('%s _socketError:', this.name);
    }
};

RiakConnection.prototype._receiveHealthCheck = function(conn, command, code, decoded) {
    // NB: this function is similar to _responseReceived in RiakNode
    logger.debug('%s receive healthcheck response', this.name);

    this.inFlight = false;
    this.removeListener('responseReceived', this._boundResponseReceived);

    this._connection.removeListener('close', this._boundConnectionError);
    this._connection.on('close', this._connClosed.bind(this));
    this._clearSocketTimeout();

    var error = false;
    var msg = null;
    var expectedCode = command.getExpectedResponseCode();
    if (code === rpbErrorRespCode) {
        error = true;
        var errmsg = decoded.getErrmsg().toString('utf8');
        var errcode = decoded.getErrcode();
        msg = util.format("%s healthCheck command '%s' received RpbErrorResp (%d) %s",
            this.name, command.name, errcode, errmsg);
        command.onRiakError(decoded);
    } else if (code !== expectedCode) {
        error = true;
        msg = util.format("%s healthCheck command '%s' received incorrect response; expected %d, got %d",
            this.name, command.name, expectedCode, code);
        command.onError(msg);
    } else {
        command.onSuccess(decoded);
    }

    if (error) {
        logger.error(msg);
        this._connectionError(msg);
    } else {
        logger.debug('%s emit connected, healthcheck success', this.name);
        this._connectedEmitted = true;
        this.emit('connected', this);
    }
};

RiakConnection.prototype._receiveStartTls = function(data) {
    logger.debug('%s receive StartTls response', this.name);
    var expectedCode = rpb.getCodeFor('RpbStartTls');
    if (this._ensureExpectedResponse(data, 'RpbStartTls', expectedCode)) {
        var tls_secure_context = tls.createSecureContext(this.auth);
        var tls_socket_options = {
            isServer: false, // NB: required
            secureContext: tls_secure_context
        };

        this._connection = new tls.TLSSocket(this._connection, tls_socket_options);

        var auth_options = {
            user: this.auth.user,
            password: this.auth.password
        };

        // On data, move to next sequence in TLS negotiation
        this._connection.removeListener('data', this._boundReceiveStartTls);
        this._boundReceiveAuthResp = this._receiveAuthResp.bind(this);
        this._connection.on('data', this._boundReceiveAuthResp);

        // Execute AuthReq command
        this.inFlight = false;
        var command = new AuthReq(auth_options);
        this.execute(command);
    }
    // TODO failure case
};

RiakConnection.prototype._receiveAuthResp = function(data) {
    logger.debug('%s receive RpbAuthResp', this.name);
    var expectedCode = rpb.getCodeFor('RpbAuthResp');
    if (this._ensureExpectedResponse(data, 'RpbAuthResp', expectedCode)) {
        this._connection.removeListener('close', this._boundConnectionError);
        this._connection.on('close', this._connClosed.bind(this));

        this._connection.removeListener('data', this._boundReceiveAuthResp);
        this._connection.on('data', this._receiveData.bind(this));

        this._clearSocketTimeout();

        this.inFlight = false;
        logger.debug('%s emit connected, with-auth', this.name);
        this._connectedEmitted = true;
        this.emit('connected', this);
    }
    // TODO failure case
};

RiakConnection.prototype._receiveData = function(data) {
    var protobufArray = this._buildProtobufArray(data);
    for (var i = 0; i < protobufArray.length; i++) {
        this._clearSocketTimeout();
        this.emit('responseReceived', this,
            this.command, protobufArray[i].msgCode, protobufArray[i].protobuf);
    }
};

RiakConnection.prototype._ensureExpectedResponse = function(data, msgName, expectedCode) {
    var protobufArray = this._buildProtobufArray(data);
    var err;
    if (protobufArray.length === 0) {
        err = 'Expected ' + msgName + ' response message';
    } else {
        var resp = protobufArray[0];
        if (resp.msgCode === 0) {
            // We received an RpbErrorResp
            err = resp.protobuf.getErrmsg().toString('utf8');
        } else if (resp.msgCode !== expectedCode) {
            err = msgName + ' incorrect response code: ' + resp.msgCode;
        }
    }

    if (err) {
        // TODO: not really a connection error, but may prevent bugs
        // from affecting data?
        this._connectionError(err);
        return false;
    } else {
        return true;
    }
};

RiakConnection.prototype._buildProtobufArray = function(data) {
    // Create a new buffer to receive data if needed 
    if (this._buffer === null) {
        this._buffer = new ByteBuffer(this.initBufferSize);
    }

    this._buffer.append(data);
    this._buffer.flip();
    return this._getProtobufsFromBuffer();
};

RiakConnection.prototype._getProtobufsFromBuffer = function (protobufArray) {
    if (arguments.length === 0) {
        protobufArray = [];
    }

    if (this._buffer.remaining() >= 4) {
        this._buffer.mark();
        var messageLength = this._buffer.readUint32();

        // See if we have the complete message
        if (this._buffer.remaining() >= messageLength) {
            // We have a complete message from riak
            var slice = this._buffer.slice(undefined, this._buffer.offset + messageLength);
            var code = slice.readUint8();

            // Our fun API does some creative things like ... returning only 
            // a code, with 0 bytes following. In those cases we want to set 
            // decoded to null.
            var decoded = null;
            if (messageLength - 1 > 0) {
                var ResponseProto = rpb.getProtoFor(code);
                // GH issue #45
                // Must use 'true' as argument to force copy of data
                // otherwise, subsequent fetches will clobber data
                decoded = ResponseProto.decode(slice.toBuffer(true));
            } 

            protobufArray[protobufArray.length] = { msgCode : code, protobuf : decoded };
            // skip past message in buffer
            this._buffer.skip(messageLength);
            // recursively call this until we are out of messages
            return this._getProtobufsFromBuffer(protobufArray);
        } else {
            // rewind the offset 
            this._buffer.reset();
        }   
    }

    // ByteBuffer's 'flip()' effectively clears the buffer which we don't
    // want. We want to flip while preserving anything in the buffer and 
    // compact if necessary.

    var newOffset = this._buffer.remaining();
    // Compact if necessary
    if (newOffset > 0 && this._buffer.offset !== 0) {
        this._buffer.copyTo(this._buffer, 0);
    }
    this._buffer.offset = newOffset;
    this._buffer.limit = this._buffer.capacity();

    return protobufArray;
};

// TODO FUTURE: what does "had_error" really mean?
RiakConnection.prototype._connClosed = function(had_error) {
    this._emitAndClose('connectionClosed');
};

RiakConnection.prototype.close = function() {
    this.closed = true;
    this.removeAllListeners();
    this._buffer = null;
    if (this._connection) {
        this._connection.end();
        this._connection.removeAllListeners();
        this._connection.on('error', function (err) {
            if (err) {
                logger.error('%s error AFTER close:', this.name, err);
            }
        });
        this._connection = null;
    }
    var cmdname = 'unknown';
    if (this.command) {
        cmdname = this.command.name;
    }
    logger.debug('%s closed (in-flight: %s, command %s)',
        this.name, this.inFlight, cmdname);
};

RiakConnection.prototype.executeDone = function(command) {
    this.inFlight = false;
    this._resetBuffer();
};

// command includes user callback
RiakConnection.prototype.execute = function(command) {
    this.command = command;

    if (this.inFlight === true) {
        logger.error('%s attempted to run command "%s" on in-use connection',
            this.name, command.name);
        return false;
    }

    logger.debug('%s execute command:', this.name, command.name);
    this.inFlight = true;
    this.lastUsed = Date.now();
    // write PB to socket
    var message = command.getRiakMessage();

    /*
     * NB: only bind to 'timeout' if 'connected' event has been emitted.
     * Initial connection, health check and starting TLS bind 'timeout'
     * to a handler that will raise 'connectFailed' on timeout
     */
    if (this._connectedEmitted) {
        if (this._boundConnectionTimeout) {
            this._connection.removeListener('timeout', this._boundConnectionTimeout);
        }
        this._boundConnectionTimeout = this._connHandleTimeout.bind(this, command);
        this._connection.setTimeout(this.requestTimeout, this._boundConnectionTimeout);
    }

    /*
     * Use of cork()/uncork() suggested by Doug Luce
     * https://github.com/dougluce
     * https://github.com/basho/riak-nodejs-client/pull/56
     * https://github.com/basho/riak-nodejs-client/pull/57
     */
    if (this.cork) {
        this._connection.cork();
    }

    this._connection.write(message.header);

    if (message.protobuf) {
        this._connection.write(message.protobuf);
    }

    if (this.cork) {
        this._connection.uncork();
    }

    return true;
};

module.exports = RiakConnection;
