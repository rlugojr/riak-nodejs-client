/**
 *
 * Copyright 2014-present Basho Technologies, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

var CommandBase = require('../commands/commandbase');
var inherits = require('util').inherits;
var Joi = require('joi');
var logger = require('winston');

/**
 * @module Core
 */

/**
 * Provides the StartTls command used to start a TLS session with Riak.
 * @class StartTls
 * @constructor
 * @param {Function} callback the function to call when the command completes or errors
 * @extends CommandBase
 */
function StartTls() {
    CommandBase.call(this, 'RpbStartTls', 'RpbStartTls', function () {
        logger.debug('[StartTls] callback');
    });
}

inherits(StartTls, CommandBase);

StartTls.prototype.constructPbRequest = function() {
    /*
     * NB: since this is just a message code there is nothing to return
     */
    return;
};

StartTls.prototype.onSuccess = function(rpbStartTlsResp) {
    this._callback(null, true);
    return true;
};

module.exports = StartTls;
