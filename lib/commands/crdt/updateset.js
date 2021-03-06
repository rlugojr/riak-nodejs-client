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

var UpdateSetBase = require('./updatesetbase');
var inherits = require('util').inherits;
var Joi = require('joi');
var ByteBuffer = require('bytebuffer');

var utils = require('../../utils');
var rpb = require('../../protobuf/riakprotobuf');
var DtOp = rpb.getProtoFor('DtOp');
var SetOp = rpb.getProtoFor('SetOp');

/**
 * Provides the Update Set class, its builder, and its response.
 * @module CRDT
 */

/**
 * Command used tp update a set in Riak
 *
 * As a convenience, a builder class is provided:
 *
 *        var update = new UpdateSet.Builder()
 *               .withBucketType('sets')
 *               .withBucket('myBucket')
 *               .withKey('set_1')
 *               .withAdditions(['this', 'that', 'other'])
 *               .withCallback(callback)
 *               .build();
 *
 * See {{#crossLink "UpdateSet.Builder"}}UpdateSet.Builder{{/crossLink}}
 * @class UpdateSet
 * @constructor
 * @param {String[]|Buffer[]} [options.additions] The values to be added to the set.
 * @param {String[]|Buffer[]} [options.removals] The values to remove from the set. Note that a context is required.
 * @extends UpdateSetBase
 */
function UpdateSet(options, callback) {
    var set_opts = {
        additions: options.additions,
        removals: options.removals
    };
    delete options.additions;
    delete options.removals;

    UpdateSetBase.call(this, options, callback);

    var self = this;
    Joi.validate(set_opts, schema, function(err, opts) {
        if (err) {
            throw err;
        }
        self.additions = opts.additions;
        self.removals = opts.removals;
    });
}

inherits(UpdateSet, UpdateSetBase);

UpdateSet.prototype.constructDtOp = function() {
    var dt_op = new DtOp();
    var setOp = new SetOp();
    dt_op.setSetOp(setOp);
    setOp.adds = UpdateSetBase.buflist(this.additions);
    setOp.removes = UpdateSetBase.buflist(this.removals);
    return dt_op;
};

UpdateSet.prototype.getUpdateRespValues = function(dtUpdateResp) {
    return dtUpdateResp.set_value;
};

var schema = Joi.object().keys({
    additions: Joi.array().default([]).optional(),
    removals: Joi.array().default([]).optional()
});

/**
 * A builder for constructing UpdateSet instances.
 *
 * Rather than having to manually construct the __options__ and instantiating
 * a UpdateSet directly, this builder may be used.
 *
 *     var update = new UpdateSet.Builder()
 *                       .withBucketType('myBucketType')
 *                       .withBucket('myBucket')
 *                       .withKey('myKey')
 *                       .withAdditions(['this', 'that', 'other'])
 *                       .withCallback(myCallback)
 *                       .build();
 *
 * @class UpdateSet.Builder
 * @extends UpdateSetBase.Builder
 */
function Builder() {
    UpdateSetBase.Builder.call(this);
}

inherits(Builder, UpdateSetBase.Builder);

/**
 * Construct an UpdateSet instance.
 * @method build
 * @return {UpdateSet}
 */
Builder.prototype.build = function() {
    var cb = this.callback;
    delete this.callback;
    return new UpdateSet(this, cb);
};

/**
 * The values you wish to add to this set.
 * @method withAdditions
 * @param {String[]|Buffer[]} additions The values to add.
 * @chainable
 */
utils.bb(Builder, 'additions');

/**
 * The values you wish to remove from this set.
 * __Note:__ when performing removals a context must be provided.
 * @method withRemovals
 * @param {String[]|Buffer[]} removals The values to remove.
 * @chainable
 */
utils.bb(Builder, 'removals');

module.exports = UpdateSet;
module.exports.Builder = Builder;
