const deepmerge = require("deepmerge");
const clone = require("clone");
const path = require("path");
const assert = require("chai").assert;

const StixValidator = require("../../lib/validator");
const StixValidationError = require("../../lib/validator").StixValidationError;

module.exports = function(config, mod, errStr) {
    // load schema
    let helperFile = configToHelper(config);
    let data = clone (require (path.join(__dirname, helperFile)));

    // modify schema
    if (typeof mod === "object" && mod !== null) {
        // console.log("modifying schema via deepmerge");
        data = deepmerge(data, mod);
    } else if (typeof mod === "function") {
        // console.log("modifying schema via function");
        data = mod(data);
    } else if (mod !== undefined && mod !== null) {
        throw new TypeError ("expected mod to be function, object, or null / undefined. Got: " + mod);
    }
    // console.log("schema", schema);

    // setup validator
    let validator = new StixValidator(config);

    // run validator, expect a thrown StixValidationError if errStr exists
    if (errStr) {
        assert.throws(function() {
            validator.validate(data);
        }, StixValidationError, errStr);
    } else {
        validator.validate(data);
    }
};

function configToHelper(config) {
    let schema = config.schema || "common/bundle";
    let type = schema.split("/")[1];
    let prefix = config.mitre?"x-mitre":"stix";

    return path.join(prefix,type);
}