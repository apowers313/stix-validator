var Ajv = require("ajv");
const applyFormats = require("ajv-formats-draft2019");
const applyMergePatch = require("ajv-merge-patch");

var walk = require("walk");
var path = require("path");

const stixSchemaPath = path.join(__dirname,"../cti-stix2-json-schemas/schemas");
const mitreSchemaPath = path.join(__dirname,"../x-mitre-schemas");

class StixValidationError extends Error {
    constructor(...args) {
        super(...args);
        console.log("New StixValidationError!", ...args);
    }
}

class StixValidator {
    /**
     * Constructor for stix validator
     * @param  {Object} opts                Opitons for the StixValidator
     * @param  {Boolean} opts.schema        Schema to use for validation, e.g. "sros/attack-pattern"
     * @param  {Boolean} opts.throwOnError  Throw an Error on a validation error
     * @return {[type]}      [description]
     */
    constructor(opts = {}) {
        opts.schema = opts.schema || "common/bundle";
        opts.throwOnError = (opts.throwOnError===undefined)?true:opts.throwOnError;
        opts.mitre = (opts.mitre===true)?true:false;
        opts.allErrors = (opts.allErrors===true)?true:false;
        opts.stixVersion = (opts.stixVersion===undefined)?"2.0":opts.stixVersion;

        this.opts = opts;

        // XXX: uses other opts, do this last
        opts.schemaJson = opts.schemaJson || this.getSchemaJson();
        this.schemaJson = opts.schemaJson;

        // TODO: build schema

        this.ajv = new Ajv({
            allErrors: opts.allErrors,
            verbose: true,
            // logger: {
            //     log: console.log.bind(console),
            //     warn: console.log.bind(console),
            //     error: console.log.bind(console),
            // }
        });
        applyFormats(this.ajv);
        applyMergePatch(this.ajv);

        // load schema files
        this.addSchemaDirectory(stixSchemaPath);
        if(opts.mitre) this.addSchemaDirectory(mitreSchemaPath);

        let valid = this.ajv.validateSchema(this.schemaJson);
        if(!valid) throw new Error("Error while validating schema");
        this.ajvValidate = this.ajv.compile(this.schemaJson);
    }

    validate(data) {
        let valid = this.ajvValidate(data);
        if (!valid) {
            // console.log("messages", this.ajvValidate.messages);
            // console.log("errorsText", this.ajv.errorsText(this.ajvValidate.errors));

            // XXX: $merge and $patch always create errors, so remove them from the error list
            // https://github.com/ajv-validator/ajv-merge-patch/issues/8
            this.errorList = this.ajvValidate.errors.filter(e => e.keyword != "$merge").filter(e => e.keyword != "$patch");
            this.toFriendlyErrors();
            // console.log("error list", this.errorList);
            // throw new Error(this.ajv.errorsText(this.errorList));
            throw new StixValidationError(this.errorList);
        }
        return valid;
    }

    getSchemaPath() {
        let schemaUri;
        let opts = this.opts;

        if (!opts.mitre) schemaUri = `../cti-stix2-json-schemas/schemas/${opts.schema}.json`;
        else schemaUri = `../x-mitre-schemas/${opts.schema}.json`;

        return schemaUri;
    }

    getSchemaJson() {
        let opts = this.opts;
        let ap;
        let err;
        let schemaPath;

        schemaPath = this.getSchemaPath();

        try {
            ap = require(schemaPath);
        } catch(e) {
            err = e;
        }

        if (err) {
            throw new Error(`Schema: '${opts.schema}' not found or couldn't be loaded: ${err.message}`);
        }

        // let ap = require("../cti-stix2-json-schemas/schemas/sdos/attack-pattern.json");
        return ap;
    }

    getSchemaUri() {
        if(typeof this.schemaJson !== "object") throw new Error ("bad schema JSON in getSchemaUri");

        return this.schemaJson.$id;
    }

    addSchemaDirectory(dir) {
        var options = {
            listeners: {
                file: foundFile,
                errors: walkError
            }
        };
        let ajv = this.ajv;

        walk.walkSync(dir, options);

        function foundFile (root, fileStats, next) {
            let file = fileStats.name;
            if (path.extname(file) !== ".json") {
                return next();
            }

            let fileDir = path.basename(root);
            let filePath = path.join(dir, fileDir, file);
            let schema = require(filePath);
            // console.log("Adding schema:", filePath);
            ajv.addSchema(schema);

            next();
        }

        function walkError(root, nodeStatsArray, next) {
            console.log("ERROR", nodeStatsArray);
            next();
        }

        // console.log ("done walking");
    }

    toFriendlyErrors() {
        this.errorList = this.errorList.map((e) => toFriendlyError(e)).filter((e) => e !== undefined);
    }
}

function toFriendlyError(err) {
    // console.log ("ERROR", err);

    let schemaMsg = toFriendlySchema(err);

    switch(err.keyword) {

    /*** TYPE ***/
    case "type":
        return `Property '${err.dataPath}' must be a ${err.schema} but got the value: ${toFriendlyDataType(err.data)}. ${schemaMsg}'`;
    case "const":
        return `Property '${err.dataPath}' must be the value: ${toFriendlyDataType(err.schema)} but got the value: ${toFriendlyDataType(err.data)}. ${schemaMsg}'`;
    case "enum":
        return `Property '${err.dataPath}' must be one of the values: "${err.schema.join(", ")}" but got the value: ${toFriendlyDataType(err.data)}. ${schemaMsg}'`;

    /*** OBJECT ***/
    case "maxProperties":
        return `Object at path '${err.dataPath}' must have fewer than ${err.schema} properties but had ${Object.keys(err.data).length}: ${toFriendlyDataType(err.data)}. ${schemaMsg}`;
    case "minProperties":
        return `Object at path '${err.dataPath}' must have at least ${err.schema} properties but had ${Object.keys(err.data).length}: ${toFriendlyDataType(err.data)}. ${schemaMsg}`;
    case "dependencies":
        return `Property '${err.params.property}' requires that property '${err.params.deps}' also be present in Object ${toFriendlyDataType(err.data)}. ${schemaMsg}`;
    case "required":
        return `Missing required property '${err.params.missingProperty}' in Object ${toFriendlyDataType(err.data)}. ${schemaMsg}`;
    case "propertyNames":
        return `Property '${err.params.propertyName}' is invalid in Object ${toFriendlyDataType(err.data)}. ${schemaMsg}`;
    case "additionalProperties":
        return `Property '${err.params.additionalProperty}' is not allowed in Object ${toFriendlyDataType(err.data)}. ${schemaMsg}`;

    /*** ARRAY ***/
    case "maxItems":
        return `Array at path '${err.dataPath}' must have fewer than ${err.schema} items but had ${err.data.length}: ${toFriendlyDataType(err.data)}. ${schemaMsg}`;
    case "minItems":
        return `Array at path '${err.dataPath}' must have at least ${err.schema} items but had ${err.data.length}: ${toFriendlyDataType(err.data)}. ${schemaMsg}`;
    case "uniqueItems":
        return `Array at path '${err.dataPath}' must not have any duplicate values. Items #${err.params.j} and #${err.params.i} have the same value: ${toFriendlyDataType(err.data[err.params.i])}. ${schemaMsg}`;
    case "additionalItems":
        return `Array at path '${err.dataPath}' had extra item ${toFriendlyDataType(err.data[err.params.limit])}. ${schemaMsg}`;

    /*** NUMBER ***/
    case "maximum":
    case "minimum":
    case "exclusiveMaximum":
    case "exclusiveMinimum":
        return `Number at path '${err.dataPath}' must be ${err.params.comparison} ${err.params.limit}, value is: ${err.data}. ${schemaMsg}`;
    case "multipleOf":
        return `Number at path '${err.dataPath}' must be multiple of ${err.params.multipleOf}, value is: ${err.data}. ${schemaMsg}`;

    /*** STRING ***/
    case "maxLength":
        return `String at path '${err.dataPath}' must have fewer than ${err.schema} characters but had ${err.data.length}: ${toFriendlyDataType(err.data)}. ${schemaMsg}`;
    case "minLength":
        return `String at path '${err.dataPath}' must have at least ${err.schema} characters but had ${err.data.length}: ${toFriendlyDataType(err.data)}. ${schemaMsg}`;
    case "format":
        return toFriendlyFormat(err);
    case "pattern":
        return toFriendlyPattern(err);

    // bad $ref will fail during schema validation
    // case "$ref":
    default:
        return `Unknown error type while trying to create human-readable error message in toFriendlyError: ${JSON.stringify(err)}`;
    }
}

var inclSchema = true;
function toFriendlySchema(err) {
    if (!inclSchema) return "";
    if (err.parentSchema && err.parentSchema.$id) return `Relevant JSON schema is: '${err.parentSchema.$id}'`;
    return `Relevant JSON schema is: '${err.schemaPath}'`;
}

function toFriendlyDataType(v) {
    let type = typeof v;
    if (type === "object") {
        if (Array.isArray(v)) type = "array";
        else if (v === null) type = "null";
    }

    switch(type) {
    case "string":
        return `"${v}"`;
    case "number":
        return `${v}`;
    case "boolean":
        return `${v}`;
    case "object":
        return toFriendlyObj(type, v);
    case "array":
        return toFriendlyObj(type, v);
    case "null":
        return "null";
    case "undefined":
        return "undefined";
    default:
        throw new Error ("Unknown type in toFriendlyDataType while creating STIX error message: " + type);
    }
}

function toFriendlyObj(type, v) {
    const maxObj = 100;
    let trailingCh;
    if(type === "object") trailingCh = "}";
    if(type === "array") trailingCh = ";";

    let objStr = JSON.stringify(v);
    if (objStr.length > maxObj) {
        // XXX: a little STIX hack, since the object ID is the most interesting part of hte object
        if (v.id !== undefined) objStr = `{ "id": "${v.id}", ... }`;
        else objStr = objStr.substring(0,maxObj-5) + " ... " + trailingCh;
    }
    return objStr;
}

function toFriendlyFormat(err) {
    let schemaMsg = toFriendlySchema(err);

    switch (err.schema) {
    case "date-time":
        return `String at path '${err.dataPath}' must be date-time format like "2018-11-13T20:20:39+00:00", value is: "${err.data}". ${schemaMsg}`;
    case "date":
        return `String at path '${err.dataPath}' must be date format like "20:20:39+00:00", value is: "${err.data}". ${schemaMsg}`;
    case "time":
        return `String at path '${err.dataPath}' must be time format like "2018-11-13", value is: "${err.data}". ${schemaMsg}`;
    case "email":
        return `String at path '${err.dataPath}' must be RFC5322 compliant email address like "bob@gmail.com", value is: "${err.data}". ${schemaMsg}`;
    case "idn-email":
        return `String at path '${err.dataPath}' must be RFC6531 compliant email address, value is: "${err.data}". ${schemaMsg}`;
    case "hostname":
        return `String at path '${err.dataPath}' must be RFC1034 compliant hostname, value is: "${err.data}". ${schemaMsg}`;
    case "idn-hostname":
        return `String at path '${err.dataPath}' must be RFC5890 compliant hostname, value is: "${err.data}". ${schemaMsg}`;
    case "ipv4":
        return `String at path '${err.dataPath}' must be RFC2673 compliant IPv4 address like "127.0.0.1", value is: "${err.data}". ${schemaMsg}`;
    case "ipv6":
        return `String at path '${err.dataPath}' must be RFC2373 compliant IPv6 address like "2001:0db8:85a3:0000:0000:8a2e:0370:7334", value is: "${err.data}". ${schemaMsg}`;
    case "uri":
        return `String at path '${err.dataPath}' must be RFC3986 compliant URI like "https://google.com", value is: "${err.data}". ${schemaMsg}`;
    case "uri-reference":
        return `String at path '${err.dataPath}' must be RFC3986 compliant URI reference like "../foo/bar", value is: "${err.data}". ${schemaMsg}`;
    case "iri":
        return `String at path '${err.dataPath}' must be RFC3987 compliant IRI like "https://google.com", value is: "${err.data}". ${schemaMsg}`;
    case "iri-reference":
        return `String at path '${err.dataPath}' must be RFC3987 compliant IRI reference like "../foo/bar", value is: "${err.data}". ${schemaMsg}`;
    default:
        return `String at path '${err.dataPath}' must be in format of ${err.params.format}, value is: "${err.data}". ${schemaMsg}`;
    }
}

function toFriendlyPattern(err) {
    let schemaMsg = toFriendlySchema(err);

    // a propertyName that doesn't match a pattern causes two errors, throw away the pattern error
    if(err.schemaPath.indexOf("/propertyNames/") !== -1) return;

    switch (err.schema) {
    // type from core.json
    case "^\\-?[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\\-?$":
        return `Property '${err.dataPath}' must be a string of numbers, letters and hyphens like "attack-pattern" or "identity", value is: "${err.data}". ${schemaMsg}`;
    // timestamp_millis from core.json
    case "T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$":
        return `Property '${err.dataPath}' must be a RFC3339 timestamp that includes milliseconds "2019-10-12T07:20:50.520Z", value is: "${err.data}". ${schemaMsg}'`;
    // identifier from identifier.json
    case "^[a-z0-9][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$":
        return `Property '${err.dataPath}' must be a string of numbers, letters and hyphens followed by a UUID like "attack-pattern--fdda765f-fc57-5604-a269-52a7df8164ec", value is: "${err.data}". ${schemaMsg}'`;
    // timestamp from timestamp.json
    case "^[0-9]{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\\.[0-9]+)?Z$":
        return `Property '${err.dataPath}' must be a RFC3339 timestamp like "2019-10-12T07:20:50.52Z", value is: "${err.data}". ${schemaMsg}'`;
    default:
        return `Property '${err.dataPath}' must match RegExp pattern '${err.params.pattern}', value is: "${err.data}". ${schemaMsg}'`;
    }
}

StixValidator.StixValidationError = StixValidationError;
module.exports = StixValidator;