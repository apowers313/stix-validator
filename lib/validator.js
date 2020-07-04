var Ajv = require("ajv");
const applyFormats = require("ajv-formats-draft2019");
const applyMergePatch = require("ajv-merge-patch");

var walk = require("walk");
var path = require("path");

const stixSchemaPath = path.join(__dirname,"../cti-stix2-json-schemas/schemas");
const mitreSchemaPath = path.join(__dirname,"../x-mitre-schemas");

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

        // TODO: options:
        //   stix version

        this.opts = opts;

        // TODO: build schema
        this.getSchemaJson();

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
        if(!valid) throw new Error("Invalid schema");
        this.ajvValidate = this.ajv.compile(this.schemaJson);
    }

    validate(data) {
        let valid = this.ajvValidate(data);
        if (!valid) {
            // console.log("messages", this.ajvValidate.messages);
            // console.log("errorsText", this.ajv.errorsText(this.ajvValidate.errors));

            // XXX: $merge and $patch always create errors, so remove them from the error list
            // https://github.com/ajv-validator/ajv-merge-patch/issues/8
            let errorList = this.ajvValidate.errors.filter(e => e.keyword != "$merge").filter(e => e.keyword != "$patch");
            // console.log("error list", errorList);
            throw new Error(this.ajv.errorsText(errorList));
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

        this.schemaJson = ap;

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
}

module.exports = StixValidator;