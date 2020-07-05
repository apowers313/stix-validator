var assert = require("chai").assert;
const StixValidator = require("../lib/validator");

describe("validator", function() {
    it("is function", function() {
        assert.isFunction(StixValidator);
    });

    it("is constructable", function() {
        new StixValidator();
    });

    describe("identifies bad files", function() {
        let sv = new StixValidator();

        it("empty file");

        it("empty json throws", function() {
            let ap = require("./helpers/empty.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "Missing required property 'type' in Object {}. Relevant JSON schema is: 'http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.0/schemas/common/bundle.json'");
        });

        it("bad json");
    });
});