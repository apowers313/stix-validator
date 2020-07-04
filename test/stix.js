var assert = require("chai").assert;
const StixValidator = require("../lib/validator");

describe("stix", function() {
    describe("attack-pattern", function() {
        let sv = new StixValidator({
            schema: "sdos/attack-pattern"
        });

        it("validates", function() {
            let ap = require("./helpers/stix/attack-pattern.json");
            sv.validate(ap);
        });

        it("bad id", function() {
            let ap = require("./helpers/stix/attack-pattern-bad-id.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "data.id should match pattern \"");
        });

        it("missing id", function() {
            let ap = require("./helpers/stix/attack-pattern-missing-id.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "data should have required property 'id'");
        });

        // only required for STIX 2.1
        // it.skip("missing spec veresion", function() {
        //     let ap = require("./helpers/stix/attack-pattern-missing-spec-version.json");
        //     assert.throws(function() {
        //         sv.validate(ap);
        //     }, Error, "data should have required property 'spec_version'");
        // });
    });
});