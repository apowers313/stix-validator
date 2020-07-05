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
            }, Error, "Property '.id' must be a string of numbers, letters and hyphens followed by a UUID like \"attack-pattern--fdda765f-fc57-5604-a269-52a7df8164ec\", value is: \"attack-pattern--d7b066aa-4091-4276-a142-29d5d81c348\". Relevant JSON schema is: 'http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.0/schemas/common/identifier.json'");
        });

        it("missing id", function() {
            let ap = require("./helpers/stix/attack-pattern-missing-id.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "Missing required property 'id' in Object {\"type\":\"attack-pattern\",\"spec_version\":\"2.1\",\"created_by_ref\":\"identity--f690c992-8e7d-4b9a-93 ... }. Relevant JSON schema is: 'http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.0/schemas/common/core.json");
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