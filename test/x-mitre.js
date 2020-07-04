var assert = require("chai").assert;
const StixValidator = require("../lib/validator");

describe("mitre", function() {
    describe("bundle", function() {
        let sv = new StixValidator({
            // schema: "common/bundle" // default schema
            mitre: true
        });

        it("correct schema path", function() {
            assert.strictEqual(sv.getSchemaPath(), "../x-mitre-schemas/common/bundle.json");
        });

        it("correct schema URI", function() {
            assert.strictEqual(sv.getSchemaUri(), "https://schema.mitre.org/schemas/stix2.0/common/bundle.json");
        });

        it.skip("minimal", function() {
            let ap = require("./helpers/x-mitre/bundle-too-small.json");
            sv.validate(ap);
        });

        it("enterprise matrix", function() {
            let ap = require("./helpers/x-mitre/bundle.json");
            sv.validate(ap);
        });
    });

    describe("malware", function() {
        let sv = new StixValidator({
            schema: "sdos/malware",
            mitre: true
        });

        it("validates", function() {
            let ap = require("./helpers/x-mitre/malware.json");
            sv.validate(ap);
        });
    });

    describe("relationship", function() {
        let sv = new StixValidator({
            schema: "sros/relationship",
            mitre: true
        });

        it("validates", function() {
            let ap = require("./helpers/x-mitre/relationship.json");
            sv.validate(ap);
        });
    });

    describe("attack-pattern", function() {
        let sv = new StixValidator({
            schema: "sdos/attack-pattern",
            mitre: true
        });

        it("validates", function() {
            let ap = require("./helpers/x-mitre/attack-pattern.json");
            sv.validate(ap);
        });

        it("throws on missing id", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-missing-id.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "data should have required property 'id'");
        });

        it("throws on bad id (bad guid)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-id.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "data.id should match pattern \"");
            // }, Error, "data.id should match pattern \"^[a-z0-9][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$");
        });

        it("throws on bad id (attack-patern)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-id-2.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "data.id should match pattern \"^attack-pattern--");
        });

        it("throws on bad type", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-type.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "data.type should match pattern \"");
        });

        it("throws on bad permissions_required (not array)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-permissions-required.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "data.x_mitre_permissions_required should be array");
        });

        it("throws on bad permissions_required (not in enum)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-permissions-required-2.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "data.x_mitre_permissions_required[0] should be equal to one of the allowed values");
        });

        it("throws on bad data_sources (not array)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-data-sources.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "data.x_mitre_data_sources should be array");
        });

        it("throws on bad data_sources (bad type in array)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-data-sources-2.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "data.x_mitre_data_sources[3] should be string");
        });

        it("throws on bad platforms (not array)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-platforms.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "data.x_mitre_platforms should be array");
        });

        it("throws on bad platforms (bad enum)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-platforms-2.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "data.x_mitre_platforms[1] should be equal to one of the allowed values");
        });

        it("throws on bad version", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-version.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "data.x_mitre_version should be string");
        });

        it("throws on bad detection", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-detection.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "data.x_mitre_detection should be string");
        });

        it("throws on bad contributors (not array)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-contributors.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "data.x_mitre_contributors should be array");
        });

        it("throws on bad contributors (bad type in array)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-contributors-2.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "data.x_mitre_contributors[2] should be string");
        });

        it("throws no bad defense_bypassed (not array)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-defense-bypassed.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "data.x_mitre_defense_bypassed should be array");
        });

        it("throws no bad defense_bypassed (bad type in array)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-defense-bypassed-2.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "data.x_mitre_defense_bypassed[2] should be string");
        });
    });
});