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

        it("small", function() {
            let ap = require("./helpers/x-mitre/bundle-small.json");
            sv.validate(ap);
        });

        it("enterprise matrix", function() {
            // let ap = require("./helpers/x-mitre/enterprise-attack-20200705.json");
            let ap = require("./helpers/x-mitre/bundle.json");
            sv.validate(ap);
        });

        it.only("mobile matrix", function() {
            let ap = require("./helpers/x-mitre/mobile-attack-20200705.json");
            sv.validate(ap);
        });

        it.skip("pre matrix", function() {
            let ap = require("./helpers/x-mitre/pre-attack-20200705.json");
            sv.validate(ap);
        });

        it("capec matrix", function() {
            let ap = require("./helpers/capec/stix-capec-20200705.json");
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

        it("throws on bad x_mitre_platforms");
        it("throws on bad x_mitre_aliases");
        it("throws on bad x_mitre_version");
        it("throws on bad x_mitre_contributors");
        it("throws on bad x_mitre_old_attack_id");
    });

    describe("intrusion-set", function() {
        let sv = new StixValidator({
            schema: "sdos/intrusion-set",
            mitre: true
        });

        it("validates", function() {
            let ap = require("./helpers/x-mitre/intrusion-set.json");
            sv.validate(ap);
        });

        it("throws on bad x_mitre_version");
        it("throws on bad x_mitre_contributors");
    });

    describe("course-of-action", function() {
        let sv = new StixValidator({
            schema: "sdos/course-of-action",
            mitre: true
        });

        it("validates", function() {
            let ap = require("./helpers/x-mitre/course-of-action.json");
            sv.validate(ap);
        });

        it("throws on bad x_mitre_version");
        it("throws on bad x_mitre_deprecated");
        it("throws on bad x_mitre_old_attack_id");
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

    describe("tool", function() {
        let sv = new StixValidator({
            schema: "sdos/tool",
            mitre: true
        });

        it("validates", function() {
            let ap = require("./helpers/x-mitre/tool.json");
            sv.validate(ap);
        });

        it("throws on bad x_mitre_platforms");
        it("throws on bad x_mitre_aliases");
        it("throws on bad x_mitre_version");
        it("throws on bad x_mitre_contributors");
    });

    describe("x-mitre-matrix", function() {
        let sv = new StixValidator({
            schema: "sdos/x-mitre-matrix",
            mitre: true
        });

        it("validates", function() {
            let ap = require("./helpers/x-mitre/x-mitre-matrix.json");
            sv.validate(ap);
        });

        it("throws on bad id");
        it("throws on bad name");
        it("throws on bad description");
        it("throws on bad tactic_refs");
        it("throws on missing tactic_refs");
    });

    describe("x-mitre-tactic", function() {
        let sv = new StixValidator({
            schema: "sdos/x-mitre-tactic",
            mitre: true
        });

        it("validates", function() {
            let ap = require("./helpers/x-mitre/x-mitre-tactic.json");
            sv.validate(ap);
        });

        it("throws on bad id");
        it("throws on bad name");
        it("throws on bad description");
        it("throws on bad x_mitre_shortname");
        it("throws on missing x_mitre_shortname");
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
            }, Error, "Missing required property 'id' in Object {\"x_mitre_permissions_required\":[\"User\"],\"x_mitre_data_sources\":[\"OAuth audit logs\",\"Office 365 ... }. Relevant JSON schema is: 'http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.0/schemas/common/core.json");
        });

        it("throws on bad id (bad guid)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-id.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "Property '.id' must be a string of numbers, letters and hyphens followed by a UUID like \"attack-pattern--fdda765f-fc57-5604-a269-52a7df8164ec\", value is: \"attack-pattern--27960489-4e7f-461d-a62a-f5c0cb521e4\". Relevant JSON schema is: 'http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.0/schemas/common/identifier.json'");
            // }, Error, "data.id should match pattern \"^[a-z0-9][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$");
        });

        it("throws on bad id (attack-patern)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-id-2.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "Property '.id' must match RegExp pattern '^attack-pattern--', value is: \"attack-patern--27960489-4e7f-461d-a62a-f5c0cb521e4a\". Relevant JSON schema is: '#/allOf/1/properties/id/pattern'");
        });

        it("throws on bad type", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-type.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "Property '.type' must be a string of numbers, letters and hyphens like \"attack-pattern\" or \"identity\", value is: \"as;ldkjfa;lskdjf\". Relevant JSON schema is: '#/properties/type/pattern");
        });

        it("throws on bad permissions_required (not array)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-permissions-required.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "Property '.x_mitre_permissions_required' must be a array but got the value: {\"foo\":\"bar\"}. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_permissions_required.json'");
        });

        it("throws on bad permissions_required (not in enum)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-permissions-required-2.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "Property '.x_mitre_permissions_required[0]' must be one of the values: \"User, Administrator, SYSTEM, root, Remote Desktop Users\" but got the value: \"admin\". Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_permissions_required.json/items/enum'");
        });

        it("throws on bad data_sources (not array)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-data-sources.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "Property '.x_mitre_data_sources' must be a array but got the value: true. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_data_sources.json'");
        });

        it("throws on bad data_sources (bad type in array)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-data-sources-2.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "Property '.x_mitre_data_sources[3]' must be a string but got the value: 3. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_data_sources.json/items/type'");
        });

        it("throws on bad platforms (not array)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-platforms.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "Property '.x_mitre_platforms' must be a array but got the value: 3. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_platforms.json'");
        });

        it("throws on bad platforms (bad enum)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-platforms-2.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "Property '.x_mitre_platforms[1]' must be one of the values: \"Linux, macOS, Windows, SaaS, Office 365, Azure AD, Azure, AWS, GCP, Android, iOS\" but got the value: \"Bob\". Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_platforms.json/items/enum'");
        });

        it("throws on bad version", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-version.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "Property '.x_mitre_version' must be a string but got the value: 1.1. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_version.json'");
        });

        it("throws on bad detection", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-detection.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "Property '.x_mitre_detection' must be a string but got the value: [1,2,3]. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_detection.json'");
        });

        it("throws on bad contributors (not array)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-contributors.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "Property '.x_mitre_contributors' must be a array but got the value: \"hi there\". Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_contributors.json'");
        });

        it("throws on bad contributors (bad type in array)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-contributors-2.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "Property '.x_mitre_contributors[2]' must be a string but got the value: true. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_contributors.json/items/type'");
        });

        it("throws on bad x_mitre_defense_bypassed (not array)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-defense-bypassed.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "Property '.x_mitre_defense_bypassed' must be a array but got the value: \"bob\". Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_defense_bypassed.json'");
        });

        it("throws on bad x_mitre_defense_bypassed (bad type in array)", function() {
            let ap = require("./helpers/x-mitre/attack-pattern-bad-defense-bypassed-2.json");
            assert.throws(function() {
                sv.validate(ap);
            }, Error, "Property '.x_mitre_defense_bypassed[2]' must be a string but got the value: {\"foo\":\"bar\"}. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_defense_bypassed.json/items/type'");
        });

        it("throws on bad x_mitre_effective_permissions");
        it("throws on bad x_mitre_remote_support");
        it("throws on bad x_mitre_network_requirements");
        it("throws on bad x_mitre_system_requirements");
        it("throws on bad x_mitre_impact_type");
    });
});