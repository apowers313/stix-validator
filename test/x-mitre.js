var assert = require("chai").assert;
const StixValidator = require("../lib/validator");
const testFixture = require("./helpers/fixture");

describe("mitre", function() {
    this.slow(200);

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

        it("mobile matrix", function() {
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
        const config = {
            schema: "sdos/attack-pattern",
            mitre: true
        };

        it("validates", function() {
            testFixture(config);
        });

        it("throws on missing id", function() {
            testFixture(
                config,
                (data) => { delete data.id; return data; },
                "Missing required property 'id' in Object {\"x_mitre_permissions_required\":[\"User\"],\"x_mitre_data_sources\":[\"OAuth audit logs\",\"Office 365 ... }. Relevant JSON schema is: 'http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.0/schemas/common/core.json"
            );
        });

        it("throws on bad id (bad guid)", function() {
            testFixture(
                config,
                { id: "attack-pattern--27960489-4e7f-461d-a62a-f5c0cb521e4" },
                "Property '.id' must be a string of numbers, letters and hyphens followed by a UUID like \"attack-pattern--fdda765f-fc57-5604-a269-52a7df8164ec\", value is: \"attack-pattern--27960489-4e7f-461d-a62a-f5c0cb521e4\". Relevant JSON schema is: 'http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.0/schemas/common/identifier.json'"
            );
        });

        it("throws on bad id (attack-patern)", function() {
            testFixture(
                config,
                { id: "attack-patern--27960489-4e7f-461d-a62a-f5c0cb521e4a" },
                "Property '.id' must match RegExp pattern '^attack-pattern--', value is: \"attack-patern--27960489-4e7f-461d-a62a-f5c0cb521e4a\". Relevant JSON schema is: '#/allOf/1/properties/id/pattern'"
            );
        });

        it("throws on bad type", function() {
            testFixture(
                config,
                { type: "as;ldkjfa;lskdjf" },
                "Property '.type' must be a string of numbers, letters and hyphens like \"attack-pattern\" or \"identity\", value is: \"as;ldkjfa;lskdjf\". Relevant JSON schema is: '#/properties/type/pattern"
            );
        });

        it("throws on bad permissions_required (not array)", function() {
            testFixture(
                config,
                { "x_mitre_permissions_required": {"foo": "bar"} },
                "Property '.x_mitre_permissions_required' must be a array but got the value: {\"foo\":\"bar\"}. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_permissions_required.json'"
            );
        });

        it("throws on bad permissions_required (not in enum)", function() {
            testFixture(
                config,
                { "x_mitre_permissions_required": ["admin"] },
                "Property '.x_mitre_permissions_required[1]' must be one of the values: \"User, Administrator, SYSTEM, root, Remote Desktop Users\" but got the value: \"admin\". Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_permissions_required.json/items/enum'"
            );
        });

        it("throws on bad data_sources (not array)", function() {
            testFixture(
                config,
                { "x_mitre_data_sources": true },
                "Property '.x_mitre_data_sources' must be a array but got the value: true. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_data_sources.json'"
            );
        });

        it("throws on bad data_sources (bad type in array)", function() {
            testFixture(
                config,
                { "x_mitre_data_sources": [ 3 ] },
                "Property '.x_mitre_data_sources[2]' must be a string but got the value: 3. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_data_sources.json/items/type'"
            );
        });

        it("throws on bad platforms (not array)", function() {
            testFixture(
                config,
                { "x_mitre_platforms": 3 },
                "Property '.x_mitre_platforms' must be a array but got the value: 3. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_platforms.json'"
            );
        });

        it("throws on bad platforms (bad enum)", function() {
            testFixture(
                config,
                { "x_mitre_platforms": [ "Bob" ] },
                "Property '.x_mitre_platforms[2]' must be one of the values: \"Linux, macOS, Windows, SaaS, Office 365, Azure AD, Azure, AWS, GCP, Android, iOS\" but got the value: \"Bob\". Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_platforms.json/items/enum'"
            );
        });

        it("throws on bad version", function() {
            testFixture(
                config,
                { "x_mitre_version": 1.1 },
                "Property '.x_mitre_version' must be a string but got the value: 1.1. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_version.json'"
            );
        });

        it("throws on bad detection", function() {
            testFixture(
                config,
                { "x_mitre_detection": [ 1, 2, 3 ] },
                "Property '.x_mitre_detection' must be a string but got the value: [1,2,3]. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_detection.json'"
            );
        });

        it("throws on bad contributors (not array)", function() {
            testFixture(
                config,
                { "x_mitre_contributors": "hi there" },
                "Property '.x_mitre_contributors' must be a array but got the value: \"hi there\". Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_contributors.json'"
            );
        });

        it("throws on bad contributors (bad type in array)", function() {
            testFixture(
                config,
                { "x_mitre_contributors": [ true ] },
                "Property '.x_mitre_contributors[4]' must be a string but got the value: true. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_contributors.json/items/type'"
            );
        });

        it("throws on bad x_mitre_defense_bypassed (not array)", function() {
            testFixture(
                config,
                { "x_mitre_defense_bypassed": "bob" },
                "Property '.x_mitre_defense_bypassed' must be a array but got the value: \"bob\". Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_defense_bypassed.json'"
            );
        });

        it("throws on bad x_mitre_defense_bypassed (bad type in array)", function() {
            testFixture(
                config,
                { "x_mitre_defense_bypassed": [ { "foo": "bar" } ] },
                "Property '.x_mitre_defense_bypassed[2]' must be a string but got the value: {\"foo\":\"bar\"}. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_defense_bypassed.json/items/type'"
            );
        });

        it("throws on bad x_mitre_effective_permissions (not array)", function() {
            testFixture(
                config,
                { "x_mitre_effective_permissions": 0 },
                "Property '.x_mitre_effective_permissions' must be a array but got the value: 0. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_effective_permissions.json'"
            );
        });

        it("throws on bad x_mitre_effective_permissions (not in enum)", function() {
            testFixture(
                config,
                { "x_mitre_effective_permissions": [ "foo" ] },
                "Property '.x_mitre_effective_permissions[1]' must be one of the values: \"SYSTEM, Administrator, User, root\" but got the value: \"foo\". Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_effective_permissions.json/items/enum'"
            );
        });

        it("throws on bad x_mitre_remote_support", function() {
            testFixture(
                config,
                { "x_mitre_remote_support": 1 },
                "Property '.x_mitre_remote_support' must be a boolean but got the value: 1. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_remote_support.json'"
            );
        });

        it("throws on bad x_mitre_network_requirements", function() {
            testFixture(
                config,
                { "x_mitre_network_requirements": 0 },
                "Property '.x_mitre_network_requirements' must be a boolean but got the value: 0. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_network_requirements.json'"
            );
        });

        it("throws on bad x_mitre_system_requirements (not array)", function() {
            testFixture(
                config,
                { "x_mitre_system_requirements": 0 },
                "Property '.x_mitre_system_requirements' must be a array but got the value: 0. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_system_requirements.json'"
            );
        });

        it("throws on bad x_mitre_system_requirements (bad array member)", function() {
            testFixture(
                config,
                { "x_mitre_system_requirements": [ 0 ] },
                "Property '.x_mitre_system_requirements[1]' must be a string but got the value: 0. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_system_requirements.json/items/type'"
            );
        });

        it("throws on bad x_mitre_impact_type (not array)", function() {
            testFixture(
                config,
                { "x_mitre_network_requirements": "foo" },
                "Property '.x_mitre_network_requirements' must be a boolean but got the value: \"foo\". Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_network_requirements.json'"
            );
        });

        it("throws on bad x_mitre_impact_type (bad array member)", function() {
            testFixture(
                config,
                { "x_mitre_network_requirements": [ { foo: "bar" } ] },
                "Property '.x_mitre_network_requirements' must be a boolean but got the value: [{\"foo\":\"bar\"}]. Relevant JSON schema is: 'https://schema.mitre.org/schemas/stix2.0/common/x_mitre_network_requirements.json'"
            );
        });

    });
});