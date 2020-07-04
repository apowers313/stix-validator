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
            }, Error, "data should have required property 'type'");
        });

        it("bad json");
    });
});