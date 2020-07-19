var assert = require("chai").assert;
const StixValidationError = require("../lib/validator").StixValidationError;

describe("StixValidationError", function() {
    it("is Function", function() {
        assert.isFunction(StixValidationError);
    });

    it("instanceof Error", function() {
        let e = new StixValidationError();
        assert.instanceOf(e, Error);
    });

    it.skip("works without 'new'", function() {
        let e = StixValidationError();
        assert.instanceOf(e, Error);
    });

    it("has static validator", function() {
        let e = new StixValidationError();

        assert.isTrue(StixValidationError.isStixValidationError(e));
        assert.isFalse(StixValidationError.isStixValidationError({}));
    });

    it("has correct name", function() {
        let e = new StixValidationError();

        assert.strictEqual(e.name, "StixValidationError");
    });

    it("has default message", function() {
        let e = new StixValidationError();

        assert.strictEqual(e.message, "<< Unspecified STIX Validation Error >>");
    });

    it("accepts message", function() {
        let e = new StixValidationError("test message");

        assert.strictEqual(e.message, "test message");
    });

    it("sets details", function() {
        let err = {
            foo: "bar"
        };
        let e = new StixValidationError(err, "test");

        assert.strictEqual(e.message, "test");
        assert.deepEqual(e.details, err);
    });

    it("handles array of strings", function() {
        let e = new StixValidationError([
            "test 1",
            "test 2",
            "test 3"
        ]);

        let errMsg = "3 STIX Validation Errors:\n" +
            "\ttest 1\n" +
            "\ttest 2\n" +
            "\ttest 3\n";
        assert.strictEqual(e.message, errMsg);
    });

    it("handles array of StixValidationErrors", function() {
        let e = new StixValidationError([
            new StixValidationError("test 1"),
            new StixValidationError({testing: true}, "test 2"),
            new StixValidationError("test 3")
        ]);

        let errMsg = "3 STIX Validation Errors:\n" +
            "\ttest 1\n" +
            "\ttest 2\n" +
            "\ttest 3\n";
        assert.strictEqual(e.message, errMsg);
        assert.isArray(e.details);
        assert.strictEqual(e.details.length, 3);
        assert.isUndefined(e.details[0]);
        assert.deepEqual(e.details[1], {testing: true});
        assert.isUndefined(e.details[2]);
    });

    it("throws on mixed strings and StixValidationErrors", function() {
        assert.throws(function() {
            new StixValidationError([
                "test 1",
                new StixValidationError({testing: true}, "test 2"),
                "test 3"
            ]);
        }, TypeError, "StixValidationError: expected message array to be all strings or all StixValidationErrors");
    });

    it("throws when err is passed in with array of strings", function() {
        let err = {
            foo: "bar"
        };
        assert.throws(function() {
            new StixValidationError(err, [
                "test 1",
                "test 2",
                "test 3"
            ]);
        }, TypeError, "StixValidationError: can't pass in error with an array of messages");
    });

    it("throws when err is passed in with array of StixValidationErrors", function() {
        assert.throws(function() {
            let err = {
                foo: "bar"
            };
            new StixValidationError(err, [
                new StixValidationError("test 1"),
                new StixValidationError({testing: true}, "test 2"),
                new StixValidationError("test 3")
            ]);
        }, TypeError, "StixValidationError: can't pass in error with an array of messages");
    });
});