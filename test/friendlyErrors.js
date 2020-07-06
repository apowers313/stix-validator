var assert = require("chai").assert;
const StixValidator = require("../lib/validator");
const StixValidationError = StixValidator.StixValidationError;

describe("friendly errors", function() {
    // https://www.npmjs.com/package/ajv#validation-errors

    it("maxItems", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "type": "array",
                        "maxItems": 3
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": [1,2,3,4,5,6]
            });
        }, StixValidationError, "Array at path '.foo' must have fewer than 3 items but had 6: [1,2,3,4,5,6]. Relevant JSON schema is: '#/properties/foo/maxItems");
    });

    it("minItems", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "type": "array",
                        "minItems": 8
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": [1,2,3,4,5,6]
            });
        }, StixValidationError, "Array at path '.foo' must have at least 8 items but had 6: [1,2,3,4,5,6]. Relevant JSON schema is: '#/properties/foo/minItems");
    });

    it("maxLength", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "type": "string",
                        "maxLength": 10
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": "supercalifragilisticexpialidocious"
            });
        }, StixValidationError, "String at path '.foo' must have fewer than 10 characters but had 34: \"supercalifragilisticexpialidocious\". Relevant JSON schema is: '#/properties/foo/maxLength");
    });

    it("minLength", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "type": "string",
                        "minLength": 10
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": "hi"
            });
        }, StixValidationError, "String at path '.foo' must have at least 10 characters but had 2: \"hi\". Relevant JSON schema is: '#/properties/foo/minLength");
    });

    it("maxProperties", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "type": "object",
                        "maxProperties": 3
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": {
                    "one": 1,
                    "two": 2,
                    "three": 3,
                    "four": 4,
                    "five": 5
                }
            });
        }, StixValidationError, "Object at path '.foo' must have fewer than 3 properties but had 5: {\"one\":1,\"two\":2,\"three\":3,\"four\":4,\"five\":5}. Relevant JSON schema is: '#/properties/foo/maxProperties");
    });

    it("minProperties", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "type": "object",
                        "minProperties": 10
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": {
                    "one": 1,
                    "two": 2,
                    "three": 3,
                    "four": 4,
                    "five": 5
                }
            });
        }, StixValidationError, "Object at path '.foo' must have at least 10 properties but had 5: {\"one\":1,\"two\":2,\"three\":3,\"four\":4,\"five\":5}. Relevant JSON schema is: '#/properties/foo/minProperties");
    });

    it("additionalItems", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "type": "array",
                        "items": [
                            {
                                "type": "number"
                            },
                            {
                                "type": "string"
                            }
                        ],
                        additionalItems: false
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": [1, "two", "three"]
            });
        }, StixValidationError, "Array at path '.foo' had extra item \"three\". Relevant JSON schema is: '#/properties/foo/additionalItems");
    });

    it("additionalProperties", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "number":      { "type": "number" },
                    "street_name": { "type": "string" },
                    "street_type": { "type": "string",
                        "enum": ["Street", "Avenue", "Boulevard"]
                    }
                },
                "additionalProperties": false
            }
        });

        assert.throws(function() {
            sv.validate({
                "number": 1600,
                "street_name":
                "Pennsylvania",
                "street_type": "Avenue",
                "direction": "NW"
            });
        }, StixValidationError, "Property 'direction' is not allowed in Object {\"number\":1600,\"street_name\":\"Pennsylvania\",\"street_type\":\"Avenue\",\"direction\":\"NW\"}. Relevant JSON schema is: '#/additionalProperties");
    });

    it("object (dependencies)", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "credit_card": { "type": "number" },
                    "billing_address": { "type": "string" }
                },
                "dependencies": {
                    "credit_card": ["billing_address"]
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "name": "John Doe",
                "credit_card": 5555555555555555
            });
        }, StixValidationError, "Property 'credit_card' requires that property 'billing_address' also be present in Object {\"name\":\"John Doe\",\"credit_card\":5555555555555555}. Relevant JSON schema is: '#/dependencies");
    });

    it("string (format)", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "type": "string",
                        "format": "email"
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": "hi"
            });
        }, StixValidationError, "String at path '.foo' must be RFC5322 compliant email address like \"bob@gmail.com\", value is: \"hi\". Relevant JSON schema is: '#/properties/foo/format");
    });

    it("number (maximum)", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "type": "number",
                        "maximum": 12
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": 13
            });
        }, StixValidationError, "Number at path '.foo' must be <= 12, value is: 13. Relevant JSON schema is: '#/properties/foo/maximum");
    });

    it("number (minimum)", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "type": "number",
                        "minimum": 12
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": 11
            });
        }, StixValidationError, "Number at path '.foo' must be >= 12, value is: 11. Relevant JSON schema is: '#/properties/foo/minimum");
    });

    it("number (exclusiveMaximum)", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "type": "number",
                        "exclusiveMaximum": 12
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": 12
            });
        }, StixValidationError, "Number at path '.foo' must be < 12, value is: 12. Relevant JSON schema is: '#/properties/foo/exclusiveMaximum");
    });

    it("number (exclusiveMinimum)", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "type": "number",
                        "exclusiveMinimum": 12
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": 12
            });
        }, StixValidationError, "Number at path '.foo' must be > 12, value is: 12. Relevant JSON schema is: '#/properties/foo/exclusiveMinimum");
    });

    it("number (multipleOf)", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "type": "number",
                        "multipleOf": 2
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": 13
            });
        }, StixValidationError, "Number at path '.foo' must be multiple of 2, value is: 13. Relevant JSON schema is: '#/properties/foo/multipleOf");
    });

    describe("pattern", function() {
        describe("common", function() {
            it("core (type)", function() {
                // type: "^\\-?[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\\-?$"
                let sv = new StixValidator({
                    schemaJson: {
                        "type": "object",
                        "properties": {
                            "foo": {
                                "type": "string",
                                "pattern": "^\\-?[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\\-?$"
                            }
                        }
                    }
                });

                assert.throws(function() {
                    sv.validate({
                        "foo": "bad_type"
                    });
                }, StixValidationError, "Property '.foo' must be a string of numbers, letters and hyphens like \"attack-pattern\" or \"identity\", value is: \"bad_type\". Relevant JSON schema is: '#/properties/foo/pattern'");
            });

            // timestamp_millis: "T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$"
            it("core (timestamp_millis)", function() {
                // type: "^\\-?[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\\-?$"
                let sv = new StixValidator({
                    schemaJson: {
                        "type": "object",
                        "properties": {
                            "foo": {
                                "allOf": [
                                    {
                                        "type": "string",
                                        "pattern": "^[0-9]{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\\.[0-9]+)?Z$"
                                    },
                                    {
                                        "pattern": "T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$"
                                    }
                                ]
                            }
                        }
                    }
                });

                assert.throws(function() {
                    sv.validate({
                        "foo": "2019-10-12T07:20:50.52Z"
                    });
                }, StixValidationError, "Property '.foo' must be a RFC3339 timestamp that includes milliseconds \"2019-10-12T07:20:50.520Z\", value is: \"2019-10-12T07:20:50.52Z\". Relevant JSON schema is: '#/properties/foo/allOf/1/pattern'");
            });

            it("external-reference");
            // cve, capec, or URL
            it("hashes-type");
            it("url-regex");

            it("granular-marking");

            it("identifier", function() {
                // type: "^\\-?[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\\-?$"
                let sv = new StixValidator({
                    schemaJson: {
                        "type": "object",
                        "properties": {
                            "foo": {
                                "type": "string",
                                "pattern": "^[a-z0-9][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
                            }
                        }
                    }
                });

                assert.throws(function() {
                    sv.validate({
                        "foo": "relationship-59261bc8-0220-4e37-8018-7a3618a5dd1b"
                    });
                }, StixValidationError, "Property '.foo' must be a string of numbers, letters and hyphens followed by a UUID like \"attack-pattern--fdda765f-fc57-5604-a269-52a7df8164ec\", value is: \"relationship-59261bc8-0220-4e37-8018-7a3618a5dd1b\". Relevant JSON schema is: '#/properties/foo/pattern'");
            });

            it("timestamp", function() {
                // type: "^\\-?[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\\-?$"
                let sv = new StixValidator({
                    schemaJson: {
                        "type": "object",
                        "properties": {
                            "foo": {
                                "type": "string",
                                "pattern": "^[0-9]{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\\.[0-9]+)?Z$"
                            }
                        }
                    }
                });

                assert.throws(function() {
                    sv.validate({
                        "foo": "2019-10-12T07:20:Z"
                    });
                }, StixValidationError, "Property '.foo' must be a RFC3339 timestamp like \"2019-10-12T07:20:50.52Z\", value is: \"2019-10-12T07:20:Z\". Relevant JSON schema is: '#/properties/foo/pattern'");
            });

            it("bundle");
            it("kill-chain-phase");

            // it("binary");
            // it("cyber-observable-core");
            // it("dictionary");
            // it("hex");
            // it("marking-definition");
        });

        describe("sdos", function() {
            it("attack-pattern");
            // id: "^attack-pattern--"
            it("campaign");
            // id: "^campaign--"
            it("course-of-action");
            it("identity");
            it("indicator");
            it("intrusion-set");
            it("malware");
            it("threat-actor");
            it("tool");
        });

        describe("sros", function() {
            it("relationship");
            // id: "^relationship--"
            // relationship_type: "^[a-z0-9\\-]+$"
            // source_ref
            // target_ref
        });

        describe("observeables", function() {
            it("observed-data");
            // id: "^observed-data--"
            // objects: $ref cyber-observable-core
            it("report");
            // id: "^report--"
            it("vulnerability");
            // id: "^vulnerability--"
            it("sighting");
            // id: "^sighting--"

            it("artifact");
            it("autonomous-system");
            it("directory");
            it("domain-name");
            it("email-addr");
            it("email-message");
            it("file");
            it("ipv4-addr");
            it("ipv6-addr");
            it("mac-addr");
            it("mutex");
            it("network-traffic");
            it("process");
            it("software");
            it("url");
            it("user-account");
            it("windows-registry-key");
            it("x509-certificate");
        });
    });

    it("required", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "name":      { "type": "string" },
                    "email":     { "type": "string" },
                    "address":   { "type": "string" },
                    "telephone": { "type": "string" }
                },
                "required": ["name", "email"]
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": "test"
            });
        }, StixValidationError, "Missing required property 'name' in Object {\"foo\":\"test\"}. Relevant JSON schema is: '#/required");
    });

    it("propertyNames", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "propertyNames": {
                    "pattern": "^[A-Za-z_][A-Za-z0-9_]*$"
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "001 invalid": "test"
            });
        }, StixValidationError, "Property '001 invalid' is invalid in Object {\"001 invalid\":\"test\"}. Relevant JSON schema is: '#/propertyNames");
    });

    it("patternRequired");

    it("type (string)", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "type": "string"
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": null
            });
        }, StixValidationError, "Property '.foo' must be a string but got the value: null. Relevant JSON schema is: '#/properties/foo/type'");
    });

    it("type (integer)", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "type": "integer"
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": 3.14159
            });
        }, StixValidationError, "Property '.foo' must be a integer but got the value: 3.14159. Relevant JSON schema is: '#/properties/foo/type'");
    });

    it("type (number)", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "type": "number"
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": {
                    "bar": "baz"
                }
            });
        }, StixValidationError, "Property '.foo' must be a number but got the value: {\"bar\":\"baz\"}. Relevant JSON schema is: '#/properties/foo/type'");
    });

    it("type (object)", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "type": "object"
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": "test"
            });
        }, StixValidationError, "Property '.foo' must be a object but got the value: \"test\". Relevant JSON schema is: '#/properties/foo/type'");
    });

    it("type (array)", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "type": "array"
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": {
                    "bar": "baz"
                }
            });
        }, StixValidationError, "Property '.foo' must be a array but got the value: {\"bar\":\"baz\"}. Relevant JSON schema is: '#/properties/foo/type'");
    });

    it("type (boolean)", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "type": "boolean"
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": 0
            });
        }, StixValidationError, "Property '.foo' must be a boolean but got the value: 0. Relevant JSON schema is: '#/properties/foo/type'");
    });

    it("type (null)", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "type": "null"
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": 0
            });
        }, StixValidationError, "Property '.foo' must be a null but got the value: 0. Relevant JSON schema is: '#/properties/foo/type'");
    });

    it("uniqueItems", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "type": "array",
                        "uniqueItems": true
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": [1,2,3,1]
            });
        }, StixValidationError, "Array at path '.foo' must not have any duplicate values. Items #0 and #3 have the same value: 1. Relevant JSON schema is: '#/properties/foo/uniqueItems");
    });

    it("const", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "const": 1.4142135
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": "bob"
            });
        }, StixValidationError, "Property '.foo' must be the value: 1.4142135 but got the value: \"bob\". Relevant JSON schema is: '#/properties/foo/const'");
    });

    it("enum", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "foo": {
                        "enum": ["red", "amber", "green"]
                    }
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": "orange"
            });
        }, StixValidationError, "Property '.foo' must be one of the values: \"red, amber, green\" but got the value: \"orange\". Relevant JSON schema is: '#/properties/foo/enum'");
    });

    // bad $ref will fail during schema validation
    it.skip("$ref", function() {
        let sv = new StixValidator({
            schemaJson: {
                "type": "object",
                "properties": {
                    "$ref": "https://foo.com/bar.json"
                }
            }
        });

        assert.throws(function() {
            sv.validate({
                "foo": "orange"
            });
        }, StixValidationError, "Property '.foo' must be one of the values: \"red, amber, green\" but got the value: \"orange\". Relevant JSON schema is: '#/properties/foo/enum'");
    });

    it("oneOf");
    it("anyOf");
    it("not");
});