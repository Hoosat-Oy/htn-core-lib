"use strict";

var should = require("chai").should();
var hoosatcore = require("../");

describe("#versionGuard", function () {
  it("global._hoosatcoreLibVersion should be defined", function () {
    should.equal(global._hoosatcoreLibVersion, hoosatcore.version);
  });

  it("throw an error if version is already defined", function () {
    (function () {
      hoosatcore.versionGuard("version");
    }).should.throw("More than one instance of bitcore");
  });
});
