// Use strict
"use strict";

// Check if using React Native
if(typeof navigator !== "undefined" && navigator["product"] === "ReactNative") {

	// Throw error
	throw "Crypto not supported on platform";
}

// Set global crypto
global["crypto"] = require("crypto");

// Exports
module["exports"] = require("bindings")("secp256k1_zkp.node");
