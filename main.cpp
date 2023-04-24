// Header files
#include <cstring>
#include <node_api.h>
#include <string>
#include <tuple>
#include <vector>

extern "C" {
	#include "secp256k1_bulletproofs.h"
}

using namespace std;


// Structures

// Instance data
struct InstanceData {

	// Context
	secp256k1_context *context;
	
	// Scratch space
	secp256k1_scratch_space *scratchSpace;
	
	// Generators
	secp256k1_bulletproof_generators *generators;
};


// Secp256k1-zkp namespace
namespace Secp256k1Zkp {

	// Header files
	#include "./Secp256k1-zkp-NPM-Package-master/main.cpp"
}


// Constants

// Operation failed
static napi_value OPERATION_FAILED;

// Max 64-bit integer string length
static const size_t MAX_64_BIT_INTEGER_STRING_LENGTH = sizeof("18446744073709551615");


// Function prototypes

// Get instance data
static InstanceData *getInstanceData(napi_env environment);

// Blind switch
static napi_value blindSwitch(napi_env environment, napi_callback_info arguments);

// Blind sum
static napi_value blindSum(napi_env environment, napi_callback_info arguments);

// Is valid secret key
static napi_value isValidSecretKey(napi_env environment, napi_callback_info arguments);

// Is valid public key
static napi_value isValidPublicKey(napi_env environment, napi_callback_info arguments);

// Is valid commit
static napi_value isValidCommit(napi_env environment, napi_callback_info arguments);

// Is valid single-signer signature
static napi_value isValidSingleSignerSignature(napi_env environment, napi_callback_info arguments);

// Create bulletproof
static napi_value createBulletproof(napi_env environment, napi_callback_info arguments);

// Create bulletproof blindless
static napi_value createBulletproofBlindless(napi_env environment, napi_callback_info arguments);

// Rewind bulletproof
static napi_value rewindBulletproof(napi_env environment, napi_callback_info arguments);

// Verify bulletproof
static napi_value verifyBulletproof(napi_env environment, napi_callback_info arguments);

// Public key from secret key
static napi_value publicKeyFromSecretKey(napi_env environment, napi_callback_info arguments);

// Public key from data
static napi_value publicKeyFromData(napi_env environment, napi_callback_info arguments);

// Uncompress public key
static napi_value uncompressPublicKey(napi_env environment, napi_callback_info arguments);

// Secret key tweak add
static napi_value secretKeyTweakAdd(napi_env environment, napi_callback_info arguments);

// Public key tweak add
static napi_value publicKeyTweakAdd(napi_env environment, napi_callback_info arguments);

// Secret key tweak multiply
static napi_value secretKeyTweakMultiply(napi_env environment, napi_callback_info arguments);

// Public key tweak multiply
static napi_value publicKeyTweakMultiply(napi_env environment, napi_callback_info arguments);

// Shared secret key from secret key and public key
static napi_value sharedSecretKeyFromSecretKeyAndPublicKey(napi_env environment, napi_callback_info arguments);

// Pedersen commit
static napi_value pedersenCommit(napi_env environment, napi_callback_info arguments);

// Pedersen commit sum
static napi_value pedersenCommitSum(napi_env environment, napi_callback_info arguments);

// Pedersen commit to public key
static napi_value pedersenCommitToPublicKey(napi_env environment, napi_callback_info arguments);

// Public key to Pedersen commit
static napi_value publicKeyToPedersenCommit(napi_env environment, napi_callback_info arguments);

// Create single-signer signature
static napi_value createSingleSignerSignature(napi_env environment, napi_callback_info arguments);

// Add single-signer signatures
static napi_value addSingleSignerSignatures(napi_env environment, napi_callback_info arguments);

// Verify single-signer signature
static napi_value verifySingleSignerSignature(napi_env environment, napi_callback_info arguments);

// Single-signer signature from data
static napi_value singleSignerSignatureFromData(napi_env environment, napi_callback_info arguments);

// Compact single-signer signature
static napi_value compactSingleSignerSignature(napi_env environment, napi_callback_info arguments);

// Uncompact single-signer signature
static napi_value uncompactSingleSignerSignature(napi_env environment, napi_callback_info arguments);

// Combine public keys
static napi_value combinePublicKeys(napi_env environment, napi_callback_info arguments);

// Create secret nonce
static napi_value createSecretNonce(napi_env environment, napi_callback_info arguments);

// Create message hash signature
static napi_value createMessageHashSignature(napi_env environment, napi_callback_info arguments);

// Verify message hash signature
static napi_value verifyMessageHashSignature(napi_env environment, napi_callback_info arguments);

// Uint8 array to buffer
static tuple<uint8_t *, size_t, bool> uint8ArrayToBuffer(napi_env environment, napi_value uint8Array);

// Buffer to uint8 array
static napi_value bufferToUint8Array(napi_env environment, uint8_t *data, size_t size);

// C bool to bool
static napi_value cBoolToBool(napi_env environment, bool value);

// String to C string
static tuple<string, bool> stringToCString(napi_env environment, napi_value value);

// Random fill
static bool randomFill(napi_env environment, uint8_t *buffer, size_t size);

// Is null
static bool isNull(napi_env environment, napi_value value, bool unknownResult = true);


// Main function

// Initialize module
NAPI_MODULE_INIT() {

	// Check if creating instance data failed
	InstanceData *instanceData = new(nothrow) InstanceData;
	if(!instanceData) {
	
		// Return nothing
		return nullptr;
	}
	
	// Initialize instance data
	instanceData->context = nullptr;
	instanceData->scratchSpace = nullptr;
	instanceData->generators = nullptr;
	
	// Check if associating instance data with the instance failed
	if(napi_set_instance_data(env, instanceData, [](napi_env environment, void *finalizeData, void *finalizeHint) {
	
		// Get instance data
		InstanceData *instanceData = reinterpret_cast<InstanceData *>(finalizeData);
		
		// Check if instance data's generators exist
		if(instanceData->generators) {
		
			// Destroy instance data's generators
			secp256k1_bulletproof_generators_destroy(instanceData->context, instanceData->generators);
		}
		
		// Check if instance data's scratch space exist
		if(instanceData->scratchSpace) {
		
			// Destroy instance data's scratch space
			secp256k1_scratch_space_destroy(instanceData->scratchSpace);
		}
		
		// Check if instance data's context exists
		if(instanceData->context) {
		
			// destroy instance data's context
			secp256k1_context_destroy(instanceData->context);
		}
		
		// Free memory
		delete instanceData;
		
	}, nullptr) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if initializing operation failed failed
	if(napi_get_null(env, &OPERATION_FAILED) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating blind switch property failed
	napi_value temp;
	if(napi_create_function(env, nullptr, 0, blindSwitch, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "blindSwitch", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating blind sum property failed
	if(napi_create_function(env, nullptr, 0, blindSum, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "blindSum", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating is valid secret key property failed
	if(napi_create_function(env, nullptr, 0, isValidSecretKey, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "isValidSecretKey", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating is valid public key property failed
	if(napi_create_function(env, nullptr, 0, isValidPublicKey, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "isValidPublicKey", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating is valid commit property failed
	if(napi_create_function(env, nullptr, 0, isValidCommit, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "isValidCommit", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating is valid single-signer signature property failed
	if(napi_create_function(env, nullptr, 0, isValidSingleSignerSignature, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "isValidSingleSignerSignature", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating create bulletproof property failed
	if(napi_create_function(env, nullptr, 0, createBulletproof, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "createBulletproof", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating create bulletproof blindless property failed
	if(napi_create_function(env, nullptr, 0, createBulletproofBlindless, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "createBulletproofBlindless", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating rewind bulletproof property failed
	if(napi_create_function(env, nullptr, 0, rewindBulletproof, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "rewindBulletproof", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating verify bulletproof property failed
	if(napi_create_function(env, nullptr, 0, verifyBulletproof, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "verifyBulletproof", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating public key from secret key property failed
	if(napi_create_function(env, nullptr, 0, publicKeyFromSecretKey, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "publicKeyFromSecretKey", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating public key from data property failed
	if(napi_create_function(env, nullptr, 0, publicKeyFromData, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "publicKeyFromData", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating uncompress public key property failed
	if(napi_create_function(env, nullptr, 0, uncompressPublicKey, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "uncompressPublicKey", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating secret key tweak add property failed
	if(napi_create_function(env, nullptr, 0, secretKeyTweakAdd, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "secretKeyTweakAdd", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating public key tweak add property failed
	if(napi_create_function(env, nullptr, 0, publicKeyTweakAdd, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "publicKeyTweakAdd", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating secret key tweak multiply property failed
	if(napi_create_function(env, nullptr, 0, secretKeyTweakMultiply, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "secretKeyTweakMultiply", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating public key tweak multiply property failed
	if(napi_create_function(env, nullptr, 0, publicKeyTweakMultiply, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "publicKeyTweakMultiply", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating shared secret key from secret key and public key property failed
	if(napi_create_function(env, nullptr, 0, sharedSecretKeyFromSecretKeyAndPublicKey, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "sharedSecretKeyFromSecretKeyAndPublicKey", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating pedersen commit property failed
	if(napi_create_function(env, nullptr, 0, pedersenCommit, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "pedersenCommit", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating pedersen commit sum property failed
	if(napi_create_function(env, nullptr, 0, pedersenCommitSum, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "pedersenCommitSum", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating pedersen commit to public key property failed
	if(napi_create_function(env, nullptr, 0, pedersenCommitToPublicKey, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "pedersenCommitToPublicKey", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating public key to Pedersen commit property failed
	if(napi_create_function(env, nullptr, 0, publicKeyToPedersenCommit, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "publicKeyToPedersenCommit", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating create single-signer signature property failed
	if(napi_create_function(env, nullptr, 0, createSingleSignerSignature, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "createSingleSignerSignature", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating add single-signer signatures property failed
	if(napi_create_function(env, nullptr, 0, addSingleSignerSignatures, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "addSingleSignerSignatures", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating verify single-signer signature property failed
	if(napi_create_function(env, nullptr, 0, verifySingleSignerSignature, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "verifySingleSignerSignature", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating single-signer signature from data property failed
	if(napi_create_function(env, nullptr, 0, singleSignerSignatureFromData, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "singleSignerSignatureFromData", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating compact single-signer signature property failed
	if(napi_create_function(env, nullptr, 0, compactSingleSignerSignature, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "compactSingleSignerSignature", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating uncompact single-signer signature property failed
	if(napi_create_function(env, nullptr, 0, uncompactSingleSignerSignature, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "uncompactSingleSignerSignature", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating combine public keys property failed
	if(napi_create_function(env, nullptr, 0, combinePublicKeys, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "combinePublicKeys", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating create secret nonce property failed
	if(napi_create_function(env, nullptr, 0, createSecretNonce, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "createSecretNonce", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating create message hash signature property failed
	if(napi_create_function(env, nullptr, 0, createMessageHashSignature, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "createMessageHashSignature", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating verify message hash signature property failed
	if(napi_create_function(env, nullptr, 0, verifyMessageHashSignature, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "verifyMessageHashSignature", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating operation failed property failed
	if(napi_set_named_property(env, exports, "OPERATION_FAILED", OPERATION_FAILED) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating no secret nonce property failed
	if(napi_get_null(env, &temp) != napi_ok || napi_set_named_property(env, exports, "NO_SECRET_NONCE", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating no public nonce property failed
	if(napi_get_null(env, &temp) != napi_ok || napi_set_named_property(env, exports, "NO_PUBLIC_NONCE", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating no public nonce total property failed
	if(napi_get_null(env, &temp) != napi_ok || napi_set_named_property(env, exports, "NO_PUBLIC_NONCE_TOTAL", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Return exports
	return exports;
}


// Supporting function implementation

// Get instance data
InstanceData *getInstanceData(napi_env environment) {

	// Check if getting instance data failed
	InstanceData *instanceData;
	if(napi_get_instance_data(environment, reinterpret_cast<void **>(&instanceData)) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if instance data's context doesn't exist
	if(!instanceData->context) {
	
		// Check if creating instance data's context failed
		instanceData->context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
		if(!instanceData->context) {
		
			// Return nothing
			return nullptr;
		}
		
		// Check if creating random seed failed
		vector<uint8_t> seed(Secp256k1Zkp::seedSize(instanceData));
		if(!randomFill(environment, seed.data(), seed.size())) {
		
			// Return nothing
			return nullptr;
		}
		
		// Check if randomizing context failed
		if(!secp256k1_context_randomize(instanceData->context, seed.data())) {
		
			// Clear seed
			memset(seed.data(), 0, seed.size());
		
			// Return nothing
			return nullptr;
		}
		
		// Clear seed
		memset(seed.data(), 0, seed.size());
	}
	
	// Check if instance data's scratch space doesn't exist
	if(!instanceData->scratchSpace) {
	
		// Check if creating instance data's scratch space failed
		instanceData->scratchSpace = secp256k1_scratch_space_create(instanceData->context, Secp256k1Zkp::SCRATCH_SPACE_SIZE);
		if(!instanceData->scratchSpace) {
		
			// Return nothing
			return nullptr;
		}
	}
	
	// Check if instance data's generators doesn't exist
	if(!instanceData->generators) {
	
		// Check if creating instance data's generators failed
		instanceData->generators = secp256k1_bulletproof_generators_create(instanceData->context, &secp256k1_generator_const_g, Secp256k1Zkp::NUMBER_OF_GENERATORS);
		if(!instanceData->generators) {
		
			// Return nothing
			return nullptr;
		}
	}
	
	// Return instance data
	return instanceData;
}

// Blind switch
napi_value blindSwitch(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}

	// Check if not enough arguments were provided
	size_t argc = 2;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting blind from arguments failed
	const tuple<uint8_t *, size_t, bool> blind = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(blind)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting value from arguments failed
	const tuple<string, bool> value = stringToCString(environment, argv[1]);
	if(!get<1>(value)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if performing blind switch failed
	vector<uint8_t> result(Secp256k1Zkp::blindSize(instanceData));
	if(!Secp256k1Zkp::blindSwitch(instanceData, result.data(), get<0>(blind), get<1>(blind), get<0>(value).c_str())) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return result as a uint8 array
	return bufferToUint8Array(environment, result.data(), result.size());
}

// Blind sum
napi_value blindSum(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if not enough arguments were provided
	size_t argc = 2;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting number of positive blinds from arguments failed
	bool isArray;
	uint32_t numberOfPositiveBlinds;
	if(napi_is_array(environment, argv[0], &isArray) != napi_ok || !isArray || napi_get_array_length(environment, argv[0], &numberOfPositiveBlinds) != napi_ok) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting number of negative blinds from arguments failed
	uint32_t numberOfNegativeBlinds;
	if(napi_is_array(environment, argv[1], &isArray) != napi_ok || !isArray || napi_get_array_length(environment, argv[1], &numberOfNegativeBlinds) != napi_ok) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Initialize blinds and blinds sizes
	vector<uint8_t> blinds;
	vector<size_t> blindsSizes(numberOfPositiveBlinds + numberOfNegativeBlinds);
	
	// Go through all positive blinds
	for(uint32_t i = 0; i < numberOfPositiveBlinds; ++i) {
	
		// Check if getting blind failed
		napi_value blind;
		if(napi_get_element(environment, argv[0], i, &blind) != napi_ok) {
		
			// Clear blinds
			memset(blinds.data(), 0, blinds.size());
		
			// Return operation failed
			return OPERATION_FAILED;
		}
		
		// Check if getting blind as a buffer failed
		const tuple<uint8_t *, size_t, bool> blindBuffer = uint8ArrayToBuffer(environment, blind);
		if(!get<2>(blindBuffer)) {
		
			// Clear blinds
			memset(blinds.data(), 0, blinds.size());
		
			// Return operation failed
			return OPERATION_FAILED;
		}
		
		// Append blind buffer to blinds
		blinds.insert(blinds.cend(), get<0>(blindBuffer), get<0>(blindBuffer) + get<1>(blindBuffer));
		
		// Append blind's size to blinds sizes
		blindsSizes[i] = get<1>(blindBuffer);
	}
	
	// Go through all negative blinds
	for(uint32_t i = 0; i < numberOfNegativeBlinds; ++i) {
	
		// Check if getting blind failed
		napi_value blind;
		if(napi_get_element(environment, argv[1], i, &blind) != napi_ok) {
		
			// Clear blinds
			memset(blinds.data(), 0, blinds.size());
		
			// Return operation failed
			return OPERATION_FAILED;
		}
		
		// Check if getting blind as a buffer failed
		const tuple<uint8_t *, size_t, bool> blindBuffer = uint8ArrayToBuffer(environment, blind);
		if(!get<2>(blindBuffer)) {
		
			// Clear blinds
			memset(blinds.data(), 0, blinds.size());
		
			// Return operation failed
			return OPERATION_FAILED;
		}
		
		// Append blind buffer to blinds
		blinds.insert(blinds.cend(), get<0>(blindBuffer), get<0>(blindBuffer) + get<1>(blindBuffer));
		
		// Append blind's size to blinds sizes
		blindsSizes[i + numberOfPositiveBlinds] = get<1>(blindBuffer);
	}
	
	// Check if performing blind sum failed
	vector<uint8_t> result(Secp256k1Zkp::blindSize(instanceData));
	if(!Secp256k1Zkp::blindSum(instanceData, result.data(), blinds.data(), blindsSizes.data(), numberOfPositiveBlinds + numberOfNegativeBlinds, numberOfPositiveBlinds)) {
	
		// Clear blinds
		memset(blinds.data(), 0, blinds.size());
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Clear blinds
	memset(blinds.data(), 0, blinds.size());
	
	// Return result as a uint8 array
	return bufferToUint8Array(environment, result.data(), result.size());
}

// Is valid secret key
napi_value isValidSecretKey(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}

	// Check if not enough arguments were provided
	size_t argc = 1;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if getting secret key from arguments failed
	const tuple<uint8_t *, size_t, bool> secretKey = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(secretKey)) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if secret key is not a valid secret key
	if(!Secp256k1Zkp::isValidSecretKey(instanceData, get<0>(secretKey), get<1>(secretKey))) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Return true as a bool
	return cBoolToBool(environment, true);
}

// Is valid public key
napi_value isValidPublicKey(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}

	// Check if not enough arguments were provided
	size_t argc = 1;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if getting public key from arguments failed
	const tuple<uint8_t *, size_t, bool> publicKey = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(publicKey)) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if public key is not a valid public key
	if(!Secp256k1Zkp::isValidPublicKey(instanceData, get<0>(publicKey), get<1>(publicKey))) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Return true as a bool
	return cBoolToBool(environment, true);
}

// Is valid commit
napi_value isValidCommit(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}

	// Check if not enough arguments were provided
	size_t argc = 1;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if getting commit from arguments failed
	const tuple<uint8_t *, size_t, bool> commit = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(commit)) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if commit is not a valid commit
	if(!Secp256k1Zkp::isValidCommit(instanceData, get<0>(commit), get<1>(commit))) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Return true as a bool
	return cBoolToBool(environment, true);
}

// Is valid single-signer signature
napi_value isValidSingleSignerSignature(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}

	// Check if not enough arguments were provided
	size_t argc = 1;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if getting signature from arguments failed
	const tuple<uint8_t *, size_t, bool> signature = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(signature)) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if signature is not a valid single-signer signature
	if(!Secp256k1Zkp::isValidSingleSignerSignature(instanceData, get<0>(signature), get<1>(signature))) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Return true as a bool
	return cBoolToBool(environment, true);
}

// Create bulletproof
napi_value createBulletproof(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}

	// Check if not enough arguments were provided
	size_t argc = 6;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting blind from arguments failed
	const tuple<uint8_t *, size_t, bool> blind = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(blind)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting value from arguments failed
	const tuple<string, bool> value = stringToCString(environment, argv[1]);
	if(!get<1>(value)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting nonce from arguments failed
	const tuple<uint8_t *, size_t, bool> nonce = uint8ArrayToBuffer(environment, argv[2]);
	if(!get<2>(nonce)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting private nonce from arguments failed
	const tuple<uint8_t *, size_t, bool> privateNonce = uint8ArrayToBuffer(environment, argv[3]);
	if(!get<2>(privateNonce)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting extra commit from arguments failed
	const tuple<uint8_t *, size_t, bool> extraCommit = uint8ArrayToBuffer(environment, argv[4]);
	if(!get<2>(extraCommit)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting message from arguments failed
	const tuple<uint8_t *, size_t, bool> message = uint8ArrayToBuffer(environment, argv[5]);
	if(!get<2>(message)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if creating bulletproof failed
	vector<uint8_t> proof(Secp256k1Zkp::bulletproofProofSize(instanceData));
	char proofSize[MAX_64_BIT_INTEGER_STRING_LENGTH];
	if(!Secp256k1Zkp::createBulletproof(instanceData, proof.data(), proofSize, get<0>(blind), get<1>(blind), get<0>(value).c_str(), get<0>(nonce), get<1>(nonce), get<0>(privateNonce), get<1>(privateNonce), get<0>(extraCommit), get<1>(extraCommit), get<0>(message), get<1>(message))) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return proof as a uint8 array
	return bufferToUint8Array(environment, proof.data(), strtoull(proofSize, nullptr, 10));
}

// Create bulletproof blindless
napi_value createBulletproofBlindless(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}

	// Check if not enough arguments were provided
	size_t argc = 8;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting tau x from arguments failed
	const tuple<uint8_t *, size_t, bool> tauX = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(tauX)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting t one from arguments failed
	const tuple<uint8_t *, size_t, bool> tOne = uint8ArrayToBuffer(environment, argv[1]);
	if(!get<2>(tOne)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting t two from arguments failed
	const tuple<uint8_t *, size_t, bool> tTwo = uint8ArrayToBuffer(environment, argv[2]);
	if(!get<2>(tTwo)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting commit from arguments failed
	const tuple<uint8_t *, size_t, bool> commit = uint8ArrayToBuffer(environment, argv[3]);
	if(!get<2>(commit)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting value from arguments failed
	const tuple<string, bool> value = stringToCString(environment, argv[4]);
	if(!get<1>(value)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting nonce from arguments failed
	const tuple<uint8_t *, size_t, bool> nonce = uint8ArrayToBuffer(environment, argv[5]);
	if(!get<2>(nonce)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting extra commit from arguments failed
	const tuple<uint8_t *, size_t, bool> extraCommit = uint8ArrayToBuffer(environment, argv[6]);
	if(!get<2>(extraCommit)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting message from arguments failed
	const tuple<uint8_t *, size_t, bool> message = uint8ArrayToBuffer(environment, argv[7]);
	if(!get<2>(message)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if creating bulletproof blindless failed
	vector<uint8_t> proof(Secp256k1Zkp::bulletproofProofSize(instanceData));
	char proofSize[MAX_64_BIT_INTEGER_STRING_LENGTH];
	if(!Secp256k1Zkp::createBulletproofBlindless(instanceData, proof.data(), proofSize, get<0>(tauX), get<1>(tauX), get<0>(tOne), get<1>(tOne), get<0>(tTwo), get<1>(tTwo), get<0>(commit), get<1>(commit), get<0>(value).c_str(), get<0>(nonce), get<1>(nonce), get<0>(extraCommit), get<1>(extraCommit), get<0>(message), get<1>(message))) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return proof as a uint8 array
	return bufferToUint8Array(environment, proof.data(), strtoull(proofSize, nullptr, 10));
}

// Rewind bulletproof
napi_value rewindBulletproof(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}

	// Check if not enough arguments were provided
	size_t argc = 3;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting proof from arguments failed
	const tuple<uint8_t *, size_t, bool> proof = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(proof)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting commit from arguments failed
	const tuple<uint8_t *, size_t, bool> commit = uint8ArrayToBuffer(environment, argv[1]);
	if(!get<2>(commit)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting nonce from arguments failed
	const tuple<uint8_t *, size_t, bool> nonce = uint8ArrayToBuffer(environment, argv[2]);
	if(!get<2>(nonce)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if performing rewind bulletproof failed
	char value[MAX_64_BIT_INTEGER_STRING_LENGTH];
	vector<uint8_t> blind(Secp256k1Zkp::blindSize(instanceData));
	vector<uint8_t> message(Secp256k1Zkp::bulletproofMessageSize(instanceData));
	if(!Secp256k1Zkp::rewindBulletproof(instanceData, value, blind.data(), message.data(), get<0>(proof), get<1>(proof), get<0>(commit), get<1>(commit), get<0>(nonce), get<1>(nonce))) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if creating result failed
	napi_value result;
	if(napi_create_object(environment, &result) != napi_ok) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if adding value to result failed
	napi_value temp;
	if(napi_create_string_utf8(environment, value, NAPI_AUTO_LENGTH, &temp) != napi_ok || napi_set_named_property(environment, result, "Value", temp) != napi_ok) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if adding blind to result failed
	const napi_value uint8ArrayBlind = bufferToUint8Array(environment, blind.data(), blind.size());
	if(isNull(environment, uint8ArrayBlind) || napi_set_named_property(environment, result, "Blind", uint8ArrayBlind) != napi_ok) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if adding message to result failed
	const napi_value uint8ArrayMessage = bufferToUint8Array(environment, message.data(), message.size());
	if(isNull(environment, uint8ArrayMessage) || napi_set_named_property(environment, result, "Message", uint8ArrayMessage) != napi_ok) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return result
	return result;
}

// Verify bulletproof
napi_value verifyBulletproof(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}

	// Check if not enough arguments were provided
	size_t argc = 3;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if getting proof from arguments failed
	const tuple<uint8_t *, size_t, bool> proof = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(proof)) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if getting commit from arguments failed
	const tuple<uint8_t *, size_t, bool> commit = uint8ArrayToBuffer(environment, argv[1]);
	if(!get<2>(commit)) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if getting extra commit from arguments failed
	const tuple<uint8_t *, size_t, bool> extraCommit = uint8ArrayToBuffer(environment, argv[2]);
	if(!get<2>(extraCommit)) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if bulletproof isn't verified
	if(!Secp256k1Zkp::verifyBulletproof(instanceData, get<0>(proof), get<1>(proof), get<0>(commit), get<1>(commit), get<0>(extraCommit), get<1>(extraCommit))) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Return true as a bool
	return cBoolToBool(environment, true);
}

// Public key from secret key
napi_value publicKeyFromSecretKey(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}

	// Check if not enough arguments were provided
	size_t argc = 1;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting secret key from arguments failed
	const tuple<uint8_t *, size_t, bool> secretKey = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(secretKey)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting public key from secret key failed
	vector<uint8_t> publicKey(Secp256k1Zkp::publicKeySize(instanceData));
	if(!Secp256k1Zkp::publicKeyFromSecretKey(instanceData, publicKey.data(), get<0>(secretKey), get<1>(secretKey))) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return public key as a uint8 array
	return bufferToUint8Array(environment, publicKey.data(), publicKey.size());
}

// Public key from data
napi_value publicKeyFromData(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}

	// Check if not enough arguments were provided
	size_t argc = 1;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting data from arguments failed
	const tuple<uint8_t *, size_t, bool> data = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(data)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting public key from data failed
	vector<uint8_t> publicKey(Secp256k1Zkp::publicKeySize(instanceData));
	if(!Secp256k1Zkp::publicKeyFromData(instanceData, publicKey.data(), get<0>(data), get<1>(data))) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return public key as a uint8 array
	return bufferToUint8Array(environment, publicKey.data(), publicKey.size());
}

// Uncompress public key
napi_value uncompressPublicKey(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}

	// Check if not enough arguments were provided
	size_t argc = 1;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting public key from arguments failed
	const tuple<uint8_t *, size_t, bool> publicKey = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(publicKey)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if uncompressing the public key failed
	vector<uint8_t> uncompressedPublicKey(Secp256k1Zkp::uncompressedPublicKeySize(instanceData));
	if(!Secp256k1Zkp::uncompressPublicKey(instanceData, uncompressedPublicKey.data(), get<0>(publicKey), get<1>(publicKey))) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return uncompressed public key as a uint8 array
	return bufferToUint8Array(environment, uncompressedPublicKey.data(), uncompressedPublicKey.size());
}

// Secret key tweak add
napi_value secretKeyTweakAdd(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}

	// Check if not enough arguments were provided
	size_t argc = 2;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting secret key from arguments failed
	const tuple<uint8_t *, size_t, bool> secretKey = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(secretKey)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting tweak from arguments failed
	const tuple<uint8_t *, size_t, bool> tweak = uint8ArrayToBuffer(environment, argv[1]);
	if(!get<2>(tweak)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if performing secret key tweak add failed
	vector<uint8_t> result(Secp256k1Zkp::secretKeySize(instanceData));
	if(!Secp256k1Zkp::secretKeyTweakAdd(instanceData, result.data(), get<0>(secretKey), get<1>(secretKey), get<0>(tweak), get<1>(tweak))) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return result as a uint8 array
	return bufferToUint8Array(environment, result.data(), result.size());
}

// Public key tweak add
napi_value publicKeyTweakAdd(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}

	// Check if not enough arguments were provided
	size_t argc = 2;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting public key from arguments failed
	const tuple<uint8_t *, size_t, bool> publicKey = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(publicKey)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting tweak from arguments failed
	const tuple<uint8_t *, size_t, bool> tweak = uint8ArrayToBuffer(environment, argv[1]);
	if(!get<2>(tweak)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if performing public key tweak add failed
	vector<uint8_t> result(Secp256k1Zkp::publicKeySize(instanceData));
	if(!Secp256k1Zkp::publicKeyTweakAdd(instanceData, result.data(), get<0>(publicKey), get<1>(publicKey), get<0>(tweak), get<1>(tweak))) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return result as a uint8 array
	return bufferToUint8Array(environment, result.data(), result.size());
}

// Secret key tweak multiply
napi_value secretKeyTweakMultiply(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}

	// Check if not enough arguments were provided
	size_t argc = 2;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting secret key from arguments failed
	const tuple<uint8_t *, size_t, bool> secretKey = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(secretKey)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting tweak from arguments failed
	const tuple<uint8_t *, size_t, bool> tweak = uint8ArrayToBuffer(environment, argv[1]);
	if(!get<2>(tweak)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if performing secret key tweak multiply failed
	vector<uint8_t> result(Secp256k1Zkp::secretKeySize(instanceData));
	if(!Secp256k1Zkp::secretKeyTweakMultiply(instanceData, result.data(), get<0>(secretKey), get<1>(secretKey), get<0>(tweak), get<1>(tweak))) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return result as a uint8 array
	return bufferToUint8Array(environment, result.data(), result.size());
}

// Public key tweak multiply
napi_value publicKeyTweakMultiply(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}

	// Check if not enough arguments were provided
	size_t argc = 2;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting public key from arguments failed
	const tuple<uint8_t *, size_t, bool> publicKey = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(publicKey)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting tweak from arguments failed
	const tuple<uint8_t *, size_t, bool> tweak = uint8ArrayToBuffer(environment, argv[1]);
	if(!get<2>(tweak)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if performing public key tweak multiply failed
	vector<uint8_t> result(Secp256k1Zkp::publicKeySize(instanceData));
	if(!Secp256k1Zkp::publicKeyTweakMultiply(instanceData, result.data(), get<0>(publicKey), get<1>(publicKey), get<0>(tweak), get<1>(tweak))) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return result as a uint8 array
	return bufferToUint8Array(environment, result.data(), result.size());
}

// Shared secret key from secret key and public key
napi_value sharedSecretKeyFromSecretKeyAndPublicKey(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}

	// Check if not enough arguments were provided
	size_t argc = 2;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting secret key from arguments failed
	const tuple<uint8_t *, size_t, bool> secretKey = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(secretKey)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting public key from arguments failed
	const tuple<uint8_t *, size_t, bool> publicKey = uint8ArrayToBuffer(environment, argv[1]);
	if(!get<2>(publicKey)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting shared secret key from secret key and public key failed
	vector<uint8_t> sharedSecretKey(Secp256k1Zkp::secretKeySize(instanceData));
	if(!Secp256k1Zkp::sharedSecretKeyFromSecretKeyAndPublicKey(instanceData, sharedSecretKey.data(), get<0>(secretKey), get<1>(secretKey), get<0>(publicKey), get<1>(publicKey))) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return shared secret key as a uint8 array
	return bufferToUint8Array(environment, sharedSecretKey.data(), sharedSecretKey.size());
}

// Pedersen commit
napi_value pedersenCommit(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}

	// Check if not enough arguments were provided
	size_t argc = 2;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting blind from arguments failed
	const tuple<uint8_t *, size_t, bool> blind = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(blind)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting value from arguments failed
	const tuple<string, bool> value = stringToCString(environment, argv[1]);
	if(!get<1>(value)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if performing Pedersen commit failed
	vector<uint8_t> result(Secp256k1Zkp::commitSize(instanceData));
	if(!Secp256k1Zkp::pedersenCommit(instanceData, result.data(), get<0>(blind), get<1>(blind), get<0>(value).c_str())) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return result as a uint8 array
	return bufferToUint8Array(environment, result.data(), result.size());
}

// Pedersen commit sum
napi_value pedersenCommitSum(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if not enough arguments were provided
	size_t argc = 2;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting number of positive commits from arguments failed
	bool isArray;
	uint32_t numberOfPositiveCommits;
	if(napi_is_array(environment, argv[0], &isArray) != napi_ok || !isArray || napi_get_array_length(environment, argv[0], &numberOfPositiveCommits) != napi_ok) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Initialize positive commits and positive commits sizes
	vector<uint8_t> positiveCommits;
	vector<size_t> positiveCommitsSizes(numberOfPositiveCommits);
	
	// Go through all positive commits
	for(uint32_t i = 0; i < numberOfPositiveCommits; ++i) {
	
		// Check if getting commit failed
		napi_value commit;
		if(napi_get_element(environment, argv[0], i, &commit) != napi_ok) {
		
			// Return operation failed
			return OPERATION_FAILED;
		}
		
		// Check if getting commit as a buffer failed
		const tuple<uint8_t *, size_t, bool> commitBuffer = uint8ArrayToBuffer(environment, commit);
		if(!get<2>(commitBuffer)) {
		
			// Return operation failed
			return OPERATION_FAILED;
		}
		
		// Append commit buffer to positive commits
		positiveCommits.insert(positiveCommits.cend(), get<0>(commitBuffer), get<0>(commitBuffer) + get<1>(commitBuffer));
		
		// Append commit's size to positive commits sizes
		positiveCommitsSizes[i] = get<1>(commitBuffer);
	}
	
	// Check if getting number of negative commits from arguments failed
	uint32_t numberOfNegativeCommits;
	if(napi_is_array(environment, argv[1], &isArray) != napi_ok || !isArray || napi_get_array_length(environment, argv[1], &numberOfNegativeCommits) != napi_ok) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Initialize negative commits and negative commits sizes
	vector<uint8_t> negativeCommits;
	vector<size_t> negativeCommitsSizes(numberOfNegativeCommits);
	
	// Go through all negative commits
	for(uint32_t i = 0; i < numberOfNegativeCommits; ++i) {
	
		// Check if getting commit failed
		napi_value commit;
		if(napi_get_element(environment, argv[1], i, &commit) != napi_ok) {
		
			// Return operation failed
			return OPERATION_FAILED;
		}
		
		// Check if getting commit as a buffer failed
		const tuple<uint8_t *, size_t, bool> commitBuffer = uint8ArrayToBuffer(environment, commit);
		if(!get<2>(commitBuffer)) {
		
			// Return operation failed
			return OPERATION_FAILED;
		}
		
		// Append commit buffer to negative commits
		negativeCommits.insert(negativeCommits.cend(), get<0>(commitBuffer), get<0>(commitBuffer) + get<1>(commitBuffer));
		
		// Append commit's size to negative commits sizes
		negativeCommitsSizes[i] = get<1>(commitBuffer);
	}
	
	// Check if performing Pedersen commit sum failed
	vector<uint8_t> result(Secp256k1Zkp::commitSize(instanceData));
	if(!Secp256k1Zkp::pedersenCommitSum(instanceData, result.data(), positiveCommits.data(), positiveCommitsSizes.data(), numberOfPositiveCommits, negativeCommits.data(), negativeCommitsSizes.data(), numberOfNegativeCommits)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return result as a uint8 array
	return bufferToUint8Array(environment, result.data(), result.size());
}

// Pedersen commit to public key
napi_value pedersenCommitToPublicKey(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}

	// Check if not enough arguments were provided
	size_t argc = 1;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting commit from arguments failed
	const tuple<uint8_t *, size_t, bool> commit = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(commit)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting public key from Pedersen commit failed
	vector<uint8_t> publicKey(Secp256k1Zkp::publicKeySize(instanceData));
	if(!Secp256k1Zkp::pedersenCommitToPublicKey(instanceData, publicKey.data(), get<0>(commit), get<1>(commit))) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return public key as a uint8 array
	return bufferToUint8Array(environment, publicKey.data(), publicKey.size());
}

// Public key to Pedersen commit
napi_value publicKeyToPedersenCommit(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}

	// Check if not enough arguments were provided
	size_t argc = 1;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting public key from arguments failed
	const tuple<uint8_t *, size_t, bool> publicKey = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(publicKey)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting Pedersen commit from public key failed
	vector<uint8_t> commit(Secp256k1Zkp::commitSize(instanceData));
	if(!Secp256k1Zkp::publicKeyToPedersenCommit(instanceData, commit.data(), get<0>(publicKey), get<1>(publicKey))) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return commit as a uint8 array
	return bufferToUint8Array(environment, commit.data(), commit.size());
}

// Create single-signer signature
napi_value createSingleSignerSignature(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}

	// Check if not enough arguments were provided
	size_t argc = 6;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting message from arguments failed
	const tuple<uint8_t *, size_t, bool> message = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(message)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting secret key from arguments failed
	const tuple<uint8_t *, size_t, bool> secretKey = uint8ArrayToBuffer(environment, argv[1]);
	if(!get<2>(secretKey)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting secret nonce from arguments failed
	const tuple<uint8_t *, size_t, bool> secretNonce = uint8ArrayToBuffer(environment, argv[2]);
	if(!get<2>(secretNonce) && !isNull(environment, argv[2], false)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting public key from arguments failed
	const tuple<uint8_t *, size_t, bool> publicKey = uint8ArrayToBuffer(environment, argv[3]);
	if(!get<2>(publicKey)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting public nonce from arguments failed
	const tuple<uint8_t *, size_t, bool> publicNonce = uint8ArrayToBuffer(environment, argv[4]);
	if(!get<2>(publicNonce) && !isNull(environment, argv[4], false)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting public nonce total from arguments failed
	const tuple<uint8_t *, size_t, bool> publicNonceTotal = uint8ArrayToBuffer(environment, argv[5]);
	if(!get<2>(publicNonceTotal) && !isNull(environment, argv[5], false)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if creating random seed failed
	vector<uint8_t> seed(Secp256k1Zkp::seedSize(instanceData));
	if(!randomFill(environment, seed.data(), seed.size())) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if creating single-signer signature failed
	vector<uint8_t> signature(Secp256k1Zkp::singleSignerSignatureSize(instanceData));
	if(!Secp256k1Zkp::createSingleSignerSignature(instanceData, signature.data(), get<0>(message), get<1>(message), get<0>(secretKey), get<1>(secretKey), get<0>(secretNonce), get<1>(secretNonce), get<0>(publicKey), get<1>(publicKey), get<0>(publicNonce), get<1>(publicNonce), get<0>(publicNonceTotal), get<1>(publicNonceTotal), seed.data(), seed.size())) {
	
		// Clear seed
		memset(seed.data(), 0, seed.size());
		
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Clear seed
	memset(seed.data(), 0, seed.size());
	
	// Return signature as a uint8 array
	return bufferToUint8Array(environment, signature.data(), signature.size());
}

// Add single-signer signatures
napi_value addSingleSignerSignatures(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if not enough arguments were provided
	size_t argc = 2;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting number of signatures from arguments failed
	bool isArray;
	uint32_t numberOfSignatures;
	if(napi_is_array(environment, argv[0], &isArray) != napi_ok || !isArray || napi_get_array_length(environment, argv[0], &numberOfSignatures) != napi_ok) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Initialize signatures and signatures sizes
	vector<uint8_t> signatures;
	vector<size_t> signaturesSizes(numberOfSignatures);
	
	// Go through all signatures
	for(uint32_t i = 0; i < numberOfSignatures; ++i) {
	
		// Check if getting signature failed
		napi_value signature;
		if(napi_get_element(environment, argv[0], i, &signature) != napi_ok) {
		
			// Return operation failed
			return OPERATION_FAILED;
		}
		
		// Check if getting signature as a buffer failed
		const tuple<uint8_t *, size_t, bool> signatureBuffer = uint8ArrayToBuffer(environment, signature);
		if(!get<2>(signatureBuffer)) {
		
			// Return operation failed
			return OPERATION_FAILED;
		}
		
		// Append signature buffer to signatures
		signatures.insert(signatures.cend(), get<0>(signatureBuffer), get<0>(signatureBuffer) + get<1>(signatureBuffer));
		
		// Append signature's size to signatures sizes
		signaturesSizes[i] = get<1>(signatureBuffer);
	}
	
	// Check if getting public nonce total from arguments failed
	const tuple<uint8_t *, size_t, bool> publicNonceTotal = uint8ArrayToBuffer(environment, argv[1]);
	if(!get<2>(publicNonceTotal)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if adding single-signer signatures failed
	vector<uint8_t> result(Secp256k1Zkp::singleSignerSignatureSize(instanceData));
	if(!Secp256k1Zkp::addSingleSignerSignatures(instanceData, result.data(), signatures.data(), signaturesSizes.data(), numberOfSignatures, get<0>(publicNonceTotal), get<1>(publicNonceTotal))) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return result as a uint8 array
	return bufferToUint8Array(environment, result.data(), result.size());
}

// Verify single-signer signature
napi_value verifySingleSignerSignature(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}

	// Check if not enough arguments were provided
	size_t argc = 6;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if getting signature from arguments failed
	const tuple<uint8_t *, size_t, bool> signature = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(signature)) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if getting message from arguments failed
	const tuple<uint8_t *, size_t, bool> message = uint8ArrayToBuffer(environment, argv[1]);
	if(!get<2>(message)) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if getting public nonce from arguments failed
	const tuple<uint8_t *, size_t, bool> publicNonce = uint8ArrayToBuffer(environment, argv[2]);
	if(!get<2>(publicNonce) && !isNull(environment, argv[2], false)) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if getting public key from arguments failed
	const tuple<uint8_t *, size_t, bool> publicKey = uint8ArrayToBuffer(environment, argv[3]);
	if(!get<2>(publicKey)) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if getting public key total from arguments failed
	const tuple<uint8_t *, size_t, bool> publicKeyTotal = uint8ArrayToBuffer(environment, argv[4]);
	if(!get<2>(publicKeyTotal)) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if getting is partial from arguments failed
	bool isPartial;
	if(napi_get_value_bool(environment, argv[5], &isPartial) != napi_ok) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if single-signer signature isn't verified
	if(!Secp256k1Zkp::verifySingleSignerSignature(instanceData, get<0>(signature), get<1>(signature), get<0>(message), get<1>(message), get<0>(publicNonce), get<1>(publicNonce), get<0>(publicKey), get<1>(publicKey), get<0>(publicKeyTotal), get<1>(publicKeyTotal), isPartial)) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Return true as a bool
	return cBoolToBool(environment, true);
}

// Single-signer signature from data
napi_value singleSignerSignatureFromData(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}

	// Check if not enough arguments were provided
	size_t argc = 1;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting data from arguments failed
	const tuple<uint8_t *, size_t, bool> data = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(data)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting single-signer signature from data failed
	vector<uint8_t> signature(Secp256k1Zkp::singleSignerSignatureSize(instanceData));
	if(!Secp256k1Zkp::singleSignerSignatureFromData(instanceData, signature.data(), get<0>(data), get<1>(data))) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return signature as a uint8 array
	return bufferToUint8Array(environment, signature.data(), signature.size());
}

// Compact single-signer signature
napi_value compactSingleSignerSignature(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}

	// Check if not enough arguments were provided
	size_t argc = 1;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting signature from arguments failed
	const tuple<uint8_t *, size_t, bool> signature = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(signature)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if compacting single-signer signature failed
	vector<uint8_t> result(Secp256k1Zkp::singleSignerSignatureSize(instanceData));
	if(!Secp256k1Zkp::compactSingleSignerSignature(instanceData, result.data(), get<0>(signature), get<1>(signature))) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return result as a uint8 array
	return bufferToUint8Array(environment, result.data(),result.size());
}

// Uncompact single-signer signature
napi_value uncompactSingleSignerSignature(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}

	// Check if not enough arguments were provided
	size_t argc = 1;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting signature from arguments failed
	const tuple<uint8_t *, size_t, bool> signature = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(signature)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if uncompacting single-signer signature failed
	vector<uint8_t> result(Secp256k1Zkp::uncompactSingleSignerSignatureSize(instanceData));
	if(!Secp256k1Zkp::uncompactSingleSignerSignature(instanceData, result.data(), get<0>(signature), get<1>(signature))) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return result as a uint8 array
	return bufferToUint8Array(environment, result.data(), result.size());
}

// Combine public keys
napi_value combinePublicKeys(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if not enough arguments were provided
	size_t argc = 1;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting number of public keys from arguments failed
	bool isArray;
	uint32_t numberOfPublicKeys;
	if(napi_is_array(environment, argv[0], &isArray) != napi_ok || !isArray || napi_get_array_length(environment, argv[0], &numberOfPublicKeys) != napi_ok) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Initialize public keys and public keys sizes
	vector<uint8_t> publicKeys;
	vector<size_t> publicKeysSizes(numberOfPublicKeys);
	
	// Go through all public keys
	for(uint32_t i = 0; i < numberOfPublicKeys; ++i) {
	
		// Check if getting public key failed
		napi_value publicKey;
		if(napi_get_element(environment, argv[0], i, &publicKey) != napi_ok) {
		
			// Return operation failed
			return OPERATION_FAILED;
		}
		
		// Check if getting public key as a buffer failed
		const tuple<uint8_t *, size_t, bool> publicKeyBuffer = uint8ArrayToBuffer(environment, publicKey);
		if(!get<2>(publicKeyBuffer)) {
		
			// Return operation failed
			return OPERATION_FAILED;
		}
		
		// Append public key buffer to public keys
		publicKeys.insert(publicKeys.cend(), get<0>(publicKeyBuffer), get<0>(publicKeyBuffer) + get<1>(publicKeyBuffer));
		
		// Append public key's size to public keys sizes
		publicKeysSizes[i] = get<1>(publicKeyBuffer);
	}
	
	// Check if combining public keys failed
	vector<uint8_t> result(Secp256k1Zkp::publicKeySize(instanceData));
	if(!Secp256k1Zkp::combinePublicKeys(instanceData, result.data(), publicKeys.data(), publicKeysSizes.data(), numberOfPublicKeys)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return result as a uint8 array
	return bufferToUint8Array(environment, result.data(), result.size());
}

// Create secret nonce
napi_value createSecretNonce(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}

	// Check if arguments were provided
	size_t argc = 0;
	if(napi_get_cb_info(environment, arguments, &argc, nullptr, nullptr, nullptr) != napi_ok || argc) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if creating random seed failed
	vector<uint8_t> seed(Secp256k1Zkp::seedSize(instanceData));
	if(!randomFill(environment, seed.data(), seed.size())) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if creating secure nonce failed
	vector<uint8_t> nonce(Secp256k1Zkp::nonceSize(instanceData));
	if(!Secp256k1Zkp::createSecretNonce(instanceData, nonce.data(), seed.data(), seed.size())) {
	
		// Clear seed
		memset(seed.data(), 0, seed.size());
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Clear seed
	memset(seed.data(), 0, seed.size());
	
	// Return nonce as a uint8 array
	return bufferToUint8Array(environment, nonce.data(), nonce.size());
}

// Create message hash signature
napi_value createMessageHashSignature(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}

	// Check if not enough arguments were provided
	size_t argc = 2;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting message hash from arguments failed
	const tuple<uint8_t *, size_t, bool> messageHash = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(messageHash)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting secret key from arguments failed
	const tuple<uint8_t *, size_t, bool> secretKey = uint8ArrayToBuffer(environment, argv[1]);
	if(!get<2>(secretKey)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if creating message hash signature failed
	vector<uint8_t> signature(Secp256k1Zkp::maximumMessageHashSignatureSize(instanceData));
	char signatureSize[MAX_64_BIT_INTEGER_STRING_LENGTH];
	if(!Secp256k1Zkp::createMessageHashSignature(instanceData, signature.data(), signatureSize, get<0>(messageHash), get<1>(messageHash), get<0>(secretKey), get<1>(secretKey))) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return signature as a uint8 array
	return bufferToUint8Array(environment, signature.data(), strtoull(signatureSize, nullptr, 10));
}

// Verify message hash signature
napi_value verifyMessageHashSignature(napi_env environment, napi_callback_info arguments) {

	// Check if getting instance data failed
	InstanceData *instanceData = getInstanceData(environment);
	if(!instanceData) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}

	// Check if not enough arguments were provided
	size_t argc = 3;
	vector<napi_value> argv(argc);
	if(napi_get_cb_info(environment, arguments, &argc, argv.data(), nullptr, nullptr) != napi_ok || argc != argv.size()) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if getting signature from arguments failed
	const tuple<uint8_t *, size_t, bool> signature = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(signature)) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if getting message hash from arguments failed
	const tuple<uint8_t *, size_t, bool> messageHash = uint8ArrayToBuffer(environment, argv[1]);
	if(!get<2>(messageHash)) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if getting public key from arguments failed
	const tuple<uint8_t *, size_t, bool> publicKey = uint8ArrayToBuffer(environment, argv[2]);
	if(!get<2>(publicKey)) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Check if message hash signature isn't verified
	if(!Secp256k1Zkp::verifyMessageHashSignature(instanceData, get<0>(signature), get<1>(signature), get<0>(messageHash), get<1>(messageHash), get<0>(publicKey), get<1>(publicKey))) {
	
		// Return false as a bool
		return cBoolToBool(environment, false);
	}
	
	// Return true as a bool
	return cBoolToBool(environment, true);
}

// Uint8 array to buffer
tuple<uint8_t *, size_t, bool> uint8ArrayToBuffer(napi_env environment, napi_value uint8Array) {

	// Check if uint8 array isn't a typed array
	bool isTypedArray;
	if(napi_is_typedarray(environment, uint8Array, &isTypedArray) != napi_ok || !isTypedArray) {
	
		// Return failure
		return {nullptr, 0, false};
	}
	
	// Check if uint8 array isn't a uint8 array
	napi_typedarray_type type;
	size_t size;
	uint8_t *data;
	if(napi_get_typedarray_info(environment, uint8Array, &type, &size, reinterpret_cast<void **>(&data), nullptr, nullptr) != napi_ok || type != napi_uint8_array) {
	
		// Return failure
		return {nullptr, 0, false};
	}
	
	// Return data and size
	return {data, size, true};
}

// Buffer to uint8 array
napi_value bufferToUint8Array(napi_env environment, uint8_t *data, size_t size) {

	// Check if creating array buffer failed
	uint8_t *arrayBufferData;
	napi_value arrayBuffer;
	if(napi_create_arraybuffer(environment, size, reinterpret_cast<void **>(&arrayBufferData), &arrayBuffer) != napi_ok) {
	
		// Clear data
		memset(data, 0, size);
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Copy data to array buffer
	memcpy(arrayBufferData, data, size);
	
	// Clear data
	memset(data, 0, size);
	
	// Check if creating uint8 array from array buffer failed
	napi_value uint8Array;
	if(napi_create_typedarray(environment, napi_uint8_array, size, arrayBuffer, 0, &uint8Array) != napi_ok) {
	
		// Clear array buffer
		memset(arrayBufferData, 0, size);
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return uint8 array
	return uint8Array;
}

// C bool to bool
napi_value cBoolToBool(napi_env environment, bool value) {

	// Check if creating boolean from value failed
	napi_value result;
	if(napi_get_boolean(environment, value, &result) != napi_ok) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return result
	return result;
}

// String to C string
tuple<string, bool> stringToCString(napi_env environment, napi_value value) {

	// Check if getting the string's size failed
	size_t size;
	if(napi_get_value_string_utf8(environment, value, nullptr, 0, &size) != napi_ok) {
	
		// Return failure
		return {"", false};
	}
	
	// Check if getting the string failed
	vector<char> result(size + sizeof('\0'));
	memset(result.data(), 0, result.size());
	if(napi_get_value_string_utf8(environment, value, result.data(), result.size(), nullptr) != napi_ok) {
	
		// Return failure
		return {"", false};
	}
	
	// Return result
	return {result.data(), true};
}

// Random fill
bool randomFill(napi_env environment, uint8_t *buffer, size_t size) {

	// Check if getting random fill sync failed
	napi_value global;
	bool hasProperty;
	napi_value crypto;
	napi_value randomFillSync;
	if(napi_get_global(environment, &global) != napi_ok || napi_has_named_property(environment, global, "node_crypto", &hasProperty) != napi_ok || !hasProperty || napi_get_named_property(environment, global, "node_crypto", &crypto) != napi_ok || napi_has_named_property(environment, crypto, "randomFillSync", &hasProperty) != napi_ok || !hasProperty || napi_get_named_property(environment, crypto, "randomFillSync", &randomFillSync) != napi_ok) {
	
		// Return false
		return false;
	}
	
	// Check if creating uint8 array failed
	napi_value arrayBuffer;
	napi_value uint8Array;
	if(napi_create_arraybuffer(environment, size, nullptr, &arrayBuffer) != napi_ok || napi_create_typedarray(environment, napi_uint8_array, size, arrayBuffer, 0, &uint8Array) != napi_ok) {
	
		// Return false
		return false;
	}
	
	// Check if filling uint8 array with random values failed
	if(napi_call_function(environment, global, randomFillSync, 1, &uint8Array, nullptr) != napi_ok) {
	
		// Return false
		return false;
	}
	
	// Check if getting uint8 array's data failed
	uint8_t *data;
	if(napi_get_typedarray_info(environment, uint8Array, nullptr, nullptr, reinterpret_cast<void **>(&data), nullptr, nullptr) != napi_ok) {
	
		// Return false
		return false;
	}
	
	// Copy data to buffer
	memcpy(buffer, data, size);
	
	// Clear data
	memset(data, 0, size);
	
	// Return true
	return true;
}

// Is null
bool isNull(napi_env environment, napi_value value, bool unknownResult) {

	// Check if getting value's type failed
	napi_valuetype type;
	if(napi_typeof(environment, value, &type) != napi_ok) {
	
		// Return unknown result
		return unknownResult;
	}

	// Return if value is null
	return type == napi_null;
}
