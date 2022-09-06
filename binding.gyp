{
	"targets": [
		{
			"target_name": "libsecp256k1_zkp",
			"type": "static_library",
			"sources": [
				"./secp256k1-zkp-master/src/secp256k1.c"
			],
			"include_dirs": [
				"./secp256k1-zkp-master/",
				"./secp256k1-zkp-master/src"
			],
			"defines": [
				"USE_ENDOMORPHISM",
				"USE_NUM_NONE",
				"USE_FIELD_INV_BUILTIN",
				"USE_SCALAR_INV_BUILTIN",
				"USE_FIELD_10X26",
				"USE_SCALAR_8X32",
				"ENABLE_MODULE_ECDH",
				"ENABLE_MODULE_GENERATOR",
				"ENABLE_MODULE_COMMITMENT",
				"ENABLE_MODULE_BULLETPROOF",
				"ENABLE_MODULE_AGGSIG"
			]
		},
		{
			"target_name": "secp256k1_zkp",
			"dependencies": [
				"libsecp256k1_zkp"
			],
			"sources": [
				"./main.cpp"
			],
			"include_dirs": [
				"./secp256k1-zkp-master/include/"
			]
		}
	]
}
