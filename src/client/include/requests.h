typedef enum requset_type {
	HELLO,
	GET_INFORMATION,
	GET_PAYLOAD
} REQUEST_TYPE;

typedef enum payload_type {
	DLL_PAYLOAD,
	EXE_PAYLOAD,
	ABORT_PAYLOAD
} PAYLOAD_TYPE;