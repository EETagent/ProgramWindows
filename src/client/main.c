#include "include/requests.h"

// ICMP
int SendICMP(char* gDestination, REQUEST_TYPE request_type);

#define SendICMP_GetHello(gDestination) SendICMP(char* gDestination, HELLO);
#define SendICMP_GetOrders(gDestination) SendICMP(char* gDestination, GET_INFORMATION);
#define SendICMP_GetPayload(gDestination) SendICMP(char* gDestination, GET_PAYLOAD);

// HTTP
int SendHTTP(char* gDestination, REQUEST_TYPE request_type);

#define SendHTTP_GetHello(gDestination) SendHTTP(char* gDestination, HELLO);
#define SendHTTP_GetOrders(gDestination) SendHTTP(char* gDestination, GET_INFORMATION);
#define SendHTTP_GetPayload(gDestination) SendHTTP(char* gDestination, GET_PAYLOAD);


int main(void) {
	SendICMP("8.8.8.8", HELLO);
	return 0;
}
