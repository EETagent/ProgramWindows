#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#include "../../include/requests.h"

INT SendHTTP(LPSTR destination, REQUEST_TYPE request_type) {
    switch (request_type) {
        default:    
        case GET_HELLO:
            return 0;
        case GET_INSTRUCTION:
            return SendHTTP_Text(destination);
        case GET_PAYLOAD:
            return 1;
    }
}

INT SendHTTP_Text(LPSTR destination) {
    INT status;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    BOOL bResults = FALSE;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

    LPWSTR destination_w[100];
    MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, destination, -1, destination_w, 100);

    hSession = WinHttpOpen(L"WinHTTP Pozadavek",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    // HTTP server
    if (hSession)
        hConnect = WinHttpConnect(hSession, destination_w,
            INTERNET_DEFAULT_HTTPS_PORT, 0);

    // Otevøení HTTP požadavku
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", NULL,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);

    // Odeslání požadavku.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);

    // Pøijetí odpovìdi
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);

    if (bResults) {
        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                printf("Error %u in WinHttpQueryDataAvailable.\n",
                    GetLastError());

            pszOutBuffer = malloc(dwSize + 1);

            if (!pszOutBuffer) {
                printf("Out of memory\n");
                dwSize = 0;
            }
            else {
                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                else
                    printf("%s", pszOutBuffer);

                free(pszOutBuffer);
            }
        } while (dwSize > 0);
    }


    if (!bResults) {
        printf("Error %d has occurred.\n", GetLastError());
        status = 1;
        goto CLEANUP;
    }

    status = 0;

CLEANUP:
    if (hRequest) 
        WinHttpCloseHandle(hRequest);
    if (hConnect) 
        WinHttpCloseHandle(hConnect);
    if (hSession) 
        WinHttpCloseHandle(hSession);
EXIT:
    return status;
}