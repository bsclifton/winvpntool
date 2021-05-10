#include <iostream>
#include <string>
#include <windows.h>
#include <winerror.h>
#include <ras.h>
#include <raserror.h>

// Windows VPN Proof of Concept
// Using RAS API

// https://docs.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasenumconnectionsa
int EnumConnections() {
    DWORD dwCb = 0;
    DWORD dwRet = ERROR_SUCCESS;
    DWORD dwConnections = 0;
    LPRASCONN lpRasConn = NULL;

    // Call RasEnumConnections with lpRasConn = NULL. dwCb is returned with the required buffer size and 
    // a return code of ERROR_BUFFER_TOO_SMALL
    dwRet = RasEnumConnections(lpRasConn, &dwCb, &dwConnections);
    if (dwRet == ERROR_BUFFER_TOO_SMALL) {
        // Allocate the memory needed for the array of RAS structure(s).
        lpRasConn = (LPRASCONN)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwCb);
        if (lpRasConn == NULL) {
            wprintf(L"HeapAlloc failed!\n");
            return 0;
        }
        // The first RASCONN structure in the array must contain the RASCONN structure size
        lpRasConn[0].dwSize = sizeof(RASCONN);

        // Call RasEnumConnections to enumerate active connections
        dwRet = RasEnumConnections(lpRasConn, &dwCb, &dwConnections);

        // If successful, print the names of the active connections.
        if (ERROR_SUCCESS == dwRet) {
            wprintf(L"The following RAS connections are currently active:\n");
            for (DWORD i = 0; i < dwConnections; i++) {
                wprintf(L"%s\n", lpRasConn[i].szEntryName);
            }
        }
        //Deallocate memory for the connection buffer
        HeapFree(GetProcessHeap(), 0, lpRasConn);
        lpRasConn = NULL;
        return 0;
    }

    // There was either a problem with RAS or there are no connections to enumerate    
    if (dwConnections >= 1) {
        wprintf(L"The operation failed to acquire the buffer size.\n");
    } else {
        wprintf(L"There are no active RAS connections.\n");
    }

    return 0;
}

// https://docs.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasenumdevicesa
int EnumDevices() {
    DWORD dwCb = 0;
    DWORD dwRet = ERROR_SUCCESS;
    DWORD dwDevices = 0;
    LPRASDEVINFO lpRasDevInfo = NULL;

    // Call RasEnumDevices with lpRasDevInfo = NULL. dwCb is returned with the required buffer size and 
    // a return code of ERROR_BUFFER_TOO_SMALL
    dwRet = RasEnumDevices(lpRasDevInfo, &dwCb, &dwDevices);

    if (dwRet == ERROR_BUFFER_TOO_SMALL) {
        // Allocate the memory needed for the array of RAS structure(s).
        lpRasDevInfo = (LPRASDEVINFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwCb);
        if (lpRasDevInfo == NULL) {
            wprintf(L"HeapAlloc failed!\n");
            return 0;
        }
        // The first RASDEVINFO structure in the array must contain the structure size
        lpRasDevInfo[0].dwSize = sizeof(RASDEVINFO);

        // Call RasEnumDevices to enumerate RAS devices
        dwRet = RasEnumDevices(lpRasDevInfo, &dwCb, &dwDevices);

        // If successful, print the names of the RAS devices
        if (ERROR_SUCCESS == dwRet) {
            wprintf(L"The following RAS devices were found:\n");
            for (DWORD i = 0; i < dwDevices; i++) {
                wprintf(L"%s\n", lpRasDevInfo[i].szDeviceName);
            }
        }
        //Deallocate memory for the connection buffer
        HeapFree(GetProcessHeap(), 0, lpRasDevInfo);
        lpRasDevInfo = NULL;
        return 0;
    }

    // There was either a problem with RAS or there are no RAS devices to enumerate    
    if (dwDevices >= 1) {
        wprintf(L"The operation failed to acquire the buffer size.\n");
    } else {
        wprintf(L"There were no RAS devices found.\n");
    }

    return 0;
}

// https://docs.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasenumentriesa
int EnumEntries() {
    DWORD dwCb = 0;
    DWORD dwRet = ERROR_SUCCESS;
    DWORD dwEntries = 0;
    LPRASENTRYNAME lpRasEntryName = NULL;

    // Call RasEnumEntries with lpRasEntryName = NULL. dwCb is returned with the required buffer size and 
    // a return code of ERROR_BUFFER_TOO_SMALL
    dwRet = RasEnumEntries(NULL, NULL, lpRasEntryName, &dwCb, &dwEntries);

    if (dwRet == ERROR_BUFFER_TOO_SMALL) {
        // Allocate the memory needed for the array of RAS entry names.
        lpRasEntryName = (LPRASENTRYNAME)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwCb);
        if (lpRasEntryName == NULL) {
            wprintf(L"HeapAlloc failed!\n");
            return 0;
        }
        // The first RASENTRYNAME structure in the array must contain the structure size
        lpRasEntryName[0].dwSize = sizeof(RASENTRYNAME);

        // Call RasEnumEntries to enumerate all RAS entry names
        dwRet = RasEnumEntries(NULL, NULL, lpRasEntryName, &dwCb, &dwEntries);

        // If successful, print the RAS entry names 
        if (ERROR_SUCCESS == dwRet) {
            wprintf(L"The following RAS entry names were found:\n");
            for (DWORD i = 0; i < dwEntries; i++) {
                wprintf(L"%s\n", lpRasEntryName[i].szEntryName);
            }
        }
        //Deallocate memory for the connection buffer
        HeapFree(GetProcessHeap(), 0, lpRasEntryName);
        lpRasEntryName = NULL;
        return 0;
    }

    // There was either a problem with RAS or there are RAS entry names to enumerate    
    if (dwEntries >= 1) {
        wprintf(L"The operation failed to acquire the buffer size.\n");
    } else {
        wprintf(L"There were no RAS entry names found:.\n");
    }

    return 0;
}

int main() {
    std::cout << "[RAS (Remote Access Service) demo]\nSee https://docs.microsoft.com/en-us/windows/win32/rras/remote-access-service-functions for more info\n\n";
    EnumConnections();

    std::cout << std::endl;
    EnumDevices();

    std::cout << std::endl;
    EnumEntries();
	
    /*
    RASCONN abc;

    DWORD result = RasCreatePhonebookEntry(HWND_DESKTOP, L"DEMO1");
    if (result == ERROR_SUCCESS) {
        std::cout << "success";
    } else {
        std::cout << "failure";
    }*/

	return 0;
}