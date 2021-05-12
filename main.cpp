#include <stdio.h>
#include <windows.h>
#include <winerror.h>
#include <ras.h>
#include <raserror.h>

// Simple Windows VPN configuration tool (using RAS API)
// By Brian Clifton (brian@clifton.me)
//
// See https://docs.microsoft.com/en-us/windows/win32/rras/remote-access-service-functions

#define DEFAULT_PHONE_BOOK NULL

// https://docs.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasenumconnectionsa
int PrintConnections() {
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
        wprintf(L"\n");
        //Deallocate memory for the connection buffer
        HeapFree(GetProcessHeap(), 0, lpRasConn);
        lpRasConn = NULL;
        return 0;
    }

    // There was either a problem with RAS or there are no connections to enumerate    
    if (dwConnections >= 1) {
        wprintf(L"The operation failed to acquire the buffer size.\n\n");
    } else {
        wprintf(L"There are no active RAS connections.\n\n");
    }

    return 0;
}

// https://docs.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasenumdevicesa
int PrintDevices() {
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
        wprintf(L"\n");
        //Deallocate memory for the connection buffer
        HeapFree(GetProcessHeap(), 0, lpRasDevInfo);
        lpRasDevInfo = NULL;
        return 0;
    }

    // There was either a problem with RAS or there are no RAS devices to enumerate    
    if (dwDevices >= 1) {
        wprintf(L"The operation failed to acquire the buffer size.\n\n");
    } else {
        wprintf(L"There were no RAS devices found.\n\n");
    }

    return 0;
}

void PrintOptions(DWORD options) {
    wprintf(L"\tdwfOptions = {\n");
    if (options & RASEO_UseCountryAndAreaCodes) wprintf(L"\t\tRASEO_UseCountryAndAreaCodes\n");
    if (options & RASEO_SpecificIpAddr) wprintf(L"\t\tRASEO_SpecificIpAddr\n");
    if (options & RASEO_SpecificNameServers) wprintf(L"\t\tRASEO_SpecificNameServers\n");
    if (options & RASEO_IpHeaderCompression) wprintf(L"\t\tRASEO_IpHeaderCompression\n");
    if (options & RASEO_RemoteDefaultGateway) wprintf(L"\t\tRASEO_RemoteDefaultGateway\n");
    if (options & RASEO_DisableLcpExtensions) wprintf(L"\t\tRASEO_DisableLcpExtensions\n");
    if (options & RASEO_TerminalBeforeDial) wprintf(L"\t\tRASEO_TerminalBeforeDial\n");
    if (options & RASEO_TerminalAfterDial) wprintf(L"\t\tRASEO_TerminalAfterDial\n");
    if (options & RASEO_ModemLights) wprintf(L"\t\tRASEO_ModemLights\n");
    if (options & RASEO_SwCompression) wprintf(L"\t\tRASEO_SwCompression\n");
    if (options & RASEO_RequireEncryptedPw) wprintf(L"\t\tRASEO_RequireEncryptedPw\n");
    if (options & RASEO_RequireMsEncryptedPw) wprintf(L"\t\tRASEO_RequireMsEncryptedPw\n");
    if (options & RASEO_RequireDataEncryption) wprintf(L"\t\tRASEO_RequireDataEncryption\n");
    if (options & RASEO_NetworkLogon) wprintf(L"\t\tRASEO_NetworkLogon\n");
    if (options & RASEO_UseLogonCredentials) wprintf(L"\t\tRASEO_UseLogonCredentials\n");
    if (options & RASEO_PromoteAlternates) wprintf(L"\t\tRASEO_PromoteAlternates\n");

#if (WINVER >= 0x401)
    if (options & RASEO_SecureLocalFiles) wprintf(L"\t\tRASEO_SecureLocalFiles\n");
#endif

#if (WINVER >= 0x500)
    if (options & RASEO_RequireEAP) wprintf(L"\t\tRASEO_RequireEAP\n");
    if (options & RASEO_RequirePAP) wprintf(L"\t\tRASEO_RequirePAP\n");
    if (options & RASEO_RequireSPAP) wprintf(L"\t\tRASEO_RequireSPAP\n");
    if (options & RASEO_Custom) wprintf(L"\t\tRASEO_Custom\n");

    if (options & RASEO_PreviewPhoneNumber) wprintf(L"\t\tRASEO_PreviewPhoneNumber\n");
    if (options & RASEO_SharedPhoneNumbers) wprintf(L"\t\tRASEO_SharedPhoneNumbers\n");
    if (options & RASEO_PreviewUserPw) wprintf(L"\t\tRASEO_PreviewUserPw\n");
    if (options & RASEO_PreviewDomain) wprintf(L"\t\tRASEO_PreviewDomain\n");
    if (options & RASEO_ShowDialingProgress) wprintf(L"\t\tRASEO_ShowDialingProgress\n");
    if (options & RASEO_RequireCHAP) wprintf(L"\t\tRASEO_RequireCHAP\n");
    if (options & RASEO_RequireMsCHAP) wprintf(L"\t\tRASEO_RequireMsCHAP\n");
    if (options & RASEO_RequireMsCHAP2) wprintf(L"\t\tRASEO_RequireMsCHAP2\n");
    if (options & RASEO_RequireW95MSCHAP) wprintf(L"\t\tRASEO_RequireW95MSCHAP\n");
    if (options & RASEO_CustomScript) wprintf(L"\t\tRASEO_CustomScript\n");
#endif

    wprintf(L"\t};\n");
}

void PrintOptions2(DWORD options) {
    wprintf(L"\tdwfOptions2 = {\n");

#if (WINVER >= 0x501)
    if (options & RASEO2_SecureFileAndPrint) wprintf(L"\t\tRASEO2_SecureFileAndPrint\n");
    if (options & RASEO2_SecureClientForMSNet) wprintf(L"\t\tRASEO2_SecureClientForMSNet\n");
    if (options & RASEO2_DontNegotiateMultilink) wprintf(L"\t\tRASEO2_DontNegotiateMultilink\n");
    if (options & RASEO2_DontUseRasCredentials) wprintf(L"\t\tRASEO2_DontUseRasCredentials\n");
    if (options & RASEO2_UsePreSharedKey) wprintf(L"\t\tRASEO2_UsePreSharedKey\n");
    if (options & RASEO2_Internet) wprintf(L"\t\tRASEO2_Internet\n");
    if (options & RASEO2_DisableNbtOverIP) wprintf(L"\t\tRASEO2_DisableNbtOverIP\n");
    if (options & RASEO2_UseGlobalDeviceSettings) wprintf(L"\t\tRASEO2_UseGlobalDeviceSettings\n");
    if (options & RASEO2_ReconnectIfDropped) wprintf(L"\t\tRASEO2_ReconnectIfDropped\n");
    if (options & RASEO2_SharePhoneNumbers) wprintf(L"\t\tRASEO2_SharePhoneNumbers\n");
#endif

#if (WINVER >= 0x600)
    if (options & RASEO2_SecureRoutingCompartment) wprintf(L"\t\tRASEO2_SecureRoutingCompartment\n");
    if (options & RASEO2_UseTypicalSettings) wprintf(L"\t\tRASEO2_UseTypicalSettings\n");
    if (options & RASEO2_IPv6SpecificNameServers) wprintf(L"\t\tRASEO2_IPv6SpecificNameServers\n");
    if (options & RASEO2_IPv6RemoteDefaultGateway) wprintf(L"\t\tRASEO2_IPv6RemoteDefaultGateway\n");
    if (options & RASEO2_RegisterIpWithDNS) wprintf(L"\t\tRASEO2_RegisterIpWithDNS\n");
    if (options & RASEO2_UseDNSSuffixForRegistration) wprintf(L"\t\tRASEO2_UseDNSSuffixForRegistration\n");
    if (options & RASEO2_IPv4ExplicitMetric) wprintf(L"\t\tRASEO2_IPv4ExplicitMetric\n");
    if (options & RASEO2_IPv6ExplicitMetric) wprintf(L"\t\tRASEO2_IPv6ExplicitMetric\n");
    if (options & RASEO2_DisableIKENameEkuCheck) wprintf(L"\t\tRASEO2_DisableIKENameEkuCheck\n");
#endif

#if (WINVER >= 0x601)
    if (options & RASEO2_DisableClassBasedStaticRoute) wprintf(L"\t\tRASEO2_DisableClassBasedStaticRoute\n");
    if (options & RASEO2_SpecificIPv6Addr) wprintf(L"\t\tRASEO2_SpecificIPv6Addr\n");
    if (options & RASEO2_DisableMobility) wprintf(L"\t\tRASEO2_DisableMobility\n");
    if (options & RASEO2_RequireMachineCertificates) wprintf(L"\t\tRASEO2_RequireMachineCertificates\n");
#endif

#if (WINVER >= 0x602)
    if (options & RASEO2_UsePreSharedKeyForIkev2Initiator) wprintf(L"\t\tRASEO2_UsePreSharedKeyForIkev2Initiator\n");
    if (options & RASEO2_UsePreSharedKeyForIkev2Responder) wprintf(L"\t\tRASEO2_UsePreSharedKeyForIkev2Responder\n");
    if (options & RASEO2_CacheCredentials) wprintf(L"\t\tRASEO2_CacheCredentials\n");
#endif

#if (WINVER >= 0x603)
    if (options & RASEO2_AutoTriggerCapable) wprintf(L"\t\tRASEO2_AutoTriggerCapable\n");
    if (options & RASEO2_IsThirdPartyProfile) wprintf(L"\t\tRASEO2_IsThirdPartyProfile\n");
    if (options & RASEO2_AuthTypeIsOtp) wprintf(L"\t\tRASEO2_AuthTypeIsOtp\n");
#endif

#if (WINVER >= 0x604)
    if (options & RASEO2_IsAlwaysOn) wprintf(L"\t\tRASEO2_IsAlwaysOn\n");
    if (options & RASEO2_IsPrivateNetwork) wprintf(L"\t\tRASEO2_IsPrivateNetwork\n");
#endif

#if (WINVER >= 0xA00)
    if (options & RASEO2_PlumbIKEv2TSAsRoutes) wprintf(L"\t\tRASEO2_PlumbIKEv2TSAsRoutes\n");
#endif

    wprintf(L"\t};");
}

int PrintEntryDetails(LPCTSTR entry_name) {
    DWORD dwCb = 0;
    DWORD dwRet = ERROR_SUCCESS;
    LPRASENTRY lpRasEntry = NULL;

    // Call RasGetEntryProperties with lpRasEntry = NULL. dwCb is returned with the required buffer size and 
    // a return code of ERROR_BUFFER_TOO_SMALL
    dwRet = RasGetEntryProperties(DEFAULT_PHONE_BOOK, entry_name, lpRasEntry, &dwCb, NULL, NULL);
    if (dwRet == ERROR_BUFFER_TOO_SMALL) {
        lpRasEntry = (LPRASENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwCb);
        if (lpRasEntry == NULL) {
            wprintf(L"HeapAlloc failed!\n");
            return 0;
        }

        // The first LPRASENTRY structure in the array must contain the structure size
        lpRasEntry[0].dwSize = sizeof(RASENTRY);
        dwRet = RasGetEntryProperties(DEFAULT_PHONE_BOOK, entry_name, lpRasEntry, &dwCb, NULL, NULL);
        switch (dwRet) {
            case ERROR_INVALID_SIZE:
                wprintf(L"An incorrect structure size was detected.\n");
                break;
        }
        
        // great place to set debug breakpoint when inspecting existing connections
        PrintOptions(lpRasEntry->dwfOptions);
        PrintOptions2(lpRasEntry->dwfOptions2);

        wprintf(L"\n");
        //Deallocate memory for the entry buffer
        HeapFree(GetProcessHeap(), 0, lpRasEntry);
        lpRasEntry = NULL;
        return 0;
    }

    return 0;
}

// https://docs.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasenumentriesa
int PrintEntries() {
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
                PrintEntryDetails(lpRasEntryName[i].szEntryName);
            }
        }
        //Deallocate memory for the connection buffer
        HeapFree(GetProcessHeap(), 0, lpRasEntryName);
        lpRasEntryName = NULL;
        return 0;
    }

    // There was either a problem with RAS or there are RAS entry names to enumerate    
    if (dwEntries >= 1) {
        wprintf(L"The operation failed to acquire the buffer size.\n\n");
    } else {
        wprintf(L"There were no RAS entry names found:.\n\n");
    }

    return 0;
}

void PrintSystemError(DWORD error) {
    LPTSTR lpMsgBuf = NULL;
    DWORD bufLen = FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        lpMsgBuf,
        0, NULL);
    if (bufLen) {
        wprintf(L"%s\n", lpMsgBuf);
        LocalFree(lpMsgBuf);
    }
}

void PrintRasError(DWORD error) {
    switch (error) {
        case ERROR_CANNOT_OPEN_PHONEBOOK:
            wprintf(L"The system could not open the phone book file.\n");
            break;
        case ERROR_CANNOT_FIND_PHONEBOOK_ENTRY:
            wprintf(L"The system could not find the phone book entry for this connection.\n");
            break;
        case ERROR_INVALID_PARAMETER:
        case ERROR_ACCESS_DENIED:
            PrintSystemError(error);
            break;
        default:
            // if you want to be fancy, you can load module handle for `Rasapi32.lib`
            if (error > RASBASE && error < RASBASEEND) {
                wprintf(L"Ras error; check RasError.h for code %d", error);
            } else {
                wprintf(L"OTHER ERROR: (%d) ", error);
                PrintSystemError(error);
            }
            break;
    }
}

// https://docs.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rassetcredentialsa
DWORD SetCredentials(LPCTSTR entry_name, LPCTSTR username, LPCTSTR password) {
    RASCREDENTIALS credentials;

    ZeroMemory(&credentials, sizeof(RASCREDENTIALS));
    credentials.dwSize = sizeof(RASCREDENTIALS);
    credentials.dwMask = RASCM_UserName | RASCM_Password;

    wcscpy_s(credentials.szUserName, 256, username);
    wcscpy_s(credentials.szPassword, 256, password);

    DWORD dwRet = RasSetCredentials(DEFAULT_PHONE_BOOK, entry_name, &credentials, FALSE);
    if (dwRet != ERROR_SUCCESS) {
        PrintRasError(dwRet);
        return dwRet;
    }

    return ERROR_SUCCESS;
}

// https://docs.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rassetentrypropertiesa
DWORD CreateEntry(LPCTSTR entry_name, LPCTSTR hostname, LPCTSTR username, LPCTSTR password) {
    RASENTRY entry;
    ZeroMemory(&entry, sizeof(RASENTRY));
    // For descriptions of each field (including valid values) see:
    // https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa377274(v=vs.85)
    entry.dwSize = sizeof(RASENTRY);
    entry.dwfOptions = RASEO_RemoteDefaultGateway | RASEO_RequireEAP | RASEO_PreviewUserPw | RASEO_PreviewDomain | RASEO_ShowDialingProgress;
    wcscpy_s(entry.szLocalPhoneNumber, 128, hostname);
    entry.dwfNetProtocols = RASNP_Ip | RASNP_Ipv6;
    entry.dwFramingProtocol = RASFP_Ppp;
    wcscpy_s(entry.szDeviceType, 16, RASDT_Vpn);
    wcscpy_s(entry.szDeviceName, 128, TEXT("WAN Miniport (IKEv2)"));
    entry.dwType = RASET_Vpn;
    entry.dwEncryptionType = ET_Require; //3 = ET_Optional
    entry.dwCustomAuthKey = 26; //???
    // entry.guidId ??
    entry.dwVpnStrategy = VS_Ikev2Only;
    entry.dwfOptions2 = RASEO2_DontNegotiateMultilink | RASEO2_ReconnectIfDropped | RASEO2_IPv6RemoteDefaultGateway | RASEO2_CacheCredentials;  

    DWORD dwRet = RasSetEntryProperties(DEFAULT_PHONE_BOOK, entry_name, &entry, entry.dwSize, NULL, NULL);
    if (dwRet != ERROR_SUCCESS) {
        PrintRasError(dwRet);
        return dwRet;
    }

    //AuthenticationTransformConstants: GCMAES256
    //CipherTransformConstants : GCMAES256
    //DHGroup : ECP384
    //IntegrityCheckMethod : SHA256
    //PfsGroup : None
    //EncryptionMethod : GCMAES256


    // TODO: what options needed?
    // - `Provider` should be `Windows (built-in)
    // - `Credentials` - are they set here? or separately (ex: with RasSetCredentials)
    SetCredentials(entry_name, username, password);

    return ERROR_SUCCESS;
}

int wmain(int argc, wchar_t* argv[]) {    
    if (argc == 1) {
        wprintf(L"usage: winvpntool.exe [--connections] [--devices] [--entries]");
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"--connections") == 0) {
            PrintConnections();
        }
        if (wcscmp(argv[i], L"--devices") == 0) {
            PrintDevices();
        }
        if (wcscmp(argv[i], L"--entries") == 0) {
            PrintEntries();
        }

        if (wcscmp(argv[i], L"--create") == 0) {
            // TODO: parse name/hostname/username/password
            // TODO: make this create OR update
            CreateEntry(TEXT("BUBBA"), TEXT("hostname.website.com"), TEXT("bsmith"), TEXT("Password1!"));
        }
        
        // TODO: --remove (parse name)
    }

	return 0;
}