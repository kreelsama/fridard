#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <ws2def.h>
#include <stdio.h>

#pragma comment (lib, "Ws2_32.lib")
#define EXPORT_SYMBOL __declspec(dllexport)
void init(void) {
    printf("C initialized");
}

EXPORT_SYMBOL int get_address_info(_In_ const SOCKADDR* raddr, _Out_ char* dst){
    USHORT sa_family = raddr->sa_family;
    char *addr = raddr->sa_data;
    if(!dst)
        return 1;
    const len = 14; // the length of sa_data is fixed
    int port = *addr;
    addr += 1;
    port = (port << 8) + (*addr);
    addr += 1;

    if (sa_family == AF_INET6){
        *dst = '['; // ipv6 address wapped with brackets
        inet_ntop(sa_family, addr, dst+1, 46);
    }
    else {
        inet_ntop(sa_family, addr, dst, 46);
    }

    for(int i = 0; i < 100; ++i) {
        dst +=1 ;
        if(!*dst) {
            break;
        }
    }
    if (sa_family == AF_INET6){
        *dst = ']';
    }

    return port;
}

EXPORT_SYMBOL int get_connect_state(){
    if(WSAGetLastError() == WSAEWOULDBLOCK) {
        return 0; // success
    }
    else {
        return 1; // failed
    }
}

EXPORT_SYMBOL int get_address_info_from_addrinfo(_In_ const PADDRINFOA* ainfo, _Out_ char* dst){
    return get_address_info((*ainfo)->ai_addr, dst);
}