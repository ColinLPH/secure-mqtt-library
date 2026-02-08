#include "smqtt_common.h"

int smqtt_socket(){
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);

    return fd;
}

/**
    need key, packet, place to send to
    encrypt packet
    compile full payload, deserialize smqtt packet
    send_all thing
    return 0 success
    -1 for failure and logs error

    ** NEED TO THINK ABOUT QoS ie. linked list, 
        but doesnt belong in this function
    All this function does is encrypt and send
    All thats required are the packet, the key+nonce, and the destination fd

    params: packet struct, crypto struct (key, nonce counter), destination fd
 */
int smqtt_send(smqtt_pkt *packet, crypto *crypt, int dest_fd){
    
}

// int smqtt_recv(){

// }

//-------------------------------------------------------------
// Utils
//-------------------------------------------------------------

// void print_hex(const char *label, const unsigned char *buf, size_t len) {
//     printf("%s: ", label);
//     for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
//     printf("\n");
// }

ssize_t send_all(int sock, const unsigned char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sock, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return sent;
}

ssize_t recv_all(int sock, unsigned char *buf, size_t len) {
    size_t recvd = 0;
    while (recvd < len) {
        ssize_t n = recv(sock, buf + recvd, len - recvd, 0);
        if (n <= 0) return -1;
        recvd += n;
    }
    return recvd;
}
