#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <microhttpd.h>
#include <ctype.h>
#include <unistd.h>
#include <pwd.h>
#include <regex.h>

#define MAX_PARAM_LENGTH 1024
#define MAX_COMMAND_LENGTH 2048
#define PORT 8888

// gcc -o server server.c -lmicrohttpd -lpthread -lgnutls -static

// MAC地址验证正则表达式
const char* MAC_REGEX = "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$";

// IP地址验证正则表达式
const char* IP_REGEX = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";

// URL解码函数
void url_decode(char *src) {
    char *dst = src;
    char a, b;
    while (*src) {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a')
                a -= 'a'-'A';
            if (a >= 'A')
                a -= ('A' - 10);
            else
                a -= '0';
            if (b >= 'a')
                b -= 'a'-'A';
            if (b >= 'A')
                b -= ('A' - 10);
            else
                b -= '0';
            *dst++ = 16*a+b;
            src+=3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

// 正则表达式验证函数
int validate_regex(const char* str, const char* regex_pattern) {
    regex_t regex;
    int reti;
    
    reti = regcomp(&regex, regex_pattern, REG_EXTENDED);
    if (reti) {
        fprintf(stderr, "Could not compile regex\n");
        return 0;
    }
    
    reti = regexec(&regex, str, 0, NULL, 0);
    regfree(&regex);
    
    return reti == 0;
}

// 安全地执行系统命令
int execute_safe_command(const char* cmd, const char* param1, const char* param2, const char* param3) {
    char sanitized_cmd[MAX_COMMAND_LENGTH];
    
    // 处理 shutdown 指令
    if (strcmp(cmd, "shutdown") == 0) {
        if (geteuid() != 0) {
            printf("Need root privileges to shutdown\n");
            return -1;
        }
        printf("Shutdown command authorized and executing...\n");
        return system("/usr/sbin/shutdown");
    }
    
    // 处理 wakeup 指令
    if (strcmp(cmd, "wakeup") == 0) {
        if (!param1 || !param2) {
            printf("Wakeup requires interface and MAC address\n");
            return -1;
        }

        if (!validate_regex(param2, MAC_REGEX)) {
            printf("Invalid MAC address: %s\n", param2);
            return -1;
        }

        snprintf(sanitized_cmd, sizeof(sanitized_cmd), 
                 "/usr/sbin/etherwake -i %s %s", 
                 param1,   // interface
                 param2    // MAC address
        );

        printf("Executing wake-on-lan command: %s\n", sanitized_cmd);
        return system(sanitized_cmd);
    }

    // 处理 turnoffpc 指令，使用分离的参数
    if (strcmp(cmd, "turnoffpc") == 0) {
        // 检查所有必需参数
        if (!param1 || !param2 || !param3) {
            printf("Turnoff PC requires IP, username and password\n");
            return -1;
        }

        // 验证IP地址
        if (!validate_regex(param1, IP_REGEX)) {
            printf("Invalid IP address: %s\n", param1);
            return -1;
        }

        // 构造带有&分隔符的命令
        snprintf(sanitized_cmd, sizeof(sanitized_cmd), 
                "/usr/bin/net rpc shutdown -I %s -U %s%%%s", 
                param1,    // IP
                param2,    // username
                param3     // password
        );

        printf("Executing turnoff PC command: %s\n", sanitized_cmd);
        return system(sanitized_cmd);
    }

    printf("Unauthorized command: %s\n", cmd);
    return -1;
}

// 处理请求的回调函数
static enum MHD_Result answer_to_connection(void *cls, struct MHD_Connection *connection,
                                const char *url, const char *method,
                                const char *version, const char *upload_data,
                                size_t *upload_data_size, void **con_cls) {
    const char *cmd, *interface, *mac, *ip, *user, *passwd;
    char response_text[1024];
    struct MHD_Response *response;
    enum MHD_Result ret;

    // 仅处理GET请求
    if (0 != strcmp(method, "GET")) {
        return MHD_NO;
    }

    // 获取查询参数
    cmd = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "cmd");
    interface = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "interface");
    mac = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "mac");
    ip = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "ip");
    user = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "user");
    passwd = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "passwd");
    
    if (cmd == NULL) {
        snprintf(response_text, sizeof(response_text), 
                "Error: No command parameter provided. Use:\n"
                "1. ?cmd=shutdown\n"
                "2. ?cmd=wakeup&interface=eth0&mac=00:11:22:33:44:55\n"
                "3. ?cmd=turnoffpc&ip=192.168.1.100&user=username&passwd=password");
        response = MHD_create_response_from_buffer(strlen(response_text),
                                                (void *)response_text,
                                                MHD_RESPMEM_MUST_COPY);
        ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
        MHD_destroy_response(response);
        return ret;
    }

    // 执行命令并准备响应
    int cmd_result;
    if (strcmp(cmd, "wakeup") == 0) {
        cmd_result = execute_safe_command(cmd, interface, mac, NULL);
    } else if (strcmp(cmd, "turnoffpc") == 0) {
        cmd_result = execute_safe_command(cmd, ip, user, passwd);
    } else {
        cmd_result = execute_safe_command(cmd, NULL, NULL, NULL);
    }
    
    if (cmd_result == 0) {
        if (strcmp(cmd, "shutdown") == 0) {
            snprintf(response_text, sizeof(response_text), 
                     "Shutdown command executed successfully");
        } else if (strcmp(cmd, "wakeup") == 0) {
            snprintf(response_text, sizeof(response_text), 
                     "Wake-on-LAN command executed successfully for %s", mac);
        } else if (strcmp(cmd, "turnoffpc") == 0) {
            snprintf(response_text, sizeof(response_text), 
                     "Turn off PC command executed successfully for %s", ip);
        } else {
            snprintf(response_text, sizeof(response_text), 
                     "Command executed successfully");
        }
        
        response = MHD_create_response_from_buffer(strlen(response_text),
                                                   (void *)response_text,
                                                   MHD_RESPMEM_MUST_COPY);
        ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret;
    } else {
        snprintf(response_text, sizeof(response_text), 
                 "Command execution failed");
        
        response = MHD_create_response_from_buffer(strlen(response_text),
                                                   (void *)response_text,
                                                   MHD_RESPMEM_MUST_COPY);
        ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
        MHD_destroy_response(response);
        return ret;
    }
}

int main() {
    struct MHD_Daemon *daemon;

    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root to execute commands\n");
        return 1;
    }

    daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, PORT, 
                               NULL, NULL,
                               answer_to_connection, NULL,
                               MHD_OPTION_END);
    if (NULL == daemon) {
        printf("Failed to start server on port %d\n", PORT);
        return 1;
    }

    printf("Command Server running on http://localhost:%d\n", PORT);
    printf("Use formats:\n");
    printf("1. Shutdown: http://localhost:%d/?cmd=shutdown\n", PORT);
    printf("2. Wake-on-LAN: http://localhost:%d/?cmd=wakeup&interface=eth0&mac=00:11:22:33:44:55\n", PORT);
    printf("3. Turn off PC: http://localhost:%d/?cmd=turnoffpc&ip=192.168.1.100&user=username&passwd=password\n\n", PORT);
    printf("Use Ctrl+C to stop the program\n\n");
    pause();

    MHD_stop_daemon(daemon);
    return 0;
}
