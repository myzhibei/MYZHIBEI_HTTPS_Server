
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAXBUF 1024
#define O_RDONLY 00

#define ISspace(x) isspace((int)(x))
// 函数说明：检查参数c是否为空格字符，
// 也就是判断是否为空格(' ')、定位字符(' \t ')、CR(' \r ')、换行(' \n ')、垂直定位字符(' \v ')或翻页(' \f ')的情况。
// 返回值：若参数c 为空白字符，则返回非 0，否则返回 0。

#define SERVER_STRING "Server: MYZHIBEI_Server/1.0\r\n" // 定义server名称
// #define IPSTR "192.168.145.129"
#define IPSTR "10.0.0.1"
const char *get_file_type(const char *);
void *accept_request(void *);
void *accept_request_ssl(void *);
void bad_request_ssl(SSL *);
void cat(int, FILE *);
void cat_ssl(SSL *, FILE *, int);
void cat_range_ssl(SSL *ssl, FILE *, int);
void error_die(const char *);
int get_line(int, char *, int);
void headers(int, const char *);
void headers_ssl(SSL *, const char *);
void not_found(int);
void not_found_ssl(SSL *);
void serve_file(int, const char *);
int startup(u_short *, int);
void unimplemented(int);
void unimplemented_ssl(SSL *);
void mov_to_ssl(int, const char *);
void serve_file_ssl(SSL *, char *, off_t, off_t, int);
void do_error_ssl(SSL *, char *, char *, char *, char *);

struct accSktArgs {
    int server_sock;
    int client_sock;
};
struct sslAccArgs {
    SSL_CTX *ctx;
    int client_socket;
    char rootdir[1024];
};
typedef struct
{
    const char *type;
    const char *value;
} mime_type_t;
mime_type_t mime[] =
    {
        {".html", "text/html"},
        {".xml", "text/xml"},
        {".xhtml", "application/xhtml+xml"},
        {".txt", "text/plain"},
        {".rtf", "application/rtf"},
        {".pdf", "application/pdf"},
        {".word", "application/msword"},
        {".png", "image/png"},
        {".gif", "image/gif"},
        {".jpg", "image/jpeg"},
        {".jpeg", "image/jpeg"},
        {".au", "audio/basic"},
        {".mpeg", "video/mpeg"},
        {".mpg", "video/mpeg"},
        {".mp4", "video/mp4"},
        {".avi", "video/x-msvideo"},
        {".gz", "application/x-gzip"},
        {".tar", "application/x-tar"},
        {".css", "text/css"},
        {NULL, "text/plain"}};
// 接收客户端http的连接，并读取请求数据转到https
void *accept_request(void *accarg)
{
    struct accSktArgs accArg = *(struct accSktArgs *)accarg;
    int client = accArg.client_sock;

    char buf[MAXBUF];
    int numchars;
    char method[255];
    char url[255];
    char path[512];
    size_t i, j;
    struct stat st;
    int cgi = 0; /* becomes true if server decides this is a CGI program */
    char *query_string = NULL;
    // 获取一行HTTP报文数据
    numchars = get_line(client, buf, sizeof(buf));
    printf("\nREQUEST === %s", buf);
    //
    i = 0;
    j = 0;
    // 对于HTTP报文来说，第一行的内容即为报文的起始行，格式为<method> <request-URL> <version>，
    // 每个字段用空白字符相连
    while (!ISspace(buf[j]) && (i < sizeof(method) - 1)) {
        // 提取其中的请求方式是GET还是POST
        method[i] = buf[j];
        i++;
        j++;
    }
    method[i] = '\0';
    // 函数说明：strcasecmp()用来比较参数s1 和s2 字符串，比较时会自动忽略大小写的差异。
    // 返回值：若参数s1 和s2 字符串相同则返回0。s1 长度大于s2 长度则返回大于0 的值，s1 长度若小于s2 长度则返回小于0 的值。
    if (strcasecmp(method, "GET")) {
        // 仅实现了GET
        unimplemented(client);
        return NULL;
    }
    i = 0;
    // 将method后面的后边的空白字符略过
    while (ISspace(buf[j]) && (j < sizeof(buf)))
        j++;
    // 继续读取request-URL
    while (!ISspace(buf[j]) && (i < sizeof(url) - 1) && (j < sizeof(buf))) {
        url[i] = buf[j];
        i++;
        j++;
    }
    url[i] = '\0';
    // 如果是GET请求，url可能会带有?,有查询参数
    if (strcasecmp(method, "GET") == 0) {
        query_string = url;
        while ((*query_string != '?') && (*query_string != '\0'))
            query_string++;
        if (*query_string == '?') {
            // 将解析参数截取下来
            *query_string = '\0';
            query_string++;
        }
    }
    printf("GET URL=== %s\n", url);
    //==============================================
    // 开启http转https
    char toURL[MAXBUF];
    sprintf(toURL, "https://%s%s", IPSTR, url);
    mov_to_ssl(client, toURL);
    //==============================================
    while ((numchars > 0) && strcmp("\n", buf)) // 将HTTP请求头读取并丢弃
        numchars = get_line(client, buf, sizeof(buf));
    close(client);
    printf(" Finished... \n");
    return NULL;
}
// 接受https连接
void *accept_request_ssl(void *accarg)
{
    struct sslAccArgs accArg = *(struct sslAccArgs *)accarg;
    int client = accArg.client_socket;
    SSL *ssl;
    ssl = SSL_new(accArg.ctx); /* 基于 ctx 产生一个新的 SSL */
    SSL_set_fd(ssl, client);   /* 将连接用户的 socket 加入到 SSL */
    printf("SSL accept %d return :%d \n", client, SSL_accept(ssl));
    char buf[MAXBUF];
    int numchars;
    char method[255];
    char url[255];
    char path[512];
    size_t i, j;
    struct stat st;
    char *query_string = NULL;
    char sslrow[1024];
    numchars = SSL_read(ssl, buf, MAXBUF);
    if (numchars != 0) {
        printf("接收消息成功:\n'%s'，共%d个字节的数据\n", buf, numchars);
    }
    strcpy(sslrow, buf);
    printf("\n REQUEST === %s", sslrow);
    i = 0;
    j = 0;
    // 对于HTTP报文来说，第一行的内容即为报文的起始行，格式为<method> <request-URL> <version>，
    // 每个字段用空白字符相连
    while (!ISspace(sslrow[j]) && (i < sizeof(method) - 1)) {
        // 提取其中的请求方式是GET还是POST
        method[i] = sslrow[j];
        i++;
        j++;
    }
    method[i] = '\0';
    printf("method === %s\n", method);
    // 函数说明：strcasecmp()用来比较参数s1 和s2 字符串，比较时会自动忽略大小写的差异。
    // 返回值：若参数s1 和s2 字符串相同则返回0。s1 长度大于s2 长度则返回大于0 的值，s1 长度若小于s2 长度则返回小于0 的值。
    if (strcasecmp(method, "GET")) {
        // 仅实现了GET和POST
        unimplemented_ssl(ssl);
        printf("Finished...\n\n");
        SSL_shutdown(ssl); // 关闭 SSL 连接
        SSL_free(ssl);     // 释放 SSL */
        close(client);     // 因为http是面向无连接的，所以要关闭
        return NULL;
    }
    i = 0;
    // 将method后面的后边的空白字符略过
    while (ISspace(sslrow[j]) && (j < sizeof(sslrow)))
        j++;
    while (!ISspace(sslrow[j]) && (i < sizeof(url) - 1) && (j < sizeof(sslrow))) {
        url[i] = sslrow[j];
        // printf("%ld %c , %ld %c \n",j,sslrow[j],i,url[i]);
        i++;
        j++;
    }
    url[i] = '\0';
    printf("URI=== %s\n", url);
    // 如果是GET请求，url可能会带有?,有查询参数
    if (strcasecmp(method, "GET") == 0) {
        query_string = url;
        while ((*query_string != '?') && (*query_string != '\0'))
            query_string++;
        if (*query_string == '?') {
            // 将解析参数截取下来
            *query_string = '\0';
            query_string++;
            printf("Query_string=== %s\n", query_string);
        }
    }
    // 以上已经将起始行解析完毕
    //  url中的路径格式化到path
    printf("GET URL=== %s\n", url);
    sprintf(path, ".%s", url);
    // 如果path只是一个目录，默认设置为首页index.html
    if (path[strlen(path) - 1] == '/')
        strcat(path, "index.html");
    printf("GET PATH === %s\n", path);
    // 函数定义: int stat(const char *file_name, struct stat *buf);
    // 函数说明: 通过文件名filename获取文件信息，并保存在buf所指的结构体stat中
    // 返回值: 执行成功则返回0，失败返回-1，错误代码存于errno（需要include <errno.h>）
    if (stat(path, &st) == -1) {
        // 访问的网页不存在
        not_found_ssl(ssl);
        printf("Finished...\n\n");
        SSL_shutdown(ssl); // 关闭 SSL 连接
        SSL_free(ssl);     // 释放 SSL */
        close(client);
        return NULL;
    } else {
        printf("%s exist ! \n", path);
        // 如果访问的网页存在则进行处理
        if ((st.st_mode & S_IFMT) == S_IFDIR) // S_IFDIR代表目录
            // 如果路径是个目录，那就将主页进行显示
            strcat(path, "/index.html");
        if ((st.st_mode & S_IXGRP) || (st.st_mode & S_IXOTH)) {
            // S_IXGRP:用户组具可执行权限
            // S_IXOTH:其他用户具可读取权限
            printf("400 bad request === %s \n", query_string);
            bad_request_ssl(ssl);
            printf("Finished...\n\n");
            SSL_shutdown(ssl); // 关闭 SSL 连接
            SSL_free(ssl);     // 释放 SSL */
            close(client);     // 因为http是面向无连接的，所以要关闭
            return NULL;
        } else {
            off_t offset = 0;
            off_t size = -1;
            char strbuf[255];
            char res[3][255];
            long int intRes[2];
            intRes[0] = intRes[1] = 0L;
            int y = sscanf(sslrow, "%*[^R]%[^:]", res[0]);
            printf("Y:%d cmp:%d\n", &y, strcmp(res[0], "Range") == 0);
            if (!(strcmp(res[0], "Range") == 0)) {
                printf("no range  : %s\n", res[0]);
                printf("%d\n", strcmp(res[0], "Range") == 0);
                serve_file_ssl(ssl, path, 0, 0, 0);
            } else {
                printf("range: %s\n", res[0]);
                int cnt = sscanf(sslrow, "%*[^=]%s", res[0]);
                printf("%s\n %ld-%ld\n", res[0], intRes[0], intRes[1]);
                char tmp[255];
                strcpy(tmp, res[0]);
                printf("tmp  : %s\n", tmp);
                int cd = sscanf(tmp, "=%[0-9]-%[0-9]", res[1], res[2]);
                // int cd = sscanf(tmp, "=%ld-%ld%s", intRes[0], intRes[1], res[0]);
                printf("!!!=%s-%s\n", res[1], res[2]);
                offset = atoi(&res[1]);
                size = atoi(&res[2]) - offset;
                printf("%d  %d\n", offset, size);
                serve_file_ssl(ssl, path, offset, size, 1);
                // 将静态文件返回
                printf("serve file === %s \n", path);
                // serve_file_ssl(ssl, path, 0, -1);
            }
        }
    }
    printf("Finished...\n\n");
    SSL_shutdown(ssl); // 关闭 SSL 连接
    SSL_free(ssl);     // 释放 SSL */
    close(client);     // 因为http是面向无连接的，所以要关闭
    return NULL;
}

void bad_request_ssl(SSL *ssl)
{
    char buf[MAXBUF];
    // 发送400
    strcpy(buf, "HTTP/1.1 400 BAD REQUEST\r\n");
    sprintf(buf, "%sContent-type: text/html\r\n", buf);
    sprintf(buf, "%s\r\n", buf);
    sprintf(buf, "%s<P>Your browser sent a bad request \r\n", buf);
    SSL_write(ssl, buf, sizeof(buf));
}

void cat_ssl(SSL *ssl, FILE *resource, int sizeoffile)
{
    char buf[MAXBUF] = {0};
    char str[1024];
    while (!feof(resource)) // 判断文件是否读取到末尾
    {
        // 读取并发送文件内容
        fread(buf, sizeof(char), sizeof(buf) - 1, resource);
        strcpy(str, buf);
        printf("sended %ld / %ld batyes : \n", sizeof(buf) - 1, sizeoffile);
        SSL_write(ssl, str, sizeof(str) - 1);
    }
}

void cat(int client, FILE *resource)
{
    printf("Sending File...\n");
    // 发送文件的内容
    char buf[MAXBUF];
    // 读取文件到buf中
    fgets(buf, sizeof(buf), resource);
    while (!feof(resource)) // 判断文件是否读取到末尾
    {
        // 读取并发送文件内容
        send(client, buf, strlen(buf), 0);
        fgets(buf, sizeof(buf), resource);
    }
}

void error_die(const char *sc)
{
    perror(sc);
    exit(1);
}

// 解析一行http报文
int get_line(int sock, char *buf, int size)
{ // 得到一行数据,只要发现c为\n,就认为是一行结束，如果读到\r,再用MSG_PEEK的方式读入一个字符，如果是\n，从socket读出
    // 如果是下个字符则不处理，将c置为\n，结束。如果读到的数据为0中断，或者小于0，也视为结束，c置为\n
    int i = 0;
    char c = '\0';
    int n;

    while ((i < size - 1) && (c != '\n')) {
        n = recv(sock, &c, 1, 0);
        if (n > 0) {
            if (c == '\r') {
                n = recv(sock, &c, 1, MSG_PEEK); // 偷窥一个字节，如果是\n就读走
                if ((n > 0) && (c == '\n'))
                    recv(sock, &c, 1, 0);
                else
                    // 不是\n（读到下一行的字符）或者没读到，置c为\n 跳出循环,完成一行读取
                    c = '\n';
            }
            buf[i] = c;
            i++;
        } else
            c = '\n';
    }
    buf[i] = '\0';
    return (i);
}

// 加入http的headers
void headers_ssl(SSL *ssl, const char *filename)
{
    char buf[1024];
    const char *dot_pos = strchr(filename + 1, '.');
    const char *file_type = get_file_type(dot_pos);
    printf("file %s type %s=== %s\n", filename, dot_pos, file_type);
    strcpy(buf, "HTTP/1.1 200 OK\r\n");
    sprintf(buf, "%s%s", buf, SERVER_STRING);
    sprintf(buf, "%sContent-type: %s\r\n\r\n", buf, file_type);
    SSL_write(ssl, buf, strlen(buf));
}
const char *get_file_type(const char *type)
{
    if (type == NULL)
        return "text/plain";
    int i;
    for (i = 0; mime[i].type != NULL; ++i) {
        if (strcmp(type, mime[i].type) == 0)
            return mime[i].value;
    }
    return mime[i].value;
}

// 加入对range字段回应的headers
void headers_range_ssl(SSL *ssl, const char *filename, off_t offset, off_t size)
{
    char buf[MAXBUF];
    const char *dot_pos = strchr(filename + 1, '.');
    const char *file_type = get_file_type(dot_pos);
    printf("file type === %s\n", file_type);
    strcpy(buf, "HTTP/1.1 206 Partial Content\r\n");
    sprintf(buf, "%s%s", buf, SERVER_STRING);
    sprintf(buf, "%sContent-type: %s\r\n", buf, file_type);
    sprintf(buf, "%sContent-Length: %d\r\n", buf, size);
    sprintf(buf, "%sContent-Range: bytes %d-%d/%d\r\n", buf, offset, offset + size, size);
    sprintf(buf, "%s\r\n", buf);
    printf("range header === %s\n", buf);
    SSL_write(ssl, buf, strlen(buf));
}

void headers(int client, const char *filename)
{
    char buf[MAXBUF];
    const char *dot_pos = strchr(filename, '.');
    const char *file_type = get_file_type(dot_pos);
    printf("file type === %s", file_type);
    strcpy(buf, "HTTP/1.1 200 OK\r\n");
    sprintf(buf, "%s%s", buf, SERVER_STRING);
    sprintf(buf, "%sContent-type: %s\r\n\r\n", buf, file_type);
    send(client, buf, strlen(buf), 0);
}

// 将http请求301转到https位置
void mov_to_ssl(int client, const char *toURL)
{
    printf("301 Moved to %s!\n", toURL);
    char buf[MAXBUF];
    // 返回301
    strcpy(buf, "HTTP/1.1 301 Moved Permanently\r\n");
    send(client, buf, strlen(buf), 0);
    strcpy(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Location: %s\r\n", toURL);
    send(client, buf, strlen(buf), 0);
    strcpy(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
}
void not_found(int client)
{
    printf("404 Not Find!\n");
    char buf[MAXBUF];
    // 返回404
    strcpy(buf, "HTTP/1.1 404 NOT FOUND\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><TITLE>404 Not Found</TITLE>\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>MYZHIBEI_Server could not fulfill\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "your request because the resource specified\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "is unavailable or nonexistent.\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(client, buf, strlen(buf), 0);
}

void not_found_ssl(SSL *ssl)
{
    printf("404 Not Find!\n");
    char buf[MAXBUF];
    // 返回404
    strcpy(buf, "HTTP/1.1 404 NOT FOUND\r\n");
    sprintf(buf, "%s%s", buf, SERVER_STRING);
    sprintf(buf, "%sContent-Type: text/html\r\n", buf);
    sprintf(buf, "%s\r\n", buf);
    sprintf(buf, "%s<HTML><TITLE>Not Found</TITLE>\r\n", buf);
    sprintf(buf, "%s<BODY><P>The server could not fulfill\r\n", buf);
    sprintf(buf, "%syour request because the resource specified\r\n", buf);
    sprintf(buf, "%sis unavailable or nonexistent.\r\n", buf);
    sprintf(buf, "%s</BODY></HTML>\r\n", buf);
    SSL_write(ssl, buf, strlen(buf));
}
void do_error_ssl(SSL *ssl, char *cause, char *errnum, char *shortmsg, char *longmsg)
{
    char header[1000], body[10000];
    strcpy(body, "<html><title>httpserver error </title>");
    sprintf(body, "%s<body>\n", body);
    sprintf(body, "%s%s: %s\n", body, errnum, shortmsg);
    sprintf(body, "%s<p>%s:%s\n</p>", body, longmsg, cause);
    sprintf(body, "%s<hr><em>httpserver </em>\n</body></html>", body);

    sprintf(header, "HTTP/1.1 %s %s\r\n", errnum, shortmsg);
    sprintf(header, "%s%s\r\n", header, SERVER_STRING);
    sprintf(header, "%sContent-type: text/html\r\n", header);
    sprintf(header, "%sConten-length: %d\r\n\r\n", header, (int)strlen(body));
    SSL_write(ssl, header, strlen(header));

    SSL_write(ssl, body, strlen(body));
}

// 将请求的文件发送回浏览器客户端
void serve_file(int client, const char *filename)
{
    printf("Sending File=== %s\n", filename);
    FILE *resource = NULL;
    int numchars = 1;
    char buf[MAXBUF];
    // 默认字符
    buf[0] = 'A';
    buf[1] = '\0';
    while ((numchars > 0) && strcmp("\n", buf)) // 将HTTP请求头读取并丢弃
        numchars = get_line(client, buf, sizeof(buf));

    // 打开文件
    resource = fopen(filename, "r");
    if (resource == NULL)
        // 如果文件不存在，则返回not_found
        not_found(client);
    else {
        // 添加HTTP头
        headers(client, filename);
        // 并发送文件内容
        cat(client, resource);
    }
    fclose(resource); // 关闭文件句柄
}

void serve_file_ssl(SSL *ssl, char *fin_path, off_t offset, off_t size, int range)
{
    printf("Sending File=== %s\n", fin_path);
    FILE *resource = NULL;
    // 打开文件
    resource = fopen(fin_path, "rb");
    if (resource == NULL)
        // 如果文件不存在，则返回not_found
        do_error_ssl(ssl, fin_path, "404", "Not Found", "Server can't find the file");
    else {
        // offset TO all
        struct stat sizefile;
        int sizeoffile;
        if (stat(fin_path, &sizefile) == 0) {
            printf("file1 size = %d\n", sizefile.st_size);
            sizeoffile = sizefile.st_size;
        }
        if (range) {
            char buf[MAXBUF]; //= {0};
            if (size < 1) {

                size = sizeoffile - offset;
            }
            headers_range_ssl(ssl, fin_path, offset, size);
            printf("sending file offset=%d size=%d\n", offset, size);
            // 读取文件到buf中
            fseek(resource, offset, SEEK_SET);                // 光标移到文件开始起第offset个字节处。
            while (!feof(resource) && size > sizeof(buf) - 1) // 判断文件是否读取到末尾
            {
                // 读取并发送文件内容
                fread(buf, sizeof(char), sizeof(buf) - 1, resource);
                printf("sended %ld / %ld batyes : \n", sizeof(buf) - 1, size);
                SSL_write(ssl, buf, sizeof(buf) - 1);
                size = size - (sizeof(buf) - 1);
            }
            if ((size < sizeof(buf) - 1) && size > 0) {
                fread(buf, sizeof(char), size, resource);
                printf("sended %ld / %ld batyes : \n", size, size);
                SSL_write(ssl, buf, size);
            }
        } else {
            // 添加HTTP头
            headers_ssl(ssl, fin_path);
            // 并发送文件内容
            cat_ssl(ssl, resource, sizeoffile);
        }
    }
    fclose(resource); // 关闭文件句柄
}

// 启动服务端
int startup(u_short *port, int lisnum)
{
    int httpskt = 0;
    // name,Structure describing an Internet socket address
    struct sockaddr_in name;
    // 设置http socket
    //  2,1,0 Create a new socket of type TYPE1 in domain DOMAIN2, using protocol PROTOCOL0
    httpskt = socket(PF_INET, SOCK_STREAM, 0);
    if (httpskt == -1) //
        error_die("socket");
    memset(&name, 0, sizeof(name));
    name.sin_family = AF_INET;
    name.sin_port = htons(*port);

    name.sin_addr.s_addr = htonl(INADDR_ANY);

    printf("binding port:%d addr:%d\n", *port, INADDR_ANY);
    // 绑定端口
    if (bind(httpskt, (struct sockaddr *)&name, sizeof(name)) < 0)
        error_die("bind");
    if (*port == 0) /*动态分配一个端口 */
    {
        socklen_t namelen = sizeof(name);
        if (getsockname(httpskt, (struct sockaddr *)&name, &namelen) == -1)
            error_die("getsockname");
        *port = ntohs(name.sin_port);
    }
    // 监听连接
    if (listen(httpskt, lisnum) < 0)
        error_die("listen");
    return (httpskt);
}

void unimplemented_ssl(SSL *ssl)
{
    printf("501 Method Not Implemented");
    char buf[MAXBUF];
    // 发送501说明相应方法没有实现
    sprintf(buf, "%sHTTP/1.1 501 Method Not Implemented\r\n", buf);
    sprintf(buf, "%s%s", buf, SERVER_STRING);
    sprintf(buf, "%sContent-Type: text/html\r\n", buf);
    sprintf(buf, "%s\r\n", buf);
    sprintf(buf, "%s<HTML><HEAD><TITLE>Method Not Implemented\r\n", buf);
    sprintf(buf, "%s</TITLE></HEAD>\r\n", buf);
    sprintf(buf, "%s<BODY><P>HTTP request method not supported.\r\n", buf);
    sprintf(buf, "%s</BODY></HTML>\r\n", buf);
    SSL_write(ssl, buf, strlen(buf));
}

void unimplemented(int client)
{
    char buf[MAXBUF];
    // 发送501说明相应方法没有实现
    sprintf(buf, "HTTP/1.1 501 Method Not Implemented\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><HEAD><TITLE>Method Not Implemented\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</TITLE></HEAD>\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>HTTP request method not supported.\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(client, buf, strlen(buf), 0);
}

void *Server(void *arg)
{
    u_short port = *(u_short *)arg;
    printf("MYZHIBEI Server Creating on port %d !\n", port);
    struct accSktArgs accSktarg;
    int server_sock = -1;
    int client_sock = -1;
    struct sockaddr_in client_name;
    socklen_t client_name_len = sizeof(client_name);
    pthread_t newAcceptThread;
    // 启动server socket

    server_sock = startup(&port, 5);
    accSktarg.server_sock = server_sock;

    printf("MYZHIBEI Server running on port %d !\n", port);

    while (1) {
        // 接受客户端连接
        accSktarg.client_sock = accept(server_sock, (struct sockaddr *)&client_name, &client_name_len);
        if (accSktarg.client_sock == -1)
            error_die("accept");
        /*启动线程处理新的连接 */
        printf("HTTP Server: got connection from %s, port %d, socket %d\n",
               inet_ntoa(client_name.sin_addr),
               ntohs(client_name.sin_port), server_sock);
        if (pthread_create(&newAcceptThread, NULL, accept_request, &accSktarg) != 0)
            perror("pthread_create");
    }

    // 关闭server socket
    close(server_sock);
    printf("MYZHIBEI Server closed on port %d !\n", port);
    return NULL;
}

struct SSLargs {
    u_short port;
    int lisnum;
    char ctf[1024];
    char prikey[1024];
};

void *ServerSSL(void *args)
{
    struct SSLargs sslarg = *(struct SSLargs *)args;
    u_short port = sslarg.port;
    int lisnum = sslarg.lisnum;
    SSL_CTX *ctx;
    SSL_library_init();
    OpenSSL_add_all_algorithms(); // 载入所有 SSL 算法
    SSL_load_error_strings();     // 载入所有 SSL 错误消息
    // 以 SSL V2 和 V3 标准兼容方式产生一个 SSL_CTX ，即 SSL Content Text
    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL) {
        error_die("ctx");
        exit(1);
    }
    if (SSL_CTX_use_certificate_file(ctx, sslarg.ctf, SSL_FILETYPE_PEM) <= 0)
        error_die("ctx_certificate");
    if (SSL_CTX_use_PrivateKey_file(ctx, sslarg.prikey, SSL_FILETYPE_PEM) <= 0)
        error_die("ctx_privateKey");
    if (!SSL_CTX_check_private_key(ctx))
        error_die("CTX_check_private_key");
    printf("MYZHIBEI https Server Creating on port %d !\n", port);
    int server_sock = -1;
    int client_sock = -1;
    struct sockaddr_in client_name;
    socklen_t client_name_len = sizeof(client_name);
    pthread_t newAcceptSSLThread;
    // 启动server socket
    server_sock = startup(&port, lisnum);
    while (1) {
        struct sslAccArgs accarg;
        accarg.ctx = ctx;
        strcpy(accarg.rootdir, "");
        /* 等待客户端连上来 */
        client_sock = accept(server_sock, (struct sockaddr *)&client_name, &client_name_len);
        if (client_sock == -1)
            error_die("accept");
        printf("HTTPS Server: got connection from %s, port %d, socket %d to clientskt %d\n ",
               inet_ntoa(client_name.sin_addr),
               ntohs(client_name.sin_port), server_sock, client_sock);
        accarg.client_socket = client_sock;
        if (pthread_create(&newAcceptSSLThread, NULL, accept_request_ssl, &accarg))
            perror("pthread_create");
    }
    close(server_sock);
    SSL_CTX_free(ctx);
    return 0;
}

int main(void)
{
    int port80 = 80;
    void *state;
    printf("Create 80 Server Thread...\n");
    pthread_t newServerThread;
    if (pthread_create(&newServerThread, NULL, Server, &port80))
        perror("pthread_create 80");
    struct SSLargs sslarg;
    sslarg.port = 443;
    sslarg.lisnum = 2;
    strcpy(sslarg.ctf, "keys/cnlab.cert");
    strcpy(sslarg.prikey, "keys/cnlab.prikey");
    printf("Create 443 Server Thread...\n");
    if (pthread_create(&newServerThread, NULL, ServerSSL, &sslarg))
        perror("pthread_create 443");

    pthread_join(newServerThread, &state);
    return (0);
}
