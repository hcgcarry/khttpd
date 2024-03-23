
#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/tcp.h>

#include "http_parser.h"
#include "http_server.h"
#include "content_cache_table.h"

#define CRLF "\r\n"

#define HTTP_RESPONSE_200_DUMMY                               \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Close" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_200_KEEPALIVE_DUMMY                     \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Keep-Alive" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_501                                              \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: Close" CRLF CRLF "501 Not Implemented" CRLF
#define HTTP_RESPONSE_501_KEEPALIVE                                    \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: KeepAlive" CRLF CRLF "501 Not Implemented" CRLF

#define RECV_BUFFER_SIZE 4096
#define SEND_BUFFER_SIZE 4096

struct content_cache_table cache_table;

struct http_request {
    struct socket *socket;
    enum http_method method;
    char request_url[128];
    int complete;
    struct dir_context dir;
};

static int http_server_recv(struct socket *sock, char *buf, size_t size)
{
    struct kvec iov = {.iov_base = (void *) buf, .iov_len = size};
    struct msghdr msg = {.msg_name = 0,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    return kernel_recvmsg(sock, &msg, &iov, 1, size, msg.msg_flags);
}

static int http_server_send(struct socket *sock, const char *buf, size_t size)
{
    struct msghdr msg = {.msg_name = NULL,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    int done = 0;
    while (done < size) {
        struct kvec iov = {
            .iov_base = (void *) ((char *) buf + done),
            .iov_len = size - done,
        };
        int length = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (length < 0) {
            pr_err("write error: %d\n", length);
            break;
        }
        done += length;
    }
    return done;
}


// static int tracedir(struct dir_context *dir,
//                     const char *name,
//                     int namelen,
//                     loff_t offset,
//                     u64 ino,
//                     unsigned int d_type)
// {
//     if (strcmp(name, ".") && strcmp(name, "..")) {
//         struct http_request *request =
//             container_of(dir, struct http_request, dir);
//         char buf[SEND_BUFFER_SIZE] = {0};

//         snprintf(buf, SEND_BUFFER_SIZE,
//                  "<tr><td><a href=\"%s\">%s</a></td></tr>\r\n", name, name);
//         http_server_send(request->socket, buf, strlen(buf));
//     }
//     return 0;
// }



static int tracedir(struct dir_context *dir,
                    const char *name,
                    int namelen,
                    loff_t offset,
                    u64 ino,
                    unsigned int d_type)
{

    struct http_request *request =
        container_of(dir, struct http_request, dir);
    char buf[SEND_BUFFER_SIZE] = {0};
    char file_path[1024] = {0};
    if(strcmp(request->request_url,"/") == 0){
        snprintf(file_path,1024 ,"/%s",name);
    }
    else{
        snprintf(file_path,1024 ,"%s/%s",request->request_url,name);
    }

    // char* file_path_ptr = file_path;
    // if(file_path[0] == '/'){
    //     file_path_ptr = file_path+1;
    // }
    snprintf(buf, SEND_BUFFER_SIZE,
                "<tr><td><a href=\"%s\">%s</a></td></tr>\r\n", file_path, name);
    http_server_send(request->socket, buf, strlen(buf));
    return 0;
}

static void handle_dir(struct http_request *request, struct file *fp,struct cache_element* element)
{
    printk("----handle_dir");



    char buf[SEND_BUFFER_SIZE] = {0};
    

    snprintf(buf, SEND_BUFFER_SIZE, "HTTP/1.1 200 OK\r\n%s%s%s",
             "Connection: Keep-Alive\r\n", "Content-Type: text/html\r\n",
             "Keep-Alive: timeout=5, max=1000\r\n\r\n");
    http_server_send(request->socket, buf, strlen(buf));


    snprintf(buf, SEND_BUFFER_SIZE, "%s%s%s%s", "<html><head><style>\r\n",
             "body{font-family: monospace; font-size: 15px;}\r\n",
             "td {padding: 1.5px 6px;}\r\n",
             "</style></head><body><table>\r\n");

    http_server_send(request->socket, buf, strlen(buf));


    iterate_dir(fp, &request->dir);

    snprintf(buf, SEND_BUFFER_SIZE, "</table></body></html>\r\n");

    http_server_send(request->socket,buf,strlen(buf));

    return;

}

static void handle_file(struct http_request *request, struct file *fp,struct cache_element* element)
{

    pr_info("----- handle_file");
    int bufLen =  fp->f_inode->i_size + 4906;
    // int bufLen =  20000;
    char *buf = kmalloc(bufLen, GFP_KERNEL);

    snprintf(buf, bufLen, "HTTP/1.1 200 OK\r\n%s%s%s%d%s",
             "Connection: Keep-Alive\r\n", "Content-Type: text/plain\r\n",
             "Content-Length: ",fp->f_inode->i_size,"\r\n\r\n");
    http_server_send(request->socket,buf,strlen(buf));
    int len = kernel_read(fp, buf + strlen(buf), fp->f_inode->i_size, 0);

    element->content = buf;
    element->content_len = bufLen;

    http_server_send(request->socket,buf,strlen(buf));

    return;
}

static void send_dir_file_content(struct http_request *request,struct cache_element* element)
{
    pr_info("--- send_dir_file_content");
    struct file *fp;

    request->dir.actor = tracedir;
    // char* file_name = request->request_url;

    char file_path[1024] = "/home/jimmy/khttpd_project";
    strcat(file_path, request->request_url);

    printk(KERN_INFO "file_name: %s \n", file_path);


    fp = filp_open(file_path, O_RDONLY, 0);

    if (IS_ERR(fp)) {
        pr_info("Open file failed");
        return;
    }

    char* content = NULL;

    if (S_ISDIR(fp->f_inode->i_mode)) {
        handle_dir(request, fp,element);
    } else if (S_ISREG(fp->f_inode->i_mode)) {
        handle_file(request, fp,element);
    }
    printk("---send_dir_file end");
    filp_close(fp, NULL);
    return ;
}

static int http_server_response(struct http_request *request, int keep_alive)
{
    pr_info("--- http_server_response requested_url = %s\n", request->request_url);
    char* key = request->request_url;

    char* content = cache_table.get_element(&cache_table,key);

    if(content){
        pr_info("--- have cache");
        printk("---content:%s",content);
        http_server_send(request->socket,content,strlen(content));

    }
    else{
        pr_info("--- do not have cache");
        
        struct cache_element* element = cache_element_init(key);
        send_dir_file_content(request,element);
        printk("content:%s",element->content);
        if(element->content_len != NULL){
            cache_table.insert_element(&cache_table, element);
        }
    }

    return 0;
}

static int http_parser_callback_message_begin(http_parser *parser)
{
    struct http_request *request = parser->data;
    struct socket *socket = request->socket;
    memset(request, 0x00, sizeof(struct http_request));
    request->socket = socket;
    return 0;
}

static int http_parser_callback_request_url(http_parser *parser,
                                            const char *p,
                                            size_t len)
{
    struct http_request *request = parser->data;
    strncat(request->request_url, p, len);
    return 0;
}

static int http_parser_callback_header_field(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_header_value(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_headers_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    request->method = parser->method;
    return 0;
}

static int http_parser_callback_body(http_parser *parser,
                                     const char *p,
                                     size_t len)
{
    return 0;
}



static int http_parser_callback_message_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    http_server_response(request, http_should_keep_alive(parser));
    request->complete = 1;
    return 0;
}

static int http_server_worker(void *arg)
{
    char *buf;
    struct http_parser parser;
    struct http_parser_settings setting = {
        .on_message_begin = http_parser_callback_message_begin,
        .on_url = http_parser_callback_request_url,
        .on_header_field = http_parser_callback_header_field,
        .on_header_value = http_parser_callback_header_value,
        .on_headers_complete = http_parser_callback_headers_complete,
        .on_body = http_parser_callback_body,
        .on_message_complete = http_parser_callback_message_complete};
    struct http_request request;
    struct socket *socket = (struct socket *) arg;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    buf = kzalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("can't allocate memory!\n");
        return -1;
    }

    request.socket = socket;
    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &request;

    while (!kthread_should_stop()) {
        int ret = http_server_recv(socket, buf, RECV_BUFFER_SIZE - 1);
        printk("---http_server_recv");
        if (ret <= 0) {
            if (ret)
                pr_err("recv error: %d\n", ret);
            break;
        }
        http_parser_execute(&parser, &setting, buf, ret);
        printk("---http_server_exec");
        if (request.complete && !http_should_keep_alive(&parser))
            break;
        memset(buf, 0, RECV_BUFFER_SIZE);
    }
    printk("--- kernel_sock_shutdown");
    kernel_sock_shutdown(socket, SHUT_RDWR);
    sock_release(socket);
    kfree(buf);
    return 0;
}

int http_server_daemon(void *arg)
{
    struct socket *socket;
    struct task_struct *worker;
    struct http_server_param *param = (struct http_server_param *) arg;
    content_cache_table_init(&cache_table);

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    while (!kthread_should_stop()) {
        int err = kernel_accept(param->listen_socket, &socket, 0);
        if (err < 0) {
            if (signal_pending(current))
                break;
            pr_err("kernel_accept() error: %d\n", err);
            continue;
        }
        worker = kthread_run(http_server_worker, socket, KBUILD_MODNAME);
        if (IS_ERR(worker)) {
            pr_err("can't create more worker process\n");
            continue;
        }
    }
    return 0;
}
