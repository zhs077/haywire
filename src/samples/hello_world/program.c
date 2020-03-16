#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include "opt.h"
#include "haywire.h"

#define CRLF "\r\n"

void response_complete(void* user_data)
{
}

void get_ping(http_request* request, hw_http_response* response, void* user_data)
{
    hw_string status_code;
    hw_string content_type_name;
    hw_string content_type_value;
    hw_string body;
    hw_string keep_alive_name;
    hw_string keep_alive_value;
    hw_string route_matched_name;
    hw_string route_matched_value;
    
    hw_print_request_headers(request);
    hw_print_body(request);
    
    SETSTRING(status_code, HTTP_STATUS_200);
    hw_set_response_status_code(response, &status_code);
    
    SETSTRING(content_type_name, "Content-Type");
    
    SETSTRING(content_type_value, "text/html");
    hw_set_response_header(response, &content_type_name, &content_type_value);
    
    body.value = request->body->value;
    body.length = request->body->length;
    hw_set_body(response, &body);
    
    if (request->keep_alive)
    {
        SETSTRING(keep_alive_name, "Connection");
        
        SETSTRING(keep_alive_value, "Keep-Alive");
        hw_set_response_header(response, &keep_alive_name, &keep_alive_value);
    }
    else
    {
        hw_set_http_version(response, 1, 0);
    }
    
    hw_http_response_send(response, "user_data", response_complete);
}


void get_root(http_request* request, hw_http_response* response, void* user_data)
{
    hw_string status_code;
    hw_string content_type_name;
    hw_string content_type_value;
    hw_string body;
    hw_string keep_alive_name;
    hw_string keep_alive_value;
    hw_string route_matched_name;
    hw_string route_matched_value;
    
    SETSTRING(status_code, HTTP_STATUS_200);
    hw_set_response_status_code(response, &status_code);
    
    SETSTRING(content_type_name, "Content-Type");
    
    SETSTRING(content_type_value, "text/html");
    hw_set_response_header(response, &content_type_name, &content_type_value);
    body.value = hw_get_peer_ip(request);
	body.length = strlen(hw_get_peer_ip(request));
    //printf("%s\n, %d\n", body.value, body.length);

	//SETSTRING(body, "hello");
	hw_set_body(response, &body);

    if (request->keep_alive)
    {
        SETSTRING(keep_alive_name, "Connection");
        
        SETSTRING(keep_alive_value, "Keep-Alive");
        hw_set_response_header(response, &keep_alive_name, &keep_alive_value);
    }
    else
    {
        hw_set_http_version(response, 1, 0);
    }
    
    hw_http_response_send(response, "user_data", response_complete);
}
void on_uv_close2(uv_handle_t* handle)
{
    if (handle != NULL){
        free(handle);
    }
}
void on_uv_walk2(uv_handle_t* handle, void* arg)
{
	(void)(arg);
    uv_close(handle, on_uv_close2);
}
void on_sigint_received(uv_signal_t *handle, int signum)
{
	(void)(signum);
	hw_http_stop();
	while(1){
		if ( 1 == hw_http_check_stop()){
			break;
		}
		usleep(5);
	}

	printf("ALL threads have exit\n");
	//退出父进程
    int result = uv_loop_close(handle->loop);
    if (result == UV_EBUSY){
    	printf("UV_EBUSY\n");
        uv_walk(handle->loop, on_uv_walk2, NULL);
    }
}
int main(int args, char** argsv)
{
    char root_route[] = "/";
    char ping_route[] = "/ping";
    configuration config;
    hw_configuration_init(&config);
    config.http_listen_port = 10086;
    config.thread_count = 60;
    config.listen_backlog = 10240;


    hw_print_configuration(&config);
    uv_loop_t *loop = uv_default_loop();
    //hw_configuration_init(&config);
    hw_http_init(&config);

    hw_http_add_route(ping_route, get_ping, NULL);
    hw_http_add_route(root_route, get_root, NULL);

    uv_signal_t *sigint = malloc(sizeof (uv_signal_t));
	uv_signal_init(loop, sigint);
	uv_signal_start(sigint, on_sigint_received, SIGUSR1);

    hw_http_start(loop);
    printf("Stop\n");

    return 0;
}
