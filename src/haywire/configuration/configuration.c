#include "configuration.h"
#include "../hw_string.h"
#include "../khash.h"
#include "ini.h"

KHASH_MAP_INIT_STR(route_hashes, char*)

int configuration_handler(void* user, const char* section, const char* name, const char* value)
{
    configuration* config = (configuration*)user;

#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
    if (MATCH("http", "listen_address")){
        snprintf(config->http_listen_address, sizeof(config->http_listen_address), "%s", value);
    }
    else if (MATCH("http", "listen_port")){
        config->http_listen_port = atoi(value);
    }
    else if (MATCH("http", "thread_count")){
    	config->thread_count = atoi(value);
    	if (config->thread_count <= 0){
    		config->thread_count = 8;
    	}
    }else if (MATCH("http", "tcp_nodelay")){
    	config->tcp_nodelay = atoi(value);
    }else if (MATCH("http", "max_request_size")){
    	config->max_request_size = atoi(value);
    }else if (MATCH("http", "listen_backlog")){
    	config->listen_backlog = atoi(value);
    }else if (MATCH("http", "persist_interval")){
    	//config->persist_interval = atoi(value);
    }else if (MATCH("http", "server_name")){
    	snprintf(config->server_name, sizeof(config->server_name), "%s", value);
    }else{
    	 return 0;  /* unknown section/name, error */
    }
    return 1;
}
void hw_configuration_init(configuration *config)
{
	memset(config, 0, sizeof(configuration));
	memcpy(config->http_listen_address, "0.0.0.0", strlen("0.0.0.0"));
	memcpy(config->parser, "http_parser",strlen("http_parser"));
	memcpy(config->balancer, "reuseport", strlen("reuseport"));
    memcpy(config->server_name, "Haywire/master", strlen("Haywire/master"));
	config->http_listen_port = 8000;
	config->listen_backlog = 1024;
	config->max_request_size = 102400;
	config->tcp_nodelay = 1;
	config->thread_count = 8;
    
}

int hw_configuration_load_file(configuration *config, const char* filename)
{
	if (ini_parse(filename, configuration_handler, config) < 0){
		printf("Can't load configuration\n");
		return -1;
	}
	return 0;
}


void hw_print_configuration(configuration *config)
{
    printf("Address: %s\nPort: %d\nThreads: %d\nBalancer: %s\nParser: %s\nTCP No Delay: %s\nListen backlog: %d\nMaximum request size: %d\nServerName: %s\n",
           config->http_listen_address,
           config->http_listen_port,
           config->thread_count,
           config->balancer,
           config->parser,
           config->tcp_nodelay? "on": "off",
           config->listen_backlog,
           config->max_request_size,
           config->server_name);
}
