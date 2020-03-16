#pragma once
#include "haywire.h"

//configuration* load_configuration(const char* filename);

void hw_configuration_init(configuration *config);
int hw_configuration_load_file(configuration *config, const char* filename);

