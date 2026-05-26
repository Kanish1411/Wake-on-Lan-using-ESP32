// Module, to hit the ip-api endpoint get demographic details, which can latr be used in FIrewall,
//to allow or block access to the device based on the country of origin of the request.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_http_client.h"

#include <cJSON.h>


void 