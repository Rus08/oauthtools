#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>



/*
FILE* fp = 0;
fp = fopen("percentage_table.txt", "w");

for(uint32_t i = 0; i < 256; i++){
	switch(i){
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
	case 'a': case 'b': case 'c': case 'd': case 'e':
	case 'f': case 'g': case 'h': case 'i': case 'j':
	case 'k': case 'l': case 'm': case 'n': case 'o':
	case 'p': case 'q': case 'r': case 's': case 't':
	case 'u': case 'v': case 'w': case 'x': case 'y': case 'z':
	case 'A': case 'B': case 'C': case 'D': case 'E':
	case 'F': case 'G': case 'H': case 'I': case 'J':
	case 'K': case 'L': case 'M': case 'N': case 'O':
	case 'P': case 'Q': case 'R': case 'S': case 'T':
	case 'U': case 'V': case 'W': case 'X': case 'Y': case 'Z':
	case '_': case '~': case '.': case '-':
	{
		fprintf(fp, "0x010000%02x, ", i);
	}
	break;
	default:
	{
		char temp[3];
		sprintf(temp, "%02X", i);
		fprintf(fp, "0x03%02x%02x%02x, ", temp[1], temp[0], '%');
	}
	}
	if((i % 8) == 7){
		fprintf(fp, "\n");
	}
}
fclose(fp);
*/

const uint32_t percentage_table[256] = {
	0x03303025, 0x03313025, 0x03323025, 0x03333025, 0x03343025, 0x03353025, 0x03363025, 0x03373025, 
	0x03383025, 0x03393025, 0x03413025, 0x03423025, 0x03433025, 0x03443025, 0x03453025, 0x03463025, 
	0x03303125, 0x03313125, 0x03323125, 0x03333125, 0x03343125, 0x03353125, 0x03363125, 0x03373125, 
	0x03383125, 0x03393125, 0x03413125, 0x03423125, 0x03433125, 0x03443125, 0x03453125, 0x03463125, 
	0x03303225, 0x03313225, 0x03323225, 0x03333225, 0x03343225, 0x03353225, 0x03363225, 0x03373225, 
	0x03383225, 0x03393225, 0x03413225, 0x03423225, 0x03433225, 0x0100002d, 0x0100002e, 0x03463225, 
	0x01000030, 0x01000031, 0x01000032, 0x01000033, 0x01000034, 0x01000035, 0x01000036, 0x01000037, 
	0x01000038, 0x01000039, 0x03413325, 0x03423325, 0x03433325, 0x03443325, 0x03453325, 0x03463325, 
	0x03303425, 0x01000041, 0x01000042, 0x01000043, 0x01000044, 0x01000045, 0x01000046, 0x01000047, 
	0x01000048, 0x01000049, 0x0100004a, 0x0100004b, 0x0100004c, 0x0100004d, 0x0100004e, 0x0100004f, 
	0x01000050, 0x01000051, 0x01000052, 0x01000053, 0x01000054, 0x01000055, 0x01000056, 0x01000057, 
	0x01000058, 0x01000059, 0x0100005a, 0x03423525, 0x03433525, 0x03443525, 0x03453525, 0x0100005f, 
	0x03303625, 0x01000061, 0x01000062, 0x01000063, 0x01000064, 0x01000065, 0x01000066, 0x01000067, 
	0x01000068, 0x01000069, 0x0100006a, 0x0100006b, 0x0100006c, 0x0100006d, 0x0100006e, 0x0100006f, 
	0x01000070, 0x01000071, 0x01000072, 0x01000073, 0x01000074, 0x01000075, 0x01000076, 0x01000077, 
	0x01000078, 0x01000079, 0x0100007a, 0x03423725, 0x03433725, 0x03443725, 0x0100007e, 0x03463725, 
	0x03303825, 0x03313825, 0x03323825, 0x03333825, 0x03343825, 0x03353825, 0x03363825, 0x03373825, 
	0x03383825, 0x03393825, 0x03413825, 0x03423825, 0x03433825, 0x03443825, 0x03453825, 0x03463825, 
	0x03303925, 0x03313925, 0x03323925, 0x03333925, 0x03343925, 0x03353925, 0x03363925, 0x03373925, 
	0x03383925, 0x03393925, 0x03413925, 0x03423925, 0x03433925, 0x03443925, 0x03453925, 0x03463925, 
	0x03304125, 0x03314125, 0x03324125, 0x03334125, 0x03344125, 0x03354125, 0x03364125, 0x03374125, 
	0x03384125, 0x03394125, 0x03414125, 0x03424125, 0x03434125, 0x03444125, 0x03454125, 0x03464125, 
	0x03304225, 0x03314225, 0x03324225, 0x03334225, 0x03344225, 0x03354225, 0x03364225, 0x03374225, 
	0x03384225, 0x03394225, 0x03414225, 0x03424225, 0x03434225, 0x03444225, 0x03454225, 0x03464225, 
	0x03304325, 0x03314325, 0x03324325, 0x03334325, 0x03344325, 0x03354325, 0x03364325, 0x03374325, 
	0x03384325, 0x03394325, 0x03414325, 0x03424325, 0x03434325, 0x03444325, 0x03454325, 0x03464325, 
	0x03304425, 0x03314425, 0x03324425, 0x03334425, 0x03344425, 0x03354425, 0x03364425, 0x03374425, 
	0x03384425, 0x03394425, 0x03414425, 0x03424425, 0x03434425, 0x03444425, 0x03454425, 0x03464425, 
	0x03304525, 0x03314525, 0x03324525, 0x03334525, 0x03344525, 0x03354525, 0x03364525, 0x03374525, 
	0x03384525, 0x03394525, 0x03414525, 0x03424525, 0x03434525, 0x03444525, 0x03454525, 0x03464525, 
	0x03304625, 0x03314625, 0x03324625, 0x03334625, 0x03344625, 0x03354625, 0x03364625, 0x03374625, 
	0x03384625, 0x03394625, 0x03414625, 0x03424625, 0x03434625, 0x03444625, 0x03454625, 0x03464625, 
};

const char chars[] = { "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" };

struct OAuthParams{
	char* consumer_key;
	char* nonce;
	char* signature;
	char* signature_method;
	char* timestamp;
	char* token;
	char* version;
	char* consumer_secret;
	char* secret;
};


/**
* returns base64 encoded HMAC-SHA1 signature for
* given message and key.
* both data and key need to be urlencoded.
*
* the returned string needs to be freed by the caller
*
* @param m message to be signed
* @param k key used for signing
* @return signature string.
*/
char *oauth_sign_hmac_sha1 (const char *m, const char *k);

/**
* Escape 'string' according to RFC3986 and
* http://oauth.net/core/1.0/#encoding_parameters.
*
* @param string The data to be encoded
* @return encoded string otherwise NULL
* The caller must free the returned string.
*/
char* oat_url_escape(char* string)
{
	uint32_t size;
	char* out_str = 0;
	uint32_t out_alloc_size = 0;
	uint32_t out_size = 0;

	if(string == NULL){
		// return empty string
		out_str = (char*)malloc(1);
		out_str[0] = 0;
		return out_str;
	}

	size = strlen(string);
	out_alloc_size = size * 3 + 3;

	out_str = (char*)malloc(out_alloc_size);
	if(out_str == NULL){
		return NULL;
	}

	for(uint32_t i = 0; i < size; i++){
		// ch: first 3 bytes - char data, last byte data size 1 or 3 chars
		uint32_t ch = percentage_table[(uint8_t)string[i]];

		if((ch >> 24) == 1){
			out_str[out_size] = ch & 0xff;
		}else{
			*(uint32_t*)&out_str[out_size] = ch;
		}
		out_size = out_size + (ch >> 24);
	}

	out_str[out_size] = 0;
	return out_str;
}


/**
* generate a random string between 15 and 32 chars length
* and return a pointer to it. The value needs to be freed by the
* caller
*
* @return zero terminated random string.
*/
char* oat_get_nonce()
{
	uint32_t nonce_len = 15 + (rand() % (32 - 15));
	char* out_str;

	out_str = (char*)malloc(nonce_len + 1);
	if(out_str == NULL){
		return NULL;
	}

	for(uint32_t i = 0; i < nonce_len; i++){
		out_str[i] = chars[rand() % sizeof(chars)]; 
	}

	out_str[nonce_len] = 0;
	return out_str;
}

char* oat_get_timestamp()
{
	char* out_str;

	out_str = (char*)malloc(16); // max for 32 bit is 10 digits
	sprintf(out_str, "%u", (uint32_t)time(NULL));

	return out_str;
}

char* strnchr(char* string, char ch, char* pEnd)
{
	char* out_str = NULL;

	while(string < pEnd && *string != 0 && *string != ch){
		string = string + 1;
	}

	if(*string == ch){
		out_str = string;
	}

	return out_str;
}

char** oat_create_query_array(char* query_string, uint32_t* param_size)
{
	uint32_t param_num = 0;
	char* pBegin = strchr(query_string, '?') + 1;
	char* pCurr;
	char* pEnd;
	char** out_array;

	if(pBegin == NULL){
		return NULL;
	}

	if(strlen(pBegin) == 0){
		return NULL;
	}
	param_num = 1;

	pCurr = pBegin;
	while(strchr(pCurr, '&') != NULL){
		pCurr = strchr(pCurr, '&') + 1;
		param_num = param_num + 1;
	}

	out_array = (char**)malloc(sizeof(char*) * param_num);

	for(uint32_t i = 0; i < param_num; i++){
		// param=value
		uint32_t copy_size = 0;
		char* temp;


		pEnd = strchr(pBegin, '&');
		if(pEnd == NULL){
			// end of string
			pEnd = strchr(pBegin, 0);
		}

		copy_size = pEnd - pBegin;
		temp = (char*)malloc(copy_size + 1);
		strncpy(temp, pBegin, copy_size);
		temp[copy_size] = 0;

		out_array[i] = oat_url_escape(temp);
		free(temp);

		pCurr = strstr(out_array[i], "%3D");
		if(pCurr != NULL){
			*pCurr = '=';
			strcpy(pCurr + 1, pCurr + 3); // cauch
		}
		pBegin = pEnd + 1;
	}

	*param_size = param_num;
	return out_array;
}

char* oat_create_signature(struct OAuthParams* params, char* base_url, char* http_method, uint32_t query_params_num, char** query_params)
{
	char* out_str;
	char** param_array;
	char* param_string;
	char* signature_string;
	char* key_string;
	uint32_t total_param_num = 0;

	if(params->consumer_secret == NULL){
		return NULL;
	}

	params->nonce = oat_get_nonce();
	params->timestamp = oat_get_timestamp();
	params->version = "1.0";

	if(query_params_num > 0 && query_params != NULL){
		param_array = (char**)malloc(sizeof(char*) * (6 + query_params_num));

		for(uint32_t i = 0; i < query_params_num; i++){
			param_array[6 + i] = query_params[i];
		}
		total_param_num = 6 + query_params_num;
	}else{
		query_params_num = 0; // if passed by NULL only
		param_array = (char**)malloc(sizeof(char*) * 6);
		total_param_num = 6;
	}

	param_array[0] = (char*)malloc(sizeof("oauth_consumer_key=") + strlen(params->consumer_key) + 1);
	strcpy(param_array[0], "oauth_consumer_key=");
	strcat(param_array[0], params->consumer_key);

	param_array[1] = (char*)malloc(sizeof("oauth_nonce=") + strlen(params->nonce) + 1);
	strcpy(param_array[1], "oauth_nonce=");
	strcat(param_array[1], params->nonce);

	param_array[2] = (char*)malloc(sizeof("oauth_signature_method=") + strlen(params->signature_method) + 1);
	strcpy(param_array[2], "oauth_signature_method=");
	strcat(param_array[2], params->signature_method);

	param_array[3] = (char*)malloc(sizeof("oauth_timestamp=") + strlen(params->timestamp) + 1);
	strcpy(param_array[3], "oauth_timestamp=");
	strcat(param_array[3], params->timestamp);

	param_array[4] = (char*)malloc(sizeof("oauth_token=") + strlen(params->token) + 1);
	strcpy(param_array[4], "oauth_token=");
	strcat(param_array[4], params->token);

	param_array[5] = (char*)malloc(sizeof("oauth_version=1.0") + 1);
	strcpy(param_array[5], "oauth_version=1.0");

	if(query_params_num != 0){
		// perform sorting
		for(uint32_t i = 0; i < total_param_num; i++){
			char* min = param_array[i];
			uint32_t min_id = i;
			
			for(uint32_t b = i; b < total_param_num; b++){
				if(strcmp(param_array[b], min) < 0){
					min = param_array[b];
					min_id = b;
				}
			}
			param_array[min_id] = param_array[i];
			param_array[i] = min;
		}
	}

	// form param_string
	char* param_string_raw;
	uint32_t raw_size = 0;

	for(uint32_t i = 0; i < total_param_num; i++){
		raw_size = raw_size + strlen(param_array[i]);
	}
	// add space for &
	raw_size = raw_size + total_param_num - 1; // don't need for first param

	param_string_raw = (char*)malloc(raw_size + 1);
	param_string_raw[0] = 0;

	for(uint32_t i = 0; i < total_param_num; i++){
		strcat(param_string_raw, param_array[i]);
		if((total_param_num - i) > 1){
			strcat(param_string_raw, "&");
		}
	}
	param_string = oat_url_escape(param_string_raw);
	// form signature string
	uint32_t signature_size = 0;

	if(http_method != NULL){
		signature_size = signature_size + strlen(http_method) + 1; // 1 for &
	}
	if(base_url != NULL){
		signature_size = signature_size + strlen(base_url) + 1; // 1 for &
	}
	signature_size = signature_size + strlen(param_string) + 1;

	signature_string = (char*)malloc(signature_size);
	signature_string[0] = 0;

	if(http_method != NULL){
		strcat(signature_string, http_method);
		strcat(signature_string, "&");
	}
	if(base_url != NULL){
		strcat(signature_string, base_url);
		strcat(signature_string, "&");
	}
	strcat(signature_string, param_string);

	// form key
	uint32_t key_size = 0;

	key_size = strlen(params->consumer_secret) + 2; // 1 for & 1 for 0

	if(params->secret != NULL){
		key_size = key_size + strlen(params->secret);
	}
	
	key_string = (char*)malloc(key_size);

	strcpy(key_string, params->consumer_secret);
	strcat(key_string, "&");

	if(params->secret != NULL){
		strcat(key_string, params->secret);
	}
	char* temp = oauth_sign_hmac_sha1(signature_string, key_string);

	params->signature = oat_url_escape(temp);
	out_str = params->signature;

	if(query_params_num > 0 && query_params != NULL){
		for(uint32_t i = 0; i < query_params_num; i++){
			free(param_array[i]);
		}
		free(param_array);
	}
	free(param_string_raw);
	free(signature_string);
	free(key_string);
	free(temp);
	return out_str;
}

char* oat_create_http_flags(struct OAuthParams* params)
{
	uint32_t size = sizeof("Authorization: OAuth ");
	uint32_t param_count = 0;
	char** param_ptr = (char**)params;
	char* out_str;

	for(uint32_t i = 0; i < 7; i++){
		if(param_ptr[i] == NULL){
			return NULL;
		}
	}

	for(uint32_t i = 0; i < 7; i++){
		size = size + strlen(param_ptr[i]) + 3; // 3 for " " =
	}
	size = size + 2 * 6 + 2; // , + \r\n

	out_str = (char*)malloc(1024 + size + 1);
	strcpy(out_str, "Authorization: OAuth ");

	strcat(out_str, "oauth_consumer_key=\"");
	strcat(out_str, params->consumer_key);
	strcat(out_str, "\", ");
	
	strcat(out_str, "oauth_nonce=\"");
	strcat(out_str, params->nonce);
	strcat(out_str, "\", ");

	strcat(out_str, "oauth_signature=\"");
	strcat(out_str, params->signature);
	strcat(out_str, "\", ");

	strcat(out_str, "oauth_signature_method=\"");
	strcat(out_str, params->signature_method);
	strcat(out_str, "\", ");

	strcat(out_str, "oauth_timestamp=\"");
	strcat(out_str, params->timestamp);
	strcat(out_str, "\", ");

	strcat(out_str, "oauth_token=\"");
	strcat(out_str, params->token);
	strcat(out_str, "\", ");

	strcat(out_str, "oauth_version=\"");
	strcat(out_str, params->version);
	strcat(out_str, "\"");


	return out_str;
}
