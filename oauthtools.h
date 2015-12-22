#pragma once

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
* Escape 'string' according to RFC3986 and
* http://oauth.net/core/1.0/#encoding_parameters.
*
* @param string The data to be encoded
* @return encoded string otherwise NULL
* The caller must free the returned string.
*/
char* oat_url_escape(const char* string);


char** oat_create_query_array(char* query_string, uint32_t* param_size);
char* oat_create_signature(struct OAuthParams* params, char* base_url, char* http_method, uint32_t query_params_num, char** query_params);
char* oat_create_http_flags(struct OAuthParams* params);