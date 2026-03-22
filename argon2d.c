/* MIT License (c) 2023 Identeco */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "zend_exceptions.h"
#include "ext/spl/spl_exceptions.h"
#if PHP_VERSION_ID >= 80200
# include "ext/random/php_random.h"
#else
# include "ext/standard/php_random.h"
#endif
#include "php_argon2d.h"
#include "argon2d_arginfo.h"
#include "ext/argon2/include/argon2.h"


// This function creates a random salt with the given length and returns it in the passed buffer
static int create_salt(size_t amount_bytes, char *retBuffer) 
{
	// Check whether the salt can be generated safely with the specified length 
	if (amount_bytes > (INT_MAX / 3)) {
		return FAILURE;
	}
	// Create the salt randomly
	if (FAILURE == php_random_bytes_silent(retBuffer, amount_bytes)) {
		return FAILURE;
	}
	retBuffer[amount_bytes] = 0;
	return SUCCESS;
}

// This function frees the allocated buffers of the argon2d_password_hash_need_rehash() method
static void free_phc_buffer(char *password_hash_algorithm, char *password_hash_salt, char *password_hash_raw) 
{
	efree(password_hash_algorithm);
	efree(password_hash_salt);
	efree(password_hash_raw);
}

/*  
 * argon2d_raw_hash(String $password, String $salt, int $memory = 65536, int $iterations = 3, int $parallelism = 4, int $tag_length = 32, int $version = 0x13, String $secret_key = NULL, String $assoziated_data): String
 * Low level function that computes an Argon2d hash.
 * All parameters are flexible, as long as they are within the allowed range of values. 
 * If unsafe parameters are used, an E_Notice is thrown. 
 * On fatal errors, an exception is thrown and the calculation is aborted. 
 * The return of a hash is done in decimal encoding. 
 */
PHP_FUNCTION(argon2d_raw_hash)
{

	if (SIZEOF_ZEND_LONG != 8 ) {
		zend_throw_exception(spl_ce_RuntimeException, "Argon2d is supporting only for 64-Bit PHP installations", 0);
		RETURN_FALSE;
	}

	zend_long memory = 0;
	zend_long iterations = 0;
	zend_long parallelism = 0;
	zend_long tag_length = 0;
	zend_long version = 0;

	char *password;
	char *salt;
	char *secret_key;
	char *assoziated_data;
	
	size_t password_length = 0;
	size_t salt_length = 0;
	size_t secret_key_length = 0;
	size_t assoziated_data_length = 0;

	ZEND_PARSE_PARAMETERS_START(2, 9)
		Z_PARAM_STRING(password, password_length)
		Z_PARAM_STRING(salt, salt_length)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(memory)
		Z_PARAM_LONG(iterations)
		Z_PARAM_LONG(parallelism)
		Z_PARAM_LONG(tag_length)
		Z_PARAM_LONG(version)
		Z_PARAM_STRING(secret_key, secret_key_length)
		Z_PARAM_STRING(assoziated_data, assoziated_data_length)
	ZEND_PARSE_PARAMETERS_END();

	// Set the default values if no optional parameters are set

	if (memory == 0) {
		memory = ARGON2_MEMORY;
	}

	if (iterations == 0) {
		iterations = ARGON2_ITERATIONS; 
	}

	if (parallelism == 0) {
		parallelism = ARGON2_PARALLELISM;
	}

	if (tag_length == 0) {
		tag_length = ARGON2_TAG_LENGTH;
	}

	if (version == 0) {
		version = ARGON2_VERSION;
	}

	// Check if parameters are in the allowed value range and throw an exception if they are not

	if (password_length < ARGON2_MIN_PWD_LENGTH || password_length >= ARGON2_MAX_PWD_LENGTH) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Password must be in the value range from 0 to 2^32-1 bytes", 0);
		RETURN_FALSE;
	}

	if (salt_length < ARGON2_MIN_SALT_LENGTH || salt_length >= ARGON2_MAX_SALT_LENGTH) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Salt must be in the value range from 8 to 2^32-1 bytes", 0);
		RETURN_FALSE;
	}

	if (iterations < ARGON2_MIN_TIME || iterations >= ARGON2_MAX_TIME) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Iterations must be in the value range from 1 to 2^32-1", 0);
		RETURN_FALSE;
	}

	if (parallelism < ARGON2_MIN_LANES || parallelism >= ARGON2_MAX_LANES) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Parallelism must be in the value range from 1 to 2^24-1", 0);
		RETURN_FALSE;
	}

	if (memory < (8 * parallelism) || memory >= ARGON2_MAX_MEMORY) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Memory must be in the value range from (8*parallelism) to 2^32-1", 0);
		RETURN_FALSE;
	}

	if (tag_length < ARGON2_MIN_OUTLEN || tag_length >= ARGON2_MAX_OUTLEN) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Tag length must be in the value range from 4 to 2^32-1 bytes", 0);
		RETURN_FALSE;
	}

	if (!( version == EXT_VERSION_13 || version == EXT_VERSION_10 )) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Version must be VERSION_13 or VERSION_10", 0);
		RETURN_FALSE;
	}

	if (assoziated_data_length < ARGON2_MIN_AD_LENGTH || assoziated_data_length >= ARGON2_MAX_AD_LENGTH) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Assoziated data length must be in the value range from 0 to 2^32-1 bytes", 0);
		RETURN_FALSE;
	}

	if (secret_key_length < ARGON2_MIN_SECRET || secret_key_length >= ARGON2_MAX_SECRET) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Secret key length must be in the value range from 0 to 2^32-1 bytes", 0);
		RETURN_FALSE;
	}

	// Check that no insecure password hashing parameters are used, and if they are, raise a warning
	
	if (salt_length < 16) {
		php_error_docref(NULL, E_NOTICE , "For password hashing, the salt should be randomly chosen for each password with at least 16 bytes");
	}

	if (tag_length < 32) {
		php_error_docref(NULL, E_NOTICE , "For password hashing the tag length should be at least 32 bytes");
	}

	if (secret_key_length != 0 && secret_key_length < 14) {
		php_error_docref(NULL, E_NOTICE , "For password hashing the secret key should be at least 14 bytes");
	}

	if (iterations == 1 && memory < 47104) {
		php_error_docref(NULL, E_NOTICE , "To compute secure password hashes with one iteration, the memory should at least exceed 47104 KiB");
	}

	if (iterations == 2 && memory < 19456) {
		php_error_docref(NULL, E_NOTICE , "To compute secure password hashes with two iteration, the memory should at least exceed 19456 KiB");
	}

	if (iterations == 3 && memory < 12288) {
		php_error_docref(NULL, E_NOTICE , "To compute secure password hashes with three iteration, the memory should at least exceed 12288 KiB");
	}

	if (iterations == 4 && memory < 9216) {
		php_error_docref(NULL, E_NOTICE , "To compute secure password hashes with four iteration, the memory should at least exceed 9216 KiB");
	}

	if (iterations == 5 && memory < 7168) {
		php_error_docref(NULL, E_NOTICE , "To compute secure password hashes with five iteration, the memory should at least exceed 7168 KiB");
	}

	if (iterations >= 6 && memory < 7168) {
		php_error_docref(NULL, E_NOTICE , "To compute secure password hashes with more then five iteration, the memory should at least exceed 7168 KiB");
	}

	zend_string *hash = zend_string_alloc(tag_length, 0);

	argon2_context context = {
        hash->val,  
        tag_length, 
        password, 
        password_length, 
        salt,  
        salt_length,
        secret_key, secret_key_length, 
        assoziated_data, assoziated_data_length, 
        iterations, memory, parallelism, parallelism,
        version,
        NULL, NULL, 
        ARGON2_DEFAULT_FLAGS 
    };

	int result = argon2d_ctx( &context );

	// If the argon2d calculation for the hash fails, throw an exception
	if (result != ARGON2_OK) {
		efree(hash);
		zend_throw_exception(spl_ce_RuntimeException, "An error occurred during the calculation of the Argon2d hash.", 0);
		RETURN_FALSE;
	}
	
    RETURN_STR(hash);
}

/*  
 * argon2d_password_hash(String $password, int $memory = 65536, int $iterations = 3, int $parallelism = 4, int $version = 0x13): String
 * High-level function to calculate only secure password hashes.
 * The parameters are flexible, but if insecure parameters are used, the calculation will abort with an exception or if a fatal error occurs during the calculation. 
 * The hash is returned in PHC string format.
 */
PHP_FUNCTION(argon2d_password_hash)
{

	if (SIZEOF_ZEND_LONG != 8 ) {
		zend_throw_exception(spl_ce_RuntimeException, "Argon2d is supporting only for 64-Bit PHP installations", 0);
		RETURN_FALSE;
	}

	zend_long memory = 0;
	zend_long iterations = 0; 
	zend_long parallelism = 0;
	zend_long version = 0;

	char *password;

	size_t password_length;

	ZEND_PARSE_PARAMETERS_START(1, 5)
		Z_PARAM_STRING(password, password_length)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(memory)
		Z_PARAM_LONG(iterations)
		Z_PARAM_LONG(parallelism)
		Z_PARAM_LONG(version)
	ZEND_PARSE_PARAMETERS_END();

	// Set the default values if no optional parameters are set

	if (memory == 0) {
		memory = ARGON2_MEMORY;
	}

	if (iterations == 0) {
		iterations = ARGON2_ITERATIONS; 
	}

	if (parallelism == 0) {
		parallelism = ARGON2_PARALLELISM;
	}

	if (version == 0) {
		version = ARGON2_VERSION;
	}

	// Check if parameters are in the allowed value range and throw an exception if they are not

	if (password_length < ARGON2_MIN_PWD_LENGTH || password_length >= ARGON2_MAX_PWD_LENGTH) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Password must be in the value range from 0 to 2^32-1 bytes", 0);
		RETURN_FALSE;
	}

	if (iterations < ARGON2_MIN_TIME || iterations >= ARGON2_MAX_TIME) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Iterations must be in the value range from 1 to 2^32-1", 0);
		RETURN_FALSE;
	}

	if (parallelism < ARGON2_MIN_LANES || parallelism >= 256) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Parallelism must be in the value range from 1 to 255", 0);
		RETURN_FALSE;
	}

	if (memory < (8 * parallelism) || memory >= ARGON2_MAX_MEMORY) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Memory must be in the value range from (8*parallelism) to 2^32-1", 0);
		RETURN_FALSE;
	}

	if (!( version == EXT_VERSION_13 || version == EXT_VERSION_10 )) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Version must be VERSION_13 or VERSION_10", 0);
		RETURN_FALSE;
	}

	// Check that no insecure password hashing parameters are used, and throw an exception if they are

	if (iterations == 1 && memory < 47104) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "To compute secure password hashes with one iteration, the memory must at least exceed 47104 KiB", 0);
		RETURN_FALSE;
	}

	if (iterations == 2 && memory < 19456) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "To compute secure password hashes with two iteration, the memory must at least exceed 19456 KiB", 0);
		RETURN_FALSE;
	}

	if (iterations == 3 && memory < 12288) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "To compute secure password hashes with three iteration, the memory must at least exceed 12288 KiB", 0);
		RETURN_FALSE;
	}

	if (iterations == 4 && memory < 9216) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "To compute secure password hashes with four iteration, the memory must at least exceed 9216 KiB", 0);
		RETURN_FALSE;
	}

	if (iterations == 5 && memory < 7168) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "To compute secure password hashes with five iteration, the memory must at least exceed 7168 KiB", 0);
		RETURN_FALSE;
	}

	if (iterations >= 6 && memory < 7168) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "To compute secure password hashes with more then five iteration, the memory must at least exceed 7168 KiB", 0);
		RETURN_FALSE;
	}

	// Allocate memory for salt 
	char *salt = emalloc(ARGON2_SALT_LENGTH + 1);

	if (salt == NULL){
		zend_throw_exception(spl_ce_RuntimeException, "Error allocating memory for the salt", 0);
		RETURN_FALSE;
	}

	// Create a random salt
	if (create_salt(ARGON2_SALT_LENGTH, salt) == FAILURE) {
		efree(salt);
		zend_throw_exception(spl_ce_RuntimeException, "Error could not generate salt", 0);
		RETURN_FALSE;
	}

	// Calculate the length of the Argon2d password hash in PHC string format
	size_t passwort_hash_length = argon2_encodedlen(
		iterations,
		memory,
		parallelism,
		ARGON2_SALT_LENGTH,
		ARGON2_TAG_LENGTH,
		Argon2_d
	);

	// Allocate the memory for the password_hash
	zend_string *passwort_hash = zend_string_alloc(passwort_hash_length, 0);

	// Calculate the password hash
	int result = argon2_hash(
		iterations,
		memory,
		parallelism,
		password,
		password_length,
		salt,
		ARGON2_SALT_LENGTH,
		NULL,
		ARGON2_TAG_LENGTH,
		passwort_hash->val,
		passwort_hash_length,
		Argon2_d,
		version
	);

	// Free allocated memory for salt
	efree(salt);
	
	// If an error occurs during the calculation, throw an exception
	if (result != ARGON2_OK) {
		efree(passwort_hash);
		zend_throw_exception(spl_ce_RuntimeException, "An error occurred while calculating the password hash", 0);
		RETURN_FALSE;
	}
		
	RETURN_STR(passwort_hash);

}

/*  
 * argon2d_password_hash_verify(String $password_hash, String $password): Bool
 * High-level function to check if a given Argon2d password hash in PHC string format matches a given password. 
 * If an error occurs during the calculation, or if it is not a valid Argon2d password hash in PHC string format, the check is aborted with an exception.
 * A boolean value corresponding to the result of the check is returned.
 */
PHP_FUNCTION(argon2d_password_hash_verify)
{

	if (SIZEOF_ZEND_LONG != 8 ) {
		zend_throw_exception(spl_ce_RuntimeException, "Argon2d is supporting only for 64-Bit PHP installations", 0);
		RETURN_FALSE;
	}

	char *password;
	char *password_hash;

	size_t password_length;
	size_t password_hash_length;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STRING(password_hash, password_hash_length)
		Z_PARAM_STRING(password, password_length)
	ZEND_PARSE_PARAMETERS_END();

	// Check if the password match to a given password hash
	int result = argon2d_verify(password_hash, password, password_length);

	// Check if the input is not a valid argon2 password hash in PHC string format
	if (result == ARGON2_DECODING_FAIL || result == ARGON2_DECODING_LENGTH_FAIL || result == ARGON2_INCORRECT_TYPE) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Input is not a valid argon2d password hash in PHC string format", 0);
		RETURN_FALSE;
	}

	// Password does not match password hash
	if (result == ARGON2_VERIFY_MISMATCH) {
		RETURN_FALSE;
	}

	// Password match with password hash
	if (result == ARGON2_OK) {
		RETURN_TRUE;
		
	}
	// Error during argon2d calculation
	zend_throw_exception(spl_ce_RuntimeException, "An error occurred during verification", 0);
	RETURN_FALSE;
    
}

/* argon2d_password_hash_need_rehash(String $password_hash, int $memory = 65536, int $iterations = 3, int $parallelism = 4, int $version = 0x13): Bool
 * High-level function to check if a given Argon2d password hash in the PHC string needs to be updated.
 * A hash needs to be updated if the parameters in the password hash are less than those passed or if insecure parameters are used.
 * If an error occurs during the check, or if it is not a valid Argon2d password hash in PHC string format, the check is aborted with an exception. 
 * The return value is a Boolean corresponding to the result of the check.
 */

PHP_FUNCTION(argon2d_password_hash_need_rehash)
{

	//Check if the php installation is 64 bit
	if (SIZEOF_ZEND_LONG != 8 ) {
		zend_throw_exception(spl_ce_RuntimeException, "Argon2d is supporting only for 64-Bit PHP installations", 0);
		RETURN_FALSE;
	}

	zend_long memory = 0;
	zend_long iterations = 0; 
	zend_long parallelism = 0;
	zend_long version = 0;

	char *password_hash;

	size_t password_hash_length;

	ZEND_PARSE_PARAMETERS_START(1, 5)
		Z_PARAM_STRING(password_hash, password_hash_length)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(memory)
		Z_PARAM_LONG(iterations)
		Z_PARAM_LONG(parallelism)
		Z_PARAM_LONG(version)
	ZEND_PARSE_PARAMETERS_END();

	// Set the default values if no optional parameters are set

	if (memory == 0) {
		memory = ARGON2_MEMORY;
	}

	if (iterations == 0) {
		iterations = ARGON2_ITERATIONS; 
	}

	if (parallelism == 0) {
		parallelism = ARGON2_PARALLELISM;
	}

	if (version == 0) {
		version = ARGON2_VERSION;
	}

	// Check if parameters are in the allowed value range and throw an exception if they are not

	if (iterations < ARGON2_MIN_TIME || iterations >= ARGON2_MAX_TIME) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Iterations must be in the value range from 1 to 2^32-1", 0);
		RETURN_FALSE;
	}

	if (parallelism < ARGON2_MIN_LANES || parallelism >= 256) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Parallelism must be in the value range from 1 to 255", 0);
		RETURN_FALSE;
	}

	if (memory < (8 * parallelism) || memory >= ARGON2_MAX_MEMORY) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Memory must be in the value range from (8*parallelism) to 2^32-1", 0);
		RETURN_FALSE;
	}

	if (!( version == EXT_VERSION_13 || version == EXT_VERSION_10 )) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Version must be VERSION_13 or VERSION_10", 0);
		RETURN_FALSE;
	}

	//Check if the password hash is not empty
	if (password_hash_length == 0) {
		zend_throw_exception(spl_ce_InvalidArgumentException, "Password hash must can not be empty ", 0);
		RETURN_FALSE;
	}

	// Allocate memory for the parameters in the passed password hash
	char *password_hash_algorithm = emalloc(password_hash_length + 1);
    char *password_hash_salt = emalloc(password_hash_length + 1);
    char *password_hash_raw = emalloc(password_hash_length + 1);

	// Check if memory has been allocated for strings
	if(password_hash_algorithm == NULL || password_hash_salt == NULL || password_hash_raw == NULL){
		zend_throw_exception(spl_ce_RuntimeException, "Error allocating memory", 0);
		RETURN_FALSE;
	}

	zend_long password_hash_version = 0;
	zend_long password_hash_m = 0;
	zend_long password_hash_t = 0;
	zend_long password_hash_p = 0;

	int arguments = sscanf(password_hash, "$%[^$]$v=%ld$m=%ld,t=%ld,p=%ld$%[^$]$%s", password_hash_algorithm, &password_hash_version, &password_hash_m, &password_hash_t, &password_hash_p, password_hash_salt, password_hash_raw);

	if(arguments != 7 || strncmp(password_hash_algorithm,"argon2d",7) != 0){
		free_phc_buffer(password_hash_algorithm, password_hash_salt, password_hash_raw);
		zend_throw_exception(spl_ce_InvalidArgumentException, "Error no valid argon2d password hash in PHC string format", 0);
		RETURN_FALSE;
	}

	/* Check if a valid Argon2 password hash in PHC string format is given
	*  If not, throw an exception
	*/ 

	if (password_hash_t < ARGON2_MIN_TIME || password_hash_t >= ARGON2_MAX_TIME) {
		free_phc_buffer(password_hash_algorithm, password_hash_salt, password_hash_raw);
		zend_throw_exception(spl_ce_InvalidArgumentException, "Error no valid password hash in PHC string format. The iterations must be in the value range from 1 to 2^32-1", 0);
		RETURN_FALSE;
	}

	if (password_hash_p < ARGON2_MIN_LANES || password_hash_p >= 256) {
		free_phc_buffer(password_hash_algorithm, password_hash_salt, password_hash_raw);
		zend_throw_exception(spl_ce_InvalidArgumentException, "Error no valid password hash in PHC string format. The parallelism must be in the value range from 1 to 255", 0);
		RETURN_FALSE;
	}

	if (password_hash_m < (8 * password_hash_t) || password_hash_m >= ARGON2_MAX_MEMORY) {
		free_phc_buffer(password_hash_algorithm, password_hash_salt, password_hash_raw);
		zend_throw_exception(spl_ce_InvalidArgumentException, "Error no valid password hash in PHC string format. The memory must in the value range from (8*parallelism) to 2^32-1", 0);
		RETURN_FALSE;
	}

	if (!( password_hash_version == EXT_VERSION_13 || password_hash_version == EXT_VERSION_10 )) {
		free_phc_buffer(password_hash_algorithm, password_hash_salt, password_hash_raw);
		zend_throw_exception(spl_ce_InvalidArgumentException, "Error no valid password hash in PHC string format. The version must be 16 or 19", 0);
		RETURN_FALSE;
	}

	if (strnlen(password_hash_salt, password_hash_length + 1 ) < 8 || strnlen(password_hash_salt, password_hash_length + 1 ) >= 65) {
		free_phc_buffer(password_hash_algorithm, password_hash_salt, password_hash_raw);
		zend_throw_exception(spl_ce_InvalidArgumentException, "Error no valid password hash in PHC string format. The base64 salt must be in the value range from 11 to 64 bytes", 0);
		RETURN_FALSE;
	}

	if (strnlen(password_hash_raw, password_hash_length + 1 ) < 16 || strnlen(password_hash_raw, password_hash_length + 1 ) >= 87) {
		free_phc_buffer(password_hash_algorithm, password_hash_salt, password_hash_raw);
		zend_throw_exception(spl_ce_InvalidArgumentException, "Error no valid password hash in PHC string format. The base64 tag length must be in the value range from 16 to 86 bytes", 0);
		RETURN_FALSE;
	}

	// Check that the parameters of the password hash are among the parameters passed

	if (password_hash_m < memory) {
		free_phc_buffer(password_hash_algorithm, password_hash_salt, password_hash_raw);
		RETURN_TRUE;
	}

	if (password_hash_t < iterations) {
		free_phc_buffer(password_hash_algorithm, password_hash_salt, password_hash_raw);
		RETURN_TRUE;
	}

	if (password_hash_p < parallelism) {
		free_phc_buffer(password_hash_algorithm, password_hash_salt, password_hash_raw);
		RETURN_TRUE;
	}

	if (password_hash_version != version) {
		free_phc_buffer(password_hash_algorithm, password_hash_salt, password_hash_raw);
		RETURN_TRUE;
	}

	if (strnlen(password_hash_salt, password_hash_length + 1 ) < 22) {
		free_phc_buffer(password_hash_algorithm, password_hash_salt, password_hash_raw);
		RETURN_TRUE;
	}

	if (strnlen(password_hash_raw, password_hash_length + 1 ) < 43) {
		free_phc_buffer(password_hash_algorithm, password_hash_salt, password_hash_raw);
		RETURN_TRUE;
	}
	
	/* Check if no insecure password_hashing parameters are used  
	*  If a parameter is not in the allowed value range, then the password hash must be updated
	*/ 

	if (iterations == 1 && memory < 47104) {
		free_phc_buffer(password_hash_algorithm, password_hash_salt, password_hash_raw);
		RETURN_TRUE;
	}

	if (iterations == 2 && memory < 19456) {
		free_phc_buffer(password_hash_algorithm, password_hash_salt, password_hash_raw);
		RETURN_TRUE;
	}

	if (iterations == 3 && memory < 12288) {
		free_phc_buffer(password_hash_algorithm, password_hash_salt, password_hash_raw);
		RETURN_TRUE;
	}

	if (iterations == 4 && memory < 9216) {
		free_phc_buffer(password_hash_algorithm, password_hash_salt, password_hash_raw);
		RETURN_TRUE;
	}

	if (iterations == 5 && memory < 7168) {
		free_phc_buffer(password_hash_algorithm, password_hash_salt, password_hash_raw);
		RETURN_TRUE;
	}

	if (iterations >= 6 && memory < 7168) {
		free_phc_buffer(password_hash_algorithm, password_hash_salt, password_hash_raw);
		RETURN_TRUE;
	}
	RETURN_FALSE;
}

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(argon2d)
{
	// Create contants for Argon2
	REGISTER_LONG_CONSTANT("VERSION_13", EXT_VERSION_13, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("VERSION_10", EXT_VERSION_10, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("DEFAULT_VALUE", 0, CONST_CS | CONST_PERSISTENT);
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_RINIT_FUNCTION */
PHP_RINIT_FUNCTION(argon2d)
{
#if defined(ZTS) && defined(COMPILE_DL_ARGON2D)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION */
PHP_MINFO_FUNCTION(argon2d)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "argon2d support", "enabled");
	php_info_print_table_end();
}
/* }}} */

/* {{{ argon2d_module_entry */
zend_module_entry argon2d_module_entry = {
	STANDARD_MODULE_HEADER,
	"argon2d",					/* Extension name */
	ext_functions,					/* zend_function_entry */
	PHP_MINIT(argon2d),							/* PHP_MINIT - Module initialization */
	NULL,							/* PHP_MSHUTDOWN - Module shutdown */
	PHP_RINIT(argon2d),			/* PHP_RINIT - Request initialization */
	NULL,							/* PHP_RSHUTDOWN - Request shutdown */
	PHP_MINFO(argon2d),			/* PHP_MINFO - Module info */
	PHP_ARGON2D_VERSION,		/* Version */
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_ARGON2D
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(argon2d)
#endif
