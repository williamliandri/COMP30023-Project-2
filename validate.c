/* * * * * * * * *
 * List of functions that are used to validate the certificate.
 *
 * Author: William Liandri
 * Student ID: 728710
 * Project 2 - Computer System
 * 
 */

#include "validate.h"

/******************** READ AND VALIDATE THE CERTIFICATE ********************/
// Helper functions to read and validate the certificate.
int read_and_validate_cert(cert_data_t curr_cert_data, char *certpath) {
	
	char *certfile;
	BIO *certificate_bio = NULL;
    X509 *cert = NULL;
    X509_NAME *cert_issuer = NULL;
    X509_CINF *cert_inf = NULL;
    STACK_OF(X509_EXTENSION) * ext_list;
	int isValid = VALID;

	// Initialise openSSL.
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

	// Allocate the memory.
	certfile = (char *) malloc( (strlen(certpath) + 
		strlen(curr_cert_data.file) + strlen(FILE_DIR) + 2) 
		* sizeof(char));
	
	// Get the right path for the certificate.
	strcpy(certfile, FILE_DIR);
	strcat(certfile, curr_cert_data.file);
	certfile[strlen(certfile)] = '\0';

	// Create BIO object to read certificate.
    certificate_bio = BIO_new(BIO_s_file());

    //Read certificate into BIO.
    if (!(BIO_read_filename(certificate_bio, certfile)))
    {
        fprintf(stderr, "Error in reading cert BIO filename");
        exit(EXIT_FAILURE);
    }
    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL)))
    {
        fprintf(stderr, "Error in loading certificate");
        exit(EXIT_FAILURE);
    }

	// Validates the Not Before date and Not After date.
	if (!validate_not_before_and_not_after(cert)) {
		isValid = INVALID;
	}

	// Validates the domain name in Common Name.
	if (!validate_domain_name(cert, curr_cert_data.url)) {
		isValid = INVALID;
	}

	// Validates the minimum RSA key length.
	if (!validate_min_rsa_len(cert)) {
		isValid = INVALID;
	}

	// Validates the basic constraints.
	if (!validate_basic_constraints(cert)) {
		isValid = INVALID;
	}

	// Validates the extended key usage.
	if (!validate_enhanced_key_usage(cert)) {
		isValid = INVALID;
	}

	X509_free(cert);
    BIO_free_all(certificate_bio);

	return isValid;
}

/***************** VALIDATES NOT BEFORE AND NOT AFTER DATE *****************/
// Helper function to validate the Not Before and Not After date of the
// certificate.
bool validate_not_before_and_not_after(X509 *cert) {
	ASN1_TIME *notBefore = NULL, *notAfter = NULL;
	int diff_day_notbefore, diff_sec_notbefore, diff_day_notafter, 
	diff_sec_notafter;

	// Get the certificate Not Before date.
	notBefore = cert->cert_info->validity->notBefore;
	
	// Compare the Not Before time with the current time.
	ASN1_TIME_diff(&diff_day_notbefore, &diff_sec_notbefore, NULL, 
	notBefore);

	// Get the certificate Not After date.
	notAfter = cert->cert_info->validity->notAfter;

	// Compare the Not After time with the current time.
	ASN1_TIME_diff(&diff_day_notafter, &diff_sec_notafter, notAfter, NULL);

	// It is valid if the value of the variables are less than 0.
	if( (diff_day_notbefore <= 0 || diff_sec_notbefore <= 0) &&
		(diff_day_notafter <= 0 || diff_sec_notafter <= 0)) {
		return true;
	}

	return false;
}

/****************** VALIDATES DOMAIN NAME IN COMMON NAME *******************/
// Helper function to validate the domain name either in Common Name or 
// Subject Alternative Name.
bool validate_domain_name(X509 *cert, char *domainname) {
	
	char *common_name_str, **subj_alt_name;
    int total_SAN;

    // Get the Common Name in the certificate.
    common_name_str = get_common_name(cert);
	
    // Check if the certificate has Subject Alternative Name.
    if (X509_get_ext_by_NID(cert, NID_subject_alt_name, -1) != -1) {
        
        // If exists, get the Subject Alternative Name.
        subj_alt_name = split_text_into_array(
            get_ext_as_string(cert, NID_subject_alt_name), &total_SAN);

        // Check if the domain name matches one of the Subject Alternative
        // name.
        for(int i = 0; i < total_SAN; i++) {
            if (fnmatch(subj_alt_name[i], domainname, FNM_NOMATCH) == 0) {
                return true;
            }
        }
    }
	
    // Otherwise, check if the domain name matches the common name.
	if (fnmatch(common_name_str, domainname, FNM_NOMATCH) == 0) {
		return true;
	}

	return false;
}

/***************************** GET COMMON NAME *****************************/
// Helper function to get the Common Name as a string.
char* get_common_name(X509 *cert) {
    int common_name_loc = -1;
	X509_NAME_ENTRY *common_name_entry = NULL;
	ASN1_STRING *common_name_asn1 = NULL;
    X509_NAME *cert_subject = NULL;
    char *common_name_str;

    // Get the certificate subject name.
	cert_subject = X509_get_subject_name(cert);

	// Get the the subject Common Name.
    common_name_loc = X509_NAME_get_index_by_NID(cert_subject, 
	NID_commonName, -1);

    common_name_entry = X509_NAME_get_entry(cert_subject, common_name_loc);

    common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);

	// Convert the subject Common Name into string.
    common_name_str = (char *) ASN1_STRING_data(common_name_asn1);

    return common_name_str;
}

/******************* VALIDATES THE MINIMUM RSA KEY LENGTH ******************/ 
// Helper function to validate the minimum RSA key length is 2048 bits.
bool validate_min_rsa_len(X509 *cert) {
	EVP_PKEY *public_key;
    int key_length; 
    
	// Get the RSA public key.
	public_key = X509_get_pubkey(cert);

	// Get the bit length of the key.
	key_length = BN_num_bits(public_key->pkey.rsa->n);

	EVP_PKEY_free (public_key);

	// Check if the key is 2048 bit.
	if (key_length == REQ_BIT_SIZE) {
		return true;
	}

	return false;
	
}

/**************** VALIDATES THE BASIC CONSTRAINTS EXTENSION ****************/
// Helper function to validate if the basic constraints include CA:FALSE.
bool validate_basic_constraints(X509 *cert) {
    char *ext_basic_constraints;

	// Get the Basic Constraints extension as a string.
	ext_basic_constraints = get_ext_as_string(cert, NID_basic_constraints);

    // Check if the Basic Constraints equal to CA:FALSE.
	if(strcasecmp(CA_FALSE, ext_basic_constraints) == 0) {
    	free(ext_basic_constraints);
		return true;
	} 

    free(ext_basic_constraints);

	return false;
}

/**************** VALIDATES THE ENHANCED KEY USAGE EXTENSION ***************/
// Helper function to validate if the enhanced key usage includes
// TLS Web Server Authentication.
bool validate_enhanced_key_usage(X509 *cert) {
    char *ext_enh_key_usage = NULL;

	// Get the Enhanced Key Usage extension as a string.
    ext_enh_key_usage = get_ext_as_string(cert, NID_ext_key_usage);

	if (strstr(ext_enh_key_usage,TLS_AUTH) != NULL 
    || strcasecmp(ext_enh_key_usage, TLS_AUTH) == 0) {

        free(ext_enh_key_usage);
		return true;
	}
    free(ext_enh_key_usage);
	
	return false;
}

/******************* GET CERTIFICATE EXTENSIONS AS STRING ******************/
// Helper function to get Certificate Extensions and return it as a string.
char* get_ext_as_string(X509 *cert, int nid) {
	X509_EXTENSION *ext;
	BUF_MEM *bptr = NULL;
    char *buff = NULL; 

	// Get the specified Certificate Extensions.
	ext = X509_get_ext(cert, X509_get_ext_by_NID(
	cert, nid, -1));
	
	BIO *bio = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(bio, ext, 0, 0))
    {
        fprintf(stderr, "Error in reading extensions");
		exit(1);
    }
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

	//bptr->data is not NULL terminated - add null character
    buff = (char *)malloc((bptr->length + 1) * sizeof(char));
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = '\0';

    BIO_free_all(bio);

    return buff;
}

/********************** SPLIT THE TEXT INTO AN ARRAY **********************/ 
// Helper function to split the text based on comma and store it in an 
// array.
char** split_text_into_array(char* text, int *index) {

    char *token = strtok (text, ",");
    int currSize = 1;
    char **array;
	*index = 0;

	// Allocate the memory of the array.
    array = (char **) malloc(currSize * sizeof(*array));

    while (token != NULL)
    {   
		// Remove the "DNS:" and space (if any).
        if (currSize > 1) {
            memmove(&token[0], &token[5], strlen(token) - 4);
        }
        else {
            memmove(&token[0], &token[4], strlen(token) - 3);
        }

		// Allocate the memory to store the string.
        array[*index] = (char *) malloc(strlen(token) * sizeof(char));
        array[*index] = token;
        array[*index][strlen(token)] = '\0';

        // Reallocate the memory of the array.
        array = (char **) realloc(array, (currSize + 1) * sizeof(*array));
	
		// Taking the next string.
        token = strtok (NULL, ",");

        currSize++;
        *index += 1;
    }

    return array;
}

