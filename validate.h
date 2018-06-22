/* * * * * * * * *
 * List of functions that are used to validate the certificate.
 
 * Author: William Liandri
 * Student ID: 728710
 * Project 2 - Computer System
 * 
 */

#define _GNU_SOURCE

#ifndef VALIDATE_H
#define VALIDATE_H

#include <fnmatch.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "struct.h"

/******************************** CONSTANTS ********************************/
#define VALID 1 // Indicating the certificate is valid.
#define INVALID 0 // Indicating the certificate is invalid.
#define FILE_DIR "./" // The required file directory to open the certificate.
#define REQ_BIT_SIZE 2048 // The required bit size for the RSA key.
#define CA_FALSE "CA:FALSE" // The basic constraints must include CA:FALSE.
#define TLS_AUTH "TLS Web Server Authentication" // The enhanced key usage
                                                // must include this.

/*************************** FUNCTION PROTOTYPES ***************************/

// Helper functions to read and validate the certificate.
int read_and_validate_cert(cert_data_t curr_cert_data, char *certpath);

// Helper function to validate the Not Before and Not After date of the
// certificate.
bool validate_not_before_and_not_after(X509 *cert);

// Helper function to validate the domain name either in Common Name or 
// Subject Alternative Name.
bool validate_domain_name(X509 *cert, char *domainname);

// Helper function to get the Common Name as a string.
char* get_common_name(X509 *cert);

// Helper function to validate the minimum RSA key length is 2048 bits.
bool validate_min_rsa_len(X509 *cert);

// Helper function to validate if the basic constraints include CA:FALSE.
bool validate_basic_constraints(X509 *cert);

// Helper function to validate if the enhanced key usage includes
// TLS Web Server Authentication.
bool validate_enhanced_key_usage(X509 *cert);

// Helper function to get Certificate Extensions and return it as a string.
char* get_ext_as_string(X509 *cert, int nid);

// Helper function to split the text based on comma and store it in an 
// array.
char** split_text_into_array(char *text, int *index);

#endif