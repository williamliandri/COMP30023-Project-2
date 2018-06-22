/* * * * * * * * *
 * Struct to store information about the certificate that are going to 
 * be validated. 
 * 
 * Author: William Liandri
 * Student ID: 728710
 * Project 2 - Computer System
 */

#ifndef CERT_DATA_H
#define CERT_DATA_H

/***************************** TYPEDEF STRUCT ******************************/
typedef struct cert_data {
	char *file;
	char *url;
	int valid;
} cert_data_t;

#endif