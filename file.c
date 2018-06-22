/* * * * * * * * *
 * Function that is used to open the input and write the output 
 * as csv file.
 * 
 * Author: William Liandri
 * Student ID: 728710
 * Project 2 - Computer System
 * 
 */

#include "file.h"

/************* READ THE CSV FILE AND PUT THE DATA INTO A STRUCT ************/
// Helper function to read data from the csv file and store it in an array.
// During the iteration, the certificate will also be validated. 
void read_and_process_data(char *filepath) {
	
	FILE *fp, *foutput;
	char buffer[BUFFER_SIZE], *temp_cert_file, *temp_cert_url, *certpath;
	cert_data_t cert_data;

	// Open the csv file
	fp = fopen(filepath, "r");

	// Open the output csv file.
	foutput = fopen(FILE_OUTPUT, "w");

	
	if (fp == NULL) {
		fprintf(stderr, "Error reading file\n");
		exit(EXIT_FAILURE);	
	}

	// Get the directory path for the certificate.
	certpath = strtok(filepath,"/");
	
	// Read every row of the csv file.
	while(fgets(buffer,sizeof(buffer),fp) != NULL) {
	
		// Get the certificate file.
		temp_cert_file = strtok(buffer,",");
		
		// Get the URL.
		temp_cert_url = strtok(NULL, "");
		
		// Remove the new line.
		temp_cert_url[strlen(temp_cert_url) - 1] = 0;
		
		// Store the current certificate information in the struct.
		cert_data.file = (char *) malloc((strlen(temp_cert_file) + 1) 
		* sizeof(char));
		strcpy(cert_data.file, temp_cert_file);
		cert_data.file[strlen(temp_cert_file)] = '\0';

		cert_data.url = (char *) malloc((strlen(temp_cert_url) + 1) 
		* sizeof(char));
		strcpy(cert_data.url, temp_cert_url);
		cert_data.url[strlen(temp_cert_url)] = '\0';


		/******** READ AND VALIDATE THE CERTIFICATE ********/ 
		cert_data.valid = read_and_validate_cert(cert_data, certpath);

		// Write the output on the csv file.
		fprintf(foutput, "%s,%s,%d\n", cert_data.file, cert_data.url, 
		cert_data.valid);

		free(cert_data.file);
		free(cert_data.url);
		
	}

	// Close the file
	fclose(fp);
	fclose(foutput);
	
}