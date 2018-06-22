/* * * * * * * * *
 * Main Program: Validates TLS certificate file by reading csv file that
 * contains the file path for the certificate and the URL from which that
 * certificates belong. 
 * It will validate the Not Before date,Not After date, domain name in 
 * Common Name, minimum RSA key length to be 2048 bits, Basic Constraints, 
 * Enhanced Key Usage, and Subject Alternative Name (SAN). 
 * The result of the validation will be exported as csv file, called 
 * output.csv. 
 * 
 * Author: William Liandri
 * Student ID: 728710
 * Project 2 - Computer System
 *
 */

#include "file.h"

/*************************** FUNCTION PROTOTYPES ***************************/
void read_and_process_data(char *filepath); 

/****************************** MAIN FUNCTION ******************************/
int main (int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "./certcheck pathToTestFile\n");
		exit(1);
	}

	// Read the input file, validate each certificate, and write
	// the output.
	read_and_process_data(argv[1]);
	
	return 0;
}