/* * * * * * * * *
 * Function tha is used to open the input and write the output 
 * as csv file.
 * 
 * Author: William Liandri
 * Student ID: 728710
 * Project 2 - Computer System
 * 
 */

#include <stdio.h>
#include <stdlib.h>

#include "validate.h"

/******************************** CONSTANTS ********************************/
#define BUFFER_SIZE 5000 // The size to read the row of the csv file.
#define FILE_OUTPUT "output.csv" // The name of the file to write the output.

/*************************** FUNCTION PROTOTYPES ***************************/
// Helper function to read data from the csv file and store it in an array.
// During the iteration, the certificate will also be validated. 
void read_and_process_data(char *filepath); 