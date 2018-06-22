# # # # # # #
# Makefile for Project 2 Computer System
# 
# Author: William Liandri
# Student ID: 728710
# 

CC = gcc
RM = rm -f
EXE = certcheck
LIBS = -lssl -lcrypto
OBJ = main.o file.o validate.o

# MAIN PROGRAM
$(EXE): $(OBJ)
	$(CC) -o $(EXE) $(OBJ) $(LIBS)

main.o: file.h
file.o: validate.h
validate.o: struct.h

# CLEANING TARGETS
clean:
	$(RM) $(OBJ)
	$(RM) $(EXE)
