/*
 * Written By nightLamp
 *
 * Use below to compile on linux
 * 	$ cc -o secureboi secureboi.c -lssl -lcrypto
 */



#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/sha.h>



//prototypes
char *strdup(const char *s);




/**
 * frees each element of a whole checklist/array. works for static and dynamic checklists/arrays.
 *
 * @param 	cl 				pointer to checklist
 * @param 	size			size of checklist
 * @param		dynamic		true if cl is dynamicly allocated, false if cl is statically allocated
 */
void freeChecklist(char ** cl, int size, bool dynamic) {
	
	for (int a = 0; a < size; a++) {
		free(cl[a]);
	}

	if (dynamic == true) {
		free(cl);
	}
}



/**
 * prints each element of an aray of arrays char by char on a separate line
 *
 * @param 	cl 		pointer to checklist
 * @param		size	size of checklist (amount of elements)	
 */
void printChecklist(char **cl, int size) {
	for (int a = 0; a < size; a++) {
				printf("0x");
				for (int c = 0; c < strlen(cl[a]); c++) {
					printf("%c", cl[a][c]);
				}
				printf("\n");
			}
}



/**
 *  The main function
 */
int main(int argc, char ** argv) {

	char * filePath;
	

	if ( (filePath = getenv("HOME")) == NULL) {
		perror("secureboi");
		exit(EXIT_FAILURE);
	}
	else {
		filePath = strdup(filePath);
		strcat(filePath, "/.secureboi");
		
		if (filePath == NULL) {
			fprintf(stderr, "secureboi: error finding homepath.\n");
		}
	}

	//if file doesnt exist then make it


	if (argc == 1) {
		printf("This is powered by \"Have I been Pwned?\"\n\n");
		printf("This program cannot guarantee security at this state,\nuse at your OWN risk.\n");
	}
	else {
		if (strcmp(argv[1], "store") == 0) {
			
			if(argc == 2) {
				//get pw through stdin
			}
			else if (argc == 3) {
				
				printf("storing to your file...\n");
				int fd = open(filePath, O_WRONLY | O_APPEND);
				if (fd == -1) {
					perror("secureboi");
					exit(EXIT_FAILURE);
				}

				unsigned char fullHash[SHA_DIGEST_LENGTH + 1];	// +1 for \o
				fullHash[SHA_DIGEST_LENGTH] = '\0';
				SHA1( (unsigned char *) argv[2], strlen(argv[2]), fullHash);

				if (write(fd, fullHash, SHA_DIGEST_LENGTH) == -1) {
					perror("secureboi write");
					close(fd);
					exit(EXIT_FAILURE);
				}
				else {
					close(fd);
				}
			}
		}
		else if (strcmp(argv[1], "check") == 0) {
			//check password hashes using "Have I Been Pwned?" database 
			
			//is there a password given?
				//check for that password

			//check all stored passwords


			char ** checklist;		//Null terminated checklist
			bool dynCl = false;
			int i = 0;

			// If given a passwd, hash it then make a checklist of size 1; 
			if (argc == 3) {
				unsigned char * fullHash = calloc(sizeof(char), SHA_DIGEST_LENGTH + 1);
				fullHash[SHA_DIGEST_LENGTH] = '\0';
				SHA1( (unsigned char *) argv[2], strlen(argv[2]), fullHash);

				static char * arr[2];
				checklist = arr;
				checklist[0] = fullHash;
				i = 1;	//used to add Null terminator later
			}
			// Else check all the stored hashes
			else if (argc == 2) {
		
				dynCl = true;

				//open file to read it
				int fd = open(filePath, O_RDONLY);
				if (fd == -1) {
					perror("secureboi");
					exit(EXIT_FAILURE);
				}

				//add all stored passwd to checklist
				unsigned char hashTemp[SHA_DIGEST_LENGTH];
				hashTemp[SHA_DIGEST_LENGTH] = '\0';
				int clBufSize = 10;				
				checklist = calloc(sizeof(char *), clBufSize);

				while (read(fd, hashTemp, SHA_DIGEST_LENGTH) != 0) {
					//check if read did read the whole thing
					
					//add each one to checklist
					checklist[i++] = strdup(hashTemp);
					if (i >= clBufSize) {
						clBufSize += 10;
						if (realloc(checklist, clBufSize) == NULL) {
							perror("secureboi check");
							exit(EXIT_SUCCESS);
						} 
					}
				}
				close(fd);
			}
			//go through all checklist items and see if they are bad

			checklist[i] = NULL;	//TODO what do if checklist is already full?
			
			//print and free checklist
			printChecklist(checklist, i);
			freeChecklist(checklist, i, dynCl);	
		} 
	}	

	exit(EXIT_SUCCESS);
}

