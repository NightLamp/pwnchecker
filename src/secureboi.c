/*
 * Written By nightLamp
 *
 * Use below to compile on linux
 * 	$ cc -o secureboi secureboi.c -lssl -lcrypto
 * 
 */



#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/sha.h>



//prototypes
char *strdup(const char *s);


void printWarning(void) {
	printf("This is powered by \"Have I been Pwned?\" and Curl\n\n"
					"This program cannot guarantee security at this state,\n"
					"use at your OWN risk.\n"
					"Note that any password typed in will be shown in plain text on a cli.\n\n"
					"Commands:\n"
					"store [passwd]\n"
					"check [passwd]\n");
	
}



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
void printRawChecklist(char **cl, int size) {
	for (int a = 0; a < size; a++) {
		printf("0x");
		for (int c = 0; c < strlen(cl[a]); c++) {
			printf("%c", cl[a][c]);
		}
		printf("\n");
	}
}



/**
 * Returns a raw hash of a string
 * Assumes dest array is of appropriate size.
 *
 *
 * @param		dest		array to be filled with raw hash
 * @param		source	array holding string to be hashed
 * @return 					pointer to result char array
 */
char * stringToRawSHA1(unsigned char * dest, char * source) {

	dest[SHA_DIGEST_LENGTH] = '\0';
	SHA1( (unsigned char *) source, strlen(source), dest);

	return dest;
}

/**
 * Changes from raw SHA1 output to string binary 
 * Assumes arrays are SHA_DIGEST_LENGTH in size 
 *
 */
char * rawToHexString(char * hexStr, char * rawStr) {

	for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
		unsigned char rawByte = rawStr[i];
		sprintf((char *)&(hexStr[i*2]), "%02X", rawByte);
	}
	return hexStr;
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

	//TODO if file doesnt exist then make it


	if (argc == 1) {
		printWarning();
	}
	else {
		if (strcmp(argv[1], "store") == 0) {

			//open passwd storing file and get descriptor
			//should be in ~/.secureboi
			int fd = open(filePath, O_WRONLY | O_APPEND);
			if (fd == -1) {
				perror("secureboi");
				exit(EXIT_FAILURE);
			}

			if(argc == 2) {
				//get pw through stdin
			}
			else if (argc == 3) {
				
				printf("storing to your file...\n");

				//setup vars for hashing
				unsigned char fullHash[SHA_DIGEST_LENGTH + 1];	// +1 for \o
				stringToRawSHA1(fullHash, argv[2]);

				//write raw hash to file
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

			char ** checklist;		//Null terminated checklist
			bool dynCl = false;
			int clSize = 0;

			// If given a passwd, hash it then make a checklist of size 1; 
			if (argc == 3) {
				
				//make a raw hash.
				unsigned char * fullHash = calloc(sizeof(char), SHA_DIGEST_LENGTH + 1);
				stringToRawSHA1(fullHash, argv[2]);

				static char * arr[2]; //static to ensure it doesnt dissapear on me
				checklist = arr;
				checklist[0] = fullHash;
				clSize = 1;
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

				unsigned char hashTemp[SHA_DIGEST_LENGTH];
				hashTemp[SHA_DIGEST_LENGTH] = '\0';
				int clBufSize = 10;				
				checklist = calloc(sizeof(char *), clBufSize);

				//add all stored passwd to checklist
				while (read(fd, hashTemp, SHA_DIGEST_LENGTH) != 0) {
					//TODO check if read did read the whole thing or some
					
					//add each one to checklist
					checklist[clSize++] = strdup(hashTemp);
					if (clSize >= clBufSize) {
						clBufSize += 10;
						if (realloc(checklist, clBufSize) == NULL) {
							perror("secureboi check");
							exit(EXIT_SUCCESS);
						} 
					}
				}
				close(fd);
			}

			checklist[clSize] = NULL;	//TODO what do if checklist is already full?

			//go through all checklist items and see if they are compromised
			
			char hashString[SHA_DIGEST_LENGTH];
			char hashStart[6];													// 5 for hash 1 for nullbyte 
			char hashEnd[SHA_DIGEST_LENGTH-5 + 1];		// -5 for missing start, +1 for nullbyte 

			//add nullbytes
			hashStart[5] = '\0';	
			hashEnd[SHA_DIGEST_LENGTH-5] = '\0';

			// go though each item in checklist
			for (int a = 0; a < clSize; a++) {
		
				rawToHexString(hashString, checklist[a]);

				//split hashString into first 5 and remaining hex values
				strncpy(hashStart, hashString, 5);
				strcpy(hashEnd, &hashString[5]);


				//get pipe doing its thing
				int pipfd[2];
				pipe(pipfd);

				//call curl
				if (fork() == 0) 	{

					char url[200] = "https://api.pwnedpasswords.com/range/";
					strcat(url, hashStart);	

					dup2(pipfd[1], STDOUT_FILENO);
					close(pipfd[0]);
					close(pipfd[1]);
		
					execlp("curl", "curl", "-s",  url, NULL); 				
					fprintf(stderr, "secureboi: error calling curl\n");
					exit(EXIT_FAILURE);
				}			

				
				//setup curl output to be read
				FILE * fp;
				if ( (fp = fdopen(pipfd[0], "r" )) == NULL) {
					fprintf(stderr, "secureboi: fdopen error\n");
					exit(EXIT_FAILURE);
				}
				close(pipfd[1]);

				//wait and then check status of child (curl)
				int stat;
				wait(&stat);
				if(WIFEXITED(stat)) {
					if (WEXITSTATUS(stat) > 0) {
						fprintf(stderr, "not a real URL\n");
						exit(EXIT_FAILURE);
					}
				}

				char buffer[SHA_DIGEST_LENGTH+20];
				bool matchFound = false;

				//read curl output line by line
				while (fgets(buffer, sizeof(buffer) -1, fp) != NULL) {

					if (strncmp(buffer, hashEnd, strlen(hashEnd)-1) == 0) {
						matchFound = true;
						printf("Password Compromised\n");
					}
				}
				if (!matchFound) {
					printf("no matches.\n");
				}
			}

			freeChecklist(checklist, clSize, dynCl);	
		} 
	}	

	exit(EXIT_SUCCESS);
}

