/*
 * Written By nightLamp
 *
 * Use below to compile on linux
 * 	$ cc -o secureboi secureboi.c -lssl -lcrypto
 */



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/sha.h>



//prototypes
char *strdup(const char *s);



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


				//need to hash the thing
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
			char * arr[2];
			int i = 0;

			if (argc == 3) {
				//passwd given. have a checklist of 1
				checklist = arr;
				checklist[0] = argv[2];
				i = 1;	//used to add Null terminator later
			}
			else if (argc == 2) {
				//add all stored passwd to checklist

				//open file to read it
				int fd = open(filePath, O_RDONLY);
				if (fd == -1) {
					perror("secureboi");
					exit(EXIT_FAILURE);
				}

				unsigned char hashTemp[SHA_DIGEST_LENGTH];
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
			for (int a = 0; a < i; a++) {
				printf("0x");
				for (int c = 0; c < strlen(checklist[a]); c++) {
					printf("%2x", checklist[a][c]);
				}
				printf("\n");
			}
		} 
	}	

	exit(EXIT_SUCCESS);
}
