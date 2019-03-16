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
				int fd = open("/home/ben/.secureboi", O_RDWR | O_APPEND);
				if (fd == -1) {
					perror("secureboi");
					exit(EXIT_FAILURE);
				}

				unsigned char fullHash[200];		
				char partHash[7];		//5 for hash start, 1 for \n, 1 for NULLbyte				

				//need to hash the thing
				SHA1( (unsigned char *) argv[2], strlen(argv[2]), fullHash);
				strncpy(partHash, fullHash, 5);
				partHash[5] = '\n';
				partHash[6] = '\0';				


				if (write(fd, argv[2], 5) == -1) {
					perror("secureboi write");
					close(fd);
					exit(EXIT_FAILURE);
				}
				else {
					close(fd);
				}
			}
		} 
	}	

	exit(EXIT_SUCCESS);
}
