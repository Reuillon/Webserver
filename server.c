#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>


typedef struct 
{
	char* data;
	char fileName[256];
	size_t fileSize;
}CachedFile;

CachedFile* LoadCacheList();

int cachedFileSize = 0;

//LOADS THE DATA FROM GET REQUEST ON THE WEBSERVER
void LoadGetRequest(char* filename, SSL* ssl, char* metadata);

CachedFile InitCachedFile(char* fileName, int isTextFile);

int CheckFileExtenstion(char* FileName);

char* metadata;

CachedFile* cachedFiles;

int main() 
{
	cachedFiles = LoadCacheList();
	
	//CREATES SOCKET
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	{
		perror("ERROR: could not create socket!");
		return 1;
	}
	
	//DATA STRUCTURE FOR SOCKET DATA e.g. IP AND PORT
	struct sockaddr_in addr = 
	{
		AF_INET,
		htons(54000),
		INADDR_ANY
	};
	
	//CLIENT DATA
	struct sockaddr_in clientAddr;
	socklen_t clientLen = sizeof(clientAddr);
	
	//BINDS PORT AND IP ADDRESS TO SOCKET
	if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		perror("ERROR: unable to bind socket!");
		return 1;
	}
	
	//CREATES LISTENER ON SOCKET
	if (listen(sockfd, 10))
	{
		perror("ERROR: unable to listen on this socket!");
		return 1;	
	}
		
	//CREATES TLS CONTEXT
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
	if(ctx == NULL)
	{
		return 1;
	}
	
	//LOADS CERTIFICATE CHAIN FILE
	if (SSL_CTX_use_certificate_chain_file(ctx, "localhost+1.pem") != 1)
    {
        ERR_print_errors_fp(stderr);
		close(sockfd);
		SSL_CTX_free(ctx);
        return 1;
    }
	
	//LOADS CERTIFICATE CHAIN KEY
	if (SSL_CTX_use_PrivateKey_file(ctx, "localhost+1-key.pem", SSL_FILETYPE_PEM) != 1)
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match certificate\n");
        return 1;
    }
	
	//TIMEOUT STRUCT
	struct timeval timeout;
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;

	metadata = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";

	//MAIN LOOP FOR SENDING AND RECEIVING
	while (1)
	{

		//CHECKS HEADER FOR CONTENT TYPE IN THIS CASE FOR IMAGES
		int isTextFile = 1;
		printf("awaiting connection....\n");
		
		int clientfd = accept(sockfd, (struct sockaddr*)&clientAddr, &clientLen);
		printf("Connection from: %s\n\n\n", inet_ntoa(clientAddr.sin_addr));
		
		//LOOPS BACK IF NO CLIENT CONNECTION
		if (clientfd < 0)
		{
		   continue;
		}
		
		//CREATES AND CHECKS SSL OBJECT
		SSL* ssl = SSL_new(ctx);
		if(ssl == NULL)
		{
			close(clientfd);
			continue;
		}
		
		//SET SEND AND RECEIVE TIMEOUTS
		setsockopt(clientfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		setsockopt(clientfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
		
		//CHECK IF FILE DESCRIPTOR IS VALID
        if(SSL_set_fd(ssl, clientfd) <= 0)
		{
			SSL_free(ssl);
			close(clientfd);
			continue;
		}

		//CHECK WETHER HANDSHAKE IS VALID
		if (SSL_accept(ssl) <= 0)
		{
			ERR_print_errors_fp(stderr);
			SSL_free(ssl);
			close(clientfd);
			continue;
		}
		else
		{
			char buffer[65536] = {0};
			int sslRead = SSL_read(ssl, buffer, sizeof(buffer) - 1);
			if (sslRead <= 0)
			{
				SSL_free(ssl);
				close(clientfd);
				continue;
			}
			buffer[sslRead] = '\0';
			
			
			
			char method[16];
			char filename[256];
			char version[16];
			
			//CHECK IF REQUEST IS A VALID GET REQUEST
			if (sscanf(buffer, "%15s /%255s %15s", method, filename, version) == 3 && strcmp(method, "GET") == 0)
			{
				isTextFile = CheckFileExtenstion(filename);
				
				

				//IF FILE TYPE IS A VALID FILETYPE
				if (isTextFile != -1)
				{
					LoadGetRequest(filename, ssl, metadata);	
				}
				//IF UNKNOWN/UNAUTHORIZED FILE EXTENSION OR FILE NAME DEFAULT TO HOMEPAGE
				else
				{
					LoadGetRequest("index.html", ssl, metadata);	
				}
			}
			//IF REQUEST IS MALFORMED OR NOT A GET REQUEST
			else
			{
				char* response = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
				SSL_write(ssl, response, strlen(response));
			}
			
		}		
		SSL_shutdown(ssl);
		SSL_free(ssl);	
		close(clientfd);
	}

    SSL_CTX_free(ctx);
    close(sockfd);
	if (cachedFileSize != 0)
	{
		for (int i = 0; i < cachedFileSize; i++)
		{
			free(cachedFiles[i].data);
		}
		free(cachedFiles);
	}
}

CachedFile* LoadCacheList()
{
	int File_Amount = 0;
	int readChar;
	int lastChar = '\0';
	FILE* List_Cached_Files = fopen("CachedFilesList.txt", "r");
	while((readChar = fgetc(List_Cached_Files)) != EOF)
	{
		if (readChar == '\n')
		{
			++File_Amount;
		}
		lastChar = readChar;
	}
	if (lastChar != '\n' && lastChar != '\0')
	{
		++File_Amount;
	} 
	
	cachedFileSize = File_Amount;
	CachedFile* cachedFiles = malloc(sizeof(CachedFile) * File_Amount);
	
	rewind(List_Cached_Files);
	char line[256];
	int currentFileIndex = 0;
	while (fgets(line, sizeof(line), List_Cached_Files))
	{
		line[strcspn(line, "\r\n")] = '\0';
		cachedFiles[currentFileIndex] = InitCachedFile(line, CheckFileExtenstion(line));
		++currentFileIndex;
	}
	fclose(List_Cached_Files);
	return cachedFiles;
}

//LOADS A FILE DIRECTLY INTO MEMORY TO PREVENT MULTIPLE FILE READS
CachedFile InitCachedFile(char* fileName, int isTextFile)
{
	CachedFile newFile;
	
	if (isTextFile == 1)
	{
		FILE* loadedFile = fopen(fileName, "rb");;
		if (loadedFile)
		{
			fseek(loadedFile, 0, SEEK_END);
			size_t fileSize = ftell(loadedFile);
			rewind(loadedFile);
			newFile.data = malloc(fileSize);
			newFile.fileSize = fileSize;
			strcpy(newFile.fileName, fileName);
			fread(newFile.data, 1, fileSize + 1, loadedFile);
			newFile.data[fileSize] = '\0';
			fclose(loadedFile);
		}
		else
		{
			printf("ERROR LOADING FILE %s INTO MEMORY! ABORTING SERVER\n", fileName);
			exit(-1);
		}
	}
	else if (isTextFile != 1)
	{
		FILE* loadedFile = fopen(fileName, "rb");;
		if (loadedFile)
		{
			fseek(loadedFile, 0, SEEK_END);
			size_t fileSize = ftell(loadedFile);
			rewind(loadedFile);
			newFile.data = malloc(fileSize);
			newFile.fileSize = fileSize;
			strcpy(newFile.fileName, fileName);

			fread(newFile.data, 1, fileSize, loadedFile);
			fclose(loadedFile);
		}
		else
		{
			printf("ERROR LOADING FILE %s INTO MEMORY! ABORTING SERVER", fileName);
			exit(-1);
		}
	}

	return newFile;
}

//LOADS THE DATA FROM GET REQUEST ON THE WEBSERVER
void LoadGetRequest(char* filename, SSL* ssl, char* metadata)
{
	//IF THERE IS NO ESTABLISHED SSL CONNECTION DO NOTHING
	if (SSL_write(ssl, metadata, strlen(metadata)) <= 0)
	{
		return;
	}

	int CacheExists = 0;	
	//CHECKS IF FILE REQUEST EXISTS ON DISK
	for(int i = 0; i < cachedFileSize; i++)
	{
		if (strncmp(cachedFiles[i].fileName, filename, strlen(filename)) == 0)
		{
			printf("WritingFromCache!\n");
			CacheExists = 1;
			SSL_write(ssl, cachedFiles[i].data, cachedFiles[i].fileSize);
			return;
		}
	}
	//IF NO CACHE FILE EXIST THEN SERVER ATTEMPTS TO LOAD FROM DISK
	if (CacheExists != 1)
	{
		printf("WritingFromDisk!\n");
		FILE* f = fopen(filename, "rb");
		char buffer[65536];
		size_t bytesRead; 
			
		if (f)
		{			
			while ((bytesRead = fread(buffer, 1, sizeof(buffer), f)) > 0)
			{
				if (SSL_write(ssl, buffer, bytesRead) <= 0)
				{
					return;
				}
			}
			fclose(f);
		}
		else
		{
			f = fopen("index.html", "rb");
			if (f)
			{
				while ((bytesRead = fread(buffer, 1, sizeof(buffer), f)) > 0)
				{
					if (SSL_write(ssl, buffer, bytesRead) <= 0)
					{
						return;
					}
				}
				fclose(f);
			}
			else
			{
				//THIS REALLY SHOULDNT BE POSSIBLE BUT IT IS A FAILSAFE
				printf("ERROR NO FILE FOUND!\n");
			}
			
		}
	}
}

//CHECKS EXTENSION OF FILENAME AND SETS METADATA TO CORRECT VALUES
int CheckFileExtenstion(char* fileName)
{
	if (strstr(fileName, ".html"))
	{
		metadata = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
		return 1;
	}
	else if (strstr(fileName, ".css"))
	{
		metadata = "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\n";
		return 1;
	}
	else if (strstr(fileName, ".js"))
	{
		metadata = "HTTP/1.1 200 OK\r\nContent-Type: text/javascript\r\n\r\n";
		return 1;
	}
	else if (strstr(fileName, ".jpg") || strstr(fileName, ".jpeg"))
	{
		metadata = "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\n\r\n";
		return 0;
	}
	else if (strstr(fileName, ".png"))
	{
		metadata = "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n";
		return 0;
	}
	else if (strchr(fileName, '%') != NULL || strchr(fileName, '/') != NULL || strchr(fileName, '\\')  != NULL || strstr(fileName, "..")  != NULL || strlen(fileName) > 100)
	{
		printf("BAD URL\n\n");
		metadata = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
		return -1;
	}
	else
	{
		metadata = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
		return -1;
	}

	return 1;
}