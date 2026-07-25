#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

//LOADS THE DATA FROM GET REQUEST ON THE WEBSERVER
void LoadGetRequest(FILE* f, SSL* ssl, char* metadata);


int main() 
{
	
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

	//MAIN LOOP FOR SENDING AND RECEIVING
	while (1)
	{
		//CHECKS HEADER FOR CONTENT TYPE IN THIS CASE FOR IMAGES
		int isImage = 0;
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
			
			char* metadata = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
			
			char method[16];
			char filename[256];
			char version[16];
			
			//CHECK IF REQUEST IS A VALID GET REQUEST
			if (sscanf(buffer, "%15s /%255s %15s", method, filename, version) == 3 && strcmp(method, "GET") == 0)
			{
				if (strstr(filename, ".css"))
				{
					isImage = 0;
					char* newMetaData = "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\n";
					metadata = newMetaData;
				}
				else if (strstr(filename, ".jpg") || strstr(filename, ".jpeg"))
				{
					isImage = 1;
					char* newMetaData = "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\n\r\n";
					metadata = newMetaData;
				}
				else if (strstr(filename, ".png"))
				{
					isImage = 1;
					char* newMetaData = "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n";
					metadata = newMetaData;
				}
				else if (strchr(filename, '%') != NULL || strchr(filename, '/') != NULL || strchr(filename, '\\')  != NULL || strstr(filename, "..")  != NULL || strlen(filename) > 100)
				{
					printf("BAD URL\n\n");
					isImage = -1;
					char* newMetaData = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
					snprintf(filename, sizeof(filename), "index.html");
					metadata = newMetaData;
				}
				else
				{
					isImage = 0;
					char* newMetaData = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
					metadata = newMetaData;
				}
				
				//IF FILE TYPE IS PLAINTEXT
				if (isImage == 0)
				{				
					FILE* f = fopen(filename, "r");
					if (f)
					{
						LoadGetRequest(f, ssl, metadata);
						fclose(f);
					}
					else
					{
						FILE* defaultPage = fopen("index.html", "r");
						if (defaultPage)
						{
							LoadGetRequest(defaultPage, ssl, metadata);
							fclose(defaultPage);
						}
					}
				}
				//IF FILE TYPE IS AN IMAGE
				else if (isImage == 1)
				{
					FILE* f = fopen(filename, "rb");
					if (f)
					{
						LoadGetRequest(f, ssl, metadata);
						fclose(f);
					}	
					else
					{
						FILE* defaultPage = fopen("index.html", "r");
						if (defaultPage)
						{
							char* defaultMetadata = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
							LoadGetRequest(defaultPage, ssl, defaultMetadata);
							fclose(defaultPage);
						}
					}	
				}
				//IF UNKNOWN/UNAUTHORIZED FILE EXTENSION OR FILE NAME DEFAULT TO HOMEPAGE
				else
				{
					FILE* defaultPage = fopen("index.html", "r");
					if (defaultPage)
					{
						LoadGetRequest(defaultPage, ssl, metadata);
						fclose(defaultPage);
					}
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
}

//LOADS THE DATA FROM GET REQUEST ON THE WEBSERVER
void LoadGetRequest(FILE* f, SSL* ssl, char* metadata)
{
	char buffer[65536];
	size_t bytesRead;
	if (SSL_write(ssl, metadata, strlen(metadata)) <= 0)
	{
		return;
	}
	while ((bytesRead = fread(buffer, 1, sizeof(buffer), f)) > 0)
	{
		if (SSL_write(ssl, buffer, bytesRead) <= 0)
		{
			return;
		}
	}
}