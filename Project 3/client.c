#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int rsa_encrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){ 
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  ctx = EVP_PKEY_CTX_new(key, NULL);
  if (!ctx)
    handleErrors();
  if (EVP_PKEY_encrypt_init(ctx) <= 0)
    handleErrors();
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0)
    handleErrors();
  return outlen;
}

int rsa_decrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){ 
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  ctx = EVP_PKEY_CTX_new(key,NULL);
  if (!ctx)
    handleErrors();
  if (EVP_PKEY_decrypt_init(ctx) <= 0)
    handleErrors();
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    handleErrors();
  if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    handleErrors();
  if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0)
    handleErrors();
  return outlen;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	    unsigned char *iv, unsigned char *plaintext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

int main(int argc, char **argv)
{

  unsigned char *pubfilename = "RSApub.pem";
  unsigned char key[32];
  RAND_bytes(key,32);
  unsigned char encrypted_key[256];
  int encryptedkey_len;
  unsigned char iv[16];
  unsigned char *plaintext = (unsigned char *)"";
  unsigned char ciphertext[1024], decryptedtext[1024];
  int decryptedtext_len, ciphertext_len;
  OpenSSL_add_all_algorithms();
  RAND_bytes(iv,16);
  EVP_PKEY *pubkey;
  FILE* pubf = fopen(pubfilename,"rb");
  pubkey = PEM_read_PUBKEY(pubf,NULL,NULL,NULL);
  

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
  {
    printf("Error in socket creation");
    return 1;
  }

  char *ip;
  short port;

  if (argc == 3)
  {
    ip = argv[1];
    port = atoi(argv[2]);
  }
  else
  {
    printf("usage: ./client  <ip> <port>\n");
    return 1;
  }

  struct sockaddr_in serveraddr;
  serveraddr.sin_family = AF_INET;
  serveraddr.sin_port = htons(port);
  serveraddr.sin_addr.s_addr = inet_addr(ip);

  int n = connect(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
  if (n < 0)
  {
    printf("There was a problem connecting\n");
    return 1;
  }
  while (1)
  {
    printf("Enter a username: ");
    char username[5000];
    fgets(username, 5000, stdin);
    username[strcspn(username, "\n")] = 0;
    if (strlen(username) > 16)
    {
      printf("username is too big try a shorter one\n");
    }
    else
    {
      //generate symmetric key
      encryptedkey_len = rsa_encrypt(key, 32, pubkey, encrypted_key);
      //send username
      char sendThis[300];
      memcpy(sendThis,"0",1);
      memcpy(&sendThis[1], encrypted_key, encryptedkey_len);
      memcpy(&sendThis[258], username,strlen(username));
      send(sockfd, sendThis, 300, 0);
      break;
    }
  }
  fd_set sockets;
  FD_ZERO(&sockets);
  FD_SET(sockfd, &sockets);
  FD_SET(fileno(stdin), &sockets);

  while (1)
  {
    char command[5000];
    char gotTemp[5000];
    char isAdmin[2];

    fd_set tmpset = sockets;

    select(FD_SETSIZE, &tmpset, NULL, NULL, NULL);
    if (FD_ISSET(fileno(stdin), &tmpset)) // got input from user
    {
      fgets(command, 5000, stdin);
      command[strcspn(command, "\n")] = 0;
      if (!strcmp(command, "/help"))
      {
        printf("************************************************\n");
        printf("Commands:\n");
        printf("Get list of other users: /list\n");
        printf("Send message to user: /msg <username> <message>\n");
        printf("Send message to all users: /all <message>\n");
        printf("Check for new messages received: /r");
        printf("Disconnect from server: /quit\n");
        printf("\n");
        printf("Admin only:\n");
        printf("Become an admin: /admin\n");
        printf("Kick off user: /kick <username>\n");
        printf("Rename user: /rename <username> <new username>\n");
        printf("************************************************\n");
      }
      else if (!strcmp(command, "/quit"))
      {
        char yourCharArray[4];
        char sendThisCommand[5000];
        memcpy(sendThisCommand, "1", 1);
        RAND_bytes(iv,16);
        memcpy(&sendThisCommand[1],iv,16);
        ciphertext_len = encrypt(command, strlen ((char *)command), key, iv, ciphertext);
        sprintf(yourCharArray,"%d", ciphertext_len);
        memcpy(&sendThisCommand[18],yourCharArray,4);
        memcpy(&sendThisCommand[23],ciphertext,ciphertext_len);
        send(sockfd, sendThisCommand, 5000, 0);
        printf("Disconnected.\n");
        close(sockfd);
        EVP_cleanup();
        ERR_free_strings();
        return 0;
      }
      else if (command[0] == '/')
      {
        char yourCharArray[4];
        char sendThisCommand[5000];
        memcpy(sendThisCommand, "1", 1);
        RAND_bytes(iv,16);
        memcpy(&sendThisCommand[1],iv,16);
        ciphertext_len = encrypt(command, strlen ((char *)command), key, iv, ciphertext);
        sprintf(yourCharArray,"%d", ciphertext_len);
        memcpy(&sendThisCommand[18],yourCharArray,4);
        memcpy(&sendThisCommand[23],ciphertext,ciphertext_len);
        send(sockfd, sendThisCommand, 5000, 0);
      }
      else
      {
        printf("Invalid command, try /help to get a list of commands.\n");
      }
    }
    if (FD_ISSET(sockfd, &tmpset)) // got data from server
    {
      recv(sockfd, gotTemp, 5000, 0);
      gotTemp[strcspn(gotTemp, "\n")] = 0;

      memcpy(iv,gotTemp,16);
      char templen[4];
      memcpy(templen, &gotTemp[17],4);
      ciphertext_len = atoi(templen);
      memcpy(ciphertext,&gotTemp[22],ciphertext_len);
      decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
      decryptedtext[decryptedtext_len] = '\0';

      if (!strcmp(decryptedtext, "/quit"))
      {
        char yourCharArray[4];
        char sendThisCommand[5000];
        memcpy(sendThisCommand, "1", 1);
        RAND_bytes(iv,16);
        memcpy(&sendThisCommand[1],iv,16);
        ciphertext_len = encrypt(decryptedtext, strlen ((char *)decryptedtext), key, iv, ciphertext);
        sprintf(yourCharArray,"%d", ciphertext_len);
        memcpy(&sendThisCommand[18],yourCharArray,4);
        memcpy(&sendThisCommand[23],ciphertext,ciphertext_len);
        send(sockfd, sendThisCommand, 5000, 0);
        printf("Disconnected.\n");
        close(sockfd);
        EVP_cleanup();
        ERR_free_strings();
        return 0;
      }
      else if (!strncmp(decryptedtext, "Users", 5)) // list command
      {
        printf("%s\n", decryptedtext);
      }
      else if (!strncmp(decryptedtext, "Got a message from ", 19)) // list command
      {
        printf("%s\n", decryptedtext);
      }
      else if (!strncmp(decryptedtext, "admin: ", 7))
      {
        isAdmin[0] = decryptedtext[7];
        isAdmin[1] = decryptedtext[8];
        if (!strncmp(isAdmin, "ye", 2)) // user is admin
        {
          printf("You are an admin.\n");
        }
        else if (!strncmp(isAdmin, "no", 2)) // user is not admin
        {
          printf("Enter password: ");
          struct termios term;
          tcgetattr(fileno(stdin), &term);

          term.c_lflag &= ~ECHO;
          tcsetattr(fileno(stdin), 0, &term);
          char password[5000];
          fgets(password, 5000, stdin);

          term.c_lflag |= ECHO;
          tcsetattr(fileno(stdin), 0, &term);
          password[strcspn(password, "\n")] = 0;
          if (!strcmp(password, "1234567890"))
          {
            printf("password correct\n");
            char tempcommand[] = "/makeadmin";

            char yourCharArray[4];
            char sendThisCommand[5000];
            memcpy(sendThisCommand, "1", 1);
            RAND_bytes(iv,16);
            memcpy(&sendThisCommand[1],iv,16);
            ciphertext_len = encrypt(tempcommand, strlen ((char *)tempcommand), key, iv, ciphertext);
            sprintf(yourCharArray,"%d", ciphertext_len);
            memcpy(&sendThisCommand[18],yourCharArray,4);
            memcpy(&sendThisCommand[23],ciphertext,ciphertext_len);
            send(sockfd, sendThisCommand, 5000, 0);
          }
          else
          {
            printf("password incorrect\n");
          }
        }
      }
      else
      {
        printf("%s\n", decryptedtext);
      }
    }
  }
  close(sockfd);
  EVP_cleanup();
  ERR_free_strings();
  return 0;
}
