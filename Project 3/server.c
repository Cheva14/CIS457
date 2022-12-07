#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#define SIZE 20 // How many clients can join

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

struct DataItem
{
  int key;
  char username[16];
  bool admin;
  unsigned char symKey[32];
};

struct DataItem *hashArray[SIZE];
struct DataItem *dummyItem;
struct DataItem *item;

int hashCode(int key)
{
  return key % SIZE;
}

struct DataItem *search(int key)
{
  // get the hash
  int hashIndex = hashCode(key);

  // move in array until an empty
  while (hashArray[hashIndex] != NULL)
  {

    if (hashArray[hashIndex]->key == key)
      return hashArray[hashIndex];

    // go to next cell
    ++hashIndex;

    // wrap around the table
    hashIndex %= SIZE;
  }

  return NULL;
}

int getKey(char username[16])
{
  int i = 0;

  for (i = 0; i < SIZE; i++)
  {

    if (hashArray[i] != NULL)
    {
      if (!strcmp(hashArray[i]->username, username))
      {
        return hashArray[i]->key;
      }
    }
  }
  return -1;
}

bool userExist(char *list, char username[])
{
  // list[strcspn(list, "\n")] = 0;
  // username[strcspn(username, "\n")] = 0;

  if (strstr(list, username))
    return true;
  return false;
}

bool isAdmin(int key)
{

  if (hashArray[key] != NULL)
  {
    if (hashArray[key]->admin)
    {
      return true;
    }
  }
  return false;
}

void insert(int key, char username[16], unsigned char symKey[32])
{
  struct DataItem *item = (struct DataItem *)malloc(sizeof(struct DataItem));
  strcpy(item->username, username);
  item->key = key;
  strcpy(item->symKey, symKey);
  item->admin = false;

  // get the hash
  int hashIndex = hashCode(key);

  // move in array until an empty or deleted cell
  while (hashArray[hashIndex] != NULL && hashArray[hashIndex]->key != -1)
  {
    // go to next cell
    ++hashIndex;

    // wrap around the table
    hashIndex %= SIZE;
  }

  hashArray[hashIndex] = item;
}

void makeAdmin(int key)
{
  hashArray[key]->admin = true;
}

struct DataItem *delete (struct DataItem *item)
{
  int key = item->key;

  // get the hash
  int hashIndex = hashCode(key);

  // move in array until an empty
  while (hashArray[hashIndex] != NULL)
  {

    if (hashArray[hashIndex]->key == key)
    {
      struct DataItem *temp = hashArray[hashIndex];

      // assign a dummy item at deleted position
      hashArray[hashIndex] = dummyItem;
      return temp;
    }

    // go to next cell
    ++hashIndex;

    // wrap around the table
    hashIndex %= SIZE;
  }

  return NULL;
}

void display()
{
  int i = 0;

  for (i = 0; i < SIZE; i++)
  {

    if (hashArray[i] != NULL)
      printf("(%d,%s)\n", hashArray[i]->key, hashArray[i]->username);
  }

  printf("\n");
}

char *getUsers()
{
  char *result = "";

  for (int i = 0; i < SIZE; i++)
  {

    if (hashArray[i] != NULL)
    {
      if (!strcmp(result, ""))
      {
        char *startStr = "Users Connected: ";
        int firstSize = strlen(startStr) + strlen(result) + 1;
        char *firstBuffer = (char *)malloc(firstSize);
        strcpy(firstBuffer, result);
        strcat(firstBuffer, startStr);
        result = firstBuffer;

        char *tempstr = hashArray[i]->username;
        int newSize = strlen(tempstr) + strlen(result) + 1;
        char *newBuffer = (char *)malloc(newSize);
        strcpy(newBuffer, result);
        strcat(newBuffer, tempstr);
        result = newBuffer;
      }
      else
      {
        char *tempstr = hashArray[i]->username;
        char *divider = ", ";
        int newSize = strlen(tempstr) + strlen(divider) + strlen(result) + 1;
        char *newBuffer = (char *)malloc(newSize);
        strcpy(newBuffer, result);
        strcat(newBuffer, divider);
        strcat(newBuffer, tempstr);
        result = newBuffer;
      }
    }
  }

  return result;
}
char *appendmsg(char *msg, int key)
{
  char *user = hashArray[key]->username;
  char *result = "Got a message from ";
  int firstSize = strlen(user) + strlen(result) + 1;
  char *firstBuffer = (char *)malloc(firstSize);
  strcpy(firstBuffer, result);
  strcat(firstBuffer, user);
  result = firstBuffer;

  firstSize = strlen(": ") + strlen(result) + 1;
  firstBuffer = (char *)malloc(firstSize);
  strcpy(firstBuffer, result);
  strcat(firstBuffer, ": ");
  result = firstBuffer;

  firstSize = strlen(msg) + strlen(result) + 1;
  firstBuffer = (char *)malloc(firstSize);
  strcpy(firstBuffer, result);
  strcat(firstBuffer, msg);
  result = firstBuffer;

  return result;
}

int main(int argc, char **argv)
{

  unsigned char *privfilename = "RSApriv.pem";
  OpenSSL_add_all_algorithms();
  EVP_PKEY *privkey;
  FILE* privf = fopen(privfilename,"rb");
  privkey = PEM_read_PrivateKey(privf,NULL,NULL,NULL);

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
  {
    printf("Error in socket creation");
    return 1;
  }

  fd_set sockets;
  FD_ZERO(&sockets);
  FD_SET(sockfd, &sockets);
  short port;

  if (argc == 2)
  {
    port = atoi(argv[1]);
  }
  else
  {
    printf("usage: ./client <port>\n");
    return 0;
  }

  struct sockaddr_in serveraddr, clientaddr;
  serveraddr.sin_family = AF_INET;
  serveraddr.sin_port = htons(port);
  serveraddr.sin_addr.s_addr = INADDR_ANY;

  bind(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
  listen(sockfd, 10);

  while (1)
  {
    fd_set tmpset = sockets;
    select(FD_SETSIZE, &tmpset, NULL, NULL, NULL);
    if (FD_ISSET(sockfd, &tmpset))
    {
      socklen_t len = sizeof(struct sockaddr_in);
      int clientsocket = accept(sockfd, (struct sockaddr *)&clientaddr, &len);
      FD_SET(clientsocket, &sockets);
    }
    for (int i = 0; i < FD_SETSIZE; i++)
    {
      if (FD_ISSET(i, &tmpset) && i != sockfd)
      {
        char data[5000];
        recv(i, data, 5000, 0);

        if (data[0] == '1') // is a command
        {
          unsigned char iv[16];
          unsigned char ciphertext[1024], decryptedtext[1024];
          int decryptedtext_len, ciphertext_len;
          memcpy(iv,&data[1],16);
          char templen[4];
          memcpy(templen, &data[18],4);
          ciphertext_len = atoi(templen);
          memcpy(ciphertext,&data[23],ciphertext_len);
          decryptedtext_len = decrypt(ciphertext, ciphertext_len, hashArray[i]->symKey, iv, decryptedtext);
          decryptedtext[decryptedtext_len] = '\0';
          EVP_cleanup();
          ERR_free_strings();
          //printf("got from server: %s\n",decryptedtext);
          if (!strcmp(decryptedtext, "/quit")) // quit command
          {
            item = search(i);
            printf("%s has left the server.\n", item->username);
            delete (item);
            FD_CLR(i, &sockets);
            close(i);
          }
          else if (!strcmp(decryptedtext, "/list")) // list command
          {
            char *list = getUsers();
            char yourCharArray[4];
            char sendThisCipher[5000];
            RAND_bytes(iv,16);
            memcpy(sendThisCipher,iv,16);
            ciphertext_len = encrypt (list, strlen ((char *)list), hashArray[i]->symKey, iv, ciphertext);
            sprintf(yourCharArray,"%d", ciphertext_len);
            memcpy(&sendThisCipher[17],yourCharArray,4);
            memcpy(&sendThisCipher[22],ciphertext,ciphertext_len);
            send(i, sendThisCipher, 5000, 0);
          }
          else if (!strncmp(decryptedtext, "/msg ", 5)) // list command
          {
            int spaceAt;
            char userTarget[500];
            int keyTarget;
            char msg[5000];
            for (int k = 5; k < strlen(decryptedtext); k++)
            {
              if (decryptedtext[k] == ' ')
              {
                spaceAt = k;
                break;
              }
            }
            strcpy(userTarget, &decryptedtext[5]);
            for (int k = 0; k < strlen(userTarget); k++)
            {
              if (userTarget[k] == ' ')
              {
                spaceAt = k;
                break;
              }
            }
            char *tempUser = strtok(userTarget, " ");
            strcpy(msg, &userTarget[spaceAt + 1]);
            if (userExist(getUsers(), tempUser)) // user in list
            {
              keyTarget = getKey(tempUser);
              char *result = appendmsg(msg, i);
              char yourCharArray[4];
              char sendThisCipher[5000];
              RAND_bytes(iv,16);
              memcpy(sendThisCipher,iv,16);
              ciphertext_len = encrypt (result, strlen ((char *)result), hashArray[keyTarget]->symKey, iv, ciphertext);
              sprintf(yourCharArray,"%d", ciphertext_len);
              memcpy(&sendThisCipher[17],yourCharArray,4);
              memcpy(&sendThisCipher[22],ciphertext,ciphertext_len);
              send(keyTarget, sendThisCipher, 5000, 0);
            }
            else
            {
              char yourCharArray[4];
              char sendThisCipher[5000];
              RAND_bytes(iv,16);
              memcpy(sendThisCipher,iv,16);
              ciphertext_len = encrypt ("User is not connected.\n", 24, hashArray[i]->symKey, iv, ciphertext);
              sprintf(yourCharArray,"%d", ciphertext_len);
              memcpy(&sendThisCipher[17],yourCharArray,4);
              memcpy(&sendThisCipher[22],ciphertext,ciphertext_len);
              send(i, sendThisCipher, 5000, 0);
            }
          }
          else if (!strncmp(decryptedtext, "/all ", 5)) // list command
          {
            char msg[5000]; // at data[5] to end
            strcpy(msg, &decryptedtext[5]);

            int k = 0;

            for (k = 0; k < SIZE; k++)
            {
              if (hashArray[k] != NULL)
              {
                int tempKey = hashArray[k]->key;
                char *result = appendmsg(msg, i);
                if (tempKey != i)
                {
                  char yourCharArray[4];
                  char sendThisCipher[5000];
                  RAND_bytes(iv,16);
                  memcpy(sendThisCipher,iv,16);
                  ciphertext_len = encrypt (result, strlen ((char *)result), hashArray[tempKey]->symKey, iv, ciphertext);
                  sprintf(yourCharArray,"%d", ciphertext_len);
                  memcpy(&sendThisCipher[17],yourCharArray,4);
                  memcpy(&sendThisCipher[22],ciphertext,ciphertext_len);
                  send(tempKey, sendThisCipher, 5000, 0);
                }
              }
            }
          }
          else if (!strncmp(decryptedtext, "/admin", 6))
          {
            if (hashArray[i]->admin) // is admin
            {
              char yourCharArray[4];
              char sendThisCipher[5000];
              RAND_bytes(iv,16);
              memcpy(sendThisCipher,iv,16);
              ciphertext_len = encrypt ("admin: ye", 10, hashArray[i]->symKey, iv, ciphertext);
              sprintf(yourCharArray,"%d", ciphertext_len);
              memcpy(&sendThisCipher[17],yourCharArray,4);
              memcpy(&sendThisCipher[22],ciphertext,ciphertext_len);
              send(i, sendThisCipher, 5000, 0);
            }
            else // is not admin
            {
              char yourCharArray[4];
              char sendThisCipher[5000];
              RAND_bytes(iv,16);
              memcpy(sendThisCipher,iv,16);
              ciphertext_len = encrypt ("admin: no", 10, hashArray[i]->symKey, iv, ciphertext);
              sprintf(yourCharArray,"%d", ciphertext_len);
              memcpy(&sendThisCipher[17],yourCharArray,4);
              memcpy(&sendThisCipher[22],ciphertext,ciphertext_len);
              send(i, sendThisCipher, 5000, 0);
            }
          }
          else if (!strncmp(decryptedtext, "/makeadmin", 10)) // set admin true for i
          {
            makeAdmin(i);
          }
          else if (!strncmp(decryptedtext, "/kick ", 6))
          {
            if (hashArray[i]->admin) // user is admin
            {
              char userTarget[16]; // at data[6] to data[spaceAt]
              int keyTarget;
              strcpy(userTarget, &decryptedtext[6]);
              if (userExist(getUsers(), userTarget)) // user in list
              {
                keyTarget = getKey(userTarget);

                char yourCharArray[4];
                char sendThisCipher[5000];
                RAND_bytes(iv,16);
                memcpy(sendThisCipher,iv,16);
                ciphertext_len = encrypt ("/quit", 6, hashArray[keyTarget]->symKey, iv, ciphertext);
                sprintf(yourCharArray,"%d", ciphertext_len);
                memcpy(&sendThisCipher[17],yourCharArray,4);
                memcpy(&sendThisCipher[22],ciphertext,ciphertext_len);
                send(keyTarget, sendThisCipher, 5000, 0);
              }
              else
              {
              }
            }
            else // user is not admin
            {
              // nothing
            }
          }
          else if (!strncmp(decryptedtext, "/rename ", 8))
          {
            if (hashArray[i]->admin) // user is admin
            {
              int spaceAt;
              char userTarget[500];
              int keyTarget;
              char newUser[5000];
              for (int k = 8; k < strlen(decryptedtext); k++)
              {
                if (decryptedtext[k] == ' ')
                {
                  spaceAt = k;
                  break;
                }
              }
              strcpy(userTarget, &decryptedtext[8]);
              for (int k = 0; k < strlen(userTarget); k++)
              {
                if (userTarget[k] == ' ')
                {
                  spaceAt = k;
                  break;
                }
              }
              char *tempUser = strtok(userTarget, " ");
              strcpy(newUser, &userTarget[spaceAt + 1]);
              if (userExist(getUsers(), tempUser)) // user in list
              {
                keyTarget = getKey(tempUser);
                strcpy(hashArray[keyTarget]->username, newUser);
              }
              else
              {

                char yourCharArray[4];
                char sendThisCipher[5000];
                RAND_bytes(iv,16);
                memcpy(sendThisCipher,iv,16);
                ciphertext_len = encrypt ("User is not connected.\n", 24, hashArray[i]->symKey, iv, ciphertext);
                sprintf(yourCharArray,"%d", ciphertext_len);
                memcpy(&sendThisCipher[17],yourCharArray,4);
                memcpy(&sendThisCipher[22],ciphertext,ciphertext_len);
                send(i, sendThisCipher, 5000, 0);
              }
            }
            else // user is not admin
            {
              // nothing
            }
          }
          else
          {
          }
        }
        else  if (data[0] == '0') // is a username
        {
          unsigned char decrypted_key[32];
          unsigned char encrypted_key[256];
          int decryptedkey_len;
          memcpy(encrypted_key,&data[1],256);
          decryptedkey_len = rsa_decrypt(encrypted_key, 256, privkey, decrypted_key); 
          insert(i, &data[258], decrypted_key);
          printf("%s has joined the server.\n", hashArray[i]->username);
        }
      }
    }
  }
}