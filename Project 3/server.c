#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>

#define SIZE 20 // How many clients can join

struct DataItem
{
  int key;
  char username[16];
  bool admin;
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

void insert(int key, char username[16])
{
  struct DataItem *item = (struct DataItem *)malloc(sizeof(struct DataItem));
  strcpy(item->username, username);
  item->key = key;
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

        if (data[0] == '/') // is a command
        {
          if (!strcmp(data, "/quit")) // quit command
          {
            item = search(i);
            printf("%s has left the server.\n", item->username);
            delete (item);
            FD_CLR(i, &sockets);
            close(i);
          }
          else if (!strcmp(data, "/list")) // list command
          {
            char *list = getUsers();
            send(i, list, strlen(list) + 1, 0);
          }
          else if (!strncmp(data, "/msg ", 5)) // list command
          {
            int spaceAt;
            char userTarget[500];
            int keyTarget;
            char msg[5000];
            for (int k = 5; k < strlen(data); k++)
            {
              if (data[k] == ' ')
              {
                spaceAt = k;
                break;
              }
            }
            strcpy(userTarget, &data[5]);
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
              send(keyTarget, result, 5000, 0);
            }
            else
            {
              send(i, "User is not connected.\n", 24, 0);
            }
          }
          else if (!strncmp(data, "/all ", 5)) // list command
          {
            char msg[5000]; // at data[5] to end
            strcpy(msg, &data[5]);

            // send(all, msg, 5000, 0);
            int k = 0;

            for (k = 0; k < SIZE; k++)
            {
              if (hashArray[k] != NULL)
              {
                int tempKey = hashArray[k]->key;
                char *result = appendmsg(msg, i);
                if (tempKey != i)
                  send(tempKey, result, 5000, 0);
              }
            }
          }
          else if (!strncmp(data, "/admin", 6))
          {
            if (hashArray[i]->admin) // is admin
            {
              send(i, "admin: ye", 10, 0);
            }
            else // is not admin
            {
              send(i, "admin: no", 10, 0);
            }
          }
          else if (!strncmp(data, "/makeadmin", 10)) // set admin true for i
          {
            makeAdmin(i);
          }

          else if (!strncmp(data, "/kick ", 6))
          {
            if (hashArray[i]->admin) // user is admin
            {
              char userTarget[16]; // at data[6] to data[spaceAt]
              int keyTarget;
              strcpy(userTarget, &data[6]);
              if (userExist(getUsers(), userTarget)) // user in list
              {
                printf("%s disconnected.\n", userTarget);
                keyTarget = getKey(userTarget);
                send(keyTarget, "/quit", 6, 0);
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
          else if (!strncmp(data, "/rename ", 8))
          {
            if (hashArray[i]->admin) // user is admin
            {
              int spaceAt;
              char userTarget[500];
              int keyTarget;
              char newUser[5000];
              for (int k = 8; k < strlen(data); k++)
              {
                if (data[k] == ' ')
                {
                  spaceAt = k;
                  break;
                }
              }
              strcpy(userTarget, &data[8]);
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
                send(i, "User is not connected.\n", 24, 0);
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
        else // is a username
        {
          printf("%s has joined the server.\n", data);
          insert(i, data);
        }
      }
    }
  }
}