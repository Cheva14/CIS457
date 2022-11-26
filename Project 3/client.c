#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
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
      send(sockfd, username, 17, 0);
      break;
    }
  }
  char temp[5000];

  while (1)
  {
    printf("Enter command: ");
    char command[5000];
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
      send(sockfd, command, strlen(command) + 1, 0);
      printf("Disconnected.\n");
      break;
    }
    else if (!strcmp(command, "/r"))
    {
      printf("wait for messages\n");
      recv(sockfd, temp, 5000, 0);
      printf("Got from server: %s\n", temp);
    }
    else if (command[0] == '/')
    {
      send(sockfd, command, strlen(command) + 1, 0);
      if (!strcmp(command, "/list")) // list command
      {
        char *list;
        recv(sockfd, list, 5000, 0);
        printf("List of Users:\n");
        printf("%s\n", list);
      }
    }
    else
    {
      printf("Invalid command, try /help to get a list of commands.\n");
    }
  }
  close(sockfd);
  return 0;
}
