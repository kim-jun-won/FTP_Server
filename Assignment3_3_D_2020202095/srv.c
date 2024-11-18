/////////////////////////////////////////////////////
// File Name  : srv.c                              //
// Date       : 2024/05/28                         //
// OS         : Ubuntu 20.04.06 LTS 64bits         //
// Author     : Junwon Kim                         //
// Student ID : 20202020295                        //
// ------------------------------------------------//
// Title : System Programming Assignment #3-2      //
/////////////////////////////////////////////////////

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h> // For write(), read(), STDERR_FILENO, and STDOUT_FILENO
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>

#define MAX_BUFF 1024
#define SAFE_FREE(p) {if(p!=NULL){free(p);p=NULL;}}
#define FLAGS (O_RDWR | O_CREAT | O_TRUNC)
#define ASCII_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
#define BIN_MODE (S_IXUSR | S_IXGRP | S_IXOTH)

int is_binary = 1; // defaule binary mode;

const char *error1 = "Error : invalid option\n";
const char *error2 = "Can't find such file of directory\n";
const char *error3 = "Error : argument is not required\n";
const char *error4 = "Error : No such file or directory\n";
const char *error5 = "Error : cannot access\n";
const char *error6 = "Error : argument is required\n";
const char *message = " is current directory\n";
const char * lserror1 = "Error : Too many arguemnts\n";
const char * openerror = "Error : file open error\n";
const char * lstaterror = "Error : lstat\n";

const char * msg0 = "200 Port command successfully.\n";
const char * msg1 = "550 Failed to access.\n";
const char * msg2 = "150 Opening data connection for directory list.\n";
const char * msg3 = "226 Complete transmission.\n";
const char * msg4 = "550 Failed transmission.\n";
const char * msg5 = "221 Goodbye.\n";

///////////////////////////////////////////////////////////////////
// error_handling                                                //
// ==============================================================//
// Input : const char * message                                  //
//                                                               //
// Ouput : void                                                  //
// Purpose : print error message to STDERR                       //
///////////////////////////////////////////////////////////////////
void error_handling(const char * message);
///////////////////////////////////////////////////////////////////
// cmd_process                                                   //
// ==============================================================//
// Input : char * -> buff                                        //
//         char * -> result_buff                                 //
//                                                               //
// Ouput : return 1 if success                                   //
//         return -1 if error                                    //
// Purpose : execute cmd and save result in result_buff          //
///////////////////////////////////////////////////////////////////
int cmd_process(char*buff , char * result_buff, int control_sock);
///////////////////////////////////////////////////////////////////
// handle_client                                                 //
// ==============================================================//
// Input : int -> control_sock                                   //
//                                                               //
// Ouput : void                                                  //
// Purpose : execute connection with client in child process     //
///////////////////////////////////////////////////////////////////
void handle_client(int control_sock);
///////////////////////////////////////////////////////////////////
// print _file_info                                              //
// ==============================================================//
// Input : const char * -> file_path                             //
//         char * -> result_buff                                 //
//                                                               //
// Ouput : return 1 if success                                   //
//         return -1 if error                                    //
// Purpose : save file_info in result_buff                       //
///////////////////////////////////////////////////////////////////
int print_file_info(const char * file_path, char * result_buff);
///////////////////////////////////////////////////////////////////
// nlst                                                          //
// ==============================================================//
// Input : char ** -> tokens                                     //
//         char * -> result_buff                                 //
//         int -> token_count                                    //
//                                                               //
// Ouput : return 1 if success                                   //
//         return -1 if error                                    //
// Purpose : execute ls command                                  //
///////////////////////////////////////////////////////////////////
int nlst(char ** tokens, int token_count, char * result);
int pwd(char ** tokens, int token_count, char * result_buff);
int list(char ** tokens, int token_count, char * result_buff);
int cd(char ** tokens, int token_count, char * result_buff);
int mkd(char ** tokens, int token_count, char * result_buff);
int del(char ** tokens, int token_count, char * result_buff);
int rmd(char ** tokens, int token_count, char* result_buff);
int my_rename(char ** tokens, int token_count, char* result_buff, int control_sock);
int checkAccess(char * client_ip);
int user_match(char *information, int is_username);
int log_auth(int connfd);

void error_handling(const char * message)
{
    write(STDERR_FILENO, message, strlen(message));
    exit(1);
}


int main(int argc, char**argv)
{
    time_t curTime = time(NULL);
    struct tm *pLocal = localtime(&curTime);
    int control_sock, client_sock;
    struct sockaddr_in control_addr, client_addr;
    socklen_t client_addr_size;

    // Create a socket for the control connection
    control_sock = socket(PF_INET, SOCK_STREAM, 0);
    if(control_sock == -1){
        error_handling("socket() error!");
    }

    // Initialize the control address structure
    bzero((char*)&control_addr, sizeof(control_addr));
    control_addr.sin_family = AF_INET;
    control_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    control_addr.sin_port = htons(atoi(argv[1]));
    
    // Bind the socket to the address and port
    if (bind(control_sock, (struct sockaddr*)&control_addr, sizeof(control_addr)) == -1) {
        error_handling("bind() error");
    }

    // Listen for incoming connections, with a backlog of 5
    if (listen(control_sock, 5) == -1) {
        error_handling("listen() error");
    }

    // Main server loop to accept and handle client connections
    while(1)
    {
        client_addr_size = sizeof(client_addr);
        client_sock = accept(control_sock, (struct sockaddr*)&client_addr, &client_addr_size );
        if(client_sock==-1){
            error_handling("accept() error");
        }

        printf("** Client is connected **\n"); // if accept succes print success message
        fflush(stdout);

        char client_ip[MAX_BUFF];
        memset(client_ip , 0 , sizeof(client_ip));
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN); // inver client_ip to string

        ////////////////////////////////////////// execute LOG-IN /////////////////////////////////////////////////////////////////////
         if((checkAccess(client_ip)) > 0){ // check Access
            char welcome_message[MAX_BUFF];
            memset(welcome_message, 0, sizeof(welcome_message));
            snprintf(welcome_message, MAX_BUFF, "220 sswlab.kw.ac.kr FTP server (version myftp [1.0] %04d-%02d-%02dT%02d:%02d:%02d ) ready.\n", pLocal->tm_year + 1900, pLocal->tm_mon + 1, pLocal->tm_mday, pLocal->tm_hour, pLocal->tm_min, pLocal->tm_sec);

            write(client_sock, welcome_message , strlen(welcome_message));     // if access ok, write accepted
         }else{
            write(client_sock,"431 This client can't access. Close the session\n",strlen("431 This client can't access. Close the session\n")); // else write rejection
            close(client_sock);
            exit(1);
         } 

         log_auth(client_sock);

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        if (fork() == 0) { // Child process
            close(control_sock);
            handle_client(client_sock);
            close(client_sock);
            exit(0);
        } else { // Parent process
            close(client_sock);
            wait(NULL); // Reap child process to prevent zombie processes
        }
    }

    close(control_sock);
    return 0;
}

int checkAccess(char * client_ip){ // check if client_ip is accessable

    const int max = 1024;
    char * compare[5];
    char * origin[5];
    char * token1;
    char * token2;
    char * readline;
    char line[max];

    int i=0;
    token1 = strtok(client_ip, ".\n");
    while(token1!=NULL){
        origin[i] = token1;
        token1 = strtok(NULL,".\n");
        i++;
    }

    FILE * fp_checkIP = fopen("access.txt" , "r"); // open access.txt
    
    if(fp_checkIP == NULL){ // if fp_cehckIP is NULL print error msg
        printf("** File open error!! **\n");
        exit(1);
    }

    while(fgets(line, max, fp_checkIP) != NULL){  // read one by one line

        int j =0;
        bzero(compare , sizeof(compare));

        token2 = strtok(line, ".\n");
        while(token2!=NULL){
           compare[j] = token2;
           token2 = strtok(NULL,".\n");
           j++;
        }
       
        for(int i=0; i<4; i++){
            if(strcmp(compare[i],"*") ==0) continue;
            else if(strcmp(origin[i], compare[i])!=0) break;
            else if(strcmp(origin[i], compare[i])==0 && i==3) return 1;
        }
    }
    
    return -1;
}

int log_auth(int connfd)
{
    char information[MAX_BUFF]={0};
    char user[MAX_BUFF]={0};
    char passwd[MAX_BUFF]={0};
    int n;
    int count = 1;

    while(1){
        memset(information, 0, sizeof(information));
        // receive username and password from client
        if(read(connfd, information, MAX_BUFF) <0 ){
            write(STDERR_FILENO, "Read error!\n" , strlen("Read error!\n"));
            exit(1);
        }

        if(strncmp(information,"USER",4)==0)
        {
            memset(user, 0, strlen(user));
            sscanf(information + 5, "%s", user);
            
           if(count>=4)
            {
               write(connfd,"530 Failed to log-in.\n", strlen("530 Failed to log-ing.\n"));
               exit(1);
            }


            if(user_match(user,1)==1)
            {
               write(connfd, "331 Password is required for user name.\n", strlen("331 Password is required for user name.\n"));
               write(STDOUT_FILENO, "331 Password is required for user name.\n", strlen("331 Password is required for user name.\n"));
            }
            else
            {
               write(connfd, "430 Invalid username or password.\n", strlen("430 Invalid username or password.\n"));
               write(STDOUT_FILENO, "430 Invalid username or password.\n", strlen("430 Invalid username or password.\n"));
               count++;
            }
        }
        else if(strncmp(information,"PASS",4)==0)
        {
            memset(passwd, 0, strlen(passwd));
            sscanf(information + 5, "%s", passwd);

            if(count>=4)
            {
               write(connfd,"530 Failed to log-in.\n", strlen("530 Failed to log-ing.\n"));
               exit(1);
            }

            if(user_match(passwd,0)==1){
               char command[MAX_BUFF];
               memset(command, 0, sizeof(command));
               snprintf(command, MAX_BUFF, "230 User [%s] logged in.\n" , user);
               write(connfd, command, strlen(command));
               write(STDOUT_FILENO, command, strlen(command));
               return 0;

            }else{
               write(connfd, "430 Invalid username or password.\n", strlen("430 Invalid username or password.\n"));
               write(STDOUT_FILENO, "430 Invalid username or password.\n", strlen("430 Invalid username or password.\n"));
               count++;
            }
        }
    }

       
}


int user_match(char*information, int is_username) // check login succes or fail
{

    FILE * fp;
    struct passwd *pw;

    if( information == NULL) return 0; // is user and password is null
    fp = fopen("passwd", "r");
    if(fp==NULL){
      printf("file open error!\n"); exit(1);
    }

    if(is_username == 1)           ////////////////// compare ID
    {
      while((pw=fgetpwent(fp)) != NULL){

            char * c_user = pw->pw_name; // savae name in c_user
            if(strcmp(information,c_user) ==0) return 1;
         }

    }
    else if(is_username ==0)       ///////////////// compare Password
    {
      while((pw=fgetpwent(fp)) != NULL){
         char * c_passwd = pw->pw_passwd; // save password in c_passwd

         if(strcmp(information, c_passwd) ==0) return 1; // sucess 
      }
    }

    close(fp);

    return 0;
}


void handle_client(int control_sock){

    char buffer[MAX_BUFF];
    char control_buffer[MAX_BUFF];
    char result_buffer[MAX_BUFF];
    char port_command[MAX_BUFF];
    int len , len_out;

    memset(buffer, 0, sizeof(buffer));
    // Loop to handle client commands
    while(len = read(control_sock, buffer, sizeof(buffer)-1) != 0) 
    {
        ///////////////////////////////////////////////////////////// quit /////////////////////////////////////////////////////////////////
        if(strncmp(buffer, "QUIT",4)==0)
        {
            write(control_sock, msg5, strlen(msg5));
            write(STDOUT_FILENO, msg5, strlen(msg5));
            close(control_sock);
            exit(1);
        }

        ///////////////////////////////////////////////////////////////// ls ////////////////////////////////////////////////////////////////
        if(strncmp(buffer, "PORT", 4) ==0)
        {          
            memset(result_buffer, 0, sizeof(result_buffer));
            memset(control_buffer, 0, sizeof(control_buffer));

            unsigned int h1,h2,h3,h4,p1,p2;
            unsigned client_port;
            char client_ip[MAX_BUFF];

            // Parse the PORT command to get client's IP address and port number
            sscanf(buffer + 5, "%u.%u.%u.%u,%u,%u", &h1, &h2, &h3, &h4, &p1, &p2);
            snprintf(client_ip, sizeof(client_ip), "%u.%u.%u.%u", h1, h2, h3, h4);
            snprintf(port_command , MAX_BUFF, "PORT %u,%u,%u,%u,%u,%u" , h1, h2, h3, h4 , p1, p2);
            printf("%s\n", port_command);
            client_port = p1 * 256 + p2;
           
            // Create a socket for the data connection
            int data_sock = socket(PF_INET, SOCK_STREAM,0);
            if(data_sock == -1){
                error_handling("data socket() error");
            }

            // Initialize the client address structure
            struct sockaddr_in client_addr;
            memset(&client_addr, 0, sizeof(client_addr));
            client_addr.sin_family = AF_INET;
            client_addr.sin_addr.s_addr = inet_addr(client_ip);
            client_addr.sin_port = htons(client_port);

            // Connect to the client's data socket
            if (connect(data_sock, (struct sockaddr*)&client_addr, sizeof(client_addr)) == -1) {
                write(control_sock, msg1, strlen(msg1)); // 550 Fail to access   
                exit(1);
            }

            // If it is connected succesfully
            write(control_sock, msg0, strlen(msg0)); // 200 port command succesful
            write(STDOUT_FILENO, msg0, strlen(msg0));
            memset(control_buffer, 0, sizeof(control_buffer));

            if(read(control_sock, control_buffer , sizeof(control_buffer)-1) < 0){ // receive converted command
                error_handling("read() error");
            }else{
                write(STDOUT_FILENO, control_buffer, strlen(control_buffer));  //////////////// print command
                write(STDOUT_FILENO, "\n", 1);
            }

            ///////////////////////////////////////////////////////////// NLST /////////////////////////////////////////////////////////////
            if(strncmp(control_buffer, "NLST", 4)==0){

              // Send message indicating data connection is being opened
               write(control_sock, msg2 , strlen(msg2)); // 150 Opening data connection for directory list
               write(STDOUT_FILENO, msg2 , strlen(msg2));

               len_out = strlen(control_buffer);
               control_buffer[len_out] = '\0';

               memset(result_buffer, 0, sizeof(result_buffer));      

               if(cmd_process(control_buffer, result_buffer,control_sock) < 0){
                write(control_sock, msg4, strlen(msg4)); // 550 Failed transmission
                write(STDOUT_FILENO, result_buffer , strlen(result_buffer));
                close(data_sock);
               }
               else{
                  write(data_sock, result_buffer , strlen(result_buffer));
                  fflush(stdout);
                  write(control_sock, msg3, strlen(msg3)); // 226 Complete transmission
                  write(STDOUT_FILENO, msg3, strlen(msg3));
                  close(data_sock);
               }
            }
            /////////////////////////////////////////////////////////// RETR  /////////////////////////////////////////////////////////////////////
            else if(strncmp(control_buffer, "RETR", 4)==0)
            {
               // Extract the filename from the RETR command
               char filename[MAX_BUFF];
               sscanf(control_buffer + 5, "%s", filename);

               // Open the file to be sent
               FILE *fp = fopen(filename, (is_binary==1) ? "rb" : "r"); // Open file to save received data
               if(fp==NULL) exit(1);

               char msg[MAX_BUFF];
               memset(msg, 0, sizeof(msg));
               snprintf(msg, sizeof(msg), "150 Opening %s mode data connection.\n", (is_binary==1) ? "binary" : "ascii");

               write(control_sock, msg, strlen(msg));
               write(STDOUT_FILENO, msg, strlen(msg));

               // Read from the file and send the data to the client
               memset(result_buffer, 0, sizeof(result_buffer));
               int total_bytes_sent = 0;
               int bytes_read;
               while ((bytes_read = fread(result_buffer, 1, sizeof(result_buffer), fp)) > 0) {
                  if (write(data_sock, result_buffer, bytes_read) != bytes_read) {
                        write(control_sock, "550 Failed transmission.\n", strlen("550 Failed transmission.\n"));
                        write(STDOUT_FILENO, "555 Failed transmission.\n", strlen("550 Failed transmission.\n"));
                        fclose(fp);
                        close(data_sock);
                        continue;
                  }
                  memset(result_buffer, 0, sizeof(result_buffer));
                  total_bytes_sent += bytes_read;
               }

               fclose(fp);
               close(data_sock);

               // Send message indicating completion of file transmission
               write(control_sock, "226 Complete transmission.\n", strlen("226 Complete transmission.\n"));
               write(STDOUT_FILENO, "226 Complete transmission.\n", strlen("226 Complete transmission.\n"));

               // Print the number of bytes sent
               memset(result_buffer, 0 ,sizeof(result_buffer));
               snprintf(result_buffer, MAX_BUFF, "OK. %d bytes sent.\n", total_bytes_sent);
               write(STDOUT_FILENO, result_buffer, strlen(result_buffer));
            }
            //////////////////////////////////////////////////////////////// STOR /////////////////////////////////////////////////////////////////////
            else if(strncmp(control_buffer, "STOR", 4)==0)
            {
               printf("Received STOR command\n");
               fflush(stdout);
               // Extract the filename from the RETR command
               char filename[MAX_BUFF];
               sscanf(control_buffer + 5, "%s", filename); 

               // Receive the server's response to the RETR command
               memset(result_buffer, 0, sizeof(result_buffer));
               if((len = read(control_sock, result_buffer, MAX_BUFF)) < 0) error_handling("control_sock read() error\n"); // 150 Opening data connection for directory list
         
               // Check if data connection is opened
               if(strncmp(result_buffer, "150", 3) == 0) {
                  write(STDOUT_FILENO, result_buffer, strlen(result_buffer));

                  // Open the file to be sent
                  FILE *fp = fopen(filename, (is_binary==1) ? "wb" : "w"); // Open file to save write data

                  memset(result_buffer, 0, sizeof(result_buffer));
                  int total_bytes_received = 0;
                  while((len_out = read(data_sock, result_buffer, MAX_BUFF)) > 0) {
                    fwrite(result_buffer, 1, len_out, fp);
                    total_bytes_received += len_out;
                  }

                  fclose(fp);

                 // Receive the final server response after transmission
                 memset(result_buffer, 0, sizeof(result_buffer));
                 //if((len = read(control_sock, result_buffer, MAX_BUFF)) < 0) error_handling("control_sock read() error\n");
                 
                 write(STDOUT_FILENO, result_buffer, strlen(result_buffer)); // complete transmission or Failed transmission

                 // Print the number of bytes received
                 memset(result_buffer, 0, sizeof(result_buffer));

                 snprintf(result_buffer, MAX_BUFF, "OK. %d bytes is received.\n", total_bytes_received);
                 write(STDOUT_FILENO, result_buffer, strlen(result_buffer));
                 memset(result_buffer, 0, sizeof(result_buffer));



               }
               memset(buffer, 0, sizeof(buffer));
               memset(control_buffer, 0, sizeof(control_buffer));
               memset(result_buffer, 0, sizeof(result_buffer));
               close(data_sock);
            }

        }
        ////////////////////////////////////////////////////// PWD /////////////////////////////////////////////////////////
        else if(strncmp(buffer, "PWD", 3) ==0)
        {
            memset(result_buffer, 0, sizeof(result_buffer));
            cmd_process(buffer, result_buffer,control_sock); // execute pwd  
            write(STDOUT_FILENO, result_buffer, strlen(result_buffer));     
            write(control_sock, result_buffer , strlen(result_buffer));
        }
        //////////////////////////////////////////////////// CD ////////////////////////////////////////////////////////////
        else if(strncmp(buffer , "CWD" , 3)==0)
        {
            memset(result_buffer, 0, sizeof(result_buffer));
            cmd_process(buffer, result_buffer,control_sock); // execute cd  
            write(STDOUT_FILENO, result_buffer, strlen(result_buffer));     
            write(control_sock, result_buffer , strlen(result_buffer));
        }
        //////////////////////////////////////////////////// delete ////////////////////////////////////////////////////////
        else if(strncmp(buffer , "DELE" , 4)==0)
        {
            memset(result_buffer, 0, sizeof(result_buffer));
            cmd_process(buffer, result_buffer,control_sock); // execute delete 
            write(STDOUT_FILENO, result_buffer, strlen(result_buffer));    
            write(control_sock, result_buffer , strlen(result_buffer));
        }
        ////////////////////////////////////////////////// rename //////////////////////////////////////////////////////////
        else if(strncmp(buffer , "RNFR" , 4)==0)
        {
            memset(result_buffer, 0, sizeof(result_buffer));
            cmd_process(buffer, result_buffer,control_sock); // execute rename     
        }
        ////////////////////////////////////////////////// mkdir ////////////////////////////////////////////////////////////
        else if(strncmp(buffer , "MKD" , 3)==0)
        {
            memset(result_buffer, 0, sizeof(result_buffer));
            cmd_process(buffer, result_buffer,control_sock); // execute delete    
            write(STDOUT_FILENO, result_buffer, strlen(result_buffer));  
            write(control_sock, result_buffer , strlen(result_buffer));
        }
        /////////////////////////////////////////////////// rmdir ////////////////////////////////////////////////////////////
        else if(strncmp(buffer , "RMD" , 3)==0)
        {
            memset(result_buffer, 0, sizeof(result_buffer));
            cmd_process(buffer, result_buffer,control_sock); // execute delete  
            write(STDOUT_FILENO, result_buffer, strlen(result_buffer));  
            write(control_sock, result_buffer , strlen(result_buffer));
        }
        else if(strncmp(buffer , "TYPE I" , 6)==0)
        {
            memset(result_buffer, 0, sizeof(result_buffer));
            
            if(strlen(buffer) == 6){
               write(control_sock, "201 Type set to I.\n", strlen("201 Type set to I.\n"));
               write(STDOUT_FILENO, "201 Type set to I.\n", strlen("201 Type set to I.\n"));
               is_binary = 1;
            }else{
               write(control_sock, "502 Type doesn't set\n", strlen("502 Type doesn't set\n"));
               write(STDOUT_FILENO, "502 Type doesn't set\n", strlen("502 Type doesn't set\n"));
            }
        }
        else if(strncmp(buffer , "TYPE A" , 6)==0)
        {
            memset(result_buffer, 0, sizeof(result_buffer));
             
            if(strlen(buffer) == 6){
               write(control_sock, "201 Type set to A.\n", strlen("201 Type set to A.\n"));
               write(STDOUT_FILENO, "201 Type set to A.\n", strlen("201 Type set to A.\n"));
               is_binary = 0;
            }else{
               write(control_sock, "502 Type doesn't set\n", strlen("502 Type doesn't set\n"));
               write(STDOUT_FILENO, "502 Type doesn't set\n", strlen("502 Type doesn't set\n"));
            }
        }
        

        memset(buffer, 0, sizeof(buffer));
    
    }
}


int cmd_process(char*buff , char * result_buff, int control_sock)
{
    char * tokens[512];
    bzero(tokens, sizeof(tokens));
    int token_count  = 0;

    // toke buff in delimeter " " "\n" "\t" and save it int token
    char *origin = buff;
    char *token = strtok(origin, " \n\t");
    memset(result_buff, 0, sizeof(result_buff));

    while (token != NULL && token_count < 512) 
    {
        // save token in tokens array
        if (strlen(token) > 0) {
                tokens[token_count++] = token;
        }
        token = strtok(NULL, " \n\t");
   }

   // if tokens[0] is NLST
   if(strcmp(tokens[0],"NLST")==0){

      if( nlst(tokens, token_count, result_buff) < 0 ){
        // execute nlst
        return -1;
      } 
      else{
        return 1;
      }
   }else if(strcmp(tokens[0], "PWD") ==0 ) {
       if(pwd(tokens, token_count, result_buff) < 0 ) // execute PWD
        return -1;
      else
        return 1;
   }
   else if(strcmp(tokens[0], "LIST") ==0 ){
       if(list(tokens, token_count, result_buff) < 0 ) // execute LIST
        return -1;
      else
        return 1;
   }
   else if( (strcmp(tokens[0], "CWD") ==0) || (strcmp(tokens[0],"CDUP")==0) ){
       if(cd(tokens, token_count, result_buff) < 0 ) // execute CD
        return -1;
      else
        return 1;
   }
   else if(strcmp(tokens[0], "MKD") ==0 ){
      if(mkd(tokens, token_count, result_buff) < 0 ) // execute MKD
        return -1;
      else
        return 1;
   }
   else if(strcmp(tokens[0], "DELE") ==0 ){
       if(del(tokens, token_count, result_buff) < 0 ) // execute DELE
        return -1;
      else
        return 1;
   }
   else if(strcmp(tokens[0], "RMD") ==0 ){
       if(rmd(tokens, token_count, result_buff) < 0 ) // execute RMD
        return -1;
      else
        return 1;
   }
   else if(strcmp(tokens[0], "RNFR") ==0 ){
       if(my_rename(tokens, token_count, result_buff, control_sock) < 0 ) // execute rename
        return -1;
      else
        return 1;
   }
   else if(strcmp(tokens[0], "QUIT")==0){ // if tokens[0] is quit
      strcpy(result_buff, "program quit!!\n"); // execute QUIT
      return 1;
   }
   else{
      strcpy(result_buff, "invalid command\n");
      return -1;
   }

}

int print_file_info(const char * file_path, char * result_buff)
{
   // declare file_stat , pw , gr
   struct stat file_stat;
   struct passwd *pw;
   struct group * gr;
   
   if(!lstat(file_path, &file_stat))
   {
        // Is it directory file?
         (S_ISDIR(file_stat.st_mode) ? strcat(result_buff, "d") : strcat(result_buff, "-") );
         // read, write , execute permission
         (file_stat.st_mode & S_IRUSR) ? strcat(result_buff, "r") : strcat(result_buff, "-");
         (file_stat.st_mode & S_IWUSR) ? strcat(result_buff, "w") : strcat(result_buff, "-");
         (file_stat.st_mode & S_IXUSR) ? strcat(result_buff, "x") : strcat(result_buff, "-");
         
         (file_stat.st_mode & S_IRGRP) ? strcat(result_buff, "r") : strcat(result_buff, "-");
         (file_stat.st_mode & S_IWGRP) ? strcat(result_buff, "w") : strcat(result_buff, "-");
         (file_stat.st_mode & S_IXGRP) ? strcat(result_buff, "x") : strcat(result_buff, "-");

         (file_stat.st_mode & S_IROTH) ? strcat(result_buff, "r") : strcat(result_buff, "-");
         (file_stat.st_mode & S_IWOTH) ? strcat(result_buff, "w") : strcat(result_buff, "-");
         (file_stat.st_mode & S_IXOTH) ? strcat(result_buff, "x") : strcat(result_buff, "-");
         strcat(result_buff, "\t");
         
         // print number of links
         int link = file_stat.st_nlink;
         char buffer1[20];
         int num_chars1 = sprintf(buffer1,"%d", link);
         strcat(result_buff, buffer1);
         strcat(result_buff, "\t");

         // print owner name
         pw = getpwuid(file_stat.st_uid);
         if(pw != NULL){
            char * name = pw->pw_name;
            strcat(result_buff,name);
            strcat(result_buff,"\t");
         }else{
            char * error = "Error: getpwuid\n";
            strcpy(result_buff, error);
            return -1;
         }

         // Print group name
         gr = getgrgid(file_stat.st_gid);
         if (gr != NULL) {
            char * name = gr->gr_name;
            strcat(result_buff,name);
            strcat(result_buff,"\t");
         } else {
            char * error = "Error: getgrgid\n";
            strcpy(result_buff, error);
            return -1;
         }
         // print file size
         int filesize = file_stat.st_size;
         char buffer2[20];
         int num_chars2 = sprintf(buffer2,"%d", filesize);
         strcat(result_buff, buffer2);
         strcat(result_buff, "\t");

         // print data , time
         char time[128]={0,};
         strftime(time, sizeof(time), "%b %d %H:%M", localtime(&file_stat.st_mtime));

         // save in reuslt_buff
         strcat(result_buff, time);
         strcat(result_buff, "\t");

         strcat(result_buff, file_path);
         strcat(result_buff, "\n");
   }

   return 1;
}

int nlst(char ** tokens, int token_count, char * result_buff)
{
   // initialize result_buff
   strcpy(result_buff, "");
   // set aflag, lflag as zero
   int aflag=0;
   int lflag=0;

   int name_count =0;
   struct dirent ** name_list = NULL;

   // too many arguments
   if(token_count >= 4){
      strcpy(result_buff, lserror1);
      return -1;
   }
   ////////////////////////////////////////// [Execute ls] ////////////////////////////////////////////////////
   else if(token_count ==1)
   {
      struct stat file_stat;
      // scandir
      name_count = scandir(".", &name_list, NULL, alphasort);
      int count =0;
      
      // name_count 만큼 돌면서 result_buff 에 file 이름 저장
      for(int i=0; i<name_count; i++){
         if(name_list[i]->d_name[0] != '.')
         {
            if(lstat(name_list[i]->d_name , &file_stat) == -1){
               strcpy(result_buff, lstaterror);
               return-1;
            }
            // file 이름 저장
            strcat(result_buff, name_list[i]->d_name);
               if(S_ISDIR(file_stat.st_mode)){
                      strcat(result_buff, "/");
               }
            ++count;

            strcat(result_buff, "\n");
         }
         // memeroy free
         SAFE_FREE(name_list[i]);
      }
      //strcat(result_buff, "\n");

      return 1;
   }

   DIR *dir;
   struct dirent * entry;
   struct stat file_stat;
   struct passwd *pw;
   struct group * gr;
   
   ///////////////////////////////////////////////////// determine option ///////////////////////////////////////////////////////////
   if(strcmp(tokens[1],"-a")==0){
      aflag++;
   }else if(strcmp(tokens[1],"-l")==0){
      lflag++;
   }else if(strcmp(tokens[1],"-al")==0 || strcmp(tokens[1],"-la")==0) {
      aflag++;
      lflag++;
   }else if(tokens[1][0] =='-'){
      strcpy(result_buff, error1);
      return -1;
   }else{
      char * lserror = "Non-invalid option\n";
      strcpy(result_buff, lserror);
      return -1;
   }

   ////////////////////////////////////////////////////// ls -al , ls -l //////////////////////////////////////////////////////////////
   if(lflag ==1){
     
      if(token_count ==3){

         if(access(tokens[2],F_OK) == -1){
            strcpy(result_buff,error4);
            return -1;
         }
         else if(access(tokens[2],R_OK) == -1){
            strcpy(result_buff, error5);
            return -1;
         }
         /////////////////////////////////// print file ///////////////////////////////////////////
         if(stat(tokens[2], &file_stat) == -1) {
            perror("Error getting file information");
            return -1;
         }
         //////////////////////////////////// FILE ////////////////////////////////////////
         if (!S_ISDIR(file_stat.st_mode)) {
            print_file_info(tokens[2], result_buff);
            return 1;
         }

         name_count = scandir(tokens[2], &name_list, NULL, alphasort);
      }
      else{
         name_count = scandir(".", &name_list, NULL, alphasort);
      }
      
      for(int i=0; i<name_count; i++)
      {
         if(aflag ==0 && name_list[i]->d_name[0] == '.') continue;

         if(lstat(name_list[i]->d_name , &file_stat) == -1){
            strcpy(result_buff, lstaterror);
            return -1;
         }
         // Is it directory file?
         (S_ISDIR(file_stat.st_mode)) ? strcat(result_buff, "d") : strcat(result_buff, "-");
         // read, write , execute permission
         (file_stat.st_mode & S_IRUSR) ? strcat(result_buff, "r") : strcat(result_buff, "-");
         (file_stat.st_mode & S_IWUSR) ? strcat(result_buff, "w") : strcat(result_buff, "-");
         (file_stat.st_mode & S_IXUSR) ? strcat(result_buff, "x") : strcat(result_buff, "-");
         
         (file_stat.st_mode & S_IRGRP) ? strcat(result_buff, "r") : strcat(result_buff, "-");
         (file_stat.st_mode & S_IWGRP) ? strcat(result_buff, "w") : strcat(result_buff, "-");
         (file_stat.st_mode & S_IXGRP) ? strcat(result_buff, "x") : strcat(result_buff, "-");

         (file_stat.st_mode & S_IROTH) ? strcat(result_buff, "r") : strcat(result_buff, "-");
         (file_stat.st_mode & S_IWOTH) ? strcat(result_buff, "w") : strcat(result_buff, "-");
         (file_stat.st_mode & S_IXOTH) ? strcat(result_buff, "x") : strcat(result_buff, "-");
         strcat(result_buff, "\t");
        
         // print number of links
         int link = file_stat.st_nlink;
         char buffer1[20];
         strcpy(buffer1,"");
         int num_chars1 = sprintf(buffer1,"%d", link);
         strcat(result_buff, buffer1);
         strcat(result_buff, "\t");

         // print owner name
         pw = getpwuid(file_stat.st_uid);
         if(pw != NULL){
            char * name = pw->pw_name;
            strcat(result_buff,name);
            strcat(result_buff, "\t");
         }else{
            char * error = "Error: getpwuid\n";
            strcpy(result_buff, error);
            return -1;
         }

         // Print group name
         gr = getgrgid(file_stat.st_gid);
         if (gr != NULL) {
            char * name = gr->gr_name;
            strcat(result_buff, name);
            strcat(result_buff, "\t");
         } else {
            char * error = "Error: getgrgid\n";
            strcpy(result_buff, error);
            return -1;
         }


         // print file size
         int filesize = file_stat.st_size;
         char buffer2[20];
         strcpy(buffer2,"");

         int num_chars2 = sprintf(buffer2,"%d", filesize);
         strcat(result_buff, buffer2);
         strcat(result_buff,"\t");

         // print data , time
         char time[128]={0,};
         strftime(time, sizeof(time), "%b %d %H:%M", localtime(&file_stat.st_mtime));
         strcat(result_buff, time);
         strcat(result_buff,"\t");

         // print file/dir name
         strcat(result_buff, name_list[i]->d_name);
            if(S_ISDIR(file_stat.st_mode)){
                strcat(result_buff, "/");
            }
         strcat(result_buff, "\n");

         SAFE_FREE(name_list[i]);
      }

      return 1;
      
   }
   /////////////////////////////////////////////////////////////////////// ls -a /////////////////////////////////////////////////////////////
   else if(aflag ==1 && lflag ==0){

    strcat(result_buff,tokens[0]);
    strcat(result_buff, " ");
    strcat(result_buff, tokens[1]);
    strcat(result_buff, "\n");
    
    // same as ls execution
    name_count = scandir(".", &name_list, NULL, alphasort);
    int count =0;
    
    for(int i=0; i<name_count; i++){

        strcat(result_buff, name_list[i]->d_name);
        SAFE_FREE(name_list[i]);
        ++count;
        strcat(result_buff, "\t");

        if(count == 5){
            strcat(result_buff, "\n");
            count =0;
        } 

    }

    strcat(result_buff, "\n");
    return 1;
   }
  
}

// execute PWD
int pwd(char ** tokens, int token_count, char * result_buff){

   char cwd[1024];

   if(token_count == 1){
      getcwd(cwd, sizeof(cwd));
      strcat(result_buff, "257 ");
      strcat(result_buff, "\"");
      strcat(result_buff, cwd );
      strcat(result_buff, "\"");
      strcat(result_buff, message);
      return 1;
   }
   else if(tokens[1][0] == '-'){
      strcat(result_buff, error1);
      return -1;
   }else{
      strcat(result_buff, error3);
      return -1;
   }
}

// execute list
int list(char ** tokens, int token_count, char * result_buff){


   DIR *dir;
   struct dirent * entry;
   struct stat file_stat;
   struct passwd *pw;
   struct group * gr;

   int name_count =0;
   struct dirent ** name_list = NULL;

   // initialize result_buff
   strcpy(result_buff, "");

   strcat(result_buff, tokens[0]);
   strcat(result_buff, "\n");

   for(int i=1; i<token_count; i++)
   {
      if(tokens[i][0] == '-')
      {
         strcpy(result_buff, error1);
         return -1;
      }
   }

   if(token_count ==2){
         if(access(tokens[1],F_OK) == -1){
            strcat(result_buff, error4);
            return -1;
         }
         else if(access(tokens[1],R_OK) == -1){
            strcat(result_buff, error5);
            return -1;
         }

         name_count = scandir(tokens[1], &name_list, NULL, alphasort);
        
      }
      else
         name_count = scandir(".", &name_list, NULL, alphasort);

      for(int i=0; i<name_count; i++)
      {

         if(lstat(name_list[i]->d_name , &file_stat) == -1){
            strcat(result_buff, lstaterror);
            return -1;
         }
         // is it directory file?
         (S_ISDIR(file_stat.st_mode) ? strcat(result_buff, "d") : strcat(result_buff, "-"));
         // read, write , execute permission
         (file_stat.st_mode & S_IRUSR) ? strcat(result_buff, "r") : strcat(result_buff, "-");
         (file_stat.st_mode & S_IWUSR) ? strcat(result_buff, "w") : strcat(result_buff, "-");
         (file_stat.st_mode & S_IXUSR) ? strcat(result_buff, "x") : strcat(result_buff, "-");
         
         (file_stat.st_mode & S_IRGRP) ? strcat(result_buff, "r") : strcat(result_buff, "-");
         (file_stat.st_mode & S_IWGRP) ? strcat(result_buff, "w") : strcat(result_buff, "-");
         (file_stat.st_mode & S_IXGRP) ? strcat(result_buff, "x") : strcat(result_buff, "-");

         (file_stat.st_mode & S_IROTH) ? strcat(result_buff, "r") : strcat(result_buff, "-");
         (file_stat.st_mode & S_IWOTH) ? strcat(result_buff, "w") : strcat(result_buff, "-");
         (file_stat.st_mode & S_IXOTH) ? strcat(result_buff, "x") : strcat(result_buff, "-");

         strcat(result_buff, " ");
         
         // print number of links
         int link = file_stat.st_nlink;
         char buffer1[20];
         int num_chars1 = sprintf(buffer1,"%d", link);
         strncat(result_buff, buffer1 , num_chars1);
         strcat(result_buff, " ");

         // print owner name
         pw = getpwuid(file_stat.st_uid);
         if(pw != NULL){
            char * name = pw->pw_name;
            strncat(result_buff, name , strlen(name));
            strcat(result_buff, " ");
         }else{
            char * error = "Error: getpwuid\n";
            strncat(result_buff, error , strlen(error));
            return -1;
         }

         // Print group name
         gr = getgrgid(file_stat.st_gid);
         if (gr != NULL) {
            char * name = gr->gr_name;
            strncat(result_buff, name ,strlen(name));
            strcat(result_buff, " ");
         } else {
            char * error = "Error: getgrgid\n";
            strncat(result_buff, error , strlen(error));
            return -1;
         }

         // print file size
         int filesize = file_stat.st_size;
         char buffer2[20];
         int num_chars2 = sprintf(buffer2,"%d", filesize);
         strncat(result_buff, buffer2 , num_chars2);
         strcat(result_buff, " ");

         // print file/dir name
         strncat(result_buff, name_list[i]->d_name , strlen(name_list[i]->d_name));
            if(S_ISDIR(file_stat.st_mode))
               strcat(result_buff, "/");
         strcat(result_buff, "\n");
      }

      return 1;
}

int cd(char ** tokens, int token_count, char * result_buff)
{
   int flag;
   char cwd[1024];
   strcpy(result_buff, "");

   if(token_count ==1){
      strcat(result_buff, error6);
      return -1;
   }

   for (int i = 1; i < token_count; i++) {
      // If the token starts with '-', it's an option
      if (tokens[i][0] == '-') {
            // Print error message for invalid option
            strncat(result_buff, error1, strlen(error1));
            return -1;
      }
   }

   
   if(strcmp(tokens[0],"CWD")==0) flag = 1;
   else if(strcmp(tokens[0], "CDUP")==0) flag =0;

   // CWD
   if(flag ==1)
   {
      if(token_count > 2){
         strcat(result_buff, "550 : ");
         strncat(result_buff, error1 , strlen(error1));
         return -1;
      }

      if(chdir(tokens[1])==-1){
         strcat(result_buff, "550 ");
         strcat(result_buff, tokens[1]);
         strcat(result_buff, " : ");
         strncat(result_buff, error2, strlen(error2));
         return -1;
      }else{   
         strcat(result_buff, "250 CWD command suceeds.");
         //getcwd(cwd,sizeof(cwd));
         //strcat(result_buff, "\"");
         //strcat(result_buff, cwd );
         //strcat(result_buff, "\"");
         //strcat(result_buff, message);
      }
   // CDUP
   }else if(flag ==0)
   {
       if (chdir("..") == -1) {
         strcat(result_buff, "550 ");
         strcat(result_buff, error2);
         return -1;
      }
      else {
         strcat(result_buff, "250 CWD command suceeds.");
         //getcwd(cwd, sizeof(cwd));
         //strcat(result_buff, "\"");
         //strcat(result_buff, cwd);
         //strcat(result_buff, "\"");
         //strcat(result_buff, message);
      }
   }
   return 1;

}

int mkd(char ** tokens, int token_count, char * result_buff)
{
   memset(result_buff, 0, sizeof(result_buff));
   char * mkdirerror1 = "Error: cannot create directory ";
   char * mkdirerror2 = ": File exists\n";
   char cwd[1024];
   getcwd(cwd,sizeof(cwd));

   for (int i = 1; i < token_count; i++) {
      // If the token starts with '-', it's an option
      if (tokens[i][0] == '-') {
            // Print error message for invalid option
            error_handling(error1);
            return -1;
      }
   }

   if(token_count ==1){
      error_handling(error6);
      return -1;
   }else
   {
      for(int i=1; i<token_count; i++){

      	 getcwd(cwd,sizeof(cwd));
      	 strcat(cwd, "/");
      	 strcat(cwd,tokens[i]);
      	 
         if(mkdir(cwd,0777) == -1){
            strcat(result_buff,"550 ");
            strcat(result_buff, tokens[i]);
            strcat(result_buff, " :");
            strcat(result_buff, "can't create directory.\n");   
         }else{
            strcat(result_buff, "250 MKD command performed successfully.\n");
         }
      }
      
   }
}

int del(char ** tokens, int token_count, char * result_buff)
{
   strcpy(result_buff, "");
   char cwd[1024];
   getcwd(cwd,sizeof(cwd));

   char * delerror = "Error: failed to delete ";
    for (int i = 1; i < token_count; i++) {
      // If the token starts with '-', it's an option
      if (tokens[i][0] == '-') {
            // Print error message for invalid option
            strcat(result_buff, "550 ");
            strncat(result_buff, error1, strlen(error1));
            return -1;
      }
   }

   if(token_count ==1){
      strcat(result_buff, "550 ");
      strncat(result_buff, error3, strlen(error3));
      return -1;
   }
   else{
      for(int i=1; i<token_count; i++)
      {
         char filepath[1024];
         strcpy(filepath, cwd); // 복사한 경로에 파일명 또는 디렉토리명 추가
      	strcat(filepath, "/");
      	strcat(filepath,tokens[i]);

          if(unlink(filepath)==-1){
            strcat(result_buff, "550 ");
            strcat(result_buff, tokens[i]);
            strcat(result_buff, ": ");
            strcat(result_buff, "'\n");
          }
          else{
            strcat(result_buff,"250 DELE command performed succesfully");
          }
      }
   }

   return 1;
}

int rmd(char ** tokens, int token_count, char* result_buff)
{
   char cwd[1024];
   getcwd(cwd,sizeof(cwd));
   memset(result_buff, 0 , sizeof(result_buff));

   char * delerror = "Error: failed to delete ";
    for (int i = 1; i < token_count; i++) {
      // If the token starts with '-', it's an option
      if (tokens[i][0] == '-') {
            // Print error message for invalid option
            error_handling(error1);
            return -1;
      }
   }

   if(token_count ==1){
      error_handling(error3);
      return -1;
   }
   else{
      for(int i=1; i<token_count; i++)
      {
         char dirpath[1024];
         strcpy(dirpath, cwd); // 복사한 경로에 파일명 또는 디렉토리명 추가
      	strcat(dirpath, "/");
      	strcat(dirpath,tokens[i]);

          if(rmdir(dirpath)==-1){
            strcat(result_buff, "550 ");
            strcat(result_buff, tokens[i]);
            strcat(result_buff, ": can't remove directory.\n");
          }
          else{
            strcat(result_buff, "250 RMD command performed successfully.\n");
          }
      }
   }

   return 1;
}

int my_rename(char ** tokens, int token_count, char* result_buff, int control_sock)
{
   char cwd[1024];
   getcwd(cwd,sizeof(cwd));
   

   char *rerror1 = "Error: two arguments are required\n";
   char *rerror2 = "Error: too many argument\n";
   char *rerror3 = "Error: name to change already exists\n";
   char *rerror4 = "Error: File is not exist\n";

   memset(result_buff, 0 ,sizeof(result_buff));
   for (int i = 1; i < token_count; i++) {
      // If the token starts with '-', it's an option
      if (tokens[i][0] == '-') {
            // Print error message for invalid option
            strncat(result_buff, error1, strlen(error1));
            return -1;
      }
   }

   
   if(token_count ==1){
      strncat(result_buff, rerror1, strlen(rerror1));
      return -1;
   }
   else{
     if(token_count > 4){
         strncat(result_buff, rerror2, strlen(rerror2));
         return -1;
      }else
      {
          if(access(tokens[1],F_OK) == -1){   

            strcat(result_buff, "550 ");
            strcat(result_buff, tokens[1]);
            strcat(result_buff, ": Can't find such file or directory\n");
            write(STDOUT_FILENO, result_buff, strlen(result_buff));
            write(control_sock, result_buff, strlen(result_buff));
            
            return -1;
         }else{
            strcat(result_buff,"350 File exists, ready to rename\n");
            write(STDOUT_FILENO, result_buff, strlen(result_buff));
            write(control_sock, result_buff, strlen(result_buff));
            memset(result_buff, 0, sizeof(result_buff));

            if(access(tokens[3],F_OK) ==0 )  // 바꿀 이름이 이미 존재한다면
            {
               strcat(result_buff,"550 ");
               strcat(result_buff, tokens[3]);
               strcat(result_buff,": can't be renamed\n");
               write(STDOUT_FILENO, result_buff, strlen(result_buff));
               write(control_sock, result_buff, strlen(result_buff));
              
               return -1;
            }
            rename(tokens[1], tokens[3]);
            strcat(result_buff,"250 RNTO command succeeds\n");
            write(STDOUT_FILENO, result_buff, strlen(result_buff));
            write(control_sock, result_buff, strlen(result_buff));
            
            return 1;
     
         }
         
      }
   }

   return 1;
}
