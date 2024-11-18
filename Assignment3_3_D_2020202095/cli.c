/////////////////////////////////////////////////////
// File Name  : cli.c                              //
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
#include <time.h>

#define MAX_BUFF 1024
#define RCV_BUFF 1024
int is_binary = 1; // default binary mode;

void log_in(int sockfd);
////////////////////////////////////////////////////////
// make_data_connection                               //
// ===================================================//
// Input : int -> control_sock                        //
//         unsigned int * -> port                     //
//         unsinged long -> ip_addr                   //
// Ouput : int                                        //
// Purpose : make data connection                     //
////////////////////////////////////////////////////////
int make_data_connection(int control_sock, unsigned int * port, unsigned long ip_addr);
////////////////////////////////////////////////////////
// convert_adder_to_str                               //
// ===================================================//
// Input : unsigned long -> ip_addr                   //
//         unsigned int -> port                       //
// Ouput : char *                                     //
// Purpose : convert address to string                //
////////////////////////////////////////////////////////
char* convert_addr_to_str(unsigned long ip_addr, unsigned int port);
////////////////////////////////////////////////////////
// conv_cmd                                           //
// ===================================================//
// Input : char * -> buf                              //
//         char * -> cmd_buf                          //
// Ouput : void                                       //
// Purpose : convert command                          //
////////////////////////////////////////////////////////
void conv_cmd(char*buf, char*cmd_buf);
////////////////////////////////////////////////////////
// process_result                                     //
// ===================================================//
// Input : char * -> rcv_buff                         //
//         int -> len                                 //
// Ouput : void                                       //
// Purpose : print to result in kernel                //
////////////////////////////////////////////////////////
void process_result(char * rcv_buff, int len);


void process_result(char * rcv_buff, int len){ // process result

    write(STDOUT_FILENO, rcv_buff , len); // write rcv_buff to STDOUT
    return;
}

void error_handling(const char * message) // error handling
{
    write(STDERR_FILENO, message, strlen(message)); // write message to STDOUT
    exit(1);
}

///////////////////////////////////////////////////////log_in///////////////////////////////////////////////////////////////////////
void log_in(int sockfd){

    int n;
    char user[MAX_BUFF] , passwd[MAX_BUFF], buf[MAX_BUFF];
    char user_command[MAX_BUFF] , pass_command[MAX_BUFF];

    memset(user, 0, sizeof(user));
    memset(passwd, 0, sizeof(passwd));
    memset(buf, 0, sizeof(buf));

    // Check if the ip is acceptable
    read(sockfd, buf, MAX_BUFF);
    if(strncmp(buf,"431",3)==0) // Rejection
    { 
        write(STDOUT_FILENO, buf , strlen(buf));
        exit(1);
    }
    else if(strncmp(buf,"220",3)==0){ // Accepted
        write(STDOUT_FILENO, buf, strlen(buf));

        while(1){
            
            memset(user,0,sizeof(user));
            ///////////////// USER NAME //////////////////
            printf("Input ID : "); // input message
            scanf("%s", user);
            fflush(stdout);
            fflush(stdin);

            snprintf(user_command , MAX_BUFF , "USER %s" , user);
            write(sockfd, user_command, strlen(user_command));
           // write(STDOUT_FILENO, user_command, strlen(user_command));

            memset(buf, 0, sizeof(buf));
            read(sockfd, buf, MAX_BUFF);

            if(strncmp(buf,"530",3)==0){
                write(STDOUT_FILENO, buf, strlen(buf));
                exit(1);
            }
            
            if(strncmp(buf,"331",3)==0)           ///////////////// password require
            {
                write(STDOUT_FILENO, buf, strlen(buf));
                while(1){
                    
                    memset(passwd,0,sizeof(passwd));
                    printf("Input Password : "); // input message
                    scanf("%s", passwd);
                    fflush(stdout);
                    fflush(stdin);
                   
                    snprintf(pass_command , MAX_BUFF, "PASS %s", passwd);
                    write(sockfd, pass_command, strlen(pass_command));
                    
                    memset(buf, 0, sizeof(buf));
                    read(sockfd, buf, MAX_BUFF);

                    if(strncmp(buf,"530",3)==0){
                        write(STDOUT_FILENO, buf, strlen(buf));
                        exit(1);
                    }
                    else if(strncmp(buf,"230",3)==0){
                        write(STDOUT_FILENO,buf, strlen(buf));
                        return;
                    }
                }

            }
            else if(strncmp(buf,"430",3)==0)    ////////////////// Invalid username or password
            {
                write(STDOUT_FILENO, buf, strlen(buf));
            }
            
            memset(user_command, 0, sizeof(user_command));
            memset(pass_command,0,sizeof(pass_command));
            memset(passwd, 0, sizeof(passwd));
            memset(user, 0 , sizeof(user));
        }    
    }
}

////////////////////////////////////////////////////////
// main                                               //
// =======================================me============//
// Input : int -> argc                                //
//         char ** -> argv                            //
// Ouput : void                                       //
////////////////////////////////////////////////////////
void main(int argc, char ** argv)
{
    // Seed the random number generator with the current time
    srand(time(NULL));

    // Buffers for various purposes
    char buff[MAX_BUFF];
    char cmd_buff[MAX_BUFF];
    char rcv_buff[RCV_BUFF];
    char control_buff[RCV_BUFF];
    char command[MAX_BUFF];
    
    // Server address structure and control socket descriptor
    struct sockaddr_in server_addr;
    int control_sock;
    int n, len, len_out;
    
    // Create a TCP socket
    control_sock = socket(PF_INET, SOCK_STREAM, 0);
    if(control_sock == -1)  error_handling("can't create socket\n");
    
    // Initialize the server address structure
    bzero((char*)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(argv[1]);
    server_addr.sin_port = htons(atoi(argv[2]));
   
    socklen_t serveraddr_size;
    serveraddr_size = sizeof(server_addr);

    // Connect to the server
    if(connect(control_sock , (struct sockaddr*)&server_addr , sizeof(server_addr) )< 0)  error_handling("can't connect\n");
    printf("** It is connected to Server **\n");
    fflush(stdout);
    log_in(control_sock); // log_in

    // Prompt user for input
    memset(buff, 0, sizeof(buff));
    write(STDOUT_FILENO, "ftp> " , 5); 
    while( (len = read(STDIN_FILENO, buff, sizeof(buff)) ) > 0)
    {
        //buff[len] = '\0';  // Ensure the buffer is null-terminated
        memset(control_buff, 0 ,sizeof(control_buff));

        /////////////////////////////////////////////////////////////////  quit  /////////////////////////////////////////////////////////////////////////////////////////
        if(strncmp(buff,"quit",4) == 0){
            write(control_sock, "QUIT" , 4);
            if( (len = read(control_sock, control_buff, MAX_BUFF)) < 0) error_handling("control_sock read() error\n");
            
            write(STDOUT_FILENO, control_buff , strlen(control_buff));
            close(control_sock);
            exit(1); // Exit program
        }
        //////////////////////////////////////////////////////////// ls, ls-al, ls-l ls-a/////////////////////////////////////////////////////////////////////////////////
        if(strncmp(buff,"ls",2)==0)
        {
            // Make a data connection
            unsigned int data_port;
            int data_sock = make_data_connection(control_sock, &data_port, server_addr.sin_addr.s_addr);

            // Accept the data connection
            struct sockaddr_in client_addr;
            socklen_t client_addr_size = sizeof(client_addr);
            int data_connection = accept(data_sock, (struct sockaddr*)&client_addr, &client_addr_size);
            
            if(data_connection == -1)  error_handling("accept() error");
               
            // Convert the command entered by the user
            memset(cmd_buff, 0, sizeof(cmd_buff));
            conv_cmd(buff,cmd_buff);
            n = strlen(cmd_buff); 

            // transfer server converted_command
            if(write(control_sock, cmd_buff, n) != n)  error_handling("write() error!");
          
            // Send the converted command to the serve
            memset(control_buff, 0, sizeof(control_buff));
            if( (len = read(control_sock, control_buff, MAX_BUFF)) < 0) error_handling("control_sock read() error\n");
              
            write(STDOUT_FILENO, control_buff, strlen(control_buff)); // 150 Opening data connection
            fflush(stdout);

            // Read the server's initial response
            memset(rcv_buff, 0, sizeof(rcv_buff));
            if( (len_out = read(data_connection, rcv_buff, MAX_BUFF)) < 0) error_handling("data_sock read() error\n");
            
            // Process the received data and print it
            process_result(rcv_buff, len_out); // rcv_buff 에 전달된 내용 출력 및 초기화
            bzero(buff, sizeof(buff));
            bzero(rcv_buff, sizeof(rcv_buff));

            memset(control_buff, 0, sizeof(control_buff));

            // Read the server's final response
            if( (len = read(control_sock, control_buff, MAX_BUFF)) < 0) error_handling("read() error\n");
            else write(STDOUT_FILENO, control_buff, strlen(control_buff));
                
            // Print the number of bytes received
            snprintf(control_buff , MAX_BUFF, "OK. %d bytes is received.\n", len_out);   
            write(STDOUT_FILENO, control_buff, strlen(control_buff));

            memset(control_buff, 0, sizeof(control_buff));

            close(data_connection);
            close(data_sock);
        }
        else if(strncmp(buff,"pwd",3) ==0)
        {
            // Convert the command entered by the user
            memset(cmd_buff, 0, sizeof(cmd_buff));
            conv_cmd(buff,cmd_buff);
            n = strlen(cmd_buff); 

            // transfer server converted_command
            if(write(control_sock, cmd_buff, n) != n)  error_handling("write() error!");

            // Read the server's initial response
            memset(rcv_buff, 0, sizeof(rcv_buff));
            if( (len_out = read(control_sock, rcv_buff, MAX_BUFF)) < 0) error_handling("control_sock read() error\n");

            // Process the received data and print it
            process_result(rcv_buff, len_out); 
        }
        else if(strncmp(buff,"cd",2)==0)
        {
            // Convert the command entered by the user
            memset(cmd_buff, 0, sizeof(cmd_buff));
            conv_cmd(buff,cmd_buff);
            n = strlen(cmd_buff); 

            // transfer server converted_command
            if(write(control_sock, cmd_buff, n) != n)  error_handling("write() error!");

            // Read the server's initial response
            memset(rcv_buff, 0, sizeof(rcv_buff));
            if( (len_out = read(control_sock, rcv_buff, MAX_BUFF)) < 0) error_handling("control_sock read() error\n");

            // Process the received data and print it
            process_result(rcv_buff, len_out); 
        }
        else if(strncmp(buff,"delete",6)==0)
        {
            // Convert the command entered by the user
            memset(cmd_buff, 0, sizeof(cmd_buff));
            conv_cmd(buff,cmd_buff);
            n = strlen(cmd_buff); 

            // transfer server converted_command
            if(write(control_sock, cmd_buff, n) != n)  error_handling("write() error!");

            // Read the server's initial response
            memset(rcv_buff, 0, sizeof(rcv_buff));
            if( (len_out = read(control_sock, rcv_buff, MAX_BUFF)) < 0) error_handling("control_sock read() error\n");

            // Process the received data and print it
            process_result(rcv_buff, len_out);
        }
        else if(strncmp(buff,"rename",6)==0)
        {
            // Convert the command entered by the user
            memset(cmd_buff, 0, sizeof(cmd_buff));
            conv_cmd(buff,cmd_buff);
            n = strlen(cmd_buff); 

            // transfer server converted_command
            if(write(control_sock, cmd_buff, n) != n)  error_handling("write() error!");

            // receive 350 or 550
            memset(rcv_buff, 0, sizeof(rcv_buff));
            if( (len_out = read(control_sock, rcv_buff, MAX_BUFF)) < 0) error_handling("control_sock read() error\n");

            if(strncmp(rcv_buff,"550",3) ==0 ){  // first receive 550
                write(STDOUT_FILENO, rcv_buff, strlen(rcv_buff));
            }else{
                write(STDOUT_FILENO, rcv_buff, strlen(rcv_buff)); // execute rename function

                memset(rcv_buff, 0, sizeof(rcv_buff));
                if( (len_out = read(control_sock, rcv_buff, MAX_BUFF)) < 0) error_handling("control_sock read() error\n");

                write(STDOUT_FILENO, rcv_buff, strlen(rcv_buff));
            }

        }
        else if(strncmp(buff,"mkdir",5)==0)
        {
            // Convert the command entered by the user
            memset(cmd_buff, 0, sizeof(cmd_buff));
            conv_cmd(buff,cmd_buff);
            n = strlen(cmd_buff); 

            // transfer server converted_command
            if(write(control_sock, cmd_buff, n) != n)  error_handling("write() error!");

            // Read the server's initial response
            memset(rcv_buff, 0, sizeof(rcv_buff));
            if( (len_out = read(control_sock, rcv_buff, MAX_BUFF)) < 0) error_handling("control_sock read() error\n");

            // Process the received data and print it
            process_result(rcv_buff, len_out);
        }
        else if(strncmp(buff,"rmdir",5)==0)
        {
            // Convert the command entered by the user
            memset(cmd_buff, 0, sizeof(cmd_buff));
            conv_cmd(buff,cmd_buff);
            n = strlen(cmd_buff); 

            // transfer server converted_command
            if(write(control_sock, cmd_buff, n) != n)  error_handling("write() error!");

            // Read the server's initial response
            memset(rcv_buff, 0, sizeof(rcv_buff));
            if( (len_out = read(control_sock, rcv_buff, MAX_BUFF)) < 0) error_handling("control_sock read() error\n");

            // Process the received data and print it
            process_result(rcv_buff, len_out);
        }
        else if(strncmp(buff, "get", 3) == 0) {
            
            char filename[MAX_BUFF];
            memset(filename, 0, sizeof(filename));
            sscanf(buff + 4, "%s", filename);
            // Make a data connection
            unsigned int data_port;
            int data_sock = make_data_connection(control_sock, &data_port, server_addr.sin_addr.s_addr);

            // Accept the data connection
            struct sockaddr_in client_addr;
            socklen_t client_addr_size = sizeof(client_addr);
            int data_connection = accept(data_sock, (struct sockaddr*)&client_addr, &client_addr_size);

            if(data_connection == -1) error_handling("accept() error");

            // Convert the command entered by the user
            memset(cmd_buff, 0, sizeof(cmd_buff));
            snprintf(cmd_buff, sizeof(cmd_buff), "RETR %s", filename);
            n = strlen(cmd_buff);

            // Transfer the server converted_command
            if(write(control_sock, cmd_buff, n) != n) error_handling("write() error!");


            // Receive the server's response to the RETR command
            memset(control_buff, 0, sizeof(control_buff));
            if((len = read(control_sock, control_buff, MAX_BUFF)) < 0) error_handling("control_sock read() error\n"); // 150 Opening data connection for directory list

            // Check if data connection is opened
            if(strncmp(control_buff, "150", 3) == 0) {

                write(STDOUT_FILENO, control_buff, strlen(control_buff));

                // Receive the file data from the server
                FILE *fp = fopen(filename, (is_binary==1) ? "wb" : "w"); // Open file to save received data
                if(fp == NULL) error_handling("Failed to open file\n");

                memset(rcv_buff, 0, sizeof(rcv_buff));
                int total_bytes_received = 0;
                while((len_out = read(data_connection, rcv_buff, RCV_BUFF)) > 0) {
                    fwrite(rcv_buff, 1, len_out, fp);
                    total_bytes_received += len_out;
                }

                fclose(fp);

                // Receive the final server response after transmission
                memset(control_buff, 0, sizeof(control_buff));
                if((len = read(control_sock, control_buff, MAX_BUFF)) < 0) error_handling("control_sock read() error\n");

                write(STDOUT_FILENO, control_buff, strlen(control_buff)); // complete transmission or Failed transmission

                // Print the number of bytes received
                memset(control_buff, 0, sizeof(control_buff));
                snprintf(control_buff, MAX_BUFF, "OK. %d bytes is received.\n", total_bytes_received);
                write(STDOUT_FILENO, control_buff, strlen(control_buff));

                memset(control_buff, 0, sizeof(control_buff));
                } 
          
                close(data_connection);
                close(data_sock);
        }
        else if(strncmp(buff, "put", 3) == 0) {
            
            char filename[MAX_BUFF];
            memset(filename, 0, sizeof(filename));
            sscanf(buff + 4, "%s", filename);
            // Make a data connection
            unsigned int data_port;
            int data_sock = make_data_connection(control_sock, &data_port, server_addr.sin_addr.s_addr);

            // Accept the data connection
            struct sockaddr_in client_addr;
            socklen_t client_addr_size = sizeof(client_addr);
            int data_connection = accept(data_sock, (struct sockaddr*)&client_addr, &client_addr_size);

            if(data_connection == -1) error_handling("accept() error");

            // Convert the command entered by the user
            memset(cmd_buff, 0, sizeof(cmd_buff));
            snprintf(cmd_buff, sizeof(cmd_buff), "STOR %s", filename);
            n = strlen(cmd_buff);

            // Transfer the server converted_command
            if(write(control_sock, cmd_buff, n) != n) error_handling("write() error!");

            char msg[MAX_BUFF];
            memset(msg, 0, sizeof(msg));
            snprintf(msg, sizeof(msg), "150 Opening %s mode data connection.\n", is_binary ? "binary" : "ascii"); // send 150 message

            write(control_sock, msg, strlen(msg));
            write(STDOUT_FILENO, msg, strlen(msg));

            // Receive the file data from the server
            FILE *fp = fopen(filename, (is_binary==1) ? "rb" : "r"); // Open file to save received data
            if(fp == NULL) error_handling("Failed to open file\n");

            // Read from the file and send the data to the client
            memset(control_buff, 0, sizeof(control_buff));
            int total_bytes_sent = 0;
            int bytes_read;
            while ((bytes_read = fread(control_buff, 1, sizeof(control_buff), fp)) > 0) {
                if (write(data_connection, control_buff, bytes_read) != bytes_read) {
                    write(control_sock, "550 Failed transmission.\n", strlen("550 Failed transmission.\n"));
                    write(STDOUT_FILENO, "555 Failed transmission.\n", strlen("550 Failed transmission.\n"));
                    fclose(fp);
                    close(control_sock);
                    continue;
                }
                total_bytes_sent += bytes_read;
            }
            fclose(fp);

            // Send message indicating completion of file transmission
            write(control_sock, "226 Complete transmission.\n", strlen("226 Complete transmission.\n"));
            write(STDOUT_FILENO, "226 Complete transmission.\n", strlen("226 Complete transmission.\n"));

            // Print the number of bytes sent
            memset(control_buff, 0, sizeof(control_buff));
            snprintf(control_buff, MAX_BUFF, "OK. %d bytes sent.\n", total_bytes_sent);
            write(STDOUT_FILENO, control_buff, strlen(control_buff));

            close(data_connection);
            close(data_sock);
        } 
        else if(strncmp(buff, "bin", 3) == 0 || strncmp(buff,"type binary" , 11)==0) {

            write(control_sock, "TYPE I" , strlen("TYPE I"));

            memset(rcv_buff, 0, sizeof(rcv_buff));
            if( (len_out = read(control_sock, rcv_buff, MAX_BUFF)) < 0) error_handling("control_sock read() error\n");

            if(strncmp(rcv_buff,"201",3)==0){
                is_binary = 1;
            }
            // Process the received data and print it
            process_result(rcv_buff, len_out);
        }
        else if(strncmp(buff, "ascii", 5) == 0 || strncmp(buff,"type ascii" , 10)==0) {
            
            write(control_sock, "TYPE A" , strlen("TYPE A"));

            memset(rcv_buff, 0, sizeof(rcv_buff));
            if( (len_out = read(control_sock, rcv_buff, MAX_BUFF)) < 0) error_handling("control_sock read() error\n");

            if(strncmp(rcv_buff,"201",3)==0){
                is_binary = 0;
            }
            // Process the received data and print it
            process_result(rcv_buff, len_out);
        }

        
        memset(buff, 0, sizeof(buff));
        write(STDOUT_FILENO,"ftp> ", 5);
    }

    
}

// convert adder to string
char* convert_addr_to_str(unsigned long ip_addr, unsigned int port) {
    struct in_addr in_addr;
    in_addr.s_addr = ip_addr;
    char *addr = (char *)malloc(INET_ADDRSTRLEN + 10);
    snprintf(addr, INET_ADDRSTRLEN + 10, "%s,%d,%d", inet_ntoa(in_addr), port / 256, port % 256);
    return addr;
}


int make_data_connection(int control_sock, unsigned int * port, unsigned long ip_addr)
{
    int data_sock;
    struct sockaddr_in data_addr;
    char port_command[MAX_BUFF];
    char convert_command[MAX_BUFF];

    *port = 10001 + rand()%20000; //  create random port number [10001 <= port <= 30000]

    // Create a socket for data connection
    data_sock = socket(PF_INET, SOCK_STREAM, 0);
    if(data_sock == -1){
        error_handling("data socket() error");
    }

    // Initialize the data address structure
    bzero((char*)&data_addr, sizeof(data_addr));
    data_addr.sin_family = AF_INET;
    data_addr.sin_addr.s_addr = ip_addr;
    data_addr.sin_port = htons(*port);

    // Bind the socket to the address and port
    if (bind(data_sock, (struct sockaddr*)&data_addr, sizeof(data_addr)) == -1) {
        error_handling("bind() error");
    }

    // Listen for incoming connections
    if (listen(data_sock, 1) == -1) {
        error_handling("listen() error");
    }

    // Convert the address and port to a string format suitable for the PORT command
    char * addr_str = convert_addr_to_str(data_addr.sin_addr.s_addr, ntohs(data_addr.sin_port));
    snprintf(convert_command, sizeof(convert_command) , "convert to %s\n", addr_str);
    snprintf(port_command, sizeof(port_command), "PORT %s\n", addr_str);
    free(addr_str);
    printf("%s" , convert_command);
    fflush(stdout);

    // Send the PORT command to the server
    write(control_sock, port_command , strlen(port_command)); // Port command 전송

    // Read the acknowledgment from the server
    char ack[MAX_BUFF];
    memset(ack, 0, sizeof(ack));
    read(control_sock, ack , MAX_BUFF); // 200 Port command succesful
    printf("%s", ack);
    fflush(stdout);

    // Return the data socket descriptor
    return data_sock;
}

void conv_cmd(char*buf, char*cmd_buf){
    
    char * origin = buf;
    char * token = strtok(origin, " \n\t");
    // ls
    if(strncmp(buf, "ls", 2) ==0){
        strcpy(cmd_buf, "NLST");
    // dir
    }else if(strncmp(buf, "dir", 3) ==0){
         strcpy(cmd_buf, "LIST");
    //pwd
    }else if(strncmp(buf, "pwd", 3) ==0){
         strcpy(cmd_buf, "PWD");
    // cd
    }else if(strncmp(buf, "cd", 2) ==0){

        token = strtok(NULL, " ");

        if(token !=NULL){
            if(strncmp(buf, "cd .." , 5)==0)
            {
                strcpy(cmd_buf , "CDUP");
            }
            else
            {
                strcpy(cmd_buf, "CWD ");
                strcat(cmd_buf, token);
            }
        }else{
            strcpy(cmd_buf,"CWD");
            return;
        }   
    }
    // mkdir
    else if(strncmp(buf, "mkdir", 5) ==0){
         strcpy(cmd_buf, "MKD");
    }  
    // delete
    else if(strncmp(buf, "delete", 6) ==0){
         strcpy(cmd_buf, "DELE");
    }
    // mkdir
    else if(strncmp(buf, "rmdir", 5) ==0){
         strcpy(cmd_buf, "RMD");
    }
    // mkdir
    else if(strncmp(buf, "rename", 6) ==0){
         strcpy(cmd_buf, "RNFR ");
         token = strtok(NULL," ");

         if(token!=NULL){
            strcat(cmd_buf, token);
            strcat(cmd_buf , " ");
            token = strtok(NULL, " ");

            if(token!=NULL){
                strcat(cmd_buf , "RNTO ");
                strcat(cmd_buf, token);
            }
         }
    }
    // quit
    else if(strncmp(buf, "quit", 4) ==0){
         strcpy(cmd_buf, "QUIT");
    }else{
         strcpy(cmd_buf, "non-invalid command");
    }

    // 뒤에 문자열 마저 이어 붙여줌 (cmd_buf에)
    while ((token = strtok(NULL, " \n")) != NULL) {
        strcat(cmd_buf, " ");
        strcat(cmd_buf, token);
    }

}


