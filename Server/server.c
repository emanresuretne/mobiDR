#include<stdio.h>  
#include<stdlib.h>  
#include<string.h>  
#include<errno.h>  
#include<sys/types.h>  
#include<sys/socket.h>  
#include<netinet/in.h>  
#include <unistd.h>
#include <fcntl.h>
#include<sys/time.h>
#include <sys/wait.h>
#define DEFAULT_PORT 4433  
#define MAXLINE 4096  

/*
single server, single client
server is always running, client may run many times
Server function:
Receive data from client   ->     verify data     ->     store data
Receive request from client   ->     send data to client
*/

extern void hmac_sha1(unsigned char *digest, unsigned char *data, int data_length);
int string_cmp(unsigned char *s1, unsigned char *s2);

int main(int argc, char** argv){  
    int socket_fd, connect_fd;  
    struct sockaddr_in servaddr;  
    unsigned char recbuff[4096];  
    int n, nr, nw, fd2;  
    unsigned char signbuf[2060];
	int BUF_SIZE = 2048;
    unsigned char digest[20];
    unsigned char recdigest[20];
    int verify_result = 1;
    int v=0;
    int v1 = 0;    // backup version number
    int v2 = 100;    // restore version number
    unsigned char verifybuf[28];

    unsigned char buf3[2060];

    unsigned char buf4[4096];

    unsigned char buf2[20];
    unsigned char digest2[20];

    unsigned char sendbuff[2080];
    unsigned char writebuff[2048];

    const char *tmp1 = "restore start";
    const char *tmp2 = "restore stop";

    unsigned char filename[100];
    unsigned char snum[5];

    struct timeval start;
    struct timeval end;
    unsigned long timer=0;
    unsigned long dtime=0;
    unsigned long timer2=0;
    unsigned long timer3=0;

    int index=0;

    
    if( (socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ){  
        printf("create socket error: %s(errno: %d)\n",strerror(errno),errno);  
        exit(0);  
    }  
    
    memset(&servaddr, 0, sizeof(servaddr));  
    servaddr.sin_family = AF_INET;  
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);   
    servaddr.sin_port = htons(DEFAULT_PORT);      
  
      
    if( bind(socket_fd, (struct sockaddr*)&servaddr, sizeof(servaddr)) == -1){  
        printf("bind socket error: %s(errno: %d)\n",strerror(errno),errno);  
        exit(0);  
    }  
      
    if( listen(socket_fd, 10) == -1){  
        printf("listen socket error: %s(errno: %d)\n",strerror(errno),errno);  
        exit(0);  
    }  
    printf("======waiting for client's request======\n");

    while(1){  
         
        if( (connect_fd = accept(socket_fd, (struct sockaddr*)NULL, NULL)) == -1){  
            printf("accept socket error: %s(errno: %d)",strerror(errno),errno);  
            //continue;  
        }  

        
        int indicator = 0;
        n = recv(connect_fd, recbuff, MAXLINE, 0);
        recbuff[n] = 0;
        //printf("%s\n", recbuff);
        //printf("%d\n", strcmp(recbuff, "backup start\n"));
        if (strcmp(recbuff, "backup start")==0 || strcmp(recbuff, "backup start\n")==0) {
            printf("Start backup!\n");
            indicator = 1;
        }
        //printf("%d\n", indicator);
        
        if (strcmp(recbuff, "restore start")==0 || strcmp(recbuff, "restore start\n")==0) {
            printf("Start restore!\n");
            indicator = 2;
        }
        printf("indicator : %d\n", indicator);

        if (indicator == 1){
            strcpy(filename, "/home/wen/Desktop/flash_backup.v");
            snprintf(snum, 5, "%d", v1);
            strcat(filename, snum);
            if ((fd2 = open(filename, O_WRONLY | O_CREAT | O_TRUNC)) == -1) perror("[open]");
            v1 += 1;
        } else if (indicator == 2)
        {
            strcpy(filename, "/home/wen/Desktop/flash.back");
            snprintf(snum, 5, "%d", v2);
            strcat(filename, snum);
            if ((fd2 = open(filename, O_RDONLY)) == -1) perror("[open]");
            v2 += 1;
        }
        
        index = 0;

        while(indicator == 1){
            printf("index = %d\n", index);
            gettimeofday(&start, NULL);
            n = recv(connect_fd, recbuff, MAXLINE, 0);  
            gettimeofday(&end, NULL);
            dtime = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
            timer =  timer + 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
            //if(n != 0){
            index += 1;
            if (string_cmp(recbuff, "backup stop")==0 || string_cmp(recbuff, "backup stop\n")==0) {
                printf("Stop backup!\n");

                memcpy(verifybuf+4, &verify_result, 4);
                hmac_sha1(digest, verifybuf, 8);
                memcpy(verifybuf+8, digest, 20);
                if(send(connect_fd, verifybuf, 28,0) == -1){
                    perror("send error");  
                    close(connect_fd);  
                    exit(0);  
                }
                indicator == 0;
            } else {
                gettimeofday(&start, NULL);
                v = *(int *)(recbuff+2052);
                // memcpy(v1, recbuff+2052, 4);
                memcpy(verifybuf, &v, 4);
                // printf("version number is %d\n", v);
                memcpy(signbuf, recbuff, 2060);
                memcpy(recdigest, recbuff+2060, 20);
                hmac_sha1(digest, signbuf, 2060);
                gettimeofday(&end, NULL);
                dtime = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
                timer2 =  timer2 + 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
                if (string_cmp(digest, recdigest)) {
                    verify_result = 0;
                } else {
                    gettimeofday(&start, NULL);
                    if((nw = write(fd2, recbuff, 4096)) == -1) perror("[pwrite]");
                    gettimeofday(&end, NULL);
                    dtime = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
                    timer3 =  timer3 + 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
                }
                // printf("verify result is %d: \n",string_cmp(digest, recdigest));
            }
            //}
            
            
            //printf("dtime is %ld\n", dtime);
        }
        printf("version %d time1 is %ld us\n", v1, timer);
        printf("version %d time1 is  %f s\n", v1, timer/(float)1000000);
        printf("version %d time2 is %ld us\n", v1, timer2+timer3);
        printf("version %d time2 is  %f s\n", v1, (timer2+timer3)/(float)1000000);
        dtime = 0;
        timer = 0;
        timer2 = 0;
        timer3 = 0;

        while(indicator == 2){      
            printf("index = %d\n", index); 
            if((nr = read(fd2, recbuff, 4096)) == -1) perror("[pread]");
            else
            {
                printf("nr = %d\n", nr);
                // memcpy(buf, test_string, BUF_SIZE);
                if(send(connect_fd, recbuff, 4096,0) == -1){ 
                    perror("send error");  
                    close(connect_fd);  
                    exit(0);
                }
                while (nr > 0 ){
                    index += 1;  
                    printf("index = %d\n", index);
                    gettimeofday(&start, NULL);

                    // printf("curret offset is : %ld\n", lseek(fd2, 0, SEEK_CUR));
                    if((nr = read(fd2, recbuff, 4096)) == -1) perror("[pread]");
                    else
                    {
                        if (nr == 0)
                        {
                            break;
                        }
                        
                        if(send(connect_fd, recbuff, 4096,0) == -1){  
                            perror("send error");  
                            close(connect_fd);  
                            exit(0);
                        }
                    }
                    printf("nr = %d\n", nr);
                    gettimeofday(&end, NULL);
                    dtime = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
                    timer =  timer + 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
                }
                indicator = 0;
            }
        }

        printf("version %d time is %ld us\n", v1, timer);
        printf("version %d time is  %f s\n", v1, timer/(float)1000000);
        dtime = 0;
        timer = 0;
            
        memset(buf3, 0, 2060);
        strncpy(buf3, tmp2, 2059);
        // memcpy(buf3, "backup start", strlen("backup start"));
        hmac_sha1(buf2, buf3, 2060);
        memcpy(sendbuff, buf3, 2060); 
        memcpy(sendbuff+2060, buf2, 20);  
        if(send(connect_fd, sendbuff, 2080,0) == -1){  
            perror("send error");  
            close(connect_fd);  
            exit(0);
        }
  
        close(connect_fd);  
    }
    close(socket_fd);  
    if(close(fd2) == -1) perror("[close]");
}

int string_cmp(unsigned char *s2, unsigned char *s1)
{
  int i;
  for (i = 0; s1[i] == s2[i]; i++){
    // printf("%c",s1[i]);
    if (s1[i] == '\0')
      return 0;
  }
  return s1[i] - s2[i];
}