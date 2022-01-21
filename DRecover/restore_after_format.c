#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include<sys/time.h>

#define SECTOR 512

typedef unsigned char *byte_pointer;

int main(){

int fd, fd2, fd3, nr, nw, BUF_SIZE;
//char fl_nm[]={"/home/wen/Desktop/U/backup_start"};
unsigned char* buf = NULL;
unsigned char buf2[2048];

struct timeval start;
struct timeval end;
unsigned long timer=0;

int index = 0;

unsigned int offset = 0;

BUF_SIZE = 2048;


void show_bytes(byte_pointer start, int len) {
    int i;
    for (i = 0; i < len; i++)
    printf(" %.2x", start[i]);    //line:data:show_bytes_printf
    printf("\n");
}


/*
char *str = malloc(BUF_SIZE + 1);
memset(str, 'b', BUF_SIZE);
str[BUF_SIZE] = 0;
memcpy(str, back_up, 12);

printf("%s\n", str);

*/



    // DIRECT IO
printf("Direct IO ---------\n");
if (posix_memalign((void *)&buf, SECTOR, BUF_SIZE)) {
    perror("posix_memalign failed");
}
else { 

    if ((fd = open("/dev/sdb", O_WRONLY | O_DIRECT)) == -1) perror("[open]");

    memset(buf, 0, BUF_SIZE);
    lseek(fd, 960040*512, SEEK_SET);
    if((nr = write(fd, buf, BUF_SIZE)) == -1) perror("[pwrite]");

    lseek(fd, 960080*512, SEEK_SET);
    if((nr = write(fd, buf, BUF_SIZE)) == -1) perror("[pwrite]");

    lseek(fd, 960120*512, SEEK_SET);
    if((nr = write(fd, buf, BUF_SIZE)) == -1) perror("[pwrite]");

    lseek(fd, 960160*512, SEEK_SET);
    if((nr = write(fd, buf, BUF_SIZE)) == -1) perror("[pwrite]");

    lseek(fd, 960096*512, SEEK_SET);
    if((nr = write(fd, buf, BUF_SIZE)) == -1) perror("[pwrite]");

    printf("Initial restore: \n");

    // if ((fd = open("/home/wen/Desktop/U/backup_start", O_WRONLY | O_DIRECT)) == -1) perror("[open]");

    if ((fd2 = open("/home/wen/Desktop/flash.back", O_RDONLY | O_DIRECT)) == -1) perror("[open]");

    /* buf size , buf alignment and offset has to observe hardware restrictions */
    
    lseek(fd2, -BUF_SIZE, SEEK_END);
    if((nr = read(fd2, buf, BUF_SIZE)) == -1) perror("[pread]");

    offset = *((unsigned int*)buf);
    
    while (lseek(fd2, 0, SEEK_CUR) > BUF_SIZE ){
        // printf("curret offset is : %ld\n", lseek(fd2, 0, SEEK_CUR));
        index += 1;
        printf("index =  %d\n", index);
        lseek(fd2, -2*BUF_SIZE, SEEK_CUR);

        // printf("curret offset is : %ld\n", lseek(fd2, 0, SEEK_CUR));

        lseek(fd, offset*4*512, SEEK_SET);

        if((nr = read(fd2, buf, BUF_SIZE)) == -1) perror("[pread]");
        else
        {
            gettimeofday(&start, NULL);
            if((nr = write(fd, buf, BUF_SIZE)) == -1) perror("[pwrite]");
            gettimeofday(&end, NULL);
            timer =  timer + 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
        }
        if(lseek(fd2, 0, SEEK_CUR) <= BUF_SIZE){
            break;
        }
        lseek(fd2, -2*BUF_SIZE, SEEK_CUR);
        if((nr = read(fd2, buf, BUF_SIZE)) == -1) perror("[pread]");
        else
        {
            offset = *((unsigned int*)buf);
        }
        
    }

    if ((fd = open("/dev/sdb", O_WRONLY | O_DIRECT)) == -1) perror("[open]");

    memset(buf, 0, BUF_SIZE);
    lseek(fd, 960040*512, SEEK_SET);
    if((nr = write(fd, buf, BUF_SIZE)) == -1) perror("[pwrite]");

    lseek(fd, 960080*512, SEEK_SET);
    if((nr = write(fd, buf, BUF_SIZE)) == -1) perror("[pwrite]");

    lseek(fd, 960120*512, SEEK_SET);
    if((nr = write(fd, buf, BUF_SIZE)) == -1) perror("[pwrite]");

    lseek(fd, 960160*512, SEEK_SET);
    if((nr = write(fd, buf, BUF_SIZE)) == -1) perror("[pwrite]");

    lseek(fd, 960096*512, SEEK_SET);
    if((nr = write(fd, buf, BUF_SIZE)) == -1) perror("[pwrite]");

    printf("Finished restore: \n");    

    system("mount -t exfat /dev/sdb /home/wen/Desktop/U/");


    free(buf);

    if(close(fd) == -1) perror("[close]");
    if(close(fd2) == -1) perror("[close]");
}


// timer = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
printf("timer = %ld us\n", timer);
printf("timer = %f s\n", timer/(float)1000000);

return  0;
}
