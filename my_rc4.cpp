#include <iostream>
#include <openssl/rc4.h>
#include <string.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define BUFF_SIZE 1024

int argv_cnt = 1;
bool encryption = true, noSalt = false;
int fd1, fd2;
unsigned char *userKey = nullptr;


void print_help(char **argv)
{
    printf("use: %s -e|-d -k key -nosalt -in input -out output\n", argv[0]);
    exit(1);
}

void handle_option(int argc, char **argv)
{
    switch(argv[argv_cnt][0]){
        case '-':
            
            if (strcmp(argv[argv_cnt]+1,"e") == 0){
                encryption = true;
            }
            else if (strcmp(argv[argv_cnt]+1,"d") == 0 ){
                encryption = false;
            }
            else if (strcmp(argv[argv_cnt]+1,"k") == 0 ){
                argv_cnt++;
                if ( argv_cnt == argc )
                    print_help(argv);
                userKey = (unsigned char *)calloc(sizeof(argv[argv_cnt]), 1);
                strcpy((char *)userKey, argv[argv_cnt]);
            }
            else if (strcmp(argv[argv_cnt]+1, "nosalt") == 0) {
                if ( argv_cnt == argc )
                    print_help(argv);
                noSalt = true;
            }
            else if (strcmp(argv[argv_cnt]+1,"in") == 0 ){
                argv_cnt++;
                if ( argv_cnt == argc ){
                    printf("no input is specified\n");
                    print_help(argv);
                }
                printf("input = %s \n", argv[argv_cnt]);
                
                if ((fd1 = open(argv[argv_cnt], O_RDONLY)) == -1){
                    perror("Could not open file");
                }
            }
            else if (strcmp(argv[argv_cnt]+1,"out") == 0 ){
                argv_cnt++;
                if ( argv_cnt == argc )
                    print_help(argv);
                printf("output = %s \n", argv[argv_cnt]);
                
                if ((fd2 = open(argv[argv_cnt], O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) == -1){
                    perror("Could not create outfile");
                }
            }
            else if (strcmp(argv[argv_cnt]+1,"help") == 0 ){
                print_help(argv);
            }
            else {
                printf("%s: unknown option\n", argv[argv_cnt]);
                print_help(argv);
            }
            argv_cnt++;
            break;
            
        default:
            printf("%s: unknown option\n", argv[argv_cnt]);
            print_help(argv);
            break;
    }
    return;
    
}

int main(int argc, char *argv[]) {
    if ( argc == 1 )
        print_help(argv);
    
    while( argv_cnt < argc )
        handle_option(argc, argv);
    
    RC4_KEY key;
    unsigned char salt[8], saltedHeader[16], encKey[16];
    char buff[BUFF_SIZE];
    unsigned char* outputbuff = (unsigned char *) malloc(BUFF_SIZE);
    char salted_[] = "Salted__";
    ssize_t numRead;
    
    if (encryption){
        //encrypt, no salt
        if (noSalt){
            //hash pass without salt using sha256, Typically, 128 bit (16 byte) keys are used for strong encryption. computing rc4 key, stores into encKey
            if ((EVP_BytesToKey(EVP_rc4(), EVP_sha256(), NULL, (const unsigned char *)userKey, strlen((const char*)userKey), 1, encKey, NULL)) != 16) {
                perror("Error creating rc4 key");
            }
            
            //set rc4 encryption key
            RC4_set_key(&key, sizeof encKey, encKey);
            
            //read 1024 or less bytes from f1 into buffer, and encrypt those bytes from buffer and write them to f2
            while ((numRead = read(fd1, &buff, BUFF_SIZE)) > 0){
                RC4(&key, BUFF_SIZE, (const unsigned char *)buff, outputbuff);
                write(fd2, outputbuff, numRead);
            }
            
            close(fd1);
            close(fd2);
        }
        //encrypt, has salt
        else {
            //create salt header, first 8 bytes
            write(fd2, salted_, 8);
            
            //use openssl random byte generator for salt to ensure protection
            if (RAND_bytes(salt, sizeof(salt)) <= 0){
                perror("Error randomizing bytes");
            }
            
            //last 8 bytes of header
            write(fd2, salt, 8);
            
            //hash pass with salt using sha256, Typically, 128 bit (16 byte) keys are used for strong encryption. computing rc4 key, stores into encKey
            if ((EVP_BytesToKey(EVP_rc4(), EVP_sha256(), (const unsigned char *)salt, (const unsigned char *)userKey, strlen((const char*)userKey), 1, encKey, NULL)) != 16) {
                perror("Error creating rc4 key");
            }
            
            //set rc4 encryption key
            RC4_set_key(&key, sizeof encKey, encKey);
            
            //read 1024 or less bytes from f1 into buffer, and encrypt those bytes from buffer and write them to f2
            while ((numRead = read(fd1, &buff, BUFF_SIZE)) > 0){
                RC4(&key, BUFF_SIZE, (const unsigned char *)buff, outputbuff);
                write(fd2, outputbuff, numRead);
            }
            
            close(fd1);
            close(fd2);
        }
    }else {
        if (!noSalt){
            //decryption, has salt
            //read 16 byte salted header of file1
            read(fd1, &saltedHeader, 16);
            
            //store last 8 bytes of header into salt[]            
            for (int i = 0; i < 8; i++) {
                salt[i] = saltedHeader[i + 8];
            }

            //hash pass with salt using sha256, Typically, 128 bit (16 byte) keys are used for strong encryption. computing rc4 key, stores into encKey
            if ((EVP_BytesToKey(EVP_rc4(), EVP_sha256(), (const unsigned char *)salt, (const unsigned char *)userKey, strlen((const char*)userKey), 1, encKey, NULL)) != 16) {
                perror("Error creating rc4 key");
            }
            
            //set rc4 encryption key
            RC4_set_key(&key, sizeof encKey, encKey);
            
            //read 1024 or less bytes from f1 into buffer, and encrypt those bytes from buffer and write them to f2
            while ((numRead = read(fd1, &buff, BUFF_SIZE)) > 0){
                RC4(&key, BUFF_SIZE, (const unsigned char *)buff, outputbuff);
                write(fd2, outputbuff, numRead);
            }
            
            close(fd1);
            close(fd2);
        }
        else {
            //decryption, has no salt
            
            //hash pass without salt using sha256, Typically, 128 bit (16 byte) keys are used for strong encryption. computing rc4 key, stores into encKey
            if ((EVP_BytesToKey(EVP_rc4(), EVP_sha256(), NULL, (const unsigned char *)userKey, strlen((const char*)userKey), 1, encKey, NULL)) != 16) {
                perror("Error creating rc4 key");
            }
            
            //set rc4 encryption key
            RC4_set_key(&key, sizeof encKey, encKey);
            
            //read 1024 or less bytes from f1 into buffer, and encrypt those bytes from buffer and write them to f2
            while ((numRead = read(fd1, &buff, BUFF_SIZE)) > 0){
                RC4(&key, BUFF_SIZE, (const unsigned char *)buff, outputbuff);
                write(fd2, outputbuff, numRead);
            }
            
            close(fd1);
            close(fd2);
        }
    }
    
    free(outputbuff);

    return 0;
}
