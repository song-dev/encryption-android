//
// Created by 陈颂颂 on 2020/1/15.
//

#ifndef ENCRYPTION_ANDROID_UTILS_H
#define ENCRYPTION_ANDROID_UTILS_H

#define PRINT_SIZE 900

void print_long_data(char *s);

void hexstrToByte(const char *source, char *dest, int sourceLen);

void byteToHexstr(const char *source, char *dest, int sourceLen);

void tohex(unsigned char *in, char *out, size_t insz);

void randomKey(unsigned char key[]);

#endif //ENCRYPTION_ANDROID_UTILS_H
