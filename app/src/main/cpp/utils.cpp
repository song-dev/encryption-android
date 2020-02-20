//
// Created by 陈颂颂 on 2020/1/15.
//

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include "utils.h"
#include "log.h"

void print_long_data(char *s) {

    // 分割打印数据
    int len = strlen(s);
    if (len > PRINT_SIZE) {
        // d长度大于200
        char buf[PRINT_SIZE + 1];
        int n = 0;

        while ((len - n) > PRINT_SIZE) {
            memcpy(buf, s + n, PRINT_SIZE);
            buf[PRINT_SIZE] = '\0';
            LOGE("%s", buf);
            n += PRINT_SIZE;
        }

        memcpy(buf, s + n, len - n);
        buf[len - n] = '\0';
        LOGE("end %s", buf);

    } else {
        LOGE("%s", s);
    }

}

void hexstrToByte(const char *source, char *dest, int sourceLen) {

    int i;
    unsigned char highByte, lowByte;

    for (i = 0; i < sourceLen; i += 2) {
        highByte = toupper(source[i]);
        lowByte = toupper(source[i + 1]);

        if (highByte > 0x39)
            highByte -= 0x37;
        else
            highByte -= 0x30;

        if (lowByte > 0x39)
            lowByte -= 0x37;
        else
            lowByte -= 0x30;

        dest[i / 2] = (highByte << 4) | lowByte;
    }
    return;
}

/**
 * 字节流转换为十六进制字符串
 * @param source
 * @param dest
 * @param sourceLen
 */
void byteToHexstr(const char *source, char *dest, int sourceLen) {

    short i;
    unsigned char highByte, lowByte;
    for (i = 0; i < sourceLen; i++) {
        highByte = source[i] >> 4;
        lowByte = source[i] & 0x0f;
        highByte += 0x30;
        if (highByte > 0x39) {
            dest[i * 2] = highByte + 0x07;
        } else {
            dest[i * 2] = highByte;
        }
        lowByte += 0x30;
        if (lowByte > 0x39) {
            dest[i * 2 + 1] = lowByte + 0x07;
        } else {
            dest[i * 2 + 1] = lowByte;
        }
    }

}

void tohex(unsigned char *in, char *out, size_t insz) {
    unsigned char *pin = in;
    const char *hex = "0123456789ABCDEF";
    char *pout = out;
    for (; pin < in + insz; pout += 2, pin++) {
        pout[0] = hex[(*pin >> 4) & 0xF];
        pout[1] = hex[*pin & 0xF];
    }
}


void randomKey(unsigned char key[]) {
//    const char tableKey[] = "0123456789abcdefghijklmnopgrstuvwxyz";
    const unsigned char tableKey[] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                                      0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
                                      0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
                                      0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
                                      0x77, 0x78, 0x79, 0x7a};
    // 设置种子
    srandom(time(NULL));
    for (int i = 0; i < 16; i++) {
        key[i] = tableKey[random() % 36];
    }
}
