//
// Created by 陈颂颂 on 2020/1/15.
//

#include <string.h>
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
