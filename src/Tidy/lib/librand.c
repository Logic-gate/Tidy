#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char *rand_string(char *str, size_t size, const char *chars)
{
    size_t n;
    srand(time(NULL));
    for (n = 0; n < size; n++) {
        int key = rand() % strlen(chars);
        str[n] = chars[key];
    }
    str[size] = '\0';
    return str;
}