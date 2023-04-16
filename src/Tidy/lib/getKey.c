#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>


char* getKey(char* doc) {
    /* Get the contents of a file, generate a random key based on its length,
       save the key to a file, and return the key */
    FILE* fpp = fopen(doc, "rb");

    if (!fpp) {
        printf("Could not open file '%s'\n", doc);
        exit(EXIT_FAILURE);
    }
    fseek(fpp, 0L, SEEK_END);
    int size = ftell(fpp);
    rewind(fpp);
    char* buffer = malloc(size+1);
    if (!buffer) {
        printf("Memory allocation error\n");
        exit(EXIT_FAILURE);
    }
    int read = fread(buffer, 1, size, fpp);
    if (read != size) {
        printf("Could not read entire file '%s'\n", doc);
        exit(EXIT_FAILURE);
    }
    buffer[size] = '\0';
    fclose(fpp);
    char* getFile = buffer;
    int n = strlen(getFile);
    const char* chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n";
    char* rand_str = malloc(n+1);
    for (int i = 0; i < n; i++) {
        rand_str[i] = chars[rand() % strlen(chars)];
    }
    rand_str[n] = '\0';
    char* key = rand_str;
    free(getFile);
    return key;
}



char* generate_key(char* filename) {
    /* Generate a random key based on the length of a file */
    srand(time(NULL));
    return getKey(filename);
}

int main() {
    /* The main function is not used when calling from Python */
    // char* key_ = generate_key("myfile.txt", "key.txt");
    // printf("Generated key: %s\n", key_);
    // free(key_);
    return 0;
}