// cargo test --features c-headers -- generate_headers
// gcc main.c -L . -lrusty_sadl  -Wl,-rpath '-Wl,$ORIGIN'
#include "rusty_sadl.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char const *argv[])
{
    uint8_t* x = malloc(721);
    const uint8_t y[] =  { /*Binary Barcode data here */};
    memcpy(x,y,sizeof y);
    Vec_uint8_t input;
    input.cap = sizeof y + 1;
    input.len = sizeof y;
    input.ptr = x;

    Vec_uint8_t ret = c_decrypt_and_parse(input);
    // the input memmory is freed by rust.
    printf("%s\n",ret.ptr);
    // free the return object
    free_buf(ret);
    return 0;
}

