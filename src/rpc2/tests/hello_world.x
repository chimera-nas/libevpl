
struct Hello {
    unsigned int    id;
    string          greeting;
};

program HELLO_PROGRAM {
    version HELLO_V1 {
        Hello GREET(Hello) = 1;
    } = 1;
} = 42;
