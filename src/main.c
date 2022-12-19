#include "libft.h"
#include "ft_ssl.h"

int main(int argc, char **argv) {
    if (argc > 1) {
        md5_process(argv[1]);
    }
}