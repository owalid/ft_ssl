#include "ft_ssl.h"
#include "libft.h"


unsigned long S_BOX[8][4][16] = { // used to obscure the relationship between the key and the ciphertext
    { // S1
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    },
    { // S2
        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
    },
    { // S3
        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    },
    { // S4
        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
    },
    { // S5
        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
    },
    { // S6
        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    },
    { // S7
        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    },
    { // S8
        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    }
};

unsigned long PERMUTATION_COMPRESSION_KEY[] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};


unsigned long PERMUTATION_INIT_KEY[] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
};

unsigned long PERMUTATION_INIT_BLOCK[] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

unsigned long EXPANSION_TAB[] = {
    32, 1, 2, 3, 4, 5, 4, 5,
    6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27,
    28, 29, 28, 29, 30, 31, 32, 1
};

unsigned long P_TAB[] = {
    16, 7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25
};

unsigned long ROTATE_TAB[] = {
    1, 1, 2, 2,
    2, 2, 2, 2,
    1, 2, 2, 2,
    2, 2, 2, 1
};

unsigned long COMPRESS_KEY_TAB[] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

unsigned long FINAL_PERM_TAB[] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};

// ============== DES UTILS ===============


void	swap_val(unsigned long *a, unsigned long *b)
{
	unsigned long temp;

	temp = *a;
	*a = *b;
	*b = temp;
}

void permutation(unsigned long *input, unsigned long *arr, unsigned int from_s, unsigned int to_s)
{
    // Process permutation according arr table and little endian
    unsigned long tmp = 0;

    for (int i = 0; i < to_s; i++)
        tmp |= ((*input >> (from_s - arr[i])) & 1) << (to_s - i - 1);

    *input = 0;
    *input = tmp;
}

void    print_long(unsigned long n) {
    for (int index = 0; index < 64; index++) {
        if (!(index % 8) && index) printf(" ");
        printf("%d", (n >> (63 - index)) & 1);
    }
    printf("\n");
}


unsigned int shift_left(unsigned long *input, unsigned int n, unsigned int len)
{
    // Process shift_left according ROTATE_TAB
     *input = ((*input << ROTATE_TAB[n]) | (*input >> (len - ROTATE_TAB[n]))) & 0x0FFFFFFFUL;
}

// ============== END OF DES UTILS ===============


// ======== Process encrypt pt =========

unsigned long encrypt_block(unsigned long block, unsigned long *key)
{
    unsigned long end_block, right, big_right, left, sbox, xor_round, tmp;
    int row, col;

    // permutation before block process
    unsigned long tmp_xor_round = 0;


    permutation(&block, PERMUTATION_INIT_BLOCK, 64, 64);


    // the block is split into 2 halves
    left = (block >> 32) & 0x0FFFFFFFFUL;
    right = block & 0x0FFFFFFFFUL;


    for (int i = 0; i < 16; i++)
    {
        // the right half of the block is taken

        // 1 & 2-  Expansion Permutation & Key mixing
        xor_round = right;

        permutation(&xor_round, EXPANSION_TAB, 32, 48);

        xor_round ^= key[i];

        sbox = 0;
        // 3 - Substitution (S1, S2,...,S8)
        for (int f = 0; f < 8; f++)
        {
            // select current bits
            // GET ROW (extremite b1, b6)
            row = (xor_round & 0b00100000) >> 4 | (xor_round & (0b00000001));
            // GET COL (middle b2 -> b5)
            col = (xor_round & 0b00011110) >> 1;

            sbox |= S_BOX[7-f][row][col] << (4*f);
            xor_round >>= 6;
        }

        // 4 - Permutation (P)
        permutation(&sbox, P_TAB, 32, 32);

        left ^= sbox;

        if (i != 15)
            swap_val(&right, &left);
    }

    // 5 - Combine left and right
    end_block = ((left << 32) | right);

    permutation(&end_block, FINAL_PERM_TAB, 64, 64); 

    return swap64(end_block);
}

unsigned long* process_round_keys(unsigned long key, unsigned long *round_k)
{
    // get 56 bits of keys
    // split to have left and right
    unsigned long left = 0, right = 0;
    unsigned long concat;
    unsigned long curr_round;


    permutation(&key, PERMUTATION_INIT_KEY, 64, 56);

    // LEFT IS CARREY
    left = (key >> 28) & 0x0FFFFFFFUL;
    
    // RIGHT IS CARREY
    right = key & 0x0FFFFFFFUL;

    for (int i = 0; i < 16; i++)
    {
        curr_round = 0;

        // shift_left left of key
        shift_left(&left, i, 28);

        // shift_left right of key
        shift_left(&right, i, 28);

        // concate twice
        concat = (left << 28) | right;

        curr_round = concat;
        permutation(&curr_round, COMPRESS_KEY_TAB, 56, 48);
        round_k[i] = curr_round;
    }

    return round_k;
}


void        pad_block(unsigned char *input, ssize_t len_input)
{
    int diff = 8 - len_input;
    int i = len_input % 8;
    for (; i < 8; i++)
        input[i] = diff;
}

void        display_key(unsigned long *r_k)
{
    for (int i=0; i < 16; i++)
        printf("r_k[%d]\t= %lu\n", i, r_k[i]);
}

void        print_cipher_b64(unsigned long* blocks, int* len_block)
{
    // printf("len_block: %d\n", *len_block);
    // 8 char in an unsigned long (8*8)
    three_bytes_to_b64((char *)blocks, (*len_block)*8, 1);
    ft_bzero(blocks, 3*8);
    *len_block = 0;
}

void        reverse_round_key(unsigned long *r_k)
{
    unsigned long tmp_r_k[16];
    ft_bzero(tmp_r_k, 16*8);

    for (int i = 0; i < 16; i++)
        tmp_r_k[i] = r_k[i];
    for (int i = 15, j = 0; j < 16; i--, j++)
        r_k[i] = tmp_r_k[j];
}

void        des_ecb_encrypt(t_ft_ssl_mode *ssl_mode, int fd, unsigned long *r_k)
{
    //  ======== Process key =========
    unsigned long block;
    unsigned long result;
    unsigned long tmp_blocks[3]; // bc 3 * 8 = 24 is a multiple of 3 (for b64)
    int cpt = 0;
    char buffer[8];
    ssize_t readed = 0;
    int buffer_size;

    ft_bzero(tmp_blocks, 3*8);
    ft_bzero(buffer, 8);

    while ((readed = utils_read(0, buffer, 8, 0)) == 8)
    {
        block = 0;
        ft_memcpy(&block, buffer, 8);
        result = encrypt_block(swap64(block), r_k);
        tmp_blocks[cpt++] = result;
        if (cpt == 3)
            print_cipher_b64(tmp_blocks, &cpt);
    }

    // check readed and process padding
    if (readed >= 0)
    {
        block = 0;
        pad_block(buffer, readed);
        ft_memcpy(&block, buffer, 8);
        result = encrypt_block(swap64(block), r_k);
        tmp_blocks[cpt++] = result;
    }
    print_cipher_b64(tmp_blocks, &cpt);
}

ssize_t     unpad(unsigned char *plain_block)
{
    ssize_t result = 6;
    char last_char = plain_block[7];
    plain_block[7] = 0;

    for (;result >= 0; result--)
    {
        if (last_char != plain_block[result])
            return result + 1;
        else
            plain_block[result] = 0;
    }
    return result + 1;
}

void        des_ecb_decrypt(t_ft_ssl_mode *ssl_mode, int fd, unsigned long *r_k)
{
    unsigned long block;
    unsigned long result;
    unsigned long tmp_block = 0;
    int cpt = 0;
    char buffer[32];
    unsigned long tmp_buffer[3]; // 3 * 8 = 24
    ssize_t readed = 0;
    int buffer_size;
    int last_blocks_size = 0;
    ssize_t last_block_size = 0;

    ft_bzero(tmp_buffer, 24);
    ft_bzero(buffer, 32);

    // reverse round key
    reverse_round_key(r_k);

    result = 0;

    while ((readed = utils_read(0, buffer, 32, 1)) == 32)
    {
        // ----
        // with 24 we can constitute 3 blocks
        // ----
        if (tmp_buffer[0] != 0)
        {
            for (int i = 0; i < 3; i++)
            {
                // printf("in for loop: i = %d\n", i);
                result = encrypt_block(swap64(tmp_buffer[i]), r_k);
                write(1, &result, 8);
            }
        }

        block = 0;
        ft_bzero(tmp_buffer, 24);
        b64_to_three_bytes(buffer, (char *)tmp_buffer, 32, 0);
    }

    // printf("readed = %d\n", readed);

    // ----
    // with the rest we constitute n blocks who n < 3 (8 by block)
    // ----
    if (readed >= 0)
    {
        // Check if is the last read
        if (tmp_buffer[0] != 0)
        {
            for (int i = 0; i < 3; i++)
            {
                // printf("in for loop: i = %d\n", i);
                result = encrypt_block(swap64(tmp_buffer[i]), r_k);

                if (i == 2 && readed == 0)
                {
                    last_block_size = unpad((unsigned char*)&result);
                    write(1, &result, last_block_size);
                    return;
                } else write(1, &result, 8);
            } 
        }

        block = 0;
        b64_to_three_bytes(buffer, (char *)tmp_buffer, readed, 0);
        last_blocks_size = (readed/8 - 1) == 0 ? 1 : (readed/8 - 1 );
        // printf("last_blocks_size: %d", last_blocks_size);
        for (int i = 0; i < last_blocks_size; i++)
        {
            result = 0;
            result = encrypt_block(swap64(tmp_buffer[i]), r_k);

            if (i + 1 == last_blocks_size) { // process last block padding
                last_block_size = unpad((unsigned char*)&result);
                // printf("last_block : %d", last_block_size);
                write(1, &result, last_block_size);
            } else {
                write(1, &result, 8);
            }
        }
    }
}

void        des_ecb_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type, char *algo_name)
{
    int fd = (ssl_mode->input_file != 0) ? open(input, O_RDONLY) : 0;
    char key[] = "0123456789ABCDEF";
    unsigned long r_k[16];

    ft_bzero(r_k, 16*8);
    // unsigned long key_long_hex = ft_hextoi(key);

    // TODO CHECK ERROR FOR KEY_LONG_HEX

    // process round key
    process_round_keys(ssl_mode->key, r_k);

    // display_key(r_k);

    if (ssl_mode->decode_mode == 1) des_ecb_decrypt(ssl_mode, fd, r_k);
    else des_ecb_encrypt(ssl_mode, fd, r_k);
}


// 19MxvOqWjYMIb5oddMlNTg==
// 19MxvOqWjYNHeFUfjsEQanFDEiqjQsHb

// AAAAAAAAAAAA
// AAAAAAAAAAA
// AAAAAAAAAAAA
// AAAAAAAAAAAA
// AAAAAAAAAAA
// AAAAAAAAAAAA
// qCfeEJVqYJ10BBGVsjZ5Sw==