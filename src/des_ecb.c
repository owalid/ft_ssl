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

unsigned long PERMUTATION_INIT_KEY[] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
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

// ============== DES UTILS ===============


void	swap_val(unsigned long *a, unsigned long *b)
{
	unsigned long temp;

	temp = *a;
	*a = *b;
	*b = temp;
}

void permutation(unsigned long *input, unsigned long *arr, unsigned int n)
{
    unsigned long input_cpy = *input;

    for (int i = 0; i < n; i++)
    {
        *input |= input_cpy << arr[i];
    }
}

unsigned int shift_left(unsigned int *input, unsigned int n, unsigned int len)
{
    // Process shift_left according ROTATE_TAB
     *input = (*input << ROTATE_TAB[n]) | (*input >> (len - ROTATE_TAB[n]));
}

// ============== END OF DES UTILS ===============


// ======== Process encrypt pt =========

unsigned long encrypt_block(unsigned char *block, unsigned long *key)
{
    unsigned long big_block, right, big_right, left, sbox, xor_round, tmp;
    int row, col;


    // permutation before block process
    unsigned char tmp_input[64];

    ft_bzero(tmp_input, 64);
    ft_memcpy(tmp_input, block, 64);


    for (int i = 0; i < 64; i++)
        block[i] = tmp_input[PERMUTATION_INIT_BLOCK[i] - 1];

    // the block is split into 2 halves
    ft_memcpy(&left, block, 32);
    ft_memcpy(&right, block + 32, 32); 

    for (int i = 0; i < 16; i++)
    {
        // the right half of the block is taken

        // 1- Expansion Permutation
       permutation(&right, EXPANSION_TAB, 48);

        // 2- Key mixing
        xor_round = right ^ key[i];

        // 3 - Substitution (S1, S2,...,S8)
        for (int f = 0; f < 8; f++)
        {
            // GET ROW (extremite b1, b6)
            row = (xor_round & 0b10000000) >> 6 | (xor_round & (0b00000001));
            // GET COL (middle b2 -> b5)
            col = (xor_round & 0b01111110) >> 1;

            sbox |= S_BOX[f][row][col] >> f;
        }

        // 4 - Permutation (P)
        permutation(&sbox, PERMUTATION_INIT_BLOCK, 32);

        left = sbox;
        swap_val(&right, &left);
        // print_bits(&sbox, 64);
    }

    // end_block = left+right;
    // 5 - Combine left and right

    return ((left << 28) | (right >> 28));
    // return big_block;
    // ft_memcpy(big_block, left, 28);
    // ft_memcpy(big_block+28, big_right, 48);

}

unsigned long* process_round_keys(unsigned long key, unsigned long *round_k)
{
    // TODO REVIEW THIS FUNCTION
    // get 56 bits of keys
    // split to have left and right
    unsigned int left, right;
    unsigned long concat;

    permutation(&key, PERMUTATION_INIT_KEY, 56);

    left = key >> 4;
    right = key & (0b11110000);

    for (int i = 0; i < 16; i++)
    {
        // shift_left left of key
        shift_left(&left, i, 28);

        // shift_left right of key
        shift_left(&right, i, 28);

        // concate twice
        concat = (left << 4) | (right);
        
        // key_permutation with concatenation
        ft_memcpy(round_k+i, &concat, 56);
        permutation(&round_k[i], COMPRESS_KEY_TAB, 48);
    }

    return round_k;
}


void    pad_block(unsigned char *input, int len_input)
{
    int diff = 64 - (len_input % 64);
    // printf("\ndiff: %d\ni: %d\n", diff, len_input%64);
    for (int i = diff; i < len_input%64; i++)
        input[i] = diff;
}

void    des_ecb_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type, char *algo_name)
{

    //  ======== Process key =========

    unsigned char pt[64];
    unsigned char key[8];
    unsigned long r_k[16];
    unsigned char block[64];
    unsigned long lol;

    ft_bzero(pt, 64);
    ft_bzero(key, 8);

    ft_memcpy(pt, "lol", 4);
    ft_memcpy(key, "lolololo", 8);

    int len_input = ft_strlen(pt);

    // if (len_input % 64 != 0)
    //     pad_block(pt, len_input);

    printf("\n%s", pt);
    // printf("%ln\n", process_round_keys((unsigned long)key, r_k));

    for (int i = 0; i < len_input; i += 64)
    {
        if (len_input > 64) {
            ft_bzero(block, 64);
            ft_memcpy(input + i, block, 64);
            lol = encrypt_block(block, r_k);
        }
        
        if (len_input < 64 || i + 64 > len_input) {
            // printf("size of input => %d\nlen => %d", len_input, 64 - (len_input % 64));
            pad_block(block + (len_input % 64), 64 - (len_input % 64));
            // print_bits(block, 64);
            lol = encrypt_block(block, r_k);
        }
    }
    // printf("\n%s\n", pt);
    // printf("\n%lu\n", block);
    base64_process_encode(pt);
}


// key => lolololo
// pt => lol
// result => 56f74dec963f7bbf