# include "ft_ssl.h"
# include "libft.h"

// ===
// This file is part of the ft_ssl project. Is is a simple implementation of the des algorithm.
// There are parts of pure encryption of des. And parts for processing encryption and decryption with reading from stdin, files. 
// ===

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

    for (int i = 0; (unsigned int)i < to_s; i++)
        tmp |= ((*input >> (from_s - arr[i])) & 1) << (to_s - i - 1);

    *input = 0;
    *input = tmp;
}

void shift_left(unsigned long *input, unsigned int n, unsigned int len)
{
    // Process shift_left according ROTATE_TAB
     *input = ((*input << ROTATE_TAB[n]) | (*input >> (len - ROTATE_TAB[n]))) & 0x0FFFFFFFUL;
}

// ============== END OF DES UTILS ===============


// ======== Process encrypt pt =========

unsigned long encrypt_block(unsigned long block, unsigned long *key)
{
    // message block: 64 bits
    // key: 48 bits
    unsigned long end_block = 0, right = 0, left = 0, sbox = 0, xor_round = 0;
    int row = 0, col = 0;

    block = swap64(block);

    // permutation before block process
    permutation(&block, PERMUTATION_INIT_BLOCK, 64, 64);


    // the block is split into 2 halves
    left = (block >> 32) & 0x0FFFFFFFFUL;
    right = block & 0x0FFFFFFFFUL;


    for (int i = 0; i < 16; i++)
    {
        // the right half of the block is taken

        // 1 & 2-  Expansion Permutation & Key mixing
        xor_round = right;

        permutation(&xor_round, EXPANSION_TAB, 32, 48); // from 32 to 48 bits

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
    end_block = ((left << 32) | right); // from 2*32 to 64 bits

    permutation(&end_block, FINAL_PERM_TAB, 64, 64); 

    return swap64(end_block);
}

unsigned long* process_round_keys(unsigned long key, unsigned long *round_k)
{
    // get 56 bits of keys
    // split to have left and right
    unsigned long left = 0, right = 0, concat = 0, curr_round = 0;


    permutation(&key, PERMUTATION_INIT_KEY, 64, 56); // from 64 to 56 bits

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
        permutation(&curr_round, COMPRESS_KEY_TAB, 56, 48); // from 56 to 48 bits
        round_k[i] = curr_round;
    }

    return round_k;
}



void        des_encrypt_process(t_ft_ssl_mode *ssl_mode, unsigned long *r_k, t_fn_encrypt_block fn_encrypt_block)
{
    // ---
    // Process encryption according fn_encrypt_block as a function pointer
    // Read from ssl_mode->input_fd and output to ssl_mode->output_fd
    // ---

    //  ======== Process key =========
    unsigned long block, result;
    unsigned long buff_blocks[3]; // bc 3 * 8 = 24 is a multiple of 3 (for b64)
    int cpt = 0;
    char buffer[8];
    ssize_t readed = 0;

    ft_bzero(buff_blocks, 3*8);
    ft_bzero(buffer, 8);

    // WRITE SALTED IF NO KEY PROVIDED
    if (!ssl_mode->have_key)
    {
        if (ssl_mode->des_b64)
        {
            // printf("ssl_mode->salt = %d", ssl_mode->salt);
            ft_memcpy(&buff_blocks[cpt++], "Salted__", 8);
            buff_blocks[cpt++] = ssl_mode->salt;
        } else {
            write(ssl_mode->output_fd, "Salted__", 8);
            write(ssl_mode->output_fd, &ssl_mode->salt, 8);
        }
    }

    while ((readed = utils_read(ssl_mode->input_fd, buffer, 8, ssl_mode)) == 8)
    {
        block = 0;
        ft_memcpy(&block, buffer, 8);
        result = fn_encrypt_block(block, ssl_mode, r_k);
        ft_memcpy(&buff_blocks[cpt++], &result, 8);
        if (cpt == 3) {
            if (ssl_mode->des_b64 == 1) print_cipher_b64(buff_blocks, &cpt, ssl_mode->output_fd, 0);
            else print_cipher_raw(buff_blocks, &cpt, ssl_mode->output_fd, 0);
            cpt = 0;
        }
    }
    
    if (readed < 0)
        print_errors(ERROR_READ_GLOBAL, ssl_mode);

    if (readed == 0 && cpt > 0 && !ssl_mode->should_padd) // write from buff_blocks
    {
        if (ssl_mode->des_b64 == 1) print_cipher_b64(buff_blocks, &cpt, ssl_mode->output_fd, readed);
        else print_cipher_raw(buff_blocks, &cpt, ssl_mode->output_fd, readed);
    }

    // check readed and process padding
    if (readed > 0 || (readed == 0 && ssl_mode->should_padd)) // process last block and pad block
    {
        block = 0;
        if (ssl_mode->should_padd)
        {
            pad_block((unsigned char*)buffer, readed);
            readed = 8;
        }
        ft_memcpy(&block, buffer, readed);
        result = fn_encrypt_block(block, ssl_mode, r_k);

        ft_memcpy(&buff_blocks[cpt++], &result, readed);

        if (ssl_mode->des_b64 == 1) print_cipher_b64(buff_blocks, &cpt, ssl_mode->output_fd, readed);
        else print_cipher_raw(buff_blocks, &cpt, ssl_mode->output_fd, readed);
    }

    if (!ssl_mode->have_key && ssl_mode->des_b64)
        ft_putchar_fd('\n', ssl_mode->output_fd);
}


void        process_from_magic(t_ft_ssl_mode *ssl_mode, unsigned long *r_k, t_fn_decrypt_block fn_decrypt_block, unsigned long *tmp_buffer, int *flag_buffer_filled, int *flag)
{
        unsigned long result = 0;
        ssize_t last_block_size = 0;

        ft_bzero(tmp_buffer, 32);

        *flag_buffer_filled = (ssl_mode->tmp_b64_buffer_read == 56) ? 1 : 0;
        if (!*flag_buffer_filled) // if we have already read all from salt magic
        {
            if (ssl_mode->tmp_b64_buffer_read == 48) // process one tmp_buffer full
            {
                ft_memcpy((char*)tmp_buffer, ssl_mode->tmp_b64_buffer, 32);

                for (int i = 0; i < 4; i++)
                {
                    result = fn_decrypt_block(tmp_buffer[i], ssl_mode, r_k);
                    write(ssl_mode->output_fd, &result, 8);
                }
                ssl_mode->tmp_b64_buffer_read -= 32;
                ft_memcpy(ssl_mode->tmp_b64_buffer, ssl_mode->tmp_b64_buffer + 32, 16);
                ft_bzero(ssl_mode->tmp_b64_buffer + 16, 16); 
            }

            // process as tmp_buffer between 8 -> 32 and unpad as the last
            int size_block = ssl_mode->tmp_b64_buffer_read / 8;
            ft_bzero(tmp_buffer, 32);
            ft_memcpy((char*)tmp_buffer, ssl_mode->tmp_b64_buffer, ssl_mode->tmp_b64_buffer_read);

            for (int i = 0; i < size_block; i++)
            {
                result = fn_decrypt_block(tmp_buffer[i], ssl_mode, r_k);
               if (i + 1 == size_block)
                {
                    if (ssl_mode->should_padd)
                        last_block_size = unpad((unsigned char*)&result);
                    else
                        last_block_size = (ssl_mode->tmp_b64_buffer_read % 8 == 0) ? 8 : ssl_mode->tmp_b64_buffer_read % 8;

                    write(ssl_mode->output_fd, &result, last_block_size);
                    exit(0); // quit function if we don't have readed
                } else write(ssl_mode->output_fd, &result, 8);
            }
        } else {
            // process first block as 32
            // process second as 24 and update flag_buffer_filled as true
            ft_memcpy((char*)tmp_buffer, ssl_mode->tmp_b64_buffer, 32);
            for (int i = 0; i < 4; i++)
            {
                result = fn_decrypt_block(tmp_buffer[i], ssl_mode, r_k);
                write(ssl_mode->output_fd, &result, 8);
            }

            ft_bzero(tmp_buffer, 32);
            ft_memcpy((char*)tmp_buffer, ssl_mode->tmp_b64_buffer + 32, 24);
            *flag_buffer_filled = 1;
            *flag = 1;
        }
        ft_bzero(ssl_mode->tmp_b64_buffer, 32);
}


void        des_decrypt_process(t_ft_ssl_mode *ssl_mode, unsigned long *r_k, t_fn_decrypt_block fn_decrypt_block)
{
    unsigned long result;
    int flag = 0;
    char buffer[32];
    unsigned long tmp_buffer[4]; // 3 * 8 = 24 and 4 * 8 = 32
    ssize_t readed = 0, tmp_readed = 0, last_block_size = 0;
    int last_blocks_size = 0, flag_buffer_filled = 0;

    ft_bzero(tmp_buffer, 4*8);
    ft_bzero(buffer, 32);

    // reverse round key
    if (ssl_mode->should_padd) // for cfb ofb and ctr no need to reverse key.
        reverse_round_key(r_k);


    if (ssl_mode->tmp_b64_buffer != 0)
       process_from_magic(ssl_mode, r_k, fn_decrypt_block, tmp_buffer, &flag_buffer_filled, &flag);

    while ((readed = utils_read(ssl_mode->input_fd, buffer, 32, ssl_mode)) == 32)
    {
        ssl_mode->salt_from_file = 0;
        // ----
        // with 24 we can constitute 3 blocks
        // ----
        flag = 1;
        if (flag_buffer_filled)
        {
            for (int i = 0; i < 4 - ssl_mode->des_b64; i++)
            {
                result = fn_decrypt_block(tmp_buffer[i], ssl_mode, r_k);
                write(ssl_mode->output_fd, &result, 8);
            }
        }

        ft_bzero(tmp_buffer, 32);
        if (ssl_mode->des_b64 == 1) tmp_readed = b64_to_three_bytes(buffer, (char *)tmp_buffer, 32, 0, ssl_mode); // 8 * 3 = 24
        else {
            for (int i = 0; i < 4; i++) // 8 * 4 = 32
                ft_memcpy(&tmp_buffer[i], buffer + (i*8), 8);
        }
        flag_buffer_filled = 1;
    }

    if (readed < 0)
        print_errors(ERROR_READ_GLOBAL, ssl_mode);

    // ----
    // with the rest we constitute n blocks who n < 3 (8 by block)
    // ----
    if (readed >= 0)
    {
        // ---
        // Process the last read from tmp_buffer[] before process the rest 
        if (tmp_buffer[0] != 0)
        {
            flag = 1;
            for (int i = 0; i < 4 - ssl_mode->des_b64; i++)
            {
                result = fn_decrypt_block(tmp_buffer[i], ssl_mode, r_k);
                // printf("HERE MON POTE");
                if (i == (4 - ssl_mode->des_b64) - 1 && readed == 0) // -1 to get last block
                {
                    if (ssl_mode->should_padd)
                        last_block_size = unpad((unsigned char*)&result);
                    else
                        last_block_size = (tmp_readed % 8 == 0) ? 8 : tmp_readed % 8;
                    
                    write(ssl_mode->output_fd, &result, last_block_size);
                    return; // quit function if we don't have readed
                } else write(ssl_mode->output_fd, &result, 8);
            }
            ft_bzero(tmp_buffer, 4*8);
        }

        if (readed == 0 || (readed < 8 && ssl_mode->should_padd)) // quit function if we don't have readed or if the block is not good size
        {
            if (!flag && ssl_mode->should_padd) // display error when we read 0 in all program
                print_errors(ERROR_BAD_DECRYPT, ssl_mode);
            return;
        }

        // --- 
        // Process the new read from buffer[]
        if (ssl_mode->des_b64 == 1) readed = b64_to_three_bytes(buffer, (char *)tmp_buffer, readed, 0, ssl_mode);
        else {
            int j = 0;
            for (int i = 0; i < readed; j++, i += 8)
                ft_memcpy(&tmp_buffer[j], buffer + i, 8);
        }

        // calculate last_block_size to apply unpad on last padding
        last_blocks_size = ((readed/8) - 1) <= 0 ? 1 : (readed/8);

        if (readed%8 > 0 && readed > 8 && !ssl_mode->should_padd)
            last_blocks_size += 1;

        for (int i = 0; i < last_blocks_size; i++)
        {
            result = fn_decrypt_block(tmp_buffer[i], ssl_mode, r_k);
            if (i + 1 == last_blocks_size && ((readed % 8 > 0 && !ssl_mode->should_padd) || ssl_mode->should_padd)) { // process last block unpadding
                if (ssl_mode->should_padd)
                    last_block_size = unpad((unsigned char*)&result);
                else
                    last_block_size = readed % 8;
                write(ssl_mode->output_fd, &result, last_block_size);
            } else write(ssl_mode->output_fd, &result, 8);
        }
    }
}


void        des_process(t_ft_ssl_mode *ssl_mode, t_fn_encrypt_block fn_encrypt_block, t_fn_decrypt_block fn_decrypt_block)
{
    unsigned long r_k[16];

    ft_bzero(r_k, 16*8);

    // process round key
    process_round_keys(ssl_mode->key, r_k);

    if (ssl_mode->decode_mode == 1) des_decrypt_process(ssl_mode, r_k, fn_decrypt_block);
    else des_encrypt_process(ssl_mode, r_k, fn_encrypt_block);
}