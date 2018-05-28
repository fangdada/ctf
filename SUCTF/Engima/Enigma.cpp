#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define get_bit(n) (1<<(n))

typedef unsigned char uc;
unsigned char key1[] = {
	0x31,
	0x62,
	0x93,
	0xC4,
	0 };
unsigned char key2[] = {
	0x21,
	0x42,
	0x63,
	0x84,
	0
};
unsigned char key3[] = {
	0x3D,
	0x7A,
	0xB7,
	0xF4,
	0
};

unsigned char key_table[] = {
	0xA8,0x1C,0xAF,0xD9,
	0x0,0x6C,0xAC,0x2,
	0x9B,0x5,0xE3,0x68,
	0x2F,0xC7,0x78,0x3A,
	0x2,0xBC,0xBF,0xB9,
	0x4D,0x1C,0x7D,0x6E,
	0x31,0x1B,0x9B,0x84,
	0xD4,0x84,0x0,0x76,
	0x5A,0x4D,0x6,0x75,
	0x0,0x0,0x0,0x0
};

unsigned int smallkey[] = {
	0x2f9bacef,
	0x97cdd677,
	0x4be6eb3b,
	0xa5f3759d,
	0xd2f9bace,
	0x697cdd67,
	0xb4be6eb3,
	0x5a5f3759,
	0x2d2f9bac,
	0
};

unsigned char input2key[37] = { 0, };


char input[5] = { 0, };

char* dir = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_*{}~!@#$%";

unsigned char check_bit(unsigned char ch, unsigned char i)
{
	return (ch&(get_bit(i))) != 0;
}

void set_flag(uc check_input, uc check_key, uc pre_flag, uc* flag1, uc* flag2)
{
	*flag2 = pre_flag ^ check_key^check_input;
	*flag1 = check_key & check_input | pre_flag & (check_key | check_input);
}
void set_bit(uc* ch, uc flag, uc i)
{
	if (flag)
		*ch |= get_bit(i);
	else
		*ch &= ~(get_bit(i));
}

int main()
{
	uc input_ptr = 0;
	unsigned char flag1 = 0;
	unsigned char flag2 = 0;
	unsigned char check_key = 0;
	unsigned char check_input = 0;
	unsigned char step_key = 0;
	uc* p;
	unsigned int* key_ptr = (unsigned int*)key_table;
	uc pre_flag = 0;
	uc set_or_unset = 0;
	unsigned int l = 0;
	while (1)
	{
		for (int a = 0; a < 71; a++)
		{
			for (int b = 0; b < 71; b++)
				for (int c = 0; c < 71; c++)
					for (int d = 0; d < 71; d++)
					{

						input[0] = dir[a];
						input[1] = dir[b];
						input[2] = dir[c];
						input[3] = dir[d];
						for (int i = 0; i <= 3; i++)
						{
							flag1 = 0;
							flag2 = 0;
							input_ptr = input[i];
							step_key = key1[i];
							for (int j = 0; j <= 7; ++j)
							{
								pre_flag = flag1;
								check_key = check_bit(step_key, j);
								check_input = check_bit(input_ptr, j);
								set_flag(check_input, check_key, pre_flag, &flag1, &flag2);
								set_or_unset = flag2 != 0;
								set_bit(&input_ptr, set_or_unset, j);
							}
							step_key = key2[l % 4];
							for (int j = 0; j <= 7; j++)
							{
								pre_flag = flag1;
								check_key = check_bit(step_key, j);
								check_input = check_bit(input_ptr, j);
								set_flag(check_input, check_key, pre_flag, &flag1, &flag2);
								set_or_unset = flag2 != 0;
								set_bit(&input_ptr, set_or_unset, j);
							}
							step_key = key3[l / 4];
							for (int j = 0; j <= 7; j++)
							{
								pre_flag = flag1;
								check_key = check_bit(step_key, j);
								check_input = check_bit(input_ptr, j);
								set_flag(check_input, check_key, pre_flag, &flag1, &flag2);
								set_or_unset = flag2 != 0;
								set_bit(&input_ptr, set_or_unset, j);
							}
							input2key[i] = input_ptr;
						}
						unsigned char ch;
						uc check_key0;
						uc check_key1;
						uc check_key2;
						uc check_key3;
						uc check_key4;
						uc check_key5;
						for (int i = 0; i <= 3; i++)
						{
							ch = input2key[i];
							for (int j = 0; j <= 2; j++)
							{
								check_key0 = check_bit(ch, j);
								check_key1 = check_bit(ch, 7 - j) != check_key0;
								set_bit(&ch, check_key1, j);

								check_key2 = check_bit(ch, 7 - j);
								check_key3 = check_bit(ch, j) != check_key2;
								set_bit(&ch, check_key3, 7 - j);

								check_key4 = check_bit(ch, j);
								check_key5 = check_bit(ch, 7 - j) != check_key4;
								set_bit(&ch, check_key5, j);
							}
							input2key[i] = ch;
						}
						unsigned int* ptr = (unsigned int*)input2key;
						unsigned int key = smallkey[l];
						*ptr ^= key;

						if (*ptr == *key_ptr)
						{
							printf("%c%c%c%c", dir[a], dir[b], dir[c], dir[d]);
							key_ptr++;
							l++;
							if (*key_ptr == 0)
								exit(0);
							a = 0;
							b = 0;
							c = 0;
							d = 0;
						}
						//ptr++;
						//大约等个几分钟结果就会出来了:)
						//SUCTF{sm4ll_b1ts_c4n_d0_3v3rythin9!}
					}
		}
	}
	return 0;
}