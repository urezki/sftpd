#include <stdio.h>

void
str_contac(char *s)
{
	if (s == NULL)
		return;

	while (*s) {
		if (*s > 96 && *s < 123)
			*s -= 32;
		s++;
	}
}

size_t
str_strlen(const char *s)
{
	size_t i = 0;

	if (s) {
		while (*(s++) != '\0')
			i++;
	}

	return i;
}

/**
 * a - target string
 * b - string that contains reject characters
 */
size_t
str_strcspn(const char *a, const char *b)
{
	size_t a_len;
	size_t b_len;
	int i, j = 0;

	a_len = str_strlen(a);
	b_len = str_strlen(b);

	if (!a_len || !b_len)
		goto out;

	for (i = 0; i < a_len; i++) {
		/* compare two strings here */
		for (j = 0; j < b_len; j++) {
			if (a[i] != b[j])
				continue;

			goto out;
		}
	}

out:
	return i;
}

/**
 * returns index that points to the beginning
 * of found string, otherwise zero
 */
size_t
str_findss(const char *a, const char *b)
{
	size_t a_len;
	size_t b_len;
	size_t index;
	int i, j;

	a_len = str_strlen(a);
	b_len = str_strlen(b);

	if (!a_len || !b_len)
		goto not_found;

	for (i = 0; i < a_len; i++) {
		if (a[i] == b[0]) {
			index = i;
			/* compare two strings here */
			for (j = 0; i < a_len; i++) {
				if (a[i] == b[j]) {
					if (++j == b_len)
						return index;
				} else {
					i--;
					break;
				}
			}
		}
	}

not_found:
	return 0;
}

/**
 * returns new string length, otherwise zero
 */
size_t
str_removesfs(char *a, const char *b)
{
	size_t i;

	i = str_findss(a, b);
	if (i)
		a[i] = '\0';

	return i;
}
