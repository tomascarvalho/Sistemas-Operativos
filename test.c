#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define NUM_CHARS 512

void main(int argc, char *argv[])
{
	char filename[NUM_CHARS];
	char line[NUM_CHARS];
	char temp_line[NUM_CHARS], other_temp_line[NUM_CHARS];
	int run_line, conta, what_we_want, run_temp;
	int num_threads;

	strcpy(filename, argv[1]);
	FILE *fp;
	fp = fopen(filename, "r");

	conta = 0;
	while(fgets(line, NUM_CHARS, fp)!= NULL)
	{
		conta ++;
		run_line = 0;
		while (line[run_line] != '=')
		{
			run_line ++;
		}
		run_line++;

		if (line[run_line] == ' ')
		{
			run_line++;
		}

		what_we_want = 0;
		while((line[run_line] != '\0') && (line[run_line] != '\n'))
		{
			temp_line[what_we_want] = line[run_line];
			what_we_want++;
			run_line++;
		}

		temp_line[what_we_want] = '\0';

		switch(conta)
		{
			case 1:
				num_threads = atoi(temp_line);
				printf("\nNUM THREADS: %d\n", num_threads);
				break;
			case 2:
				run_line= 0;
				run_temp = 0;
				while ((temp_line[run_line] != '\n') && (temp_line[run_line] != '\0'))
				{
					if (temp_line[run_line] ==  ';')
					{
						// pôr other_temp_line na estrutura
						other_temp_line[run_temp] = '\0';
						puts(other_temp_line);
						run_line++;
						bzero(other_temp_line, sizeof(other_temp_line));
						run_temp = 0;
					}
					else if (temp_line[run_line] == ' ')
						run_line++;

					else
					{
						other_temp_line[run_temp] = temp_line[run_line];
						run_temp++;
						run_line++;
					}

				}
				other_temp_line[run_temp] = '\0';
				puts(other_temp_line);
				break;

			case 3:

				run_line= 0;
				run_temp = 0;
				while ((temp_line[run_line] != '\n') && (temp_line[run_line] != '\0'))
				{
				
					if (temp_line[run_line] == ' ')
						run_line++;

					else
					{
						other_temp_line[run_temp] = temp_line[run_line];
						run_temp++;
						run_line++;
					}

				}
				other_temp_line[run_temp] = '\0';
				//Pôr o other_temp_line na estrutura --> LOCAL DOMAIN
				puts(other_temp_line);
				break;

			case 4:

				run_line= 0;
				run_temp = 0;
				while ((temp_line[run_line] != '\n') && (temp_line[run_line] != '\0'))
				{
				
					if (temp_line[run_line] == ' ')
						run_line++;

					else
					{
						other_temp_line[run_temp] = temp_line[run_line];
						run_temp++;
						run_line++;
					}

				}
				other_temp_line[run_temp] = '\0';
				//Pôr o other_temp_line na estrutura --> NAMED PIPE STATISTICS
				puts(other_temp_line);
				break;

			default:
				printf("\nCHECK CONFIGURATION FILE!!\n");


		}

		
	}

	fclose(fp);
}