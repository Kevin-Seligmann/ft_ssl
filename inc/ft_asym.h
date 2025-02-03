#ifndef ASYM_H
# define ASYM_H

int rsautl_command(struct s_command *command, int ind, char **argv);
int rsa_command(struct s_command *command, int ind, char **argv);
int genrsa_command(struct s_command *command, int ind, char **argv);
int gendsa_command(struct s_command *command, int ind, char **argv);
int breakit_command(struct s_command *command, int ind, char **argv);
int extractkey_command(struct s_command *command, int ind, char **argv);

#endif
	
	

