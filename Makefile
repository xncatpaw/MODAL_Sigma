# A sample Makefile
# This Makefile demonstrates and explains 
# Make Macros, Macro Expansions,
# Rules, Targets, Dependencies, Commands, Goals
# Artificial Targets, Pattern Rule, Dependency Rule.

# Comments start with a # and go to the end of the line.

SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj

CC = gcc
CPPFLAGS = -Iinclude
CFLAGS = -Wall

# Here is a simple Make Macro.

LINK_TARGET = tcp_syn_flooding l2_flooding dns_client dns_server test_getname


# Here is a Make Macro that uses the backslash to extend to multiple lines.
# This allows quick modification of more object files.

SRC = $(wildcard $(SRC_DIR)/*.c)
#OBJS = \
#	header.o raw_ip.o #tcp_syn_flooding.o
#OBJ = $(patsubst %.c,%.o,$(SRC))
OBJ_ALL = $(patsubst %.c, %.o, $(addprefix $(OBJ_DIR)/, $(notdir $(SRC))))
OBJ_TAR = $(addprefix $(OBJ_DIR)/, $(addsuffix .o, $(LINK_TARGET)))
OBJ = $(filter-out $(OBJ_TAR), $(OBJ_ALL))
#OBJ = $(patsubst %.c,%.o,$(OBJ))

TCP_OBJ = $(OBJ_DIR)/tcp_syn_flooding.o
L2_OBJ = $(OBJ_DIR)/l2_flooding.o
DNS_CL_OBJ = $(OBJ_DIR)/dns_client.o
DNS_SR_OBJ = $(OBJ_DIR)/dns_server.o

	
# Here is a Make Macro defined by two Macro Expansions.
# A Macro Expansion may be treated as a textual replacement of the Make Macro.
# Macro Expansions are introduced with $ and enclosed in (parentheses).

REBUILDABLES = $(OBJ_ALL) $(LINK_TARGET) 

# There are two standard Targets your Makefile should probably have:
# "all" and "clean", because they are often command-line Goals.
# Also, these are both typically Artificial Targets, because they don't typically
# correspond to real files named "all" or "clean".  

# The rule for "all" is used to incrementally build your system.
# It does this by expressing a dependency on the results of that system,
# which in turn have their own rules and dependencies.
all : $(LINK_TARGET)


tcp_syn_flooding : $(OBJ) $(TCP_OBJ)
	$(CC) $^ -o $@
l2_flooding : $(OBJ) $(L2_OBJ)
	$(CC) $^ -o $@
dns_client : $(OBJ) $(DNS_CL_OBJ)
	$(CC) $^ -o $@
dns_server : $(OBJ) $(DNS_SR_OBJ)
	$(CC) $^ -o $@

test_getname : $(OBJ_DIR)/test_getname.o
	$(CC) $^ -o $@

# Make Macros do not need to be defined before their Macro Expansions,
# but they normally should be defined before they appear in any Rules.
# Consequently Make Macros often appear first in a Makefile.

# Here is a simple Rule (used for "cleaning" your build environment).
# It has a Target named "clean" (left of the colon ":" on the first line),
# no Dependencies (right of the colon),
# and two Commands (indented by tabs on the lines that follow).
# The space before the colon is not required but added here for clarity.

clean: 
	rm -f $(REBUILDABLES)
	rm -f log.txt

test:
	@echo $(SRC)
	@echo $(OBJ)

# There is no required order to the list of rules as they appear in the Makefile.
# Make will build its own dependency tree and only execute each rule only once
# its dependencies' rules have been executed successfully.

# Here is a Rule that uses some built-in Make Macros in its command:
# $@ expands to the rule's target
# $^ expands to the rule's dependencies
#$(LINK_TARGET) : $(OBJS)


# Here is a Pattern Rule, often used for compile-line.
# It says how to create a file with a .o suffix, given a file with a .c suffix.
# The rule's command uses some built-in Make Macros:
# $@ for the pattern-matched target
# $lt; for the pattern-matched dependency

$(OBJ_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) -g  $(CPPFLAGS) $(CFLAGS) -o $@ -c $< 
  
# These are Dependency Rules, which are rules without any command.
# Dependency Rules indicate that if any file to the right of the colon changes,
# the target to the left of the colon should be considered out-of-date.
# The commands for making an out-of-date target up-to-date may be found elsewhere
# (in this case, by the Pattern Rule above).
# Dependency Rules are often used to capture header file dependencies.
