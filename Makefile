# =====================================================================
# Makefile - Blockchain-Based Library Book Lending Tracker
# ---------------------------------------------------------------------
#   make          build ./library_chain
#   make run      build and run
#   make clean    remove build artefacts
#   make reset    also remove ledger, keys and auth store (fresh demo)
# =====================================================================
CC       := gcc
CFLAGS   := -std=c11 -Wall -Wextra -Wpedantic -O2 -Iinclude
LDFLAGS  :=
LDLIBS   := -lcrypto

TARGET   := library_chain
SRCDIR   := src
OBJDIR   := build
SRCS     := $(wildcard $(SRCDIR)/*.c)
OBJS     := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))

.PHONY: all run clean reset

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
	@echo "Built ./$(TARGET)"

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR):
	@mkdir -p $(OBJDIR)

run: $(TARGET)
	./$(TARGET)

clean:
	@rm -rf $(OBJDIR) $(TARGET)
	@echo "Build artefacts removed."

reset: clean
	@rm -rf keys chain.dat chain.dat.tmp auth.dat
	@echo "Ledger, keys and auth store removed - next run starts fresh."

# Build a demo binary whose loan period is 0 days, so option 8 flags every
# open loan immediately.  Used only to record the demo video.
demo-overdue:
	$(CC) $(CFLAGS) -DLOAN_PERIOD_DAYS=0 $(SRCS) -o library_chain_overdue $(LDLIBS)
	@echo "Built ./library_chain_overdue (loan period = 0 days)"
