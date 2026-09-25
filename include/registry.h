/* Registry access for the local books and members files. */
#ifndef REGISTRY_H
#define REGISTRY_H

#include "types.h"

/* Parse the registry files and populate the in-memory tables. */
int registry_load(Registry *reg);

/* Return a pointer to a matching record, or NULL if it is missing. */
const Book   *registry_find_book(const Registry *reg, const char *book_id);
const Member *registry_find_member(const Registry *reg, const char *member_id);

/* Console display helpers for the menu. */
void registry_print_books(const Registry *reg);
void registry_print_members(const Registry *reg);

/* Trim leading and trailing whitespace from a string in place. */
char *str_trim(char *s);

#endif /* REGISTRY_H */
