/* Registry parsing and validation for the local CSV data files. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "registry.h"

/* --------------------------------------------------------------- */
char *str_trim(char *s)
{
    char *end;
    if (s == NULL) return NULL;

    while (*s != '\0' && isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;

    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

/* Copy strings safely without risking a truncated buffer. */
static void safe_copy(char *dst, size_t dst_sz, const char *src)
{
    if (dst_sz == 0) return;
    snprintf(dst, dst_sz, "%s", src ? src : "");
}

/* Strip an optional markdown bullet prefix such as "- " or "* ". */
static char *strip_bullet(char *s)
{
    if ((s[0] == '-' || s[0] == '*') && isspace((unsigned char)s[1]))
        return str_trim(s + 1);
    return s;
}

/* --------------------------------------------------------------- */
static int load_books(Registry *reg)
{
    FILE *fp;
    char  line[256];
    int   lineno = 0;

    fp = fopen(BOOKS_FILE, "r");
    if (fp == NULL) {
        fprintf(stderr,
                "ERROR: Required file '%s' is missing. "
                "Create it before running the program.\n", BOOKS_FILE);
        return ERR_FILE_MISSING;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *p, *id, *title, *author, *save = NULL;
        int   i, dup = 0;

        lineno++;
        line[strcspn(line, "\r\n")] = '\0';
        p = strip_bullet(str_trim(line));
        if (*p == '\0' || *p == '#') continue;          /* blank / comment */

        id     = strtok_r(p,    ",", &save);
        title  = strtok_r(NULL, ",", &save);
        author = strtok_r(NULL, ",", &save);

        if (id == NULL || title == NULL || author == NULL) {
            fprintf(stderr,
                    "WARNING: %s line %d is malformed "
                    "(expected book_id,title,author) - skipped.\n",
                    BOOKS_FILE, lineno);
            continue;
        }
        id = str_trim(id); title = str_trim(title); author = str_trim(author);
        if (*id == '\0' || *title == '\0') {
            fprintf(stderr, "WARNING: %s line %d has an empty field - "
                            "skipped.\n", BOOKS_FILE, lineno);
            continue;
        }
        if (reg->book_count >= MAX_BOOKS) {
            fprintf(stderr, "WARNING: book registry full (%d) - "
                            "remaining lines ignored.\n", MAX_BOOKS);
            break;
        }
        for (i = 0; i < reg->book_count; i++)
            if (strcmp(reg->books[i].book_id, id) == 0) { dup = 1; break; }
        if (dup) {
            fprintf(stderr, "WARNING: duplicate book_id '%s' on %s line %d - "
                            "skipped.\n", id, BOOKS_FILE, lineno);
            continue;
        }

        safe_copy(reg->books[reg->book_count].book_id, 20, id);
        safe_copy(reg->books[reg->book_count].title,   80, title);
        safe_copy(reg->books[reg->book_count].author,  50, author);
        reg->book_count++;
    }
    fclose(fp);

    if (reg->book_count == 0) {
        fprintf(stderr, "ERROR: '%s' is empty or contains no valid records.\n",
                BOOKS_FILE);
        return ERR_FILE_EMPTY;
    }
    return OK;
}

/* --------------------------------------------------------------- */
static int load_members(Registry *reg)
{
    FILE *fp;
    char  line[256];
    int   lineno = 0;

    fp = fopen(MEMBERS_FILE, "r");
    if (fp == NULL) {
        fprintf(stderr,
                "ERROR: Required file '%s' is missing. "
                "Create it before running the program.\n", MEMBERS_FILE);
        return ERR_FILE_MISSING;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *p, *id, *name, *course, *save = NULL;
        int   i, dup = 0;

        lineno++;
        line[strcspn(line, "\r\n")] = '\0';
        p = strip_bullet(str_trim(line));
        if (*p == '\0' || *p == '#') continue;

        id     = strtok_r(p,    ",", &save);
        name   = strtok_r(NULL, ",", &save);
        course = strtok_r(NULL, ",", &save);

        if (id == NULL || name == NULL || course == NULL) {
            fprintf(stderr,
                    "WARNING: %s line %d is malformed "
                    "(expected member_id,full_name,course_code) - skipped.\n",
                    MEMBERS_FILE, lineno);
            continue;
        }
        id = str_trim(id); name = str_trim(name); course = str_trim(course);
        if (*id == '\0' || *name == '\0') {
            fprintf(stderr, "WARNING: %s line %d has an empty field - "
                            "skipped.\n", MEMBERS_FILE, lineno);
            continue;
        }
        if (reg->member_count >= MAX_MEMBERS) {
            fprintf(stderr, "WARNING: member registry full (%d) - "
                            "remaining lines ignored.\n", MAX_MEMBERS);
            break;
        }
        for (i = 0; i < reg->member_count; i++)
            if (strcmp(reg->members[i].member_id, id) == 0) { dup = 1; break; }
        if (dup) {
            fprintf(stderr, "WARNING: duplicate member_id '%s' on %s line %d - "
                            "skipped.\n", id, MEMBERS_FILE, lineno);
            continue;
        }

        safe_copy(reg->members[reg->member_count].member_id,  20, id);
        safe_copy(reg->members[reg->member_count].full_name,  50, name);
        safe_copy(reg->members[reg->member_count].course_code,10, course);
        reg->member_count++;
    }
    fclose(fp);

    if (reg->member_count == 0) {
        fprintf(stderr, "ERROR: '%s' is empty or contains no valid records.\n",
                MEMBERS_FILE);
        return ERR_FILE_EMPTY;
    }
    return OK;
}

/* --------------------------------------------------------------- */
int registry_load(Registry *reg)
{
    int rc;
    if (reg == NULL) return ERR_BAD_FORMAT;

    memset(reg, 0, sizeof(*reg));

    rc = load_books(reg);
    if (rc != OK) return rc;

    rc = load_members(reg);
    if (rc != OK) return rc;

    printf("[registry] Loaded %d book(s) from %s and %d member(s) from %s.\n",
           reg->book_count, BOOKS_FILE, reg->member_count, MEMBERS_FILE);
    return OK;
}

/* --------------------------------------------------------------- */
const Book *registry_find_book(const Registry *reg, const char *book_id)
{
    int i;
    if (reg == NULL || book_id == NULL) return NULL;
    for (i = 0; i < reg->book_count; i++)
        if (strcmp(reg->books[i].book_id, book_id) == 0)
            return &reg->books[i];
    return NULL;
}

const Member *registry_find_member(const Registry *reg, const char *member_id)
{
    int i;
    if (reg == NULL || member_id == NULL) return NULL;
    for (i = 0; i < reg->member_count; i++)
        if (strcmp(reg->members[i].member_id, member_id) == 0)
            return &reg->members[i];
    return NULL;
}

/* --------------------------------------------------------------- */
void registry_print_books(const Registry *reg)
{
    int i;
    printf("\n+------------+----------------------------------------"
           "+-----------------------------+\n");
    printf("| %-10s | %-38s | %-27s |\n", "BOOK ID", "TITLE", "AUTHOR");
    printf("+------------+----------------------------------------"
           "+-----------------------------+\n");
    for (i = 0; i < reg->book_count; i++)
        printf("| %-10s | %-38.38s | %-27.27s |\n",
               reg->books[i].book_id, reg->books[i].title,
               reg->books[i].author);
    printf("+------------+----------------------------------------"
           "+-----------------------------+\n");
    printf("%d book(s) in the registry.\n", reg->book_count);
}

void registry_print_members(const Registry *reg)
{
    int i;
    printf("\n+------------+----------------------------------+------------+\n");
    printf("| %-10s | %-32s | %-10s |\n", "MEMBER ID", "FULL NAME", "COURSE");
    printf("+------------+----------------------------------+------------+\n");
    for (i = 0; i < reg->member_count; i++)
        printf("| %-10s | %-32.32s | %-10.10s |\n",
               reg->members[i].member_id, reg->members[i].full_name,
               reg->members[i].course_code);
    printf("+------------+----------------------------------+------------+\n");
    printf("%d member(s) in the registry.\n", reg->member_count);
}
