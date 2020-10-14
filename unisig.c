// Copyright 2020 Lassi Kortela
// SPDX-License-Identifier: ISC

#ifdef _WIN32
#define UNISIG_WINDOWS
#else
#define UNISIG_UNIX
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef UNISIG_WINDOWS
#include <fcntl.h>
#include <io.h>
#endif

#ifdef UNISIG_UNIX
#include <unistd.h>
#endif

#ifdef __BORLANDC__
#define _setmode setmode
#endif

#ifndef PROGNAME
#define PROGNAME "unisig"
#endif

#ifndef PROGVERSION
#define PROGVERSION "0.1.0"
#endif

static unsigned char buffer[4096];
static const char *binary_input_name;
static const char *binary_output_name;
static FILE *binary_input;
static FILE *binary_output;
static const unsigned char magic[7]
    = { 0xDC, 0xDC, 0x0D, 0x0A, 0x1A, 0x0A, 0x00 };
static unsigned char *const head = buffer;
static unsigned char *const tail = head + sizeof(magic) + 1;
static const char *oflag;
static const char *newcmd;

static void generic_usage(FILE *stream, int status);

static unsigned int gettaillen(void) { return head[sizeof(magic)]; }
static int is_uuid(void) { return gettaillen() == 0; }

static void panic(const char *msg)
{
    fprintf(stderr, "%s: %s\n", PROGNAME, msg);
    exit(2);
}

static void panic_s(const char *msg, const char *s)
{
    fprintf(stderr, "%s: %s%s\n", PROGNAME, msg, s);
    exit(2);
}

#ifdef UNISIG_WINDOWS
static void binary_stdin(void) { _setmode(_fileno(stdin), _O_BINARY); }
#endif

#ifdef UNISIG_WINDOWS
static void binary_stdout(void) { _setmode(_fileno(stdout), _O_BINARY); }
#endif

#ifdef UNISIG_UNIX
static void binary_stdin(void)
{
    if (isatty(STDIN_FILENO)) {
        panic("cannot read binary data from terminal");
    }
}
#endif

#ifdef UNISIG_UNIX
static void binary_stdout(void)
{
    if (isatty(STDOUT_FILENO)) {
        panic("cannot write binary data to terminal");
    }
}
#endif

static void binary_input_file_close(void)
{
    if (fclose(binary_input) == EOF) {
        panic("cannot close file");
    }
    binary_input_name = 0;
    binary_input = 0;
}

static void binary_output_file_close(void)
{
    if (fclose(binary_output) == EOF) {
        panic("cannot close file");
    }
    binary_output_name = 0;
    binary_output = 0;
}

static void binary_input_std(void)
{
    binary_input_name = "<stdin>";
    binary_input = stdin;
    binary_stdin();
}

static void binary_output_std(void)
{
    binary_output_name = "<stdout>";
    binary_output = stdout;
    binary_stdout();
}

static void binary_input_file_open(const char *filename)
{
    binary_input_name = filename;
    if (!(binary_input = fopen(filename, "rb"))) {
        panic_s("cannot open ", filename);
    }
}

static void binary_output_file_open(const char *filename)
{
    binary_output_name = filename;
    if (!(binary_output = fopen(filename, "wb"))) {
        panic_s("cannot open ", filename);
    }
}

static size_t binary_input_at_most_n_bytes(void *bytes, size_t nbyte)
{
    size_t nread;

    nread = fread(bytes, 1, nbyte, binary_input);
    if (ferror(binary_input)) {
        panic("cannot read from");
    }
    return nread;
}

static void binary_input_exactly_n_bytes(void *bytes, size_t nbyte)
{
    if (binary_input_at_most_n_bytes(bytes, nbyte) != nbyte) {
        panic("cannot read enough data");
    }
}

static void output_exactly_n_bytes(const void *bytes, size_t nbyte)
{
    if (fwrite(bytes, 1, nbyte, binary_output) != nbyte) {
        panic("cannot write");
    }
    if (ferror(binary_output)) {
        panic("cannot write to");
    }
}

static void binary_input_random(void *bytes, size_t nbyte)
{
    binary_input_file_open("/dev/random");
    binary_input_exactly_n_bytes(bytes, nbyte);
    binary_input_file_close();
}

static const char *namespace_dns = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
static const char *namespace_url = "6ba7b811-9dad-11d1-80b4-00c04fd430c8";

static unsigned int parse_lowercase_hex_digit(int ch)
{
    const char digits[] = "0123456789abcdef";
    const char *digitp;
    if (!(digitp = strchr(digits, ch)))
        return (unsigned int)-1;
    return (unsigned int)(digitp - digits);
}

static int parse_hex_bytes(
    const char **hexp, unsigned char **bytesp, int nextch, size_t nbyte)
{
    const char *hex = *hexp;
    unsigned char *bytes = *bytesp;
    unsigned int digit;
    unsigned int byte;
    for (; nbyte; nbyte--) {
        if ((digit = parse_lowercase_hex_digit(*hex)) == (unsigned int)-1)
            return 0;
        hex++;
        byte = digit << 4;
        if ((digit = parse_lowercase_hex_digit(*hex)) == (unsigned int)-1)
            return 0;
        hex++;
        byte |= digit;
        *bytes++ = byte;
    }
    if (*hex != nextch)
        return 0;
    hex++;
    *hexp = hex;
    *bytesp = bytes;
    return 1;
}

static int parse_uuid(const char *s, unsigned char outbuf[16])
{
    unsigned char *out;

    out = outbuf;
    if (!parse_hex_bytes(&s, &out, '-', 8))
        return 0;
    if (!parse_hex_bytes(&s, &out, '-', 4))
        return 0;
    if (!parse_hex_bytes(&s, &out, '-', 4))
        return 0;
    if (!parse_hex_bytes(&s, &out, '-', 4))
        return 0;
    if (!parse_hex_bytes(&s, &out, '\0', 12))
        return 0;
    return 1;
}

static void uuid_patch(unsigned int version)
{
    tail[6] = (tail[6] & 0x0f) | version;
    tail[8] = (tail[8] & 0x3f) | 0x80;
}

static void generate_uuid_variant_1_version_four(void)
{
    binary_input_random(tail, 16);
    uuid_patch(0x40);
}

static void make_unisig_from_arg(const char *arg)
{
    size_t nbyte;
    const char *cp;
    int ch;

    nbyte = strlen(arg);
    if (nbyte > 255) {
        panic("signature cannot be longer than 255 bytes");
    }
    for (cp = arg; (ch = *cp); cp++) {
        if ((ch >= '0') && (ch <= '9'))
            continue;
        if ((ch >= 'A') && (ch <= 'Z'))
            continue;
        if ((ch >= 'a') && (ch <= 'z'))
            continue;
        if (strchr("/.-#", ch))
            continue;
        panic("bad char");
    }
    memcpy(head, magic, sizeof(magic));
    head[sizeof(magic)] = nbyte;
    memcpy(tail, arg, nbyte);
}

static void print_hex_byte(unsigned int byte) { printf("%02x", byte); }

static void print_tail_uuid(void)
{
    print_hex_byte(tail[0]);
    print_hex_byte(tail[1]);
    print_hex_byte(tail[2]);
    print_hex_byte(tail[3]);
    printf("-");
    print_hex_byte(tail[4]);
    print_hex_byte(tail[5]);
    printf("-");
    print_hex_byte(tail[6]);
    print_hex_byte(tail[7]);
    printf("-");
    print_hex_byte(tail[8]);
    print_hex_byte(tail[9]);
    printf("-");
    print_hex_byte(tail[10]);
    print_hex_byte(tail[11]);
    print_hex_byte(tail[12]);
    print_hex_byte(tail[13]);
    print_hex_byte(tail[14]);
    print_hex_byte(tail[15]);
}

static void binary_input_read_unisig(void)
{
    size_t lenbyte;
    size_t taillen;

    binary_input_exactly_n_bytes(head, sizeof(magic) + 1);
    if (memcmp(head, magic, sizeof(magic))) {
        panic("bad magic");
    }
    lenbyte = head[sizeof(magic)];
    taillen = lenbyte ? lenbyte : 16;
    binary_input_exactly_n_bytes(tail, taillen);
}

static void binary_output_write_unisig(void)
{
    size_t nbyte;

    nbyte = gettaillen();
    nbyte = nbyte ? nbyte : 16;
    nbyte += 8;
    output_exactly_n_bytes(head, nbyte);
}

static void copy_remaining_binary_input_to_output(void)
{
    size_t n;

    while ((n = binary_input_at_most_n_bytes(buffer, sizeof(buffer)))) {
        output_exactly_n_bytes(buffer, n);
    }
}

static void print_tail_ascii(void)
{
    size_t i, n;

    n = gettaillen();
    for (i = 0; i < n; i++) {
        if (isprint(tail[i])) {
            printf("%c", tail[i]);
        } else {
            printf("?");
        }
    }
}

static void subcmd_addnew(void)
{
    binary_output_write_unisig();
    copy_remaining_binary_input_to_output();
}

static void subcmd_change(void)
{
    binary_input_read_unisig();
    subcmd_addnew();
}

static void subcmd_remove(void)
{
    binary_input_read_unisig();
    copy_remaining_binary_input_to_output();
}

static void subcmd_list(void)
{
    binary_input_read_unisig();
    if (binary_input != stdin) {
        printf("%s: ", binary_input_name);
    }
    if (is_uuid()) {
        printf("UUID: ");
        print_tail_uuid();
    } else {
        printf("URI: ");
        print_tail_ascii();
    }
    printf("\n");
}

static void subcmd_uuidgen(void)
{
    generate_uuid_variant_1_version_four();
    print_tail_uuid();
    printf("\n");
}

static void subcmd_version(void) { printf("%s %s\n", PROGNAME, PROGVERSION); }

static void subcmd_help(void) { generic_usage(stdout, 0); }

#define TEXT 0
#define BINARY 1

struct cmd {
    void (*visit)(void);
    const char *name;
    unsigned int narg;
    unsigned int input_is_binary;
    unsigned int output_is_binary;
};

static const struct cmd cmds[] = {
    { subcmd_addnew, "addnew", 1, BINARY, BINARY },
    { subcmd_change, "change", 1, BINARY, BINARY },
    { subcmd_remove, "remove", 0, BINARY, BINARY },
    { subcmd_list, "list", 0, BINARY, TEXT },
    { subcmd_uuidgen, "uuidgen", 0, TEXT, TEXT },
    { subcmd_version, "version", 0, TEXT, TEXT },
    { subcmd_help, "help", 0, TEXT, TEXT },
};

static const size_t ncmd = sizeof(cmds) / sizeof(cmds[0]);

static void generic_usage(FILE *stream, int status)
{
    fprintf(stream, "usage: %s %s\n", PROGNAME,
        "addnew sig [file ...] [-o output]");
    fprintf(stream, "usage: %s %s\n", PROGNAME,
        "change sig [file ...] [-o output]");
    fprintf(
        stream, "usage: %s %s\n", PROGNAME, "remove [file ...] [-o output]");
    fprintf(stream, "usage: %s %s\n", PROGNAME, "list [file ...]");
    fprintf(stream, "usage: %s %s\n", PROGNAME, "uuidgen");
    fprintf(stream, "usage: %s %s\n", PROGNAME, "version");
    fprintf(stream, "usage: %s %s\n", PROGNAME, "help");
    exit(status);
}

static void usage(const char *msg)
{
    if (msg) {
        if (msg[0]) {
            fprintf(stderr, "%s: %s\n", PROGNAME, msg);
        } else {
            fprintf(stderr, "\n");
        }
    }
    generic_usage(stderr, 2);
}

typedef void (*visit_func_t)(void);

static const char *oflag;

static const struct cmd *cmd_by_name(const char *name)
{
    const struct cmd *cmd;

    for (cmd = cmds; cmd < cmds + ncmd; cmd++) {
        if (!strcmp(cmd->name, name))
            return cmd;
    }
    return 0;
}

static void run_cmd(const struct cmd *cmd, char **args)
{
    const char *filename;

    if (cmd->narg) {
        if (*args) {
            newcmd = *args++;
        } else {
            usage("too few arguments");
        }
    }
    if (cmd->input_is_binary && cmd->output_is_binary) {
        if (oflag) {
            if (!args[0]) {
                binary_input_std();
                binary_output_file_open(oflag);
                cmd->visit();
                binary_output_file_close();
            } else if (!args[1]) {
                filename = args[0];
                binary_input_std();
                binary_output_file_open(oflag);
                binary_input_file_open(filename);
                cmd->visit();
                binary_input_file_close();
                binary_output_file_close();
            } else {
                usage("cannot use -o option with more than one input file");
            }
        } else if (args[0]) {
            for (; (filename = *args); args++) {
                binary_input_file_open(filename);
                binary_output_file_open(filename);
                cmd->visit();
                binary_input_file_close();
                binary_output_file_close();
            }
        } else {
            binary_input_std();
            binary_output_std();
            cmd->visit();
        }
    } else if (cmd->input_is_binary) {
        if (oflag) {
            usage("cannot use -o option with this subcommand");
        } else if (args[0]) {
            for (; (filename = *args); args++) {
                binary_input_file_open(filename);
                cmd->visit();
                binary_input_file_close();
            }
        } else {
            binary_input_std();
            cmd->visit();
        }
    } else {
        if (oflag) {
            usage("cannot use -o option with this subcommand");
        } else if (args[0]) {
            usage("too many arguments");
        } else {
            cmd->visit();
        }
    }
}

int main(int argc, char **argv)
{
    const char *subcmd;
    const struct cmd *cmd;
    int ch;

    while ((ch = getopt(argc, argv, "Vho:")) != -1) {
        switch (ch) {
        case 'V':
            subcmd_version();
            exit(0);
            break;
        case 'h':
            subcmd_help();
            exit(0);
            break;
        case 'o':
            oflag = optarg;
            break;
        default:
            usage(0);
            break;
        }
    }
    if (argc < 2) {
        usage(0);
    }
    argv++;
    subcmd = *argv++;
    if (!(cmd = cmd_by_name(subcmd))) {
        usage("unknown subcommand");
    }
    run_cmd(cmd, argv);
    return 0;
}
