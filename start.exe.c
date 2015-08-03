#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>


/*
 * Stash argc, argv
 */
int saved_argc;
char** saved_argv;


/*
 * Seek to a position in the file, or exit with an error code.
 */
void
file_seek (FILE* file, char* filename, long offset)
{
  assert (NULL != file);
  assert (NULL != filename);
  assert (0 <= offset);
  if (0 != fseek(file, offset, SEEK_SET)) {
    fprintf (stderr, "\nError: Failed to set read position to %ld %s for %s; error %d (%s)\n",
             offset, (offset == 1 ? "byte" : "bytes"), filename,
             errno, strerror (errno));
    exit (8);
  }
}

/*
 * Crash due to not having 4 bytes or so of memory free
 */
void
die_no_mem (void)
{
  fprintf (stderr, "\nError: Could not allocate a small memory buffer: error %d (%s)\n",
           errno, strerror (errno));
  exit (7);
}

/*
 * Crappy global bytes buffer used all over the place.
 */
char* bytes;
const size_t BYTES_BUFFER = 4;

void
init_buffer (void)
{
  bytes = calloc (1, BYTES_BUFFER);
  if (NULL == bytes) { die_no_mem (); }
}


/*
 * Read a few bytes into the global buffer, or return an error
 */
void
read_bytes (FILE* file, char* filename, long number)
{
  assert (NULL != bytes);
  assert (NULL != file);
  assert (NULL != filename);
  if (number == 0) {
    bytes[0] = '\0';
    return;
  }
  if (number > BYTES_BUFFER) { die_no_mem (); }
#ifdef DEBUG
  long position = ftell (file);
#endif
  size_t got = fread(bytes, 1, number, file);
  if (number != got) {
    fprintf (stderr, "\nError: Failed to read %d %s needed from %s (got %d)\n",
             number, (number == 1 ? "byte" : "bytes"), filename, got);
    exit (3);
  }
#ifdef DEBUG
  for (long i = 0; i < number; ++i) {
    printf ("\n%08lx %08lx ⇒ %02hhx %c", position, position+i, bytes[i],
            ((bytes[i] > 0x20 && bytes[i] < 0x7f) ? bytes[i] : 0x20));
  }
#endif
}

  /*
   * The first two bytes must be "MZ"
   */
  void
    check_for_exe_header (FILE* file, char* filename)
  {
    assert (NULL != file);
    assert (NULL != filename);

    file_seek (file, filename, 0);
    read_bytes (file, filename, 2);
    if ('M' != bytes[0] || 'Z' != bytes[1]) {
      fprintf (stderr, "\nError: %s does not begin with MZ magic.\n\
This is probably not an EXE file\n",
             filename);
    exit (4);
  }
}

/*
 * There's an indirection pointer at 0x3c & 0x3d to the PE header.
 */
long
pe_header_offset (FILE* file, char* filename)
{
  file_seek (file, filename, 0x3c);
  read_bytes (file, filename, 2);

  return (unsigned char)(bytes[1]) * 0x100 + (unsigned char)(bytes[0]);
}

/*
 * Ensure that "PE\0\0" starts the PE header.
 */
void
check_for_pe_header (FILE* file, char* filename, long pe_offset)
{
  assert (NULL != file);
  assert (NULL != filename);

  file_seek (file, filename, pe_offset);
  read_bytes (file, filename, 4);
  if ('P' != bytes[0] || 'E' != bytes[1] ||
      '\0' != bytes[2] || '\0' != bytes[3]) {
    fprintf (stderr, "\nError: %s does not contain PE magic.\n\
This is probably not an EXE file.",
             filename);
    exit (9);
  }
}

/*
 * Try to start the thunk program provided.
 */
void
try_run (char* program, char* filename)
{
  assert (NULL != program);
  assert (NULL != filename);

  char** argv = calloc (sizeof(char*), 1+ saved_argc);
  if (NULL == argv) { die_no_mem (); }
  
  argv[0] = strdup (program);
  argv[1] = strdup (filename);
  if (saved_argc > 2) {
    for (int i = 2; i < saved_argc; ++i) {
      argv[i] = strdup (saved_argv[i]);
    }
  }
  argv[1+ saved_argc] = NULL;
#ifdef DEBUG
  for (int i = 0; i < saved_argc; ++i) {
    printf ("\n argv[%d] = %s", i, argv[i]);
  }
#endif
  execv (argv[0], argv);
  fprintf (stderr, "\nFailed to run %s %s: error %d (%s)\n",
           program, filename, errno, strerror (errno));
  for (int i = 0; i < saved_argc; ++i) {
    free (argv[i]);
  }
  free (argv);
}

    /*
     * Try to start DOSBox, but only if we seem to be running in X.
     */
    void
    try_dosbox (char* filename)
  {
    assert (NULL != filename);
    char* display = getenv ("DISPLAY");
    if (NULL == display || '\0' == display[0]) {
      fprintf (stderr, "\nCannot run DOSBox: DISPLAY is unset.\n");
    } else {
      try_run ("/usr/bin/dosbox", filename);
    }
  }

  /*
   * Try to run DOSEmu.
   */
void
try_dosemu (char* filename)
{
  assert (NULL != filename);
  try_run ("/usr/bin/dosemu", filename);
}

  /*
   * Try to run  either DOSBox or DOSEmu. DOSBox will  not actually try to
   * start if  DISPLAY is not set  in the environment, allowing  DOSEmu to
   * start up using its framebuffer mode.
   */
  void
    start_as_dos (char* filename)
  {
    assert (NULL != filename);
    try_dosbox (filename);
    try_dosemu (filename);
    fprintf (stderr, "\nError: Could not start either DOSBox nor DOSEmu for %s\n",
             filename);
    exit (5);
  }

  /*
   * See if this is  a DOS .exe file, as (The value at  0x18) & 0xc0 == 0;
   * if true, try to start something to handle a DOS program.
   */
void
maybe_dos_exe (FILE* file, char* filename)
{
  assert (NULL != file);
  assert (NULL != filename);
  file_seek (file, filename, 0x18);
  read_bytes (file, filename, 1);
  if (0 == bytes[0] & 0xc0) {
    (void) fclose (file);
    start_as_dos (filename);
  }
}

  /*
   * See if this is a .NET/Mono .exe  file. There is a magic cookie in the
   * PE header + 24 bytes, which is  either 0xb01 or 0xb02, and if it is
   * found, we have to  also ensure that there's a zero byte  at PE + (232
   * or 248, resp. of the first cookie).
   *
   * If it looks like .NET, start it with Mono.
   */
void maybe_mono_exe (FILE* file, char* filename, long pe_offset)
{
  assert (NULL != file);
  assert (NULL != filename);
  
  file_seek (file, filename, pe_offset + 24);
  read_bytes (file, filename, 2);

  long next_offset = -1;

  /* First magic  cookie present? If so,  we need to know  where to look
     for the next part. */
  if (0xb == bytes[0]) {
    switch (bytes[1]) {
    case 1:
      next_offset = 232;
      break;
    case 2:
      next_offset = 248;
      break;
    default:
      next_offset = -1;
    };
  }

  if (0 < next_offset) {
    /* This byte also has to be 0 for it to be a .NET .exe. */
    file_seek (file, filename, pe_offset + next_offset);
    read_bytes (file, filename, 1);
    if ('\0' != bytes[0]) {
      (void) fclose (file);
      try_run ("/usr/bin/mono", filename);
      exit (9);
    }
  }
}

  /*
   * As a last resort, we assume that Wine will be able to make some sense of it.
   */
  void
    start_windows_exe (FILE* file, char* filename)
  {
    assert (NULL != file);
    assert (NULL != filename);
    (void) fclose (file);
    try_run ("/usr/bin/wine", filename);
    exit (10);
  }

  /*
   * The main logic of the program.
   */
  void
    invoke_thunk_for (char* filename)
  {
    FILE* file = fopen (filename, "r");
    if (NULL == file) {
      fprintf (stderr, "\nCan't start file %s: error %d (%s)\n",
               filename, errno, strerror (errno));
      exit (2);
    }
    check_for_exe_header (file, filename);
    maybe_dos_exe (file, filename);
    long pe_offset = pe_header_offset (file, filename);
    check_for_pe_header (file, filename, pe_offset);
    maybe_mono_exe (file, filename, pe_offset);
    start_windows_exe (file, filename);
  }

  void
    print_help_and_exit (char* self)
  {
    fprintf (stderr, "\nUsage: %s filename\n\
\n\
Calls DOSBox or DOSEmu, or Wine, or Mono, depending on the exact \n\
executable file type.\n\
\n\
PC-DOS/MS-DOS/DR-DOS,  MS-Windows,  and  .NET  (Mono)  executable  files\n\
all  use  the .exe  extension, and have the  same  magic cookie bytes in\n\
their header.\n\
This program  will  look deeper  into the headers  to identify  the type\n\
of executable file you have,  and run the appropriate  helper program to\n\
start that program.\n\
\n",
           self);
  exit (0);
}

int
main (int argc, char** argv)
{
  if (argc < 2) {
    fprintf (stderr, "\nError: Usage: %s --help or %s filename\n",
             argv[0], argv[0]);
    exit (1);
  }
  
  if (0 == strcmp (argv[1], "--help")) {
    print_help_and_exit (argv[0]);
  }
  
  if (0 == geteuid () || 0 == getuid ()) {
    fprintf (stderr, "\nError: Refusing to run in superuser state\n");
    exit (6);
  }
  
  init_buffer ();

  saved_argc = argc;
  saved_argv = calloc (sizeof(char*), argc);
  for (int i = 0; i < argc; ++i) {
    saved_argv[i] = strdup (argv[i]);
    printf ("\n save argv[%d] = %s", i, saved_argv[i]);
  }
  
  invoke_thunk_for (argv[1]);
}
