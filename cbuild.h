#ifndef CBUILDSYSTEM_H
#define CBUILDSYSTEM_H

#define CB_PATH_SEPARATOR_UNIX "/"
#define CB_PATH_SEPARATOR_WINDOWS "\\"

#ifdef _WIN32
#   define _CRT_SECURE_NO_WARNINGS
#   define WIN32_MEAN_AND_LEAN
# 	include <windows.h>
# 	define CB_PATH_SEPARATOR CB_PATH_SEPARATOR_WINDOWS
typedef HANDLE Pid;
typedef HANDLE Fd;
#else
# 	define CB_PATH_SEPARATOR CB_PATH_SEPARATOR_UNIX
typedef pid_t Pid;
typedef int Fd;
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#ifndef CB_MAX_PATH
#define CB_MAX_PATH 512
#endif

#ifndef CB_STRING_BUILDER_STACK_BUFFER_SIZE
#define CB_STRING_BUILDER_STACK_BUFFER_SIZE 255
#endif  //cb_STRING_BUILDER_STACK_BUFFER_SIZE

#define cb_info(...) do{printf("INFO:"); printf(__VA_ARGS__);}while(0)
#define cb_warning(...) do{printf("WARNING:"); printf(__VA_ARGS__);}while(0)
#define cb_error(...) do{printf("ERROR:"); printf(__VA_ARGS__);}while(0)
#define cb_print(...) printf(__VA_ARGS__)
#define cb_PANIC(...) do { printf("PANIC:"); printf(__VA_ARGS__); exit(1); }while(0)

#define cb_ASSERT(condition) do{ if ((condition) == false) { fprintf(stderr, "ASSERTION FAILED at %s:%d", __FILE__, __LINE__); *((int*)0) = 0; }} while(0)


#define cb_target_sources(target, ...) cb_target_sources_(target, __VA_ARGS__, NULL)
#define cb_target_definitions(target, ...) cb_target_definitions_(target, __VA_ARGS__, NULL)
#define cb_target_include_path(target, ...) cb_target_include_path_(target, __VA_ARGS__, NULL)
#define cb_target_library_path(target, ...) cb_target_library_path_(target, __VA_ARGS__, NULL)
#define cb_target_compile_flags(target, ...) cb_target_compile_flags_(target, __VA_ARGS__, NULL)
#define cb_target_dependencies(target, ...) cb_target_dependencies_(target, __VA_ARGS__, NULL)

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned char uchar;
typedef char* cstr;
typedef struct CBChunk_t CBChunk;
typedef struct CBArena_t CBArena;
typedef struct CBDirectory_t CBDirectoryHandle;

typedef struct
{
  char *data;
  size_t capacity;
  size_t length;
} CBStringBuilder;

typedef struct
{
  char path[CB_MAX_PATH];
} CBPath;

typedef struct CBArray_t
{
  u8 *data;
  size_t size;
  size_t capacity;
  size_t elementSize;
} CBArray;

CBArena* cb_arena_create(size_t default_chunk_size);
void cb_arena_destroy(CBArena* arena);
void* cb_arena_alloc(CBArena* arena, size_t size);

void cb_string_builder_init(CBStringBuilder *sb);
void cb_string_builder_append(CBStringBuilder *sb, const char *str);
void cb_string_builder_append_format(CBStringBuilder *sb, const char *format, ...);
cstr cb_string_builder_to_string(const CBStringBuilder *sb);
void cb_string_builder_destroy(CBStringBuilder *sb);
void cb_string_builder_clear(CBStringBuilder *sb);

bool cb_path_is_file(const char *path);
bool cb_path_is_directory(const char *path);
bool cb_path_exists(const char *path);
bool cb_file_touch(const char *path);
bool cb_file_delete(const char *path);
char* cb_file_read_null_terminated(const char *path);
bool cb_directory_create(const char *path);
bool cb_directory_create_recursive(const char *path);
bool cb_directory_delete(const char *path);
time_t cb_file_write_time(const char *path);
CBDirectoryHandle *cb_directory_open(const char *path);
const char *cb_directory_get(CBDirectoryHandle *dir);

unsigned int cb_path_init(CBPath *cb_path, const cstr path);
bool cb_get_cwd(CBPath *out);

Pid cmd_run_async(const char* cmd, Fd *fdin, Fd *fdout);
void cmd_run_sync(const char* cmd);


#define CBS_IMPLEMENTATION // REMOVE THIS
#ifdef CBS_IMPLEMENTATION

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef _WIN32
# 	include <winreg.h>
# 	include <process.h>
# 	include <direct.h>
# 	include <io.h>
#   include <process.h>
#   include <fileapi.h>
#   define MAX_KEY_LENGTH 255 // Max Registry KEY length
#   define MAX_VALUE_NAME 16383 // MAx Registry Value length
# 	define mkdir(dir, mode) _mkdir(dir)
# 	define stat(path, out) _stat(path, out)
# 	define getcwd(path, size) _getcwd(path, size)
# 	define rmdir(path) _rmdir(path)
#   define strdup(path) _strdup(path)
#   define S_ISDIR(mode) ((_S_IFDIR & (mode)) == _S_IFDIR)
#   define S_ISREG(mode) ((_S_IFREG & (mode)) == _S_IFREG)
typedef struct _stat64i32 STAT;
#else
#   include <sys/types.h>
#   include <sys/wait.h>
#   include <sys/stat.h>
#   include <unistd.h>
#   include <dirent.h>
#   include <fcntl.h>
#   include <limits.h>
# 	include <unistd.h>
# 	include <dirent.h>
typedef struct stat STAT;
#endif // _WIN32

#ifndef cb_ALLOC
#define cb_ALLOC(size) malloc(size)
#endif

#ifndef cb_FREE
#define cb_FREE(ptr) free(ptr)
#endif

#ifndef cb_REALLOC
#define cb_REALLOC(ptr, size) realloc(ptr, size)
#endif


struct CBChunk_t
{
  size_t size;
  size_t used;
  CBChunk* next;
  char data[];
};

struct CBArena_t {
  CBChunk* head;
  size_t default_chunk_size;
};

struct CBDirectory_t{
#if _WIN32
  HANDLE directory;
  WIN32_FIND_DATAA find_data;
#else
  void *directory;
#endif
};

CBArena* cb_arena_create(size_t default_chunk_size)
{
  CBArena* arena = (CBArena*) cb_ALLOC(sizeof(CBArena));
  if (arena == NULL)
    cb_PANIC("Unable to allocate memory for arena");

  arena->head = NULL;
  arena->default_chunk_size = default_chunk_size;
  return arena;
}

void cb_arena_destroy(CBArena* arena)
{
  if (!arena) return;

  CBChunk* current = arena->head;
  while (current) {
    CBChunk* next = current->next;
    cb_FREE(current);
    current = next;
  }

  free(arena);
}

void* cb_arena_alloc(CBArena* arena, size_t size)
{
  if (!arena) return NULL;

  // Determine the chunk size based on the size requested
  size_t chunk_size = (size > arena->default_chunk_size) ? size : arena->default_chunk_size;

  // Allocate a new chunk
  CBChunk* new_chunk = (CBChunk*)cb_ALLOC(sizeof(CBChunk) + chunk_size);
  if (!new_chunk) return NULL;

  new_chunk->size = chunk_size;
  new_chunk->used = size;
  new_chunk->next = arena->head;
  arena->head = new_chunk;

  return new_chunk->data;
}

void cb_string_builder_init(CBStringBuilder *sb)
{
  sb->capacity = 16; // Initial capacity
  sb->data = (char *)malloc(sb->capacity * sizeof(char));
  sb->length = 0;
  sb->data[0] = '\0'; // Null-terminate the string
}

void cb_string_builder_append(CBStringBuilder *sb, const char *str)
{
  size_t strLen = strlen(str);
  size_t newLength = sb->length + strLen;

  if (newLength + 1 > sb->capacity)
  {
    while (newLength + 1 > sb->capacity)
    {
      sb->capacity *= 2; // Double the capacity
    }
    sb->data = (char *)realloc(sb->data, sb->capacity * sizeof(char));
  }

  strcat(sb->data, str);
  sb->length = newLength;
}

void cb_string_builder_append_format(CBStringBuilder *sb, const char *format, ...)
{
  va_list args;
  va_start(args, format);

  // Stack-allocated buffer for small strings
  char stack_buffer[CB_STRING_BUILDER_STACK_BUFFER_SIZE];
  static const int STACK_BUFFER_SIZE = CB_STRING_BUILDER_STACK_BUFFER_SIZE;

  // Determine the size needed for the formatted string
  size_t needed = vsnprintf(stack_buffer, STACK_BUFFER_SIZE, format, args);

  if (needed < STACK_BUFFER_SIZE)
  {
    // The formatted string fits within the stack buffer
    cb_string_builder_append(sb, stack_buffer);
  }
  else
  {
    // Allocate memory for the formatted string
    char *formatted_str = (char *)malloc((needed + 1) * sizeof(char));

    // Format the string
    vsnprintf(formatted_str, needed + 1, format, args);

    // Append the formatted string to the builder
    cb_string_builder_append(sb, formatted_str);

    // Free memory
    free(formatted_str);
  }

  va_end(args);
}

cstr cb_string_builder_to_string(const CBStringBuilder *sb)
{
  return sb->data;
}

void cb_string_builder_destroy(CBStringBuilder *sb)
{
  cb_FREE(sb->data);
  sb->data = NULL;
  sb->capacity = 0;
  sb->length = 0;
}

void cb_string_builder_clear(CBStringBuilder *sb)
{
  if (sb->length > 0)
  {
    sb->data[0] = 0;
    sb->length = 0;
  }
}

//
// filesystem
//

bool cb_path_is_file(const char *path)
{
  STAT path_stat;
  if (stat(path, &path_stat) != 0)
    return false;
  return S_ISREG(path_stat.st_mode);
}

bool cb_path_is_directory(const char *path)
{
  STAT path_stat;
  if (stat(path, &path_stat) != 0)
    return false;
  return S_ISDIR(path_stat.st_mode);
}

bool cb_path_exists(const char *path)
{
#if _WIN32
  return _access(path, 0) != -1;
#else
  return access(path, 0) != -1;
#endif
}

bool cb_file_touch(const char *path)
{
  FILE *file = fopen(path, "ab+");
  if (file == NULL)
    return false;
  fclose(file);
  return true;
}

bool cb_file_delete(const char *path)
{
  return remove(path) == 0;
}

char *cb_file_read_null_terminated(const char *path)
{
  FILE *file = fopen(path, "r");
  if (file == NULL)
    return NULL;
  fseek(file, 0, SEEK_END);
  long length = ftell(file);
  fseek(file, 0, SEEK_SET);
  char *buffer = (char *)malloc(length + 1);
  if (buffer == NULL)
  {
    fclose(file);
    return NULL;
  }
  fread(buffer, 1, length, file);
  fclose(file);
  buffer[length] = '\0';
  return buffer;
}

bool cb_directory_create(const char *path)
{
#ifdef _WIN32
  return _mkdir(path) == 0;
#else
  return mkdir(path, 0777) == 0;
#endif
}

inline bool cb_is_path_separator(char c)
{
#if _WIN32
  return c == '\\' || c == '/';
#else
  return c == '/';
#endif
}

bool cb_directory_create_recursive(const char *path)
{
  char *tmp = strdup(path);
  char *p = tmp;
  bool success = true;
  while (*p != '\0')
  {
    if (cb_is_path_separator(*p))
    {
      *p = '\0';
      if (!cb_path_exists(tmp) && !cb_directory_create(tmp))
      {
        success = false;
        break;
      }
      *p = CB_PATH_SEPARATOR[0];
    }
    p++;
  }
  free(tmp);
  return success;
}

bool cb_directory_delete(const char *path)
{
  return rmdir(path) == 0;
}

time_t cb_file_write_time(const char *path)
{
  STAT attrib;
  if (stat(path, &attrib) == 0)
    return attrib.st_mtime;
  return -1;
}

CBDirectoryHandle *cb_directory_open(const char *path)
{
  CBDirectoryHandle *dir = (CBDirectoryHandle *)malloc(sizeof(CBDirectoryHandle));
  if (dir == NULL)
    return NULL;

#ifdef _WIN32
  char search_path[CB_MAX_PATH];
  snprintf(search_path, CB_MAX_PATH, "%s\\*", path);
  dir->directory = FindFirstFile(search_path, &dir->find_data);
  if (dir->directory == INVALID_HANDLE_VALUE)
  {
    free(dir);
    return NULL;
  }
#else
  dir->directory = opendir(path);
  if (dir->directory == NULL)
  {
    free(dir);
    return NULL;
  }
#endif

  return dir;
}

const char *cb_directory_get(CBDirectoryHandle *dir)
{
#ifdef _WIN32
  if (FindNextFile(dir->directory, &dir->find_data) == 0)
  {
    return NULL;
  }
  return dir->find_data.cFileName;
#else
  // On POSIX systems, use readdir
  struct dirent *entry = readdir(dir->directory);
  if (entry == NULL)
  {
    // No more entries or error occurred
    return NULL;
  }
  return entry->d_name;
#endif
}

unsigned int cb_path_init(CBPath *cb_path, const cstr path)
{
  unsigned int len = (u32) strlen(path);
  if (len >= CB_MAX_PATH)
    return false;
  strncpy(cb_path->path, path, len);
  cb_path->path[len] = 0;
  return len;
}

bool cb_get_cwd(CBPath *out)
{
  if (out == NULL)
    return false;

  return getcwd(out->path, CB_MAX_PATH) != NULL;
}

#ifdef _WIN32
#define BUFSIZE 4096 

LPSTR GetLastErrorAsString(void)
{
  // https://stackoverflow.com/questions/1387064/how-to-get-the-error-message-from-the-error-code-returned-by-getlasterror
  DWORD errorMessageId = GetLastError();
  //assert(errorMessageId != 0);

  LPSTR messageBuffer = NULL;

  DWORD size =
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, // DWORD   dwFlags,
        NULL, // LPCVOID lpSource,
        errorMessageId, // DWORD   dwMessageId,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // DWORD   dwLanguageId,
        (LPSTR) &messageBuffer, // LPTSTR  lpBuffer,
        0, // DWORD   nSize,
        NULL // va_list *Arguments
        );

  return messageBuffer;
}

#endif  // _WIN32

//
// Command execution
//

Pid cmd_run_async(const char* cmd, Fd *fdin, Fd *fdout)
{
#ifdef _WIN32
  // https://docs.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output

  STARTUPINFO siStartInfo;
  ZeroMemory(&siStartInfo, sizeof(siStartInfo));
  siStartInfo.cb = sizeof(STARTUPINFO);
  // NOTE: theoretically setting NULL to std handles should not be a problem
  // https://docs.microsoft.com/en-us/windows/console/getstdhandle?redirectedfrom=MSDN#attachdetach-behavior
  siStartInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  // TODO(#32): check for errors in GetStdHandle
  siStartInfo.hStdOutput = fdout ? *fdout : GetStdHandle(STD_OUTPUT_HANDLE);
  siStartInfo.hStdInput = fdin ? *fdin : GetStdHandle(STD_INPUT_HANDLE);
  siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

  PROCESS_INFORMATION piProcInfo;
  ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

  BOOL bSuccess =
    CreateProcess(
        NULL,
        // TODO(#33): cmd_run_async on Windows does not render command line properly
        // It may require wrapping some arguments with double-quotes if they contains spaces, etc.
        (char*) cmd,
        NULL,
        NULL,
        TRUE,
        0,
        NULL,
        NULL,
        &siStartInfo,
        &piProcInfo
        );

  if (!bSuccess) {
    printf("Could not create child process %s: %s\n", cmd, GetLastErrorAsString());
  }

  CloseHandle(piProcInfo.hThread);

  return piProcInfo.hProcess;
#else
  pid_t cpid = fork();
  if (cpid < 0) {
    printf("Could not fork child process: %s: %s",
        cmd, strerror(errno));
  }

  if (cpid == 0) {
    args = cmd;

    if (fdin) {
      if (dup2(*fdin, STDIN_FILENO) < 0) {
        printf("Could not setup stdin for child process: %s", strerror(errno));
      }
    }

    if (fdout) {
      if (dup2(*fdout, STDOUT_FILENO) < 0) {
        printf("Could not setup stdout for child process: %s", strerror(errno));
      }
    }

    if (execvp(args.elems[0], (char * const*) args.elems) < 0) {
      printf("Could not exec child process: %s: %s",
          cmd, strerror(errno));
    }
  }

  return cpid;
#endif // _WIN32
}

static void pid_wait(Pid pid)
{
#ifdef _WIN32
  DWORD result = WaitForSingleObject(
      pid,     // HANDLE hHandle,
      INFINITE // DWORD  dwMilliseconds
      );

  if (result == WAIT_FAILED)
  {
    printf("could not wait on child process: %s", GetLastErrorAsString());
  }

  DWORD exit_status;
  if (GetExitCodeProcess(pid, &exit_status) == 0)
  {
    printf("could not get process exit code: %lu", GetLastError());
  }

  if (exit_status != 0)
  {
    printf("command exited with exit code %lu", exit_status);
  }

  CloseHandle(pid);
#else
  for (;;)
  {
    int wstatus = 0;
    if (waitpid(pid, &wstatus, 0) < 0)
    {
      printf("could not wait on command (pid %d): %s", pid, strerror(errno));
    }

    if (WIFEXITED(wstatus))
    {
      int exit_status = WEXITSTATUS(wstatus);
      if (exit_status != 0)
      {
        printf("command exited with exit code %d", exit_status);
      }

      break;
    }

    if (WIFSIGNALED(wstatus))
    {
      printf("command process was terminated by %s", strsignal(WTERMSIG(wstatus)));
    }
  }

#endif // _WIN32
}

void cmd_run_sync(const char* cmd)
{
  pid_wait(cmd_run_async(cmd, NULL, NULL));
}

typedef enum
{
  CB_DYNAMIC_LIBRARY		= 0,
  CB_EXECUTABLE					= 1,
  CB_PCH								= 2,
  CB_STATIC_LIBRARY			= 3,
  CB_CUSTOM_COMMAND			= 4,
} CBTargetType;


//
// CBArray
//

CBArray* cb_array_create(size_t elementSize, size_t capacity)
{
  CBArray* arr = (CBArray*) cb_ALLOC(sizeof(CBArray));
  if (arr == NULL)
  {
    return NULL;
  }

  arr->data = (u8*) cb_ALLOC(capacity * elementSize);
  arr->size = 0;
  arr->capacity = capacity;
  arr->elementSize = elementSize;

  cb_ASSERT(capacity > 0);
  return arr;
}

void cb_array_add(CBArray* arr, void* data)
{
  cb_ASSERT(arr->data != NULL);
  cb_ASSERT(arr->capacity > 0);

  if (arr->size >= arr->capacity)
  {
    arr->capacity = arr->capacity == 0 ? arr->capacity : arr->capacity * 2;
    arr->data = (u8*) cb_REALLOC(arr->data, arr->capacity * arr->elementSize);
    if (!arr->data)
    {
      cb_error("Memory allocation failed");
    }
  }

  if (data != NULL)
    memcpy(arr->data + (arr->size * arr->elementSize), data, arr->elementSize);

  arr->size++;
}

void cb_array_insert(CBArray* arr, void* data, size_t index)
{
  cb_ASSERT(arr->data != NULL);
  cb_ASSERT(arr->capacity > 0);

  if (index > arr->size)
  {
    cb_error("Index out of bounds");
    return;
  }

  if (arr->size >= arr->capacity)
  {
    arr->capacity = arr->capacity == 0 ? 1 : arr->capacity * 2;
    arr->data = (u8*) cb_REALLOC(arr->data, arr->capacity * arr->elementSize);
    if (!arr->data)
    {
      return;
    }
  }

  memmove(arr->data + ((index + 1) * arr->elementSize),
      arr->data + (index * arr->elementSize),
      (arr->size - index) * arr->elementSize);
  memcpy(arr->data + (index * arr->elementSize), data, arr->elementSize);
  arr->size++;
}

void* cb_array_get(CBArray* arr, size_t index)
{
  cb_ASSERT(arr->data != NULL);
  cb_ASSERT(arr->capacity > 0);
  if (index >= arr->size)
  {
    cb_error("Index out of bounds");
    return NULL;
  }

  return (char*)arr->data + (index * arr->elementSize);
}

void cb_array_destroy(CBArray* arr)
{
  cb_ASSERT(arr->data != NULL);
  cb_ASSERT(arr->capacity > 0);

  cb_FREE(arr->data);
  cb_FREE(arr);
}

void cb_array_delete_range(CBArray* arr, size_t start, size_t end)
{
  cb_ASSERT(arr->data != NULL);
  cb_ASSERT(arr->capacity > 0);

  if (start >= arr->size || end >= arr->size || start > end)
  {
    cb_error("Invalid range %d - %d on array of size %d", (int) start, (int) end, (int) arr->size);
    return;
  }

  size_t deleteCount = end - start + 1;
  memmove(
      (char*)arr->data + (start * arr->elementSize),       // Destination
      (char*)arr->data + ((end + 1) * arr->elementSize),   // Source
      (arr->size - end - 1) * arr->elementSize);            // Size
  arr->size -= deleteCount;
}

void cb_array_clear(CBArray* arr)
{
  cb_ASSERT(arr->data != NULL);
  cb_ASSERT(arr->capacity > 0);
  arr->size = 0;
}

u32 cb_array_count(CBArray* arr)
{
  cb_ASSERT(arr->data != NULL);
  cb_ASSERT(arr->capacity > 0);
  return (u32) arr->size;
}

u32 cb_array_capacity(CBArray* arr)
{
  cb_ASSERT(arr->data != NULL);
  cb_ASSERT(arr->capacity > 0);
  return (u32) arr->capacity;
}

void cb_array_delete_at(CBArray* arr, size_t index)
{
  cb_ASSERT(arr->data != NULL);
  cb_ASSERT(arr->capacity > 0);
  cb_array_delete_range(arr, index, index);
}

void* cb_array_get_data(CBArray* arr)
{
  cb_ASSERT(arr->data != NULL);
  cb_ASSERT(arr->capacity > 0);
  return arr->data;
}

typedef struct CBTarget_t CBTarget;

typedef struct
{
  int x;
}CBDynamicLibrary;

typedef struct
{
  int x;
}CBExecutable;

typedef struct
{
  int x;
}CBLibrary;

struct CBTarget_t
{
  CBTargetType	type;
  CBArray *dependecy_array;
  CBArray *include_path_array;
  CBArray *link_library_array;
  CBArray *source_array;
  CBArray *definition_array;
  CBArray *flags_array;
  CBPath  output;

  union
  {
    CBDynamicLibrary  dynamicLibrary;
    CBExecutable      executable;
    CBLibrary         library;
  };
};



typedef struct CBGraph
{
  CBArray* targets;
}CBGraph;

CBGraph* cb_graph_init()
{
  CBGraph* graph = (CBGraph*) cb_ALLOC(sizeof(CBGraph));
  graph->targets = cb_array_create(sizeof(CBTarget), 8);
  return graph;
}

void cb_graph_destroy(CBGraph* graph)
{
  if (graph->targets)
    cb_array_destroy(graph->targets);
  else
    cb_FREE(graph);
}

void cb_target_sources_(CBTarget* target, ...)
{ 
  va_list args;
  va_start(args, target);

  cstr source = NULL;
  while ((source = va_arg(args, cstr)) != NULL)
  {
    CBPath path = {0};
    cb_path_init(&path, source);
    cb_array_add(target->source_array, source);
  }
  va_end(args);
}

CBTarget* cb_target_add(CBGraph* graph, CBTargetType type, const cstr outname)
{
  CBTarget target;
  memset(&target, 0, sizeof(CBTarget));
  target.type = type;
  target.source_array = cb_array_create(sizeof(CBPath), 4);
  cb_path_init(&target.output, outname);
  cb_array_add(graph->targets, &target);
  CBTarget* target_address = (CBTarget*) cb_array_get(graph->targets, graph->targets->size-1);
  return target_address;

}

void cb_target_definitions_(CBTarget* target, ...)
{
  va_list args;
  va_start(args, target);

  if (target->definition_array == NULL)
    target->definition_array = cb_array_create(sizeof(CBPath), 8);

  cstr definition = NULL;
  while ((definition = va_arg(args, cstr)) != NULL)
  {
    CBPath entry = {0};
    cb_path_init(&entry, definition);
    cb_array_add(target->definition_array, definition);
  }
  va_end(args);
}

void cb_target_include_path_(CBTarget* target, ...) 
{ 
  va_list args;
  va_start(args, target);

  if (target->include_path_array == NULL)
    target->include_path_array = cb_array_create(sizeof(CBPath), 8);

  cstr include_path = NULL;
  while ((include_path = va_arg(args, cstr)) != NULL)
  {
    CBPath entry = {0};
    cb_path_init(&entry, include_path);
    cb_array_add(target->include_path_array, &entry);
  }
  va_end(args);
}

void cb_target_library_path_(CBTarget* target, ...)
{ 
  va_list args;
  va_start(args, target);

  if (target->link_library_array == NULL)
    target->link_library_array = cb_array_create(sizeof(CBPath), 8);

  cstr library = NULL;
  while ((library = va_arg(args, cstr)) != NULL)
  {
    CBPath entry = {0};
    cb_path_init(&entry, library);
    cb_array_add(target->link_library_array, &entry);
  }
  va_end(args);
}

void cb_target_compile_flags_(CBTarget* target, ...)
{ 
  va_list args;
  va_start(args, target);

  if (target->flags_array == NULL)
    target->flags_array = cb_array_create(sizeof(CBPath*), 8);

  cstr flags = NULL;
  while ((flags = va_arg(args, cstr)) != NULL)
  {
    CBPath entry = {0};
    cb_path_init(&entry, flags);
    cb_array_add(target->flags_array, &entry);
  }
  va_end(args);
}

void cb_target_dependencies_(CBTarget* target, ...)
{
  va_list args;
  va_start(args, target);

  if (target->dependecy_array == NULL)
    target->dependecy_array = cb_array_create(sizeof(CBTarget*), 6);

  CBTarget* dependency = NULL;
  while ((dependency = va_arg(args, CBTarget*)) != NULL)
  {
    CBPath entry = {0};
    cb_array_add(target->dependecy_array, dependency);
  }
  va_end(args);
}


int cb_build_target(CBTarget* target)
{
  printf("-- BUILDING '%s'\n", target->output.path);
  CBStringBuilder sb;
  cb_string_builder_init(&sb);
  cb_string_builder_append(&sb, "cl.exe /nologo ");

  // sources
  u32 count = (u32) target->source_array->size;
  for (u32 i = 0; i < count; i++)
  {
    CBPath* source = (CBPath*) cb_array_get(target->source_array, i);
    cb_string_builder_append_format(&sb, "%s ", source->path);
  }

  // definitions
  count = (u32) target->definition_array->size;
  for (u32 i = 0; i < count; i++)
  {
    CBPath* define = (CBPath*) cb_array_get(target->definition_array, i);
    cb_string_builder_append_format(&sb, "-D%s ", define->path);
  }

  // flags
  count = (u32) target->flags_array->size;
  for (u32 i = 0; i < count; i++)
  {
    CBPath* flag = (CBPath*) cb_array_get(target->flags_array, i);
    cb_string_builder_append_format(&sb, "%s ", flag->path);
  }

  cb_string_builder_append_format(&sb, "/Fe%s", target->output.path);
  const char* cmd = cb_string_builder_to_string(&sb);
  printf("-- %s\n", cmd);
  cmd_run_sync(cmd);
  return 0;
}

bool cb_build(CBGraph* graph)
{
  bool success = true;

  u32 num_targets = cb_array_count(graph->targets);
  for (u32 i = 0; i < num_targets; i++)
  {
    CBTarget* target = (CBTarget*) cb_array_get(graph->targets, i);
    i32 result = cb_build_target(target);
    success &= (result == 0);
  }

  return success;
}


void XXtest_build_api()
{
  CBGraph* graph = cb_graph_init();
  CBTarget* hello = cb_target_add(graph, CB_EXECUTABLE, "hello.exe");
  cb_target_definitions(hello, "DEBUG", "MY_IMPORTANT_DEFINE");
  cb_target_sources(hello, "hello.c");
  cb_target_compile_flags(hello, "/O2", "/Zi");
  cb_build(graph);

  //CBTarget* some_lib = cb_target_add(&graph, cb_DYNAMIC_LIBRARY);// "lib/some_lib.dll");
  //cb_target_sources(some_lib, "my_lib.c", "my_lib.h");
  //cb_target_definitions(some_lib, "DEBUG", "MY_IMPORTANT_DEFINE");
  //cb_target_include_path(some_lib, ".", "./my_lib");
  //cb_target_compile_flags(some_lib, "DEBUG", "FOO");

  //CBTarget* pch = cb_target_add(&graph, cb_PCH);//, "stdAfx");
  //cb_target_sources(pch, "stdAfx.c", "stdAfx.h", "internal.h");
  //cb_target_dependencies(some_lib, pch);

  //cb_Target target = cb_target_add(&graph, cb_EXECUTABLE, "program");
  //cb_target_sources(&target, "foo.c", "foo.h", "bar.c", "bar.c");
  //cb_target_include_path(&target, ".", "./my_lib");
  //cb_target_dependencies(&pch, &some_lib);

  //cb_target_flags(&targe, | cb_OPTIMZIAITON2 | cb_WALL | cb_WEXTRA | cb_WERROR);

}


#endif  // CBS_IMPLEMENTATION
#endif  // CBUILDSYSTEM_H
