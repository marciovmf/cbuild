#define CBS_IMPLEMENTATION
#include "cbuild.h"
#include <stdio.h>

void test_build_api()
{
  CBGraph* graph = cb_graph_init();
  CBTarget* hello = cb_target_add(graph, CB_EXECUTABLE, "hello.exe");
  cb_target_definitions(hello, "DEBUG", "MY_IMPORTANT_DEFINE");
  cb_target_sources(hello, "hello.c");
  cb_target_compile_flags(hello, "/O2", "/Zi");
  cb_build(graph);
}

int main(int argc, char **argv)
{
  test_build_api();
  printf("Done");
  return 0;
}
