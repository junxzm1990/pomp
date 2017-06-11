#include "insthandler.h"

void test_handler(re_list_t *instnode){

	LOG(stdout, " ****** TEST handler encountered\n");
}


void cmp_handler(re_list_t *instnode){

	LOG(stdout, " ****** CMP handler encountered\n");
}


void test_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	LOG(stdout, " ****** TEST resolver encountered\n");
}


void cmp_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	LOG(stdout, " ****** CMP resolver encountered\n");
}
