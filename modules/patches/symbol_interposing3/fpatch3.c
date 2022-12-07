const int rodata_var = 0xdeadbeef;

int foo(void)
{
	printf("I'm the new foo() function!\n");
	printf("The new value of rodata_var is %d\n", rodata_var);
	return 0;
}

/*
int __empty(void)
{
	return;
}
*/
