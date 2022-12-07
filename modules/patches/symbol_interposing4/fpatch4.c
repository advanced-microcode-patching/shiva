int bss_var;

int foo(void)
{
	bss_var = 0x31337;
	printf("I'm the new foo() function!\n");
	printf("The new value of bss_var is %lx\n", bss_var);
	return 0;
}

/*
int __empty(void)
{
	return;
}
*/
