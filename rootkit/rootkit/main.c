#include <linux/module.h>

static __init int hello_init(void)
{
	pr_info("hello: Hello World!\n");
	return 0;
}

static __exit void hello_exit(void)
{
	pr_info("hello: Goodbye.\n");
}

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("Beerware");
MODULE_DESCRIPTION("Hello module");
MODULE_AUTHOR("Waystar corporation");
