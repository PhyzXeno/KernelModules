#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int __init init_hello_4(void)
{
    printk(KERN_INFO "Hello, world 4\n");
    return 0;
}

static void __exit cleanup_hello_4(void)
{
    printk(KERN_INFO "Goodbye, world 4\n");
}

module_init(init_hello_4);
module_exit(cleanup_hello_4);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lin Yang");
MODULE_DESCRIPTION("hello-4");
MODULE_SUPPORTED_DEVICE("testdevice");