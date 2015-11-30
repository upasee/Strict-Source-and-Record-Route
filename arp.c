#include "unp.h"
#include "hw_addrs.h"


//Checking for dummy commit - trying to make both work
void convert_mac_to_string(char mac[6])
{
    int i =6;
    char *ptr = mac;
    do {
        printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
    } while (--i > 0);
    printf("\n");
}

void main() {
	
	struct hw_ip_pair *hi_pair;

	hi_pair = malloc(sizeof(struct hw_ip_pair));
	get_hw_ip_pair(hi_pair);

	printf("HW address is: \n");

	printf("IP address is: \n");
}
