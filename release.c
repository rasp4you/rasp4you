#include <time.h>
#include "rasp4you.h"
#ifdef DESKTOPPE
int arch = LINUX_64_BIT;
#else
int arch = RASPBIAN;
#endif
int release = 1;
int build = 9;
