#pragma once

#define LIBNAME "cnetlib"

#define fatal(fmt, args...) {\
  fprintf(stderr, "[%s fatal %s() %s@%d]: " fmt, LIBNAME, __FUNCTION__, __FILE__, __LINE__, ##args);\
  exit(1);\
}

#define err(fmt, args...) {\
  fprintf(stderr, "[%s error %s() %s@%d]: " fmt, LIBNAME, __FUNCTION__, __FILE__, __LINE__, ##args);\
}

#define info(fmt, args...) {\
  fprintf(stderr, "[%s info %s() %s@%d]: " fmt, LIBNAME, __FUNCTION__, __FILE__, __LINE__, ##args);\
}
