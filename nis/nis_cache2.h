/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#ifndef _NIS_CACHE2_H_RPCGEN
#define _NIS_CACHE2_H_RPCGEN

#include <rpc/rpc.h>

#include <rpcsvc/nis.h>

struct fs_result {
	nis_error status;
	long class;
	struct {
		u_int dir_data_len;
		char *dir_data_val;
	} dir_data;
	long server_used;
	long current_ep;
};
typedef struct fs_result fs_result;
#ifdef __cplusplus
extern "C" bool_t xdr_fs_result(XDR *, fs_result*);
#elif __STDC__
extern  bool_t xdr_fs_result(XDR *, fs_result*);
#else /* Old Style C */
bool_t xdr_fs_result();
#endif /* Old Style C */


struct fs_request {
	nis_name name;
	long old_class;
};
typedef struct fs_request fs_request;
#ifdef __cplusplus
extern "C" bool_t xdr_fs_request(XDR *, fs_request*);
#elif __STDC__
extern  bool_t xdr_fs_request(XDR *, fs_request*);
#else /* Old Style C */
bool_t xdr_fs_request();
#endif /* Old Style C */


#define CACHEPROG ((u_long)600100301)
#define CACHE_VER_1 ((u_long)1)

#ifdef __cplusplus
#define NIS_CACHE_READ_COLDSTART ((u_long)1)
extern "C" void * nis_cache_read_coldstart_1(void *, CLIENT *);
extern "C" void * nis_cache_read_coldstart_1_svc(void *, struct svc_req *);
#define NIS_CACHE_FIND_MASTER ((u_long)2)
extern "C" fs_result * nis_cache_find_master_1(char **, CLIENT *);
extern "C" fs_result * nis_cache_find_master_1_svc(char **, struct svc_req *);
#define NIS_CACHE_FIND_SERVER ((u_long)3)
extern "C" fs_result * nis_cache_find_server_1(char **, CLIENT *);
extern "C" fs_result * nis_cache_find_server_1_svc(char **, struct svc_req *);
#define NIS_CACHE_NEXT_SERVER ((u_long)4)
extern "C" fs_result * nis_cache_next_server_1(fs_request *, CLIENT *);
extern "C" fs_result * nis_cache_next_server_1_svc(fs_request *, struct svc_req *);

#elif __STDC__
#define NIS_CACHE_READ_COLDSTART ((u_long)1)
extern  void * nis_cache_read_coldstart_1(void *, CLIENT *);
extern  void * nis_cache_read_coldstart_1_svc(void *, struct svc_req *);
#define NIS_CACHE_FIND_MASTER ((u_long)2)
extern  fs_result * nis_cache_find_master_1(char **, CLIENT *);
extern  fs_result * nis_cache_find_master_1_svc(char **, struct svc_req *);
#define NIS_CACHE_FIND_SERVER ((u_long)3)
extern  fs_result * nis_cache_find_server_1(char **, CLIENT *);
extern  fs_result * nis_cache_find_server_1_svc(char **, struct svc_req *);
#define NIS_CACHE_NEXT_SERVER ((u_long)4)
extern  fs_result * nis_cache_next_server_1(fs_request *, CLIENT *);
extern  fs_result * nis_cache_next_server_1_svc(fs_request *, struct svc_req *);

#else /* Old Style C */
#define NIS_CACHE_READ_COLDSTART ((u_long)1)
extern  void * nis_cache_read_coldstart_1();
extern  void * nis_cache_read_coldstart_1_svc();
#define NIS_CACHE_FIND_MASTER ((u_long)2)
extern  fs_result * nis_cache_find_master_1();
extern  fs_result * nis_cache_find_master_1_svc();
#define NIS_CACHE_FIND_SERVER ((u_long)3)
extern  fs_result * nis_cache_find_server_1();
extern  fs_result * nis_cache_find_server_1_svc();
#define NIS_CACHE_NEXT_SERVER ((u_long)4)
extern  fs_result * nis_cache_next_server_1();
extern  fs_result * nis_cache_next_server_1_svc();
#endif /* Old Style C */

#endif /* !_NIS_CACHE2_H_RPCGEN */
