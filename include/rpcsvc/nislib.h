#ifndef __RPCSVC_NISLIB_H__
#include <nis/rpcsvc/nislib.h>

# ifndef _ISOMAC

libnsl_hidden_proto (nis_leaf_of_r)
libnsl_hidden_proto (nis_name_of_r)
libnsl_hidden_proto (nis_getnames)
libnsl_hidden_proto (nis_freenames)
libnsl_hidden_proto (nis_dir_cmp)
libnsl_hidden_proto (nis_destroy_object)
libnsl_hidden_proto (nis_local_directory)
libnsl_hidden_proto (nis_local_group)
libnsl_hidden_proto (nis_local_host)
libnsl_hidden_proto (nis_local_principal)
libnsl_hidden_proto (__free_fdresult)
libnsl_hidden_proto (nis_free_request)
libnsl_hidden_proto (nis_free_directory)
libnsl_hidden_proto (nis_free_object)
libnsl_hidden_proto (nis_freeresult)
libnsl_hidden_proto (readColdStartFile)
libnsl_hidden_proto (nis_print_rights)
libnsl_hidden_proto (nis_print_directory)
libnsl_hidden_proto (nis_print_group)
libnsl_hidden_proto (nis_print_table)
libnsl_hidden_proto (nis_print_link)
libnsl_hidden_proto (nis_print_entry)
libnsl_hidden_proto (nis_print_object)
libnsl_hidden_proto (nis_sperrno)
libnsl_hidden_proto (nis_sperror_r)
libnsl_hidden_proto (__nisbind_destroy)
libnsl_hidden_proto (__nisbind_next)
libnsl_hidden_proto (__nisbind_connect)
libnsl_hidden_proto (__nisbind_create)
libnsl_hidden_proto (nis_lookup)
libnsl_hidden_proto (nis_list)
libnsl_hidden_proto (__nis_finddirectory)
libnsl_hidden_proto (nis_domain_of_r)
libnsl_hidden_proto (nis_modify)
libnsl_hidden_proto (nis_remove)
libnsl_hidden_proto (nis_add)
libnsl_hidden_proto (__nis_default_owner)
libnsl_hidden_proto (__nis_default_group)
libnsl_hidden_proto (__nis_default_access)
libnsl_hidden_proto (nis_clone_object)

extern const_nis_name __nis_domain_of (const_nis_name) __THROW;

# endif /* !_ISOMAC */
#endif
