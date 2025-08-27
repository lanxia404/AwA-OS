#ifndef AWA_NT_HOOKS_H
#define AWA_NT_HOOKS_H

#ifdef __cplusplus
extern "C" {
#endif

/* 輕量 Hook 介面：dll 名、符號名、函式指標 */
struct Hook { const char* dll; const char* name; void* fn; };

/* 以函式返回掛鉤表頭指標（以 {NULL,NULL,NULL} 為終止）。 */
__attribute__((visibility("default")))
const struct Hook* nt_get_hooks(void);

#ifdef __cplusplus
}
#endif
#endif /* AWA_NT_HOOKS_H */