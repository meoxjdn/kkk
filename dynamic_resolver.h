/*
 * =====================================================================================
 *       Filename:  dynamic_resolver.h
 *    Description:  Kprobe-Based Dynamic Symbol Resolver API
 *   Architecture:  AArch64
 * =====================================================================================
 */
#ifndef _GHOST_DYNAMIC_RESOLVER_H
#define _GHOST_DYNAMIC_RESOLVER_H

/*
 * 初始化动态解析引擎，萃取 kallsyms_lookup_name。
 * 返回值: 0 成功; 负数 失败
 */
extern int ghost_resolver_init(void);

/*
 * 获取未导出内核符号的绝对物理执行地址。
 * name: 符号名称字符串
 * 返回值: 真实的函数指针地址; 解析失败返回 NULL
 */
extern void *ghost_resolve_sym(const char *name);

#endif /* _GHOST_DYNAMIC_RESOLVER_H */
