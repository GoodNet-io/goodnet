/**
 * @file   sdk/metrics.h
 * @brief  Plugin-emitted counter surface — kernel-internal counter
 *         store exposed for plugins to write into.
 *
 * GoodNet's kernel keeps a small map of named monotonic counters
 * for built-in observability targets — every router-drop reason,
 * every `RouteOutcome` value, every plugin-quota refusal. Plugins
 * with cross-cutting telemetry (dropped relay frames, retries,
 * cache hits) hand the kernel counter increments through this
 * slot rather than spinning up their own metrics infrastructure.
 *
 * The kernel exposes the resulting counter set through the
 * iteration entry below; an out-of-tree Prometheus / OpenMetrics
 * exporter plugin can scrape that view and serve it on whatever
 * endpoint the operator picks. The kernel itself never carries an
 * HTTP server or a wire-format renderer — the counter store is
 * the surface, exposition is plugin business.
 *
 * Per `docs/contracts/metrics.en.md`.
 */
#ifndef GOODNET_SDK_METRICS_H
#define GOODNET_SDK_METRICS_H

#include <stdint.h>

#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Visitor signature for `iterate_counters`. The kernel calls
 *        this once per registered counter with the counter's name
 *        and current value. Returning non-zero stops the iteration
 *        early; zero continues.
 *
 * `name` borrows from the kernel's internal store and is valid only
 * for the duration of the call. A consumer that needs to retain it
 * past the visitor's return copies into its own buffer.
 */
typedef int32_t (*gn_counter_visitor_t)(void* user_data,
                                         const char* name,
                                         uint64_t value);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_METRICS_H */
