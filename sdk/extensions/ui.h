/**
 * @file   sdk/extensions/ui.h
 * @brief  Extension vtable: `gn.ui` — view registration ABI for
 *         plugin-driven user interfaces.
 *
 * Plugin runtimes register here the same way they register a
 * `gn.store` consumer or a `gn.strategy` provider: the host (a UI
 * application — Lemma-driven native one, or a Nodex-driven HTML
 * one) publishes a `gn_ui_api_t` vtable under `GN_EXT_UI`; plugins
 * call `query_extension_checked(GN_EXT_UI, GN_EXT_UI_VERSION, &out)`
 * and reach the host through it.
 *
 * The extension is **format-agnostic**. Plugins declare the wire
 * format their render callback emits when they register; the host
 * accepts or rejects based on the formats it knows how to decode.
 * Today's known formats:
 *
 *   - `"lemma.opcode.v1"` — flat opcode stream consumed by Lemma's
 *      native (Vulkan + Cairo) renderer. Catalog lives in Lemma's
 *      `core/view_api.h` and `docs/spec/view-api.md`.
 *   - `"nodex.tree.v1"`   — HTML-shaped node tree consumed by a
 *      Nodex-backed host (GoodNet-Panel admin UI). Catalog lives in
 *      Nodex's own header set.
 *
 * The SDK does not commit to any one format. New formats land by
 * publishing the spec under that name and adding a host that
 * accepts the tag.
 *
 * @par Companion extension
 *
 * Input events (click, text input, scroll, focus, lifecycle) are
 * **not** carried through this vtable. They ride the kernel's
 * normal handler dispatch under protocol id
 * `"ui.event.v1"` — see `sdk/extensions/ui_event.h` for the
 * envelope catalog. A plugin that wants to react to input
 * subscribes its `handler_vtable_t` to one or more of the
 * `GN_UI_EVENT_*` msg ids the same way a chat plugin subscribes
 * to `chat.text.v1`. No second dispatch graph; events ride the
 * same priority chain handlers already pay for.
 *
 * @par Plugin kind
 *
 * Plugins exposing UI views must declare `kind =
 * GN_PLUGIN_KIND_UI` in their descriptor (`sdk/plugin.h`). The
 * kernel gates the registration entries below by kind: only UI
 * plugins may call `register_route` / `register_slot` /
 * `invalidate`. This mirrors the loader-side `notify_*` gating
 * applied to LINK plugins.
 */
#ifndef GOODNET_SDK_EXTENSIONS_UI_H
#define GOODNET_SDK_EXTENSIONS_UI_H

#include <stddef.h>
#include <stdint.h>

#include <sdk/abi.h>
#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Stable extension identifier. Unchanged across minor releases. */
#define GN_EXT_UI          "gn.ui"

/** v1.0.0 — initial release. */
#define GN_EXT_UI_VERSION  0x00010000u

/**
 * @brief Read-only snapshot of host state delivered to every render.
 *
 * Tail-append per ABI evolution rules — consumers read fields
 * only after they have validated `ctx_size`. Hosts always fill
 * the leading `ctx_size` bytes; older consumers safely skip the
 * tail.
 */
typedef struct gn_ui_ctx_s {
    /** sizeof(gn_ui_ctx_t) at the host's build time. */
    uint32_t ctx_size;

    /** Viewport in logical pixels (HiDPI factor already applied). */
    float viewport_x;
    float viewport_y;
    float viewport_w;
    float viewport_h;

    /** Logical-to-physical-pixel ratio. */
    float scale_factor;

    /** 1 when the registered view currently has input focus. */
    uint8_t  has_focus;
    uint8_t  _pad[3];

    /** Reserved tail — read through `ctx_size` gating. */
    uint32_t _reserved[8];
} gn_ui_ctx_t;

/**
 * @brief Output buffer the plugin fills with wire bytes.
 *
 * Lifetime: the bytes pointer must remain valid until the host
 * has consumed the stream. Plugins typically allocate from a
 * per-call arena owned by their `self`, refreshed on each
 * render. Hosts copy what they need before returning.
 */
typedef struct gn_ui_output_s {
    /** @borrowed for the duration of the host's read. */
    const uint8_t* bytes;

    /** Byte length of `bytes`. */
    size_t length;

    /** Wire-format tag — e.g. `"lemma.opcode.v1"`. NUL-terminated. */
    const char* format;
} gn_ui_output_t;

/**
 * @brief Plugin's render entry point.
 *
 * Called by the host whenever the view registered under `name`
 * needs to repaint — typically once per `invalidate(name)`, once
 * per `register_*` admission, and on host-side state changes the
 * plugin subscribed to. The plugin builds a wire stream
 * synchronously and returns `GN_OK` plus a pointer to the bytes.
 *
 * Failures (allocation failure, encoder bug) return non-OK; the
 * host paints nothing for the view that frame and surfaces the
 * failure through its diagnostic channel.
 *
 * @param self  Plugin's per-view state — the value passed at
 *              `register_route` / `register_slot` time.
 * @param ctx   @borrowed; host state for this render pass.
 * @param out   @borrowed caller-allocated; written on success.
 */
typedef gn_result_t (*gn_ui_render_fn)(
    void* self,
    const gn_ui_ctx_t* ctx,
    gn_ui_output_t* out);

/**
 * @brief Vtable surfaced as the `gn.ui` extension.
 *
 * Versioned with @ref GN_EXT_UI_VERSION. Begins with `api_size`
 * for size-prefix evolution per `abi-evolution.md` §3. Consumers
 * query the extension through `host_api->query_extension_checked`
 * which validates `api_size` against the consumer's compile-time
 * minimum before any slot fires.
 *
 * The `ctx` field carries the host's `self` pointer (its
 * internal `ViewApiHost*` or equivalent). Every slot takes it
 * as the first argument.
 */
typedef struct gn_ui_api_s {
    uint32_t api_size;          /**< sizeof(gn_ui_api_t) at producer build time */

    /**
     * @brief Register a top-level view that becomes a switchable
     *        route arm.
     *
     * `route_name` becomes the matching key in the host's
     * `Property<std::string> current_route` (or equivalent). When
     * the route flips, the host calls `render` and mounts the
     * resulting wire stream.
     *
     * @param format       Wire-format tag the plugin's `render`
     *                     will produce (e.g. `"lemma.opcode.v1"`).
     *                     Host rejects unsupported formats with
     *                     `GN_ERR_VERSION_MISMATCH`.
     * @return GN_OK on success; `GN_ERR_NULL_ARG` on a NULL
     *         pointer; `GN_ERR_VERSION_MISMATCH` on an unsupported
     *         format; `GN_ERR_INTERNAL` if `route_name` is already
     *         registered (unregister first to swap).
     */
    gn_result_t (*register_route)(
        void* ctx,
        const char* route_name,
        const char* format,
        gn_ui_render_fn render,
        void* render_self);

    /**
     * @brief Register a slot view — a named extension point inside
     *        a parent route or widget surface.
     *
     * Slot paths are dotted strings (`"chat.composer.attach"`,
     * `"chat.bubble.context"`). The parent plugin emits a slot
     * placeholder record pointing at the path; other plugins (a
     * file plugin, a slash-command bot) register their own renderers
     * under the same path and the host composes them at render
     * time.
     *
     * Multiple plugins MAY register for the same slot path — the
     * host composes them in registration order. Priority hooks
     * land in v1.1 (currently FIFO).
     */
    gn_result_t (*register_slot)(
        void* ctx,
        const char* slot_path,
        const char* format,
        gn_ui_render_fn render,
        void* render_self);

    /**
     * @brief Signal that the view registered under `name` is dirty.
     *
     * Host re-runs the plugin's `render` for that view on the next
     * frame. Idempotent — invalidating an unknown name returns
     * `GN_ERR_NOT_FOUND` quietly without affecting the host's
     * frame schedule.
     */
    gn_result_t (*invalidate)(void* ctx, const char* name);

    /**
     * @brief Cancel a `register_route` / `register_slot`.
     *
     * Returns `GN_OK` even when the name wasn't registered, so the
     * plugin's unregister path can call this unconditionally
     * during shutdown.
     */
    gn_result_t (*unregister)(void* ctx, const char* name);

    /** Host's opaque self. Plugin passes back unchanged. */
    void* ctx;

    void* _reserved[4];
} gn_ui_api_t;

GN_VTABLE_API_SIZE_FIRST(gn_ui_api_t);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_EXTENSIONS_UI_H */
