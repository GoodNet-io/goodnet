/**
 * @file   sdk/extensions/ui_event.h
 * @brief  Companion to `gn.ui`: input event envelope catalog.
 *
 * The `gn.ui` extension (`ui.h`) is the *registration* surface
 * plugins use to publish view trees. The companion piece is the
 * *event* surface — how user interaction (click, text input,
 * scroll, focus, lifecycle) flows from the host back to the
 * plugin that drew the widget.
 *
 * Rather than invent a parallel event-loop, the contract reuses
 * the kernel's existing handler dispatch:
 *
 *   - The host fires events as `gn_message_t` envelopes on
 *     protocol id `"ui.event.v1"` with the matching `msg_id`
 *     from @ref gn_ui_event_kind_t.
 *   - The plugin subscribes its `handler_vtable_t` to those
 *     msg ids the same way it would subscribe to `chat.text.v1`
 *     or `store.put.v1`.
 *   - Propagation (CONTINUE/CONSUMED/REJECT), priority order,
 *     and `on_result` hooks all work unchanged — they are the
 *     kernel's, not the UI extension's.
 *
 * @par Envelope payload shape
 *
 * Every event carries a small fixed header followed by a
 * kind-specific tail:
 *
 * ```
 *   view_name   : str (LEB128 length + UTF-8 payload)
 *   callback_id : u32 (little-endian)
 *   payload     : opaque bytes — see per-kind layout below
 * ```
 *
 * The `view_name` matches whatever the plugin registered under
 * (`register_route` / `register_slot`). The `callback_id` matches
 * the value the plugin baked into its widget tree at encode time.
 *
 * @par Wire format independence
 *
 * The event protocol is independent of the view wire format. A
 * Nodex-backed host firing a click event uses the same layout
 * as a Lemma-backed host. Plugins that switch hosts (run under
 * Lemma today, Panel tomorrow) reuse their existing handler.
 *
 * @par msg_id range
 *
 * `0x0100..0x01FF` is reserved for UI events. The block sits
 * outside the kernel-reserved `0x10..0x1F` range and outside the
 * existing handler msg-id allocations (`gn.store` 0x0600..0x0606,
 * `gn.dns` 0x0610..0x0616). Plugin authors get the rest of
 * 0x0100..0x01FF for their own UI sub-events without colliding.
 */
#ifndef GOODNET_SDK_EXTENSIONS_UI_EVENT_H
#define GOODNET_SDK_EXTENSIONS_UI_EVENT_H

#include <stddef.h>
#include <stdint.h>

#include <sdk/abi.h>
#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Stable protocol id every UI plugin's handler subscribes
 *        under. Same value across major releases — extension
 *        versioning lives on `gn.ui` itself, not on this protocol
 *        id.
 */
#define GN_UI_EVENT_PROTOCOL_ID  "ui.event.v1"

/**
 * @brief Kinds of input event delivered as `gn_message_t`
 *        envelopes on @ref GN_UI_EVENT_PROTOCOL_ID. The numeric
 *        value is the `msg_id` field on the envelope.
 *
 * Append-only after v1.0.0 — new kinds get fresh values; existing
 * ones keep their assignment. Plugins that subscribe to a kind
 * the host doesn't emit simply never wake up; plugins that don't
 * subscribe to a kind the host emits cause the host's dispatch
 * to no-op (handler chain empty for that msg_id).
 */
typedef enum gn_ui_event_kind_e {
    /**
     * Click / tap on a widget bound with the matching `on_click`
     * record. Payload: empty.
     */
    GN_UI_EVENT_CLICK         = 0x0100,

    /**
     * Text-field value changed. Payload:
     *   `new_value : str (LEB128 length + UTF-8)`
     * The plugin typically writes the value back into its own
     * state and calls `invalidate(view_name)` to redraw any
     * derived widgets.
     */
    GN_UI_EVENT_TEXT_INPUT    = 0x0101,

    /**
     * Text-field submit (Enter pressed). Payload identical to
     * `TEXT_INPUT`. Hosts fire `TEXT_INPUT` first and `TEXT_SUBMIT`
     * after when both transitions apply in the same frame.
     */
    GN_UI_EVENT_TEXT_SUBMIT   = 0x0102,

    /**
     * Scroll delta on a scroll-view. Payload:
     *   `dx : f32 (little-endian)`
     *   `dy : f32 (little-endian)`
     */
    GN_UI_EVENT_SCROLL        = 0x0103,

    /**
     * Keyboard key state. Payload:
     *   `keycode : u32 (little-endian)`
     *   `mods    : u16 (little-endian)` — bitmask of shift / ctrl
     *                                     / alt / super.
     *   `state   : u8`                 — 0 = up, 1 = down, 2 = repeat.
     * Keycodes follow GLFW's mapping today; the host normalises
     * platform-specific codes before firing the envelope.
     */
    GN_UI_EVENT_KEY           = 0x0104,

    /**
     * Focus changed on a widget. Payload:
     *   `focused : u8` — 0 = lost focus, 1 = gained focus.
     */
    GN_UI_EVENT_FOCUS         = 0x0105,

    /**
     * Lifecycle transition for the registered view. Payload:
     *   `phase : u8` — 0 = mount, 1 = visibility-show, 2 =
     *                  visibility-hide, 3 = unmount.
     *
     * Hosts fire `mount` after the first successful render and
     * `unmount` immediately before they release the registration
     * (during `unregister` cleanup, hot reload, or host shutdown).
     */
    GN_UI_EVENT_LIFECYCLE     = 0x0106
} gn_ui_event_kind_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_EXTENSIONS_UI_EVENT_H */
