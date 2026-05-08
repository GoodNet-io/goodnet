# Concurrency и завершение работы

Plugin SDK позволяет плагину держать свои потоки, async операции и
свои регистры состояния. Но граница к ядру через C ABI — узкая, и
при teardown'е её нужно пересекать осторожно. Эта глава фиксирует
правила, которые отличают рабочую реализацию от той, что иногда
проходит, иногда нет.

## Содержание

- [Контракт от ядра](#контракт-от-ядра)
- [Гонка между worker и shutdown](#гонка-между-worker-и-shutdown)
- [Протокол teardown'а](#протокол-teardown-а)
- [Почему `shutdown_` ставится под замком](#почему-shutdown_-ставится-под-замком)
- [Почему `published_ids_` отдельный список](#почему-published_ids_-отдельный-список)
- [`claim_disconnect` для runtime'а](#claim_disconnect-для-runtime-а)
- [Двойной emit и идемпотентность ядра](#двойной-emit-и-идемпотентность-ядра)
- [Skeleton link-плагина](#skeleton-link-плагина)
- [Cross-references](#cross-references)

## Контракт от ядра

Контракт [`link.md §9`](../../contracts/link.en.md) говорит:

> A link's own shutdown path **must** fire `host_api->notify_disconnect`
> synchronously for every session that was published through
> `notify_connect`, before tearing down the executor that owns the
> session strands.

Расшифровка для plugin author'а:

1. Каждой сессии, для которой плагин однажды позвал
   `host_api->notify_connect`, при teardown'е соответствует ровно
   один `notify_disconnect` на потоке вызвавшего `shutdown()`.
2. Сессии, которые завершились по EOF в runtime'е (peer закрыл
   соединение, мы получили EOF на read), должны тоже эмитить
   `notify_disconnect` — но это runtime-emit, на worker thread, и
   он **не отменяет** требования каллер-thread emit'а в shutdown'е.
3. Поток вызвавшего shutdown() — это тот, который позвал
   `IpcLink::shutdown()` или эквивалент. Тестируется через
   `sdk/test/conformance/link_teardown.hpp`'s
   `LinkTeardownConformance.ShutdownReleasesEverySession`.

## Гонка между worker и shutdown

Наивная реализация записывает сессию в `sessions_` map при
`notify_connect`, удаляет при EOF из worker'а, а в shutdown
снимает snapshot текущего map'а и эмитит для каждого id.

Возможны два сценария, в которых snapshot оказывается неполным:

**Случай A.** Peer закрыл соединение раньше, чем мы вызвали
shutdown(). Worker thread получил EOF, забрал mutex, удалил сессию
из map'а, отдал mutex, эмитнул `notify_disconnect` на worker
thread. Затем main thread вызывает `shutdown()` — снимает snapshot
пустого map'а — эмитит ноль на caller thread. Тест видит
`on_main_disconnects = 0` для этой сессии и фейлится.

**Случай B.** shutdown() поставил атомарный флаг `shutdown_`
снаружи mutex'а. Между exchange и acquire mutex'а worker thread
успел зайти под замок, удалить сессию, выйти, эмитнуть на worker.
shutdown() при snapshot'е видит пустой map.

Оба случая нарушают
[`link.md §9`](../../contracts/link.en.md): для опубликованной через
`notify_connect` сессии нет caller-thread emit'а.

## Протокол teardown'а

Линк-плагин держит три структуры под одним `sessions_mu_`:

| Структура | Содержание | Кто пишет |
|---|---|---|
| `sessions_` | id → shared_ptr<Session> для активных сессий | `register_session` добавляет; worker callback и `shutdown` удаляют |
| `published_ids_` | append-only список id, прошедших через `notify_connect` | `register_session` добавляет; только `shutdown` удаляет |
| `shutdown_` | atomic bool, ставится в `shutdown()` под `sessions_mu_` | только `shutdown()` |

Worker callback'и проходят через хелпер `claim_disconnect(id)`,
который под `sessions_mu_` атомарно проверяет `shutdown_`,
удаляет id из `sessions_` и возвращает true только если caller
отвечает за runtime emit. `published_ids_` worker не трогает.

`shutdown()` под тем же `sessions_mu_` ставит `shutdown_` через
exchange, забирает `published_ids_` через `std::move`, чистит
`sessions_`, отдаёт замок и эмитит `notify_disconnect` для каждого
id из перенесённого списка — на потоке вызвавшего.

## Почему `shutdown_` ставится под замком

Если флаг ставится снаружи и проверяется снаружи, между exchange
и snapshot'ом образуется окно: worker callback успевает
проскочить проверку флага и удалить сессию. Внутрь критической
секции shutdown заходит уже на пустом map'е — caller-thread emit
не происходит.

Под замком оба пути сериализуются через `sessions_mu_`. Worker
callback увидит флаг через `claim_disconnect`'s проверку под тем
же замком и не тронет ни `sessions_`, ни не эмитит на worker
thread. shutdown снимает полный snapshot.

## Почему `published_ids_` отдельный список

`sessions_` — это структура live-сессий. При EOF в runtime'е
worker удаляет id оттуда, чтобы освободить память
session'а и не держать `shared_ptr<Session>` на закрытом
сокете дольше нужного. Если бы shutdown снимал snapshot из
`sessions_`, runtime-disconnect'ы не попадали бы в caller-thread
emit (Случай A).

`published_ids_` хранит ВСЁ, что было опубликовано через
`notify_connect`. Worker его не трогает. shutdown забирает
содержимое целиком и эмитит для каждого id, даже для тех, что
worker уже emit'ил на своём потоке.

Память: один `gn_conn_id_t` (8 байт) на каждое historical
соединение через данный экземпляр линка. Освобождается при
`shutdown()`. Для долгоживущих узлов с миллионами соединений
поведение этого вектора нужно пересматривать; для стандартных
сценариев pre-rc1 текущая стоимость приемлема.

## `claim_disconnect` для runtime'а

```cpp
bool TcpLink::claim_disconnect(gn_conn_id_t id) {
    std::lock_guard lk(sessions_mu_);
    if (shutdown_.load(std::memory_order_acquire)) return false;
    return sessions_.erase(id) > 0;
}
```

Семантика: «если плагин ещё работает, удалить сессию из live-map
и сообщить caller'у, что он отвечает за runtime emit». Возвращает
`false`:

- если идёт shutdown — caller-thread emit разберётся
- если сессия уже удалена другим callback'ом (read EOF + write
  error для одного conn'а) — emit уже был сделан

В обоих случаях caller просто `return` без emit'а.

## Двойной emit и идемпотентность ядра

Для соединения, которое worker emit'ил во время runtime'а, а
shutdown затем emit'ит на caller thread, ядро видит два вызова
`notify_disconnect` с одинаковым `gn_conn_id_t`.

[`thunk_notify_disconnect`](../../../core/kernel/host_api_builder.cpp)
делает atomic snapshot+erase из connection registry. Первый
вызов получает snapshot, разрушает security session, чистит
attestation state, фаерит `DISCONNECTED` event. Второй получает
пустой snapshot и возвращает `GN_ERR_NOT_FOUND` без emit'а
event'а.

Плагин кастует результат в `(void)` — ошибка ожидаема и
безвредна. Ядро гарантирует, что повторный emit не приводит к
двойному `DISCONNECTED` для подписчика.

## Skeleton link-плагина

```cpp
class MyLink {
public:
    void register_session(gn_conn_id_t id, std::shared_ptr<Session> s) {
        std::lock_guard lk(sessions_mu_);
        sessions_[id] = std::move(s);
        published_ids_.push_back(id);
    }

    [[nodiscard]] bool claim_disconnect(gn_conn_id_t id) {
        std::lock_guard lk(sessions_mu_);
        if (shutdown_.load(std::memory_order_acquire)) return false;
        return sessions_.erase(id) > 0;
    }

    void shutdown() {
        std::vector<gn_conn_id_t> ids_to_emit;
        {
            std::lock_guard lk(sessions_mu_);
            if (shutdown_.exchange(true, std::memory_order_acq_rel)) return;
            ids_to_emit = std::move(published_ids_);
            published_ids_.clear();
            for (auto& [id, s] : sessions_) s->do_close();
            sessions_.clear();
        }
        if (api_ && api_->notify_disconnect) {
            for (const auto id : ids_to_emit) {
                (void)api_->notify_disconnect(api_->host_ctx, id, GN_OK);
            }
        }
        work_.reset();
        ioc_.stop();
        if (worker_.joinable()) worker_.join();
    }

private:
    mutable std::mutex                                     sessions_mu_;
    std::unordered_map<gn_conn_id_t, std::shared_ptr<Session>> sessions_;
    std::vector<gn_conn_id_t>                              published_ids_;
    std::atomic<bool>                                      shutdown_{false};
};
```

Worker async_read callback:

```cpp
void Session::start_read() {
    socket_.async_read_some(asio::buffer(read_buf_),
        asio::bind_executor(strand_,
            [self = shared_from_this()](
                const std::error_code& ec, std::size_t n) {
                auto t = self->transport_.lock();
                if (!t) return;
                if (ec) {
                    const gn_result_t reason =
                        (ec == asio::error::eof) ? GN_OK : GN_ERR_NULL_ARG;
                    if (t->claim_disconnect(self->conn_id) &&
                        t->api_ && t->api_->notify_disconnect) {
                        t->api_->notify_disconnect(
                            t->api_->host_ctx, self->conn_id, reason);
                    }
                    return;
                }
                /* ... payload path ... */
                self->start_read();
            }));
}
```

## Cross-references

- [`transports.ru.md`](./transports.ru.md) — общий гид по работе
  с link plugin'ом: threading, send/recv, listen vs extension API,
  регулярные грабли. Эта глава раскрывает teardown в деталях.
- [`link.md` §9](../../contracts/link.en.md) — формальный контракт
  shutdown release
- [`signal-channel.md`](../../contracts/signal-channel.en.md) — события,
  которые ядро фаерит в ответ на `notify_disconnect`
- [`memory-management.md`](memory-management.ru.md) — borrowed/owned
  семантика на C ABI границе
- [`error-handling.md`](error-handling.ru.md) — `gn_result_t`
  семантика для `(void)`-cast'а ошибок ожидаемого типа
- [`plugin-lifetime.md`](../../contracts/plugin-lifetime.en.md) §4 —
  как kernel'у важна caller-thread'овая полнота emit'ов для
  drain budget'а
