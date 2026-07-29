import asyncio


# ============ CAM BIEN 4: DOM MUTATION ============
async def _setup_dom_sensor(context, events):
    """
    MutationObserver dat o MAIN WORLD.
    Content script chay o isolated world (JS rieng) NHUNG DOM la CHUNG
    => van thay duoc moi thay doi DOM do content script gay ra.
    """
    async def _report(source, payload):
        try:
            payload = dict(payload or {})
            try:
                payload["page_url"] = source["page"].url
            except Exception:
                pass
            events["dom_activity"].append(payload)
            if payload.get("type") == "node_injected":
                print(f"[Analyze] * DOM inject: <{payload.get('tag')}> "
                      f"{str(payload.get('src'))[:80]}", flush=True)
        except Exception:
            pass

    await context.expose_binding("__extanalyze_report", _report)

    await context.add_init_script("""
    (() => {
      const seen = new Set();
      let injectedCount = 0;
      const send = (d) => { try { window.__extanalyze_report(d); } catch (e) {} };

      const handle = (muts) => {
        for (const m of muts) {
          for (const n of m.addedNodes) {
            if (!n || n.nodeType !== 1) continue;
            injectedCount++;
            const tag = n.tagName;
            if (tag === 'SCRIPT' || tag === 'IFRAME' || tag === 'FORM') {
              const src = n.src || n.action || '(inline)';
              const key = tag + '|' + src;
              if (!seen.has(key)) {
                seen.add(key);
                send({ type: 'node_injected', tag: tag,
                       src: String(src).slice(0, 300) });
              }
            }
          }
        }
      };

      try {
        const obs = new MutationObserver(handle);
        const start = () => {
          try { obs.observe(document.documentElement || document,
                            { childList: true, subtree: true }); } catch (e) {}
        };
        start();
        document.addEventListener('DOMContentLoaded', start);
      } catch (e) {}

      setTimeout(() => send({ type: 'mutation_summary',
                              injected_nodes: injectedCount }), 2500);
    })();
    """)
