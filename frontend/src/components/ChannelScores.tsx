import type { ChannelScores as CS } from "../api/types";
import { CHANNELS, CHANNEL_LABEL, scoreColor } from "../lib/format";
import { ScoreBar } from "./ui";

export function ChannelScores({ scores, weights, contributions, cards = false }: {
  scores: CS; weights?: Record<string, number>; contributions?: Record<string, number>; cards?: boolean;
}) {
  if (cards) {
    return (
      <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-3">
        {CHANNELS.map((ch) => {
          const v = scores[ch] ?? 0;
          return (
            <div key={ch} className="rounded-lg border border-ink-700 bg-ink-900 p-3">
              <div className="text-[11px] uppercase tracking-wider text-fg-muted">{CHANNEL_LABEL[ch]}</div>
              <div className="font-mono text-2xl font-semibold mt-1 tabular-nums" style={{ color: v >= 0.35 ? scoreColor(v) : "#d8e3ea" }}>
                {Math.round(v * 100)}%
              </div>
              <ScoreBar value={v} color={scoreColor(v)} />
              {weights && (
                <div className="mt-2 text-[11px] text-fg-dim font-mono">
                  w={weights[ch]?.toFixed(2)} · +{(contributions?.[ch] ?? 0).toFixed(1)} pts
                </div>
              )}
            </div>
          );
        })}
      </div>
    );
  }
  return (
    <ul className="space-y-2.5">
      {CHANNELS.map((ch) => {
        const v = scores[ch] ?? 0;
        return (
          <li key={ch} className="grid grid-cols-[88px_1fr_44px] items-center gap-3 text-sm">
            <span className="text-fg-muted">{CHANNEL_LABEL[ch]}</span>
            <ScoreBar value={v} color={scoreColor(v)} height={7} />
            <span className="font-mono text-right tabular-nums">{Math.round(v * 100)}%</span>
          </li>
        );
      })}
    </ul>
  );
}
