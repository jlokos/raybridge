#!/usr/bin/env bun

/**
 * Spinner adapter for interactive CLI/TUI flows.
 * Only animates when attached to a TTY; no-ops in pipes, logs, CI.
 */

import spinners from "unicode-animations";

export function isInteractive(stream: NodeJS.WriteStream = process.stdout): boolean {
  return Boolean(stream?.isTTY);
}

export function getSpinnerFrames(
  name: keyof typeof spinners = "braille"
): { frames: readonly string[]; interval: number } {
  const s = spinners[name];
  return s ? { frames: s.frames, interval: s.interval } : spinners.braille;
}

const MIN_DISPLAY_MS = 400;

/**
 * Run an async function with an optional terminal spinner.
 * Only animates when stream is a TTY; otherwise runs the task with no spinner.
 * Spinner is shown for at least minDisplayMs so it's visible even when work is instant.
 */
export async function runWithSpinner<T>(
  message: string,
  fn: () => Promise<T>,
  stream: NodeJS.WriteStream = process.stdout,
  minDisplayMs: number = MIN_DISPLAY_MS
): Promise<T> {
  if (!isInteractive(stream)) {
    return fn();
  }

  const { frames, interval } = getSpinnerFrames("braille");
  let i = 0;
  const hideCursor = "\x1B[?25l";
  const showCursor = "\x1B[?25h";
  const clearLine = "\r\x1B[2K";
  const start = Date.now();

  stream.write(hideCursor);
  const timer = setInterval(() => {
    const frame = frames[i++ % frames.length];
    stream.write(`${clearLine}  ${frame} ${message}`);
  }, interval);

  const cleanup = () => {
    clearInterval(timer);
    stream.write(clearLine + showCursor);
  };

  try {
    const result = await fn();
    const elapsed = Date.now() - start;
    if (elapsed < minDisplayMs) {
      await new Promise((r) => setTimeout(r, minDisplayMs - elapsed));
    }
    cleanup();
    return result;
  } catch (err) {
    cleanup();
    throw err;
  }
}

/** Minimum duration (ms) to show loading states so they're visible. */
export const MIN_LOADING_MS = MIN_DISPLAY_MS;

/**
 * Start a manual spinner. Returns a stop function to clear it.
 * Use when the "done" moment is signaled externally (e.g. when TUI is ready).
 * Spinner runs for at least MIN_DISPLAY_MS before stopping.
 */
export function startSpinner(
  message: string,
  stream: NodeJS.WriteStream = process.stdout,
  name: keyof typeof spinners = "orbit"
): () => void {
  if (!isInteractive(stream)) return () => {};

  const { frames, interval } = getSpinnerFrames(name);
  let i = 0;
  const hideCursor = "\x1B[?25l";
  const showCursor = "\x1B[?25h";
  const clearLine = "\r\x1B[2K";
  const start = Date.now();
  let stopped = false;

  stream.write(hideCursor);
  const timer = setInterval(() => {
    if (stopped) return;
    const frame = frames[i++ % frames.length];
    stream.write(`${clearLine}  ${frame} ${message}`);
  }, interval);

  return () => {
    const elapsed = Date.now() - start;
    const remaining = Math.max(0, MIN_DISPLAY_MS - elapsed);
    const cleanup = () => {
      stopped = true;
      clearInterval(timer);
      stream.write(clearLine + showCursor);
    };
    if (remaining > 0) {
      setTimeout(cleanup, remaining);
    } else {
      cleanup();
    }
  };
}
