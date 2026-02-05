#!/usr/bin/env bun

import { useState, useEffect, useCallback, useMemo } from "react";
import { createRoot } from "@opentui/react";
import { createCliRenderer, type CliRenderer } from "@opentui/core";
import { useKeyboard } from "@opentui/react";
import { discoverExtensions, type ExtensionEntry, type ToolEntry } from "./discovery.js";
import {
  loadToolsConfig,
  saveToolsConfig,
  type ToolsConfig,
} from "./config.js";

// UI colors with visual hierarchy
const COLORS = {
  // Brand
  red: "#FF6363",
  accent: "#FF6363",
  accentDim: "#CC5050",
  // Selection - red to match brand
  selected: "#FF6363",
  selectedDim: "#CC5050",
  // Content
  white: "#FFFFFF",
  text: "#FFFFFF",
  enabled: "#E0E0E0",
  enabledText: "#E0E0E0",
  disabled: "#606060",
  disabledText: "#606060",
  // Secondary info
  muted: "#888888",
  dim: "#555555",
  border: "#555555",
  // Feedback
  success: "#00FF94",
  warning: "#FFB800",
  error: "#FF4757",
};

// Get terminal dimensions
function getTerminalSize() {
  return {
    cols: process.stdout.columns || 80,
    rows: process.stdout.rows || 24,
  };
}

// ASCII art logo
const LOGO = `
██████╗  █████╗ ██╗   ██╗██████╗ ██████╗ ██╗██████╗  ██████╗ ███████╗
██╔══██╗██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝
██████╔╝███████║ ╚████╔╝ ██████╔╝██████╔╝██║██║  ██║██║  ███╗█████╗
██╔══██╗██╔══██║  ╚██╔╝  ██╔══██╗██╔══██╗██║██║  ██║██║   ██║██╔══╝
██║  ██║██║  ██║   ██║   ██████╔╝██║  ██║██║██████╔╝╚██████╔╝███████╗
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝ ╚══════╝
`.trim();

// Compact logo for narrow terminals
const LOGO_COMPACT = `
█▀█ ▄▀█ █▄█ █▄▄ █▀█ █ █▀▄ █▀▀ █▀▀
█▀▄ █▀█ ░█░ █▄█ █▀▄ █ █▄▀ █▄█ ██▄
`.trim();

// Navigation item types
type NavItem =
  | { type: "section"; id: string; label: string }
  | { type: "extension"; ext: ExtensionEntry }
  | { type: "tool"; ext: ExtensionEntry; tool: ToolEntry };

interface AppState {
  extensions: ExtensionEntry[];
  config: ToolsConfig;
  cursor: number;
  scrollOffset: number;
  expanded: Set<string>;
  loading: boolean;
  saved: boolean;
  error: string | null;
}

interface AppProps {
  onExit: () => void;
}

function App({ onExit }: AppProps) {
  const [state, setState] = useState<AppState>({
    extensions: [],
    config: { mode: "blocklist", extensions: {} },
    cursor: 0,
    scrollOffset: 0,
    expanded: new Set(),
    loading: true,
    saved: false,
    error: null,
  });

  // Track terminal dimensions for responsive layout
  const [terminalSize, setTerminalSize] = useState(getTerminalSize);

  useEffect(() => {
    const handleResize = () => setTerminalSize(getTerminalSize());
    process.stdout.on("resize", handleResize);
    return () => {
      process.stdout.off("resize", handleResize);
    };
  }, []);

  // Calculate visible rows (terminal height minus header and footer)
  const visibleRows = useMemo(() => {
    const { rows } = terminalSize;
    // Header: logo (7 lines) + blank + stats bar = 9
    // Footer: scroll indicator + controls = 2
    return Math.max(rows - 11, 5);
  }, []);

  // Build flat navigation list
  const navItems = useMemo((): NavItem[] => {
    const items: NavItem[] = [];

    if (state.extensions.length > 0) {
      for (const ext of state.extensions) {
        items.push({ type: "extension", ext });
        if (state.expanded.has(ext.extensionName)) {
          for (const tool of ext.tools) {
            items.push({ type: "tool", ext, tool });
          }
        }
      }
    }

    return items;
  }, [state.extensions, state.expanded]);

  // Calculate visible window
  const visibleItems = useMemo(() => {
    const start = state.scrollOffset;
    const end = start + visibleRows;
    return navItems.slice(start, end).map((item, idx) => ({
      item,
      originalIndex: start + idx,
    }));
  }, [navItems, state.scrollOffset, visibleRows]);

  useEffect(() => {
    async function load() {
      try {
        const [extensions, config] = await Promise.all([
          discoverExtensions(),
          loadToolsConfig(),
        ]);

        // First extension is at index 0 now (no section header)
        const initialCursor = 0;

        setState((s) => ({
          ...s,
          extensions,
          config,
          cursor: initialCursor,
          loading: false,
        }));
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        setState((s) => ({
          ...s,
          loading: false,
          error: message,
        }));
      }
    }
    load();
  }, []);

  const isExtensionEnabled = useCallback(
    (ext: ExtensionEntry): boolean => {
      const extConfig = state.config.extensions[ext.extensionName];
      if (state.config.mode === "blocklist") {
        return extConfig?.enabled !== false;
      } else {
        return extConfig?.enabled === true;
      }
    },
    [state.config]
  );

  const isToolEnabled = useCallback(
    (ext: ExtensionEntry, toolName: string): boolean => {
      const extConfig = state.config.extensions[ext.extensionName];
      if (!isExtensionEnabled(ext)) return false;
      if (!extConfig?.tools || extConfig.tools.length === 0) return true;
      return extConfig.tools.includes(toolName);
    },
    [state.config, isExtensionEnabled]
  );

  const getEnabledToolCount = useCallback(
    (ext: ExtensionEntry): number => {
      if (!isExtensionEnabled(ext)) return 0;
      const extConfig = state.config.extensions[ext.extensionName];
      if (!extConfig?.tools || extConfig.tools.length === 0) return ext.tools.length;
      return extConfig.tools.filter((t) => ext.tools.some((et) => et.name === t)).length;
    },
    [state.config, isExtensionEnabled]
  );

  const toggleExtension = useCallback((extName: string) => {
    setState((s) => {
      const ext = s.extensions.find((e) => e.extensionName === extName);
      if (!ext) return s;

      const currentEnabled =
        s.config.mode === "blocklist"
          ? s.config.extensions[extName]?.enabled !== false
          : s.config.extensions[extName]?.enabled === true;

      const newExtensions = { ...s.config.extensions };
      newExtensions[extName] = {
        ...newExtensions[extName],
        enabled: !currentEnabled,
      };

      if (!currentEnabled) {
        delete newExtensions[extName].tools;
      }

      return {
        ...s,
        config: { ...s.config, extensions: newExtensions },
        saved: false,
      };
    });
  }, []);

  const toggleTool = useCallback((extName: string, toolName: string) => {
    setState((s) => {
      const ext = s.extensions.find((e) => e.extensionName === extName);
      if (!ext) return s;

      const extConfig = s.config.extensions[extName] || { enabled: true };
      // If extension is disabled, treat as no tools selected
      // If tools list exists, use it; otherwise all tools are selected
      const extEnabled = s.config.mode === "blocklist"
        ? extConfig.enabled !== false
        : extConfig.enabled === true;
      const currentTools = !extEnabled
        ? new Set<string>()
        : extConfig.tools && extConfig.tools.length > 0
          ? new Set(extConfig.tools)
          : new Set(ext.tools.map((t) => t.name));

      if (currentTools.has(toolName)) {
        currentTools.delete(toolName);
      } else {
        currentTools.add(toolName);
      }

      const newExtensions = { ...s.config.extensions };

      if (currentTools.size === ext.tools.length) {
        newExtensions[extName] = { ...extConfig, enabled: true, tools: undefined };
      } else if (currentTools.size === 0) {
        newExtensions[extName] = { enabled: false, tools: undefined };
      } else {
        newExtensions[extName] = {
          ...extConfig,
          enabled: true,
          tools: Array.from(currentTools),
        };
      }

      return {
        ...s,
        config: { ...s.config, extensions: newExtensions },
        saved: false,
      };
    });
  }, []);

  const toggleExpanded = useCallback((extName: string) => {
    setState((s) => {
      const newExpanded = new Set(s.expanded);
      if (newExpanded.has(extName)) {
        newExpanded.delete(extName);
      } else {
        newExpanded.add(extName);
      }
      return { ...s, expanded: newExpanded };
    });
  }, []);

  const save = useCallback(async () => {
    try {
      await saveToolsConfig(state.config);
      setState((s) => ({ ...s, saved: true }));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setState((s) => ({ ...s, error: `Save failed: ${message}` }));
    }
  }, [state.config]);

  // Scroll to keep cursor visible
  const scrollToCursor = useCallback((newCursor: number) => {
    setState((s) => {
      let newOffset = s.scrollOffset;

      // Scroll down if cursor below visible area
      if (newCursor >= s.scrollOffset + visibleRows) {
        newOffset = newCursor - visibleRows + 1;
      }
      // Scroll up if cursor above visible area
      // Also show section header if cursor is right after one
      if (newCursor < s.scrollOffset) {
        // Check if there's a section header just before this item
        const prevItem = navItems[newCursor - 1];
        if (prevItem?.type === "section") {
          newOffset = newCursor - 1; // Show the section header too
        } else {
          newOffset = newCursor;
        }
      }

      return {
        ...s,
        cursor: newCursor,
        scrollOffset: Math.max(0, newOffset),
        saved: false,
      };
    });
  }, [visibleRows, navItems]);

  useKeyboard((key) => {
    if (state.loading) return;

    if (key.name === "q") {
      onExit();
      return;
    }

    if (key.name === "s") {
      save();
      return;
    }

    if (key.name === "up") {
      let newCursor = state.cursor - 1;
      // Skip section headers
      while (newCursor >= 0 && navItems[newCursor]?.type === "section") {
        newCursor--;
      }
      if (newCursor >= 0) {
        scrollToCursor(newCursor);
      }
      return;
    }

    if (key.name === "down") {
      let newCursor = state.cursor + 1;
      // Skip section headers
      while (newCursor < navItems.length && navItems[newCursor]?.type === "section") {
        newCursor++;
      }
      if (newCursor < navItems.length) {
        scrollToCursor(newCursor);
      }
      return;
    }

    if (key.name === "space") {
      const item = navItems[state.cursor];
      if (!item) return;

      if (item.type === "extension") {
        toggleExtension(item.ext.extensionName);
      } else if (item.type === "tool") {
        toggleTool(item.ext.extensionName, item.tool.name);
      }
      return;
    }

    if (key.name === "return" || key.name === "enter") {
      const item = navItems[state.cursor];
      if (!item) return;

      if (item.type === "extension") {
        toggleExpanded(item.ext.extensionName);
      }
      return;
    }
  });

  // Calculate statistics
  const stats = useMemo(() => {
    const total = state.extensions.length;
    const enabled = state.extensions.filter(isExtensionEnabled).length;
    const toolsTotal = state.extensions.reduce((n, e) => n + e.tools.length, 0);
    const toolsEnabled = state.extensions.reduce((n, e) => n + getEnabledToolCount(e), 0);

    return { total, enabled, toolsTotal, toolsEnabled };
  }, [state.extensions, isExtensionEnabled, getEnabledToolCount]);

  // Use compact logo for smaller terminals
  const displayLogo = terminalSize.cols < 70 ? LOGO_COMPACT : LOGO;

  if (state.loading) {
    return (
      <box flexDirection="column">
        <text fg={COLORS.accent}>{displayLogo}</text>
        <text> </text>
        <text fg={COLORS.muted}>◈ Loading extensions...</text>
      </box>
    );
  }

  if (state.error) {
    return (
      <box flexDirection="column">
        <text fg={COLORS.accent}>{displayLogo}</text>
        <text> </text>
        <text fg={COLORS.error}>✘ Error: {state.error}</text>
        <text fg={COLORS.muted}>  Press q to quit</text>
      </box>
    );
  }

  // Scroll indicator
  const showScrollUp = state.scrollOffset > 0;
  const showScrollDown = state.scrollOffset + visibleRows < navItems.length;

  // Stats bar centered in divider
  const statsText = `${stats.enabled}/${stats.total} EXTENSIONS ══ ${stats.toolsEnabled}/${stats.toolsTotal} TOOLS`;
  const dividerWidth = 60;
  const padLen = Math.max(0, Math.floor((dividerWidth - statsText.length) / 2));
  const statsBar = "─".repeat(padLen) + " " + statsText + " " + "─".repeat(padLen);

  return (
    <box flexDirection="column">
      <text fg={COLORS.accent}>{displayLogo}</text>
      <text> </text>
      <text fg={COLORS.accent}><b>{statsBar}</b></text>

      <box flexDirection="column">
        {visibleItems.map(({ item, originalIndex }) => {
          const isSelected = originalIndex === state.cursor;

          if (item.type === "section") {
            return (
              <text key={item.id} fg={COLORS.accent}>
                <b>  {item.label.toUpperCase()}</b>
              </text>
            );
          }

          if (item.type === "extension") {
            const enabled = isExtensionEnabled(item.ext);
            const enabledTools = getEnabledToolCount(item.ext);
            const totalTools = item.ext.tools.length;
            const isExpanded = state.expanded.has(item.ext.extensionName);

            // Industry-standard toggle indicators (Inquirer.js / Charm.sh style)
            // Checkbox with checkmark: [✔] for enabled, [ ] for disabled
            const checkbox = enabled ? "[✔]" : "[ ]";
            // Expand arrow: ▾ expanded, ▸ collapsed (standard across fzf, lazygit, etc.)
            const arrow = isExpanded ? "▾" : "▸";
            const toolStats = enabled && enabledTools < totalTools
              ? ` (${enabledTools}/${totalTools})`
              : ` (${totalTools})`;

            // Selection pointer: ❯ is the de-facto standard (Inquirer.js, Charm.sh)
            const pointer = isSelected ? "❯" : " ";
            const line = `${pointer} ${checkbox} ${arrow} ${item.ext.extensionTitle}${toolStats}`;

            // Color logic
            let color = COLORS.disabledText;
            if (isSelected) {
              color = COLORS.selected;
            } else if (enabled) {
              color = COLORS.enabledText;
            }

            return (
              <text key={item.ext.extensionName} fg={color}>
                {isSelected ? <b>{line}</b> : line}
              </text>
            );
          }

          if (item.type === "tool") {
            const enabled = isToolEnabled(item.ext, item.tool.name);
            // Nested items use radio-style indicators (◉/◯) to differentiate from parent checkboxes
            // This follows the UX pattern of checkbox for multi-select parent, radio for children
            const radio = enabled ? "◉" : "◯";
            const pointer = isSelected ? "❯" : " ";
            const line = `${pointer}       ${radio} ${item.tool.name}`;

            // Color logic
            let color = COLORS.disabledText;
            if (isSelected) {
              color = COLORS.selected;
            } else if (enabled) {
              color = COLORS.text;
            }

            return (
              <text key={`${item.ext.extensionName}:${item.tool.name}`} fg={color}>
                {isSelected ? <b>{line}</b> : line}
              </text>
            );
          }

          return null;
        })}
      </box>

      <text fg={COLORS.muted}>
        {showScrollUp && showScrollDown ? "  ▲ more  ▼ more" : showScrollUp ? "  ▲ more" : showScrollDown ? "  ▼ more" : ""}
      </text>
      <box flexDirection="row" gap={2}>
        <text fg={COLORS.dim}>↑↓</text>
        <text fg={COLORS.muted}>navigate</text>
        <text fg={COLORS.dim}>⎵</text>
        <text fg={COLORS.muted}>toggle</text>
        <text fg={COLORS.dim}>⏎</text>
        <text fg={COLORS.muted}>expand</text>
        <text fg={COLORS.dim}>s</text>
        <text fg={COLORS.muted}>save</text>
        <text fg={COLORS.dim}>q</text>
        <text fg={COLORS.muted}>quit</text>
      </box>
      {state.saved && <text fg={COLORS.success}>✓ Configuration saved</text>}
    </box>
  );
}

let renderer: CliRenderer | null = null;

export async function launchTUI(): Promise<void> {
  renderer = await createCliRenderer({
    exitOnCtrlC: true,
    useAlternateScreen: true,
  });

  const root = createRoot(renderer);

  return new Promise<void>((resolve) => {
    const handleExit = () => {
      root.unmount();
      renderer?.destroy();
      renderer = null;
      resolve();
    };

    root.render(<App onExit={handleExit} />);
    renderer!.start();
  });
}
