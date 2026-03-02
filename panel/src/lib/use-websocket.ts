"use client";

import { useEffect, useRef, useState, useCallback } from "react";

interface WSMessage {
  type: string;
  alert?: Record<string, unknown>;
  [key: string]: unknown;
}

type MessageHandler = (msg: WSMessage) => void;

const WS_URL =
  (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080/api/v1")
    .replace("http://", "ws://")
    .replace("https://", "wss://")
    .replace("/api/v1", "/api/v1/dashboard/ws/live");

export function useWebSocket(onMessage?: MessageHandler) {
  const wsRef = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WSMessage | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const onMessageRef = useRef<MessageHandler | undefined>(onMessage);
  onMessageRef.current = onMessage;

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    try {
      const ws = new WebSocket(WS_URL);

      ws.onopen = () => {
        setConnected(true);
        // Send initial ping
        ws.send(JSON.stringify({ type: "ping" }));
      };

      ws.onmessage = (event) => {
        try {
          const data: WSMessage = JSON.parse(event.data);
          setLastMessage(data);
          if (data.type !== "heartbeat" && data.type !== "pong") {
            onMessageRef.current?.(data);
          }
        } catch {
          // Ignore non-JSON messages
        }
      };

      ws.onclose = () => {
        setConnected(false);
        // Auto-reconnect after 3 seconds
        reconnectTimer.current = setTimeout(connect, 3000);
      };

      ws.onerror = () => {
        ws.close();
      };

      wsRef.current = ws;
    } catch {
      reconnectTimer.current = setTimeout(connect, 3000);
    }
  }, []);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  const send = useCallback((data: Record<string, unknown>) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data));
    }
  }, []);

  return { connected, lastMessage, send };
}
