import { useEffect, useRef, useState, useCallback } from "react";
import { wsUrl } from "../api";

/**
 * Connects to a WebSocket endpoint and reconnects automatically with
 * backoff if the connection drops. Calls onMessage(data) for every
 * received JSON message.
 */
export function useWebSocket(path, onMessage) {
  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);
  const retryDelay = useRef(1000);
  const retryTimer = useRef(null);
  const keepaliveTimer = useRef(null);
  const stopped = useRef(false);
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  const connect = useCallback(() => {
    if (stopped.current || wsRef.current?.readyState === WebSocket.OPEN || wsRef.current?.readyState === WebSocket.CONNECTING) return;
    const ws = new WebSocket(wsUrl(path));
    wsRef.current = ws;

    ws.onopen = () => {
      if (stopped.current || wsRef.current !== ws) return;
      setConnected(true);
      retryDelay.current = 1000;
      keepaliveTimer.current = window.setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) ws.send("ping");
      }, 20000);
    };
    ws.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        onMessageRef.current?.(data);
      } catch {
        /* ignore malformed frames */
      }
    };
    ws.onclose = () => {
      if (wsRef.current !== ws) return;
      window.clearInterval(keepaliveTimer.current);
      keepaliveTimer.current = null;
      wsRef.current = null;
      setConnected(false);
      if (stopped.current) return;
      retryTimer.current = window.setTimeout(() => {
        retryTimer.current = null;
        connect();
      }, retryDelay.current);
      retryDelay.current = Math.min(retryDelay.current * 1.5, 15000);
    };
    ws.onerror = () => {
      if (ws.readyState !== WebSocket.CLOSED) ws.close();
    };
  }, [path]);

  useEffect(() => {
    stopped.current = false;
    connect();
    return () => {
      stopped.current = true;
      window.clearTimeout(retryTimer.current);
      window.clearInterval(keepaliveTimer.current);
      retryTimer.current = null;
      keepaliveTimer.current = null;
      const ws = wsRef.current;
      wsRef.current = null;
      if (ws && ws.readyState !== WebSocket.CLOSED) ws.close();
      setConnected(false);
    };
  }, [connect]);

  return { connected };
}
