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
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  const connect = useCallback(() => {
    const ws = new WebSocket(wsUrl(path));
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      retryDelay.current = 1000;
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
      setConnected(false);
      setTimeout(connect, retryDelay.current);
      retryDelay.current = Math.min(retryDelay.current * 1.5, 15000);
    };
    ws.onerror = () => ws.close();
  }, [path]);

  useEffect(() => {
    connect();
    return () => wsRef.current?.close();
  }, [connect]);

  return { connected };
}
