import { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { getAccessToken, setAccessToken } from "@/lib/api";
import { toast } from "@/components/ui/use-toast";

const IDLE_TIMEOUT_MS = 10 * 60 * 1000;
const WARNING_LEAD_MS = 60 * 1000;
const LAST_ACTIVITY_KEY = "aegis_last_activity_at";
const ACTIVITY_EVENTS: Array<keyof WindowEventMap> = [
  "mousemove",
  "mousedown",
  "keydown",
  "scroll",
  "touchstart",
  "click",
];

export default function IdleLogoutGuard() {
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    const token = getAccessToken();
    const path = location.pathname;
    const isProtected = path.startsWith("/dashboard") || path.startsWith("/admin");
    const isLoginPath = path === "/login" || path === "/admin/login";

    if (!token || !isProtected || isLoginPath) {
      return;
    }

    let timeoutId: number | undefined;
    let warningTimeoutId: number | undefined;
    let lastPersistedAt = 0;

    const logoutForInactivity = () => {
      setAccessToken(null);
      localStorage.removeItem(LAST_ACTIVITY_KEY);
      const target = path.startsWith("/admin") ? "/admin/login" : "/login";
      navigate(target, { replace: true, state: { reason: "idle_timeout" } });
    };

    const scheduleFromLastActivity = () => {
      const raw = localStorage.getItem(LAST_ACTIVITY_KEY);
      const lastActivityAt = raw ? Number(raw) : Date.now();
      const elapsed = Date.now() - (Number.isFinite(lastActivityAt) ? lastActivityAt : Date.now());
      const remaining = IDLE_TIMEOUT_MS - elapsed;

      if (timeoutId) {
        window.clearTimeout(timeoutId);
      }
      if (warningTimeoutId) {
        window.clearTimeout(warningTimeoutId);
      }
      if (remaining <= 0) {
        logoutForInactivity();
        return;
      }
      if (remaining > WARNING_LEAD_MS) {
        warningTimeoutId = window.setTimeout(() => {
          toast({
            title: "Session expiring soon",
            description: "You will be logged out in 1 minute due to inactivity.",
          });
        }, remaining - WARNING_LEAD_MS);
      }
      timeoutId = window.setTimeout(logoutForInactivity, remaining);
    };

    const markActivity = () => {
      const now = Date.now();
      if (now - lastPersistedAt >= 5000) {
        localStorage.setItem(LAST_ACTIVITY_KEY, String(now));
        lastPersistedAt = now;
      }
      scheduleFromLastActivity();
    };

    const onStorage = (event: StorageEvent) => {
      if (event.key === LAST_ACTIVITY_KEY) {
        scheduleFromLastActivity();
      }
    };

    markActivity();
    for (const eventName of ACTIVITY_EVENTS) {
      window.addEventListener(eventName, markActivity, { passive: true });
    }
    document.addEventListener("visibilitychange", markActivity);
    window.addEventListener("focus", markActivity);
    window.addEventListener("storage", onStorage);

    return () => {
      if (timeoutId) {
        window.clearTimeout(timeoutId);
      }
      if (warningTimeoutId) {
        window.clearTimeout(warningTimeoutId);
      }
      for (const eventName of ACTIVITY_EVENTS) {
        window.removeEventListener(eventName, markActivity);
      }
      document.removeEventListener("visibilitychange", markActivity);
      window.removeEventListener("focus", markActivity);
      window.removeEventListener("storage", onStorage);
    };
  }, [location.pathname, navigate]);

  return null;
}
