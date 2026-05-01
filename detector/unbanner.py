import time
import threading
from blocker import get_ban_state, unblock_ip
from notifier import send_slack_unban


def _unban_loop(cfg, baseline):
    schedule = cfg["ban"]["backoff_schedule_minutes"]  # e.g. [10, 30, 120, -1]

    while True:
        time.sleep(30)  # Check every 30 seconds
        now = time.time()
        mean, std = baseline.get_stats()

        for ip, state in list(get_ban_state().items()):
            duration_min = state["duration_min"]
            if duration_min == -1:
                continue  # Permanent ban — never auto-unban

            banned_at = state["banned_at"]
            elapsed_min = (now - banned_at) / 60.0

            if elapsed_min >= duration_min:
                ban_index = state["ban_index"]
                next_index = ban_index + 1

                # Determine next ban duration
                if next_index < len(schedule):
                    next_duration = schedule[next_index]
                else:
                    next_duration = schedule[-1]  # Permanent

                unblock_ip(
                    ip,
                    condition="ban_expired",
                    rate=0,
                    mean=mean,
                    duration_min=duration_min,
                )
                send_slack_unban(ip, duration_min, next_duration, mean)

                # If next step is permanent, re-ban permanently
                if next_duration == -1:
                    from blocker import block_ip
                    block_ip(
                        ip, rate=0, mean=mean,
                        condition="escalated_to_permanent",
                        duration_min=-1,
                        ban_index=next_index,
                    )


def start_unbanner(cfg, baseline):
    t = threading.Thread(target=_unban_loop, args=(cfg, baseline), daemon=True)
    t.start()
