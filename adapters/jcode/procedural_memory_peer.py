"""Jcode-specific next-user-turn data bridge; borrows XNET's memory lifecycle."""
from xnet.procedural_memory import public_context_packet


class JcodeProceduralMemoryPeer:
    """No Jcode process/provider ownership, tool runner, or weight changes."""
    def __init__(self, memory):
        self.memory = memory

    def publish_background_selection(self, session_id, task_id, memory_ids, *, user_turn_id, now=None):
        return self.memory.queue(session_id, task_id, memory_ids, turn_id=user_turn_id, now=now)

    def consume_fresh_user_turn(self, session_id, request, *, project_id, user_turn_id, now=None):
        public_context_packet(request, [])  # validate the boundary before consuming pending data
        records = self.memory.consume(session_id, request["task"]["task_id"], project_id=project_id,
                                      fresh_turn_id=user_turn_id, now=now)
        return public_context_packet(request, records)
