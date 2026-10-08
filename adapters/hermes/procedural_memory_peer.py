"""Progressive procedure disclosure and factual notes over a borrowed XNET memory."""


class HermesProceduralMemoryPeer:
    """Data-only SDK peer. External Hermes, skills tools and shell scripts are not run."""
    def __init__(self, memory):
        self.memory = memory

    def procedure_catalog(self):
        return [row for row in self.memory.catalog() if row["kind"] == "procedure"]

    def procedure_view(self, memory_id):
        if memory_id not in {row["memory_id"] for row in self.procedure_catalog()}:
            raise ValueError("active procedure ID required")
        return self.memory.load(memory_id)

    def stage_procedure(self, memory_id, **public_arguments):
        return self.memory.stage_procedure(memory_id, **public_arguments)

    def stage_note(self, memory_id, **public_arguments):
        return self.memory.stage_note(memory_id, **public_arguments)
