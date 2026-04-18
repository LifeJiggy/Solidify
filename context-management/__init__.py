"""Context Management Module"""


class ContextManager:
    def __init__(self):
        self.contexts = {}

    def create(self, ctx_id):
        self.contexts[ctx_id] = {}
        return ctx_id

    def get(self, ctx_id):
        return self.contexts.get(ctx_id, {})

    def set(self, ctx_id, key, value):
        if ctx_id not in self.contexts:
            self.contexts[ctx_id] = {}
        self.contexts[ctx_id][key] = value


class ContextLoader:
    def load(self, path):
        import json

        try:
            with open(path) as f:
                return json.load(f)
        except:
            return {}


class ContextSaver:
    def save(self, data, path):
        import json

        with open(path, "w") as f:
            json.dump(data, f)


context_manager = ContextManager()
context_loader = ContextLoader()
context_saver = ContextSaver()
