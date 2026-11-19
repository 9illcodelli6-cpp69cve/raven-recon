# gi.repository modules are dynamic; modulegraph marks them missing unless they are
# registered as runtime modules, which is what lets hook-gi.repository.JavaScriptCore.py run.
def pre_safe_import_module(api):
    api.add_runtime_module(api.module_name)
