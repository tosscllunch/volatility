import os
import yara
from volatility3.framework import interfaces, renderers
from volatility3.framework.objects import utility
from volatility3.framework.configuration import requirements
from volatility3.plugins import PluginInterface
from volatility3.plugins.windows import pslist

class YaraScan(PluginInterface):
    _required_framework_version = (2, 0, 0)
    
    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name='kernel', description='Windows kernel',
                architectures=["Intel32", "Intel64"]),
            requirements.ListRequirement(
                name='yara_rules', element_type=str,
                description='List of YARA rule file paths',
                optional=False)
        ]
    
    def _load_yara_rules(self, rule_files):
        rules = {}
        for rule_file in rule_files:
            with open(rule_file, 'r') as rf:
                rule_name = os.path.basename(rule_file)
                rules[rule_name] = yara.compile(source=rf.read())
        return rules
    
    def _scan_process_memory(self, process, rules):
        process_space = process.get_process_memory()
        for rule_name, rule in rules.items():
            matches = rule.match(data=process_space.read())
            if matches:
                yield process.UniqueProcessId, rule_name, matches
    
    def _generator(self):
        kernel = self.context.modules[self.config['kernel']]
        rules = self._load_yara_rules(self.config['yara_rules'])
        
        for process in pslist.PsList.list_processes(context=self.context, layer_name=kernel.layer_name, symbol_table=kernel.symbol_table_name):
            for pid, rule_name, matches in self._scan_process_memory(process, rules):
                for match in matches:
                    yield (0, (pid, rule_name, match.rule, match.meta, match.strings))
    
    def run(self):
        return renderers.TreeGrid([
            ("PID", int),
            ("Rule Name", str),
            ("Match Rule", str),
            ("Match Meta", dict),
            ("Match Strings", list)
        ], self._generator())
