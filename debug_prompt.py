
import sys, io, logging
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, 'code')

# Helper to suppress logs
logging.basicConfig(level=logging.ERROR)

from agents.ingestion_agent import IngestionAgent
from agents.context_agent import ContextInferenceAgent
from agents.llm_analysis_agent import LLMCodeAnalysisAgent

ingestion = IngestionAgent('samples2.csv')
samples = ingestion.load()
targets = [s for s in samples if s.id in [105, 118, 120]]

context_agent = ContextInferenceAgent()
llm = LLMCodeAnalysisAgent()

print('=' * 60)
for s in targets:
    print(f'Sample {s.id}:')
    ctx = context_agent.infer(s)
    # Run 2 times to check stability
    for i in range(2):
        print(f"  Attempt {i+1}:")
        finding = llm.analyze(s, ctx, [])
        if finding:
            print(f'    Bug found: {finding.bug_detected}')
            print(f'    Type: {finding.bug_type}')
            print(f'    Conf: {finding.confidence}')
            print(f'    Reasoning: {finding.reasoning[:100]}...')
        else:
            print('    None')
    print('-' * 40)
