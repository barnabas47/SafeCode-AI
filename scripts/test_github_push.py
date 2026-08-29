import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.git_integration import GitIntegrationEngine

engine = GitIntegrationEngine()

# Test parsing repo url
clean = engine.push_file_to_github(
    target_repo="https://github.com/barnabas47/nebius_test",
    file_path="src/vulnerable_code.py",
    file_content="# Refactored by SafeCode-AI\ndef safe_function():\n    pass\n",
    token="dummy_token_test"
)

print("Test Result:", clean)
