.PHONY: help install ingest benchmark benchmark-multi benchmark-baseline ui test clean format lint

PY := python3

help:
	@echo "CodeSentinel - available targets"
	@echo ""
	@echo "  make install       Install pinned dependencies"
	@echo "  make ingest        Build the RAG knowledge base"
	@echo "  make benchmark     Run full eval (baseline + multi-agent)"
	@echo "  make benchmark-multi     Run multi-agent only"
	@echo "  make benchmark-baseline  Run baseline only"
	@echo "  make ui            Launch Streamlit UI"
	@echo "  make test          Run pytest suite"
	@echo "  make synth         Generate synthetic evaluation samples"
	@echo "  make clean         Remove build artifacts"
	@echo ""

install:
	$(PY) -m pip install -r requirements.txt

ingest:
	$(PY) -m rag.ingest

benchmark:
	$(PY) -m eval.run_benchmark --mode both

benchmark-multi:
	$(PY) -m eval.run_benchmark --mode multi

benchmark-baseline:
	$(PY) -m eval.run_benchmark --mode baseline

ui:
	streamlit run app/streamlit_app.py

test:
	CODESENTINEL_MOCK_LLM=1 $(PY) -m pytest tests/ -v

synth:
	$(PY) -m synth.generate --count 20 --out eval/datasets/synthetic_suite.json
	$(PY) -m synth.verify eval/datasets/synthetic_suite.json

clean:
	rm -rf rag/chroma_store rag/tfidf_index.pkl rag/tfidf_index.json
	rm -rf eval/results/*
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
