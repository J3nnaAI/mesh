module github.com/J3nnaAI/mesh/examples/showcase/inventory-svc

go 1.26.4

require (
	github.com/J3nnaAI/mesh/agentkit v0.2.0
	github.com/J3nnaAI/mesh/jip v0.2.0
	github.com/J3nnaAI/mesh/kernel v0.2.0
)

replace github.com/J3nnaAI/mesh/agentkit => ../../../agentkit

replace github.com/J3nnaAI/mesh/jip => ../../../jip

replace github.com/J3nnaAI/mesh/kernel => ../../../kernel
